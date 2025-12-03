//! Double-sign protection for remote signer.
//!
//! Prevents the validator from signing conflicting messages for the same
//! round/epoch, which would result in slashing.

use crate::protocol::{KeyType, SignRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Errors related to double-sign protection.
#[derive(Debug, Error)]
pub enum DoubleSignError {
    #[error("Conflicting signature detected: already signed different message for domain {domain} at round {round}, epoch {epoch}")]
    ConflictingSignature {
        domain: String,
        round: u64,
        epoch: u64,
    },

    #[error("Failed to persist state: {0}")]
    PersistError(#[from] std::io::Error),

    #[error("Failed to parse state file: {0}")]
    ParseError(#[from] serde_json::Error),
}

/// Record of a previously signed message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastSigned {
    /// Round number
    pub round: u64,
    /// Epoch number
    pub epoch: u64,
    /// SHA-256 hash of the signed message
    pub message_hash: [u8; 32],
    /// Unix timestamp when signed
    pub timestamp: u64,
    /// Key type used
    pub key_type: KeyType,
}

/// Persistent state for double-sign protection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoubleSignState {
    /// Map from domain (hex-encoded) to last signed record
    pub last_signed: HashMap<String, LastSigned>,
    /// High-water mark for each domain (highest round/epoch ever signed)
    pub high_water_mark: HashMap<String, (u64, u64)>, // (epoch, round)
}

/// Guard that prevents double-signing.
///
/// Maintains persistent state to ensure the signer never signs
/// conflicting messages, even across restarts.
pub struct DoubleSignGuard {
    state_file: PathBuf,
    state: DoubleSignState,
}

impl DoubleSignGuard {
    /// Create a new double-sign guard with persistent state.
    ///
    /// If the state file exists, it will be loaded. Otherwise, a new
    /// empty state will be created.
    pub fn new(state_file: PathBuf) -> Result<Self, DoubleSignError> {
        let state = if state_file.exists() {
            info!("Loading double-sign protection state from {:?}", state_file);
            let file = File::open(&state_file)?;
            let reader = BufReader::new(file);
            serde_json::from_reader(reader)?
        } else {
            info!(
                "Creating new double-sign protection state at {:?}",
                state_file
            );
            DoubleSignState::default()
        };

        Ok(Self { state_file, state })
    }

    /// Check if signing this request would be a double-sign violation.
    ///
    /// If allowed, records the signature. If not, returns an error.
    pub fn check_and_record(&mut self, req: &SignRequest) -> Result<(), DoubleSignError> {
        let domain_key = hex::encode(&req.domain);
        let msg_hash = self.hash_message(&req.message);

        // Extract round/epoch from message if possible
        // For now, we use a simplified approach: just track by domain + message hash
        // In production, we'd parse the actual message to extract round/epoch
        let (epoch, round) = self.extract_epoch_round(&req.message);

        debug!(
            "Checking sign request: domain={}, epoch={}, round={}, hash={}",
            domain_key,
            epoch,
            round,
            hex::encode(&msg_hash[..8])
        );

        // Check high-water mark - never sign for a round/epoch we've already passed
        if let Some(&(last_epoch, last_round)) = self.state.high_water_mark.get(&domain_key) {
            if epoch < last_epoch || (epoch == last_epoch && round < last_round) {
                warn!(
                    "Rejecting sign request for past round: domain={}, requested=({},{}), hwm=({},{})",
                    domain_key, epoch, round, last_epoch, last_round
                );
                return Err(DoubleSignError::ConflictingSignature {
                    domain: domain_key,
                    round,
                    epoch,
                });
            }
        }

        // Check if we've already signed something for this exact round/epoch
        if let Some(last) = self.state.last_signed.get(&domain_key) {
            if last.epoch == epoch && last.round == round {
                // Same round/epoch - check if it's the same message
                if last.message_hash != msg_hash {
                    error!(
                        "DOUBLE-SIGN ATTEMPT BLOCKED: domain={}, epoch={}, round={}, prev_hash={}, new_hash={}",
                        domain_key,
                        epoch,
                        round,
                        hex::encode(&last.message_hash[..8]),
                        hex::encode(&msg_hash[..8])
                    );
                    return Err(DoubleSignError::ConflictingSignature {
                        domain: domain_key,
                        round,
                        epoch,
                    });
                }
                // Same message - idempotent, allow it
                debug!("Allowing idempotent sign request for same message");
                return Ok(());
            }
        }

        // Record this signature
        let record = LastSigned {
            round,
            epoch,
            message_hash: msg_hash,
            timestamp: current_timestamp(),
            key_type: req.key_type,
        };

        self.state.last_signed.insert(domain_key.clone(), record);

        // Update high-water mark
        self.state
            .high_water_mark
            .entry(domain_key)
            .and_modify(|(e, r)| {
                if epoch > *e || (epoch == *e && round > *r) {
                    *e = epoch;
                    *r = round;
                }
            })
            .or_insert((epoch, round));

        // Persist state
        self.persist()?;

        Ok(())
    }

    /// Hash a message using SHA-256.
    fn hash_message(&self, message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().into()
    }

    /// Extract epoch and round from message.
    ///
    /// This is a simplified implementation. In production, we would
    /// parse the RLP-encoded message to extract actual consensus values.
    fn extract_epoch_round(&self, message: &[u8]) -> (u64, u64) {
        // For PoC: Use message hash as a simple identifier
        // The actual implementation would parse the message structure
        //
        // Vote message structure (from monad-consensus):
        // Vote { round: Round, epoch: Epoch, ... }
        //
        // For now, we'll use bytes 0-8 as epoch and 8-16 as round
        // This is a placeholder - real implementation needs proper parsing
        if message.len() >= 16 {
            let epoch = u64::from_le_bytes(message[0..8].try_into().unwrap_or([0; 8]));
            let round = u64::from_le_bytes(message[8..16].try_into().unwrap_or([0; 8]));
            (epoch, round)
        } else {
            // Fallback: use first 8 bytes as a combined identifier
            let id = if message.len() >= 8 {
                u64::from_le_bytes(message[0..8].try_into().unwrap_or([0; 8]))
            } else {
                0
            };
            (0, id)
        }
    }

    /// Persist state to disk.
    fn persist(&self) -> Result<(), DoubleSignError> {
        // Write to temp file first, then rename (atomic on POSIX)
        let temp_path = self.state_file.with_extension("tmp");

        // Ensure parent directory exists
        if let Some(parent) = self.state_file.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = File::create(&temp_path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &self.state)?;

        // Sync to disk before rename
        let file = File::open(&temp_path)?;
        file.sync_all()?;

        // Atomic rename
        fs::rename(&temp_path, &self.state_file)?;

        debug!("Persisted double-sign protection state");
        Ok(())
    }

    /// Get the current state (for debugging/monitoring).
    pub fn state(&self) -> &DoubleSignState {
        &self.state
    }

    /// Clear all state (use with caution - only for testing).
    #[cfg(test)]
    pub fn clear(&mut self) -> Result<(), DoubleSignError> {
        self.state = DoubleSignState::default();
        self.persist()
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_guard() -> (DoubleSignGuard, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("state.json");
        let guard = DoubleSignGuard::new(state_file).unwrap();
        (guard, temp_dir)
    }

    #[test]
    fn test_allow_first_sign() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: b"test-domain".to_vec(),
            message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1], // epoch=1, round=1
            request_id: 1,
        };

        assert!(guard.check_and_record(&req).is_ok());
    }

    #[test]
    fn test_allow_same_message_twice() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: b"test-domain".to_vec(),
            message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],
            request_id: 1,
        };

        assert!(guard.check_and_record(&req).is_ok());
        // Same request again should be idempotent
        assert!(guard.check_and_record(&req).is_ok());
    }

    #[test]
    fn test_block_conflicting_signature() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: b"test-domain".to_vec(),
            message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1], // epoch=1, round=1
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: b"test-domain".to_vec(),
            message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 99], // Same epoch/round, different content
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        assert!(guard.check_and_record(&req2).is_err());
    }

    #[test]
    fn test_allow_different_rounds() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: b"test-domain".to_vec(),
            message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1], // epoch=1, round=1
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: b"test-domain".to_vec(),
            message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2], // epoch=1, round=2
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        assert!(guard.check_and_record(&req2).is_ok());
    }

    #[test]
    fn test_block_past_round() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: b"test-domain".to_vec(),
            message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5], // epoch=1, round=5
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: b"test-domain".to_vec(),
            message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3], // epoch=1, round=3 (past!)
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        assert!(guard.check_and_record(&req2).is_err());
    }

    #[test]
    fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("state.json");

        // Create guard and sign something
        {
            let mut guard = DoubleSignGuard::new(state_file.clone()).unwrap();
            let req = SignRequest {
                key_type: KeyType::Bls,
                domain: b"test-domain".to_vec(),
                message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],
                request_id: 1,
            };
            guard.check_and_record(&req).unwrap();
        }

        // Create new guard from same file - should have same state
        {
            let mut guard = DoubleSignGuard::new(state_file).unwrap();
            let req = SignRequest {
                key_type: KeyType::Bls,
                domain: b"test-domain".to_vec(),
                message: vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 99], // Different!
                request_id: 2,
            };
            // Should be blocked because we already signed for this round
            assert!(guard.check_and_record(&req).is_err());
        }
    }
}
