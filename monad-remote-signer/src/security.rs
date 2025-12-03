//! Double-sign protection for remote signer.
//!
//! Prevents the validator from signing conflicting messages for the same
//! round/epoch, which would result in slashing.

use crate::protocol::{KeyType, SignRequest};
use alloy_rlp::Decodable;
use monad_consensus_types::timeout::TimeoutInfo;
use monad_consensus_types::voting::Vote;
use monad_crypto::signing_domain::{self, SigningDomain};
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

        // Extract round/epoch from message based on signing domain
        let Some((epoch, round)) = self.extract_epoch_round(&req.domain, &req.message) else {
            // Cannot extract epoch/round - skip double-sign protection for this domain
            // This is intentional: we only protect Vote and Timeout messages
            debug!(
                "Skipping double-sign protection for domain={} (unknown message type)",
                domain_key
            );
            return Ok(());
        };

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

    /// Extract epoch and round from message based on signing domain.
    ///
    /// Parses the RLP-encoded message to extract epoch and round values
    /// based on the signing domain prefix.
    fn extract_epoch_round(&self, domain: &[u8], message: &[u8]) -> Option<(u64, u64)> {
        // Check domain prefix to determine message type
        if domain == signing_domain::Vote::PREFIX {
            // Decode Vote message
            match Vote::decode(&mut &message[..]) {
                Ok(vote) => Some((vote.epoch.0, vote.round.0)),
                Err(e) => {
                    warn!("Failed to decode Vote message: {:?}", e);
                    None
                }
            }
        } else if domain == signing_domain::Timeout::PREFIX {
            // Decode TimeoutInfo message
            match TimeoutInfo::decode(&mut &message[..]) {
                Ok(timeout_info) => Some((timeout_info.epoch.0, timeout_info.round.0)),
                Err(e) => {
                    warn!("Failed to decode TimeoutInfo message: {:?}", e);
                    None
                }
            }
        } else {
            // Unknown domain - cannot extract epoch/round
            // This is not an error, but we cannot provide double-sign protection
            // for unknown message types
            debug!(
                "Unknown signing domain: {}, skipping epoch/round extraction",
                hex::encode(domain)
            );
            None
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
    use monad_types::{BlockId, Epoch, Hash, Round, GENESIS_ROUND};
    use tempfile::TempDir;

    fn create_test_guard() -> (DoubleSignGuard, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("state.json");
        let guard = DoubleSignGuard::new(state_file).unwrap();
        (guard, temp_dir)
    }

    /// Create a test Vote and RLP-encode it
    fn encode_vote(epoch: u64, round: u64, block_id_byte: u8) -> Vec<u8> {
        let mut hash = [0u8; 32];
        hash[0] = block_id_byte;
        let vote = Vote {
            id: BlockId(Hash(hash)),
            round: Round(round),
            epoch: Epoch(epoch),
        };
        alloy_rlp::encode(&vote)
    }

    /// Create a test TimeoutInfo and RLP-encode it
    fn encode_timeout_info(epoch: u64, round: u64, high_qc_round: u64) -> Vec<u8> {
        let timeout_info = TimeoutInfo {
            epoch: Epoch(epoch),
            round: Round(round),
            high_qc_round: Round(high_qc_round),
            high_tip_round: GENESIS_ROUND,
        };
        alloy_rlp::encode(&timeout_info)
    }

    #[test]
    fn test_allow_first_vote_sign() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 1, 0),
            request_id: 1,
        };

        assert!(guard.check_and_record(&req).is_ok());
    }

    #[test]
    fn test_allow_first_timeout_sign() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Timeout::PREFIX.to_vec(),
            message: encode_timeout_info(1, 1, 0),
            request_id: 1,
        };

        assert!(guard.check_and_record(&req).is_ok());
    }

    #[test]
    fn test_allow_same_vote_twice() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 1, 0),
            request_id: 1,
        };

        assert!(guard.check_and_record(&req).is_ok());
        // Same request again should be idempotent
        assert!(guard.check_and_record(&req).is_ok());
    }

    #[test]
    fn test_block_conflicting_vote() {
        let (mut guard, _temp) = create_test_guard();

        // First vote for epoch=1, round=1, block_id with byte 0
        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 1, 0),
            request_id: 1,
        };

        // Second vote for same epoch/round but different block_id
        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 1, 99), // Different block_id!
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        assert!(guard.check_and_record(&req2).is_err());
    }

    #[test]
    fn test_block_conflicting_timeout() {
        let (mut guard, _temp) = create_test_guard();

        // First timeout for epoch=1, round=1
        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Timeout::PREFIX.to_vec(),
            message: encode_timeout_info(1, 1, 0),
            request_id: 1,
        };

        // Second timeout for same epoch/round but different high_qc_round
        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Timeout::PREFIX.to_vec(),
            message: encode_timeout_info(1, 1, 5), // Different high_qc_round!
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
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 1, 0),
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 2, 0), // Different round
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
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 5, 0), // epoch=1, round=5
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 3, 0), // epoch=1, round=3 (past!)
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        assert!(guard.check_and_record(&req2).is_err());
    }

    #[test]
    fn test_allow_different_epochs() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 5, 0), // epoch=1, round=5
            request_id: 1,
        };

        // New epoch resets round tracking
        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(2, 1, 0), // epoch=2, round=1
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        assert!(guard.check_and_record(&req2).is_ok());
    }

    #[test]
    fn test_block_past_epoch() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(2, 1, 0), // epoch=2
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 10, 0), // epoch=1 (past epoch!)
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
                domain: signing_domain::Vote::PREFIX.to_vec(),
                message: encode_vote(1, 1, 0),
                request_id: 1,
            };
            guard.check_and_record(&req).unwrap();
        }

        // Create new guard from same file - should have same state
        {
            let mut guard = DoubleSignGuard::new(state_file).unwrap();
            let req = SignRequest {
                key_type: KeyType::Bls,
                domain: signing_domain::Vote::PREFIX.to_vec(),
                message: encode_vote(1, 1, 99), // Different block_id!
                request_id: 2,
            };
            // Should be blocked because we already signed for this round
            assert!(guard.check_and_record(&req).is_err());
        }
    }

    #[test]
    fn test_unknown_domain_allowed() {
        let (mut guard, _temp) = create_test_guard();

        // Unknown domain - should be allowed (no double-sign protection)
        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: b"unknown-domain".to_vec(),
            message: vec![1, 2, 3, 4],
            request_id: 1,
        };

        assert!(guard.check_and_record(&req).is_ok());

        // Same unknown domain with different message - also allowed
        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: b"unknown-domain".to_vec(),
            message: vec![5, 6, 7, 8],
            request_id: 2,
        };

        assert!(guard.check_and_record(&req2).is_ok());
    }

    #[test]
    fn test_vote_and_timeout_separate_tracking() {
        let (mut guard, _temp) = create_test_guard();

        // Sign a vote for epoch=1, round=1
        let vote_req = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 1, 0),
            request_id: 1,
        };

        // Sign a timeout for same epoch/round (different domain)
        let timeout_req = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Timeout::PREFIX.to_vec(),
            message: encode_timeout_info(1, 1, 0),
            request_id: 2,
        };

        // Both should succeed (different domains)
        assert!(guard.check_and_record(&vote_req).is_ok());
        assert!(guard.check_and_record(&timeout_req).is_ok());
    }
}
