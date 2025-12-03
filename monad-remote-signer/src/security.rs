//! Double-sign protection for remote signer.
//!
//! Prevents the validator from signing conflicting messages for the same
//! round/epoch, which would result in slashing.
//!
//! ## Supported Domains
//!
//! The remote signer explicitly supports these 6 domains required for validator operations:
//!
//! ### Epoch/Round Protected (BLS):
//! - Vote - Consensus voting
//! - Timeout - Timeout signaling
//! - NoEndorsement - No-tip voting
//!
//! ### Round Protected:
//! - RoundSignature (BLS) - RANDAO contribution
//! - Tip (Secp256k1) - Block header signing
//!
//! ### Idempotent:
//! - ConsensusMessage (Secp256k1) - Message wrapper
//!
//! ## Rejected Domains
//!
//! - NameRecord, RaptorcastAppMessage, RaptorcastChunk - Not required for consensus

use crate::protocol::{KeyType, SignRequest};
use alloy_rlp::Decodable;
use monad_consensus_types::no_endorsement::NoEndorsement;
use monad_consensus_types::timeout::TimeoutInfo;
use monad_consensus_types::voting::Vote;
use monad_crypto::signing_domain::{self, SigningDomain};
use monad_types::Round;
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
    #[error("Conflicting signature: domain={domain}, epoch={epoch}, round={round}")]
    ConflictingSignature { domain: String, epoch: u64, round: u64 },

    #[error("Conflicting round signature: domain={domain}, round={round}")]
    ConflictingRoundSignature { domain: String, round: u64 },

    #[error("Unsupported domain: {domain} - not required for consensus")]
    UnsupportedDomain { domain: &'static str },

    #[error("Unknown domain: {domain_hex}")]
    UnknownDomain { domain_hex: String },

    #[error("Failed to decode {domain} message: {source}")]
    DecodeError {
        domain: &'static str,
        #[source]
        source: alloy_rlp::Error,
    },

    #[error("Failed to persist state: {0}")]
    PersistError(#[from] std::io::Error),

    #[error("Failed to parse state file: {0}")]
    ParseError(#[from] serde_json::Error),
}

/// Signing domain category for protection strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningCategory {
    /// Epoch/Round based protection (Vote, Timeout, NoEndorsement)
    /// Same (epoch, round) with different message = REJECT
    EpochRoundProtected { epoch: u64, round: u64 },

    /// Round-only based protection (RoundSignature, Tip)
    /// Same round with different message = REJECT
    RoundProtected { round: u64 },

    /// No protection needed (ConsensusMessage)
    /// Always allowed - wrapper for other messages
    Idempotent,
}

/// Record of a previously signed message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastSigned {
    /// Round number
    pub round: u64,
    /// Epoch number (0 for round-only protected domains)
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
    /// High-water mark for epoch/round protected domains: (epoch, round)
    pub high_water_mark_epoch_round: HashMap<String, (u64, u64)>,
    /// High-water mark for round-only protected domains: round
    pub high_water_mark_round: HashMap<String, u64>,
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

        // Categorize the domain and extract protection parameters
        let category = Self::categorize_domain(&req.domain, &req.message)?;

        match category {
            SigningCategory::EpochRoundProtected { epoch, round } => {
                self.check_epoch_round_protected(&domain_key, epoch, round, msg_hash, req.key_type)?;
            }
            SigningCategory::RoundProtected { round } => {
                self.check_round_protected(&domain_key, round, msg_hash, req.key_type)?;
            }
            SigningCategory::Idempotent => {
                debug!(
                    "Allowing idempotent sign request for domain={}",
                    domain_key
                );
                // No protection needed, just sign
            }
        }

        Ok(())
    }

    /// Check epoch/round protected domains (Vote, Timeout, NoEndorsement)
    fn check_epoch_round_protected(
        &mut self,
        domain_key: &str,
        epoch: u64,
        round: u64,
        msg_hash: [u8; 32],
        key_type: KeyType,
    ) -> Result<(), DoubleSignError> {
        debug!(
            "Checking epoch/round protected: domain={}, epoch={}, round={}, hash={}",
            domain_key,
            epoch,
            round,
            hex::encode(&msg_hash[..8])
        );

        // Check high-water mark - never sign for a round/epoch we've already passed
        if let Some(&(last_epoch, last_round)) =
            self.state.high_water_mark_epoch_round.get(domain_key)
        {
            if epoch < last_epoch || (epoch == last_epoch && round < last_round) {
                warn!(
                    "Rejecting sign request for past round: domain={}, requested=({},{}), hwm=({},{})",
                    domain_key, epoch, round, last_epoch, last_round
                );
                return Err(DoubleSignError::ConflictingSignature {
                    domain: domain_key.to_string(),
                    round,
                    epoch,
                });
            }
        }

        // Check if we've already signed something for this exact round/epoch
        if let Some(last) = self.state.last_signed.get(domain_key) {
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
                        domain: domain_key.to_string(),
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
            key_type,
        };

        self.state
            .last_signed
            .insert(domain_key.to_string(), record);

        // Update high-water mark
        self.state
            .high_water_mark_epoch_round
            .entry(domain_key.to_string())
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

    /// Check round-only protected domains (RoundSignature, Tip)
    fn check_round_protected(
        &mut self,
        domain_key: &str,
        round: u64,
        msg_hash: [u8; 32],
        key_type: KeyType,
    ) -> Result<(), DoubleSignError> {
        debug!(
            "Checking round protected: domain={}, round={}, hash={}",
            domain_key,
            round,
            hex::encode(&msg_hash[..8])
        );

        // Check high-water mark - never sign for a round we've already passed
        if let Some(&last_round) = self.state.high_water_mark_round.get(domain_key) {
            if round < last_round {
                warn!(
                    "Rejecting sign request for past round: domain={}, requested={}, hwm={}",
                    domain_key, round, last_round
                );
                return Err(DoubleSignError::ConflictingRoundSignature {
                    domain: domain_key.to_string(),
                    round,
                });
            }
        }

        // Check if we've already signed something for this exact round
        if let Some(last) = self.state.last_signed.get(domain_key) {
            if last.round == round {
                // Same round - check if it's the same message
                if last.message_hash != msg_hash {
                    error!(
                        "DOUBLE-SIGN ATTEMPT BLOCKED: domain={}, round={}, prev_hash={}, new_hash={}",
                        domain_key,
                        round,
                        hex::encode(&last.message_hash[..8]),
                        hex::encode(&msg_hash[..8])
                    );
                    return Err(DoubleSignError::ConflictingRoundSignature {
                        domain: domain_key.to_string(),
                        round,
                    });
                }
                // Same message - idempotent, allow it
                debug!("Allowing idempotent sign request for same message");
                return Ok(());
            }
        }

        // Record this signature (epoch=0 for round-only)
        let record = LastSigned {
            round,
            epoch: 0,
            message_hash: msg_hash,
            timestamp: current_timestamp(),
            key_type,
        };

        self.state
            .last_signed
            .insert(domain_key.to_string(), record);

        // Update high-water mark
        self.state
            .high_water_mark_round
            .entry(domain_key.to_string())
            .and_modify(|r| {
                if round > *r {
                    *r = round;
                }
            })
            .or_insert(round);

        // Persist state
        self.persist()?;

        Ok(())
    }

    /// Categorize domain and extract protection parameters.
    ///
    /// Returns the signing category with extracted epoch/round values,
    /// or an error if the domain is not supported or message decode fails.
    fn categorize_domain(domain: &[u8], message: &[u8]) -> Result<SigningCategory, DoubleSignError> {
        // Category 1: Epoch/Round Protected (BLS)
        if domain == signing_domain::Vote::PREFIX {
            let vote = Vote::decode(&mut &message[..]).map_err(|e| DoubleSignError::DecodeError {
                domain: "Vote",
                source: e,
            })?;
            return Ok(SigningCategory::EpochRoundProtected {
                epoch: vote.epoch.0,
                round: vote.round.0,
            });
        }

        if domain == signing_domain::Timeout::PREFIX {
            let info =
                TimeoutInfo::decode(&mut &message[..]).map_err(|e| DoubleSignError::DecodeError {
                    domain: "Timeout",
                    source: e,
                })?;
            return Ok(SigningCategory::EpochRoundProtected {
                epoch: info.epoch.0,
                round: info.round.0,
            });
        }

        if domain == signing_domain::NoEndorsement::PREFIX {
            let ne = NoEndorsement::decode(&mut &message[..]).map_err(|e| {
                DoubleSignError::DecodeError {
                    domain: "NoEndorsement",
                    source: e,
                }
            })?;
            return Ok(SigningCategory::EpochRoundProtected {
                epoch: ne.epoch.0,
                round: ne.round.0,
            });
        }

        // Category 2: Round Protected
        if domain == signing_domain::RoundSignature::PREFIX {
            let round =
                Round::decode(&mut &message[..]).map_err(|e| DoubleSignError::DecodeError {
                    domain: "RoundSignature",
                    source: e,
                })?;
            return Ok(SigningCategory::RoundProtected { round: round.0 });
        }

        if domain == signing_domain::Tip::PREFIX {
            // ConsensusBlockHeader is generic, but block_round is the first RLP field
            let round = Self::extract_block_round_from_header(message)?;
            return Ok(SigningCategory::RoundProtected { round });
        }

        // Category 3: Idempotent
        if domain == signing_domain::ConsensusMessage::PREFIX {
            return Ok(SigningCategory::Idempotent);
        }

        // REJECT: Unsupported domains (not required for consensus)
        if domain == signing_domain::NameRecord::PREFIX {
            return Err(DoubleSignError::UnsupportedDomain {
                domain: "NameRecord",
            });
        }

        if domain == signing_domain::RaptorcastAppMessage::PREFIX {
            return Err(DoubleSignError::UnsupportedDomain {
                domain: "RaptorcastAppMessage",
            });
        }

        if domain == signing_domain::RaptorcastChunk::PREFIX {
            return Err(DoubleSignError::UnsupportedDomain {
                domain: "RaptorcastChunk",
            });
        }

        // REJECT: Unknown domain
        Err(DoubleSignError::UnknownDomain {
            domain_hex: hex::encode(domain),
        })
    }

    /// Extract block_round from ConsensusBlockHeader RLP encoding.
    ///
    /// ConsensusBlockHeader is a generic struct, but block_round is always
    /// the first field in the RLP list.
    fn extract_block_round_from_header(message: &[u8]) -> Result<u64, DoubleSignError> {
        // RLP list starts with a header, then the first element is block_round
        // We need to parse just enough to get the first u64
        let mut buf = &message[..];

        // Decode the list header to get payload
        let header = alloy_rlp::Header::decode(&mut buf).map_err(|e| DoubleSignError::DecodeError {
            domain: "Tip",
            source: e,
        })?;

        if !header.list {
            return Err(DoubleSignError::DecodeError {
                domain: "Tip",
                source: alloy_rlp::Error::UnexpectedString,
            });
        }

        // First element in the list is block_round (Round wrapper around u64)
        let round = Round::decode(&mut buf).map_err(|e| DoubleSignError::DecodeError {
            domain: "Tip",
            source: e,
        })?;

        Ok(round.0)
    }

    /// Hash a message using SHA-256.
    fn hash_message(&self, message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().into()
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

    // ==================== Encode helpers ====================

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

    /// Create a test NoEndorsement and RLP-encode it
    fn encode_no_endorsement(epoch: u64, round: u64, tip_qc_round: u64) -> Vec<u8> {
        let no_endorsement = NoEndorsement {
            epoch: Epoch(epoch),
            round: Round(round),
            tip_qc_round: Round(tip_qc_round),
        };
        alloy_rlp::encode(&no_endorsement)
    }

    /// Create a test Round and RLP-encode it (for RoundSignature)
    fn encode_round(round: u64) -> Vec<u8> {
        alloy_rlp::encode(&Round(round))
    }

    // ==================== Vote Tests ====================

    #[test]
    fn test_vote_first_sign_allowed() {
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
    fn test_vote_same_message_idempotent() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 1, 0),
            request_id: 1,
        };

        assert!(guard.check_and_record(&req).is_ok());
        assert!(guard.check_and_record(&req).is_ok());
    }

    #[test]
    fn test_vote_double_sign_blocked() {
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
            message: encode_vote(1, 1, 99), // Different block_id!
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        let err = guard.check_and_record(&req2).unwrap_err();
        assert!(matches!(err, DoubleSignError::ConflictingSignature { .. }));
    }

    #[test]
    fn test_vote_past_round_blocked() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 5, 0),
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Vote::PREFIX.to_vec(),
            message: encode_vote(1, 3, 0), // Past round!
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        let err = guard.check_and_record(&req2).unwrap_err();
        assert!(matches!(err, DoubleSignError::ConflictingSignature { .. }));
    }

    // ==================== Timeout Tests ====================

    #[test]
    fn test_timeout_first_sign_allowed() {
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
    fn test_timeout_double_sign_blocked() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Timeout::PREFIX.to_vec(),
            message: encode_timeout_info(1, 1, 0),
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::Timeout::PREFIX.to_vec(),
            message: encode_timeout_info(1, 1, 5), // Different high_qc_round!
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        let err = guard.check_and_record(&req2).unwrap_err();
        assert!(matches!(err, DoubleSignError::ConflictingSignature { .. }));
    }

    // ==================== NoEndorsement Tests ====================

    #[test]
    fn test_no_endorsement_first_sign_allowed() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::NoEndorsement::PREFIX.to_vec(),
            message: encode_no_endorsement(1, 1, 0),
            request_id: 1,
        };

        assert!(guard.check_and_record(&req).is_ok());
    }

    #[test]
    fn test_no_endorsement_double_sign_blocked() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::NoEndorsement::PREFIX.to_vec(),
            message: encode_no_endorsement(1, 1, 0),
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::NoEndorsement::PREFIX.to_vec(),
            message: encode_no_endorsement(1, 1, 5), // Different tip_qc_round!
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        let err = guard.check_and_record(&req2).unwrap_err();
        assert!(matches!(err, DoubleSignError::ConflictingSignature { .. }));
    }

    // ==================== RoundSignature Tests ====================

    #[test]
    fn test_round_signature_first_sign_allowed() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::RoundSignature::PREFIX.to_vec(),
            message: encode_round(1),
            request_id: 1,
        };

        assert!(guard.check_and_record(&req).is_ok());
    }

    #[test]
    fn test_round_signature_different_rounds_allowed() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::RoundSignature::PREFIX.to_vec(),
            message: encode_round(1),
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::RoundSignature::PREFIX.to_vec(),
            message: encode_round(2),
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        assert!(guard.check_and_record(&req2).is_ok());
    }

    #[test]
    fn test_round_signature_past_round_blocked() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::RoundSignature::PREFIX.to_vec(),
            message: encode_round(5),
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::RoundSignature::PREFIX.to_vec(),
            message: encode_round(3), // Past round!
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        let err = guard.check_and_record(&req2).unwrap_err();
        assert!(matches!(
            err,
            DoubleSignError::ConflictingRoundSignature { .. }
        ));
    }

    // ==================== ConsensusMessage Tests (Idempotent) ====================

    #[test]
    fn test_consensus_message_always_allowed() {
        let (mut guard, _temp) = create_test_guard();

        let req1 = SignRequest {
            key_type: KeyType::Secp256k1,
            domain: signing_domain::ConsensusMessage::PREFIX.to_vec(),
            message: vec![1, 2, 3, 4],
            request_id: 1,
        };

        let req2 = SignRequest {
            key_type: KeyType::Secp256k1,
            domain: signing_domain::ConsensusMessage::PREFIX.to_vec(),
            message: vec![5, 6, 7, 8], // Different message - still allowed
            request_id: 2,
        };

        assert!(guard.check_and_record(&req1).is_ok());
        assert!(guard.check_and_record(&req2).is_ok());
    }

    // ==================== Unsupported Domain Tests ====================

    #[test]
    fn test_name_record_rejected() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Secp256k1,
            domain: signing_domain::NameRecord::PREFIX.to_vec(),
            message: vec![1, 2, 3, 4],
            request_id: 1,
        };

        let err = guard.check_and_record(&req).unwrap_err();
        assert!(matches!(
            err,
            DoubleSignError::UnsupportedDomain { domain: "NameRecord" }
        ));
    }

    #[test]
    fn test_raptorcast_app_message_rejected() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Secp256k1,
            domain: signing_domain::RaptorcastAppMessage::PREFIX.to_vec(),
            message: vec![1, 2, 3, 4],
            request_id: 1,
        };

        let err = guard.check_and_record(&req).unwrap_err();
        assert!(matches!(
            err,
            DoubleSignError::UnsupportedDomain {
                domain: "RaptorcastAppMessage"
            }
        ));
    }

    #[test]
    fn test_raptorcast_chunk_rejected() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: signing_domain::RaptorcastChunk::PREFIX.to_vec(),
            message: vec![1, 2, 3, 4],
            request_id: 1,
        };

        let err = guard.check_and_record(&req).unwrap_err();
        assert!(matches!(
            err,
            DoubleSignError::UnsupportedDomain {
                domain: "RaptorcastChunk"
            }
        ));
    }

    // ==================== Unknown Domain Tests ====================

    #[test]
    fn test_unknown_domain_rejected() {
        let (mut guard, _temp) = create_test_guard();

        let req = SignRequest {
            key_type: KeyType::Bls,
            domain: b"invalid-domain".to_vec(),
            message: vec![1, 2, 3, 4],
            request_id: 1,
        };

        let err = guard.check_and_record(&req).unwrap_err();
        assert!(matches!(err, DoubleSignError::UnknownDomain { .. }));
    }

    // ==================== Cross-domain Tests ====================

    #[test]
    fn test_different_domains_separate_tracking() {
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

    // ==================== Persistence Tests ====================

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
            let err = guard.check_and_record(&req).unwrap_err();
            assert!(matches!(err, DoubleSignError::ConflictingSignature { .. }));
        }
    }
}
