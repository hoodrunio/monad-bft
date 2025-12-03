//! Wire protocol for remote signer communication.
//!
//! Uses a simple length-prefixed binary format over Unix sockets.

use serde::{Deserialize, Serialize};

/// Key type for signing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// BLS12-381 key (used for votes and certificates)
    Bls,
    /// secp256k1 key (used for consensus messages)
    Secp256k1,
}

/// Request to sign a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// Type of key to use for signing
    pub key_type: KeyType,
    /// Signing domain prefix (from SigningDomain::PREFIX)
    pub domain: Vec<u8>,
    /// Message bytes to sign
    pub message: Vec<u8>,
    /// Unique request ID for idempotency
    pub request_id: u64,
}

/// Response from signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignResponse {
    /// Successful signature
    Success {
        /// The signature bytes
        signature: Vec<u8>,
        /// Echo of request ID
        request_id: u64,
    },
    /// Signing was rejected (e.g., double-sign protection)
    Rejected {
        /// Reason for rejection
        reason: String,
        /// Echo of request ID
        request_id: u64,
    },
    /// Internal error
    Error {
        /// Error message
        message: String,
        /// Echo of request ID
        request_id: u64,
    },
}

/// Request to get public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyRequest {
    /// Type of key to get
    pub key_type: KeyType,
}

/// Response with public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyResponse {
    /// Public key bytes
    pub pubkey: Vec<u8>,
}

/// All possible messages from client to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Sign(SignRequest),
    GetPubKey(PubKeyRequest),
    Ping,
}

/// All possible messages from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Sign(SignResponse),
    PubKey(PubKeyResponse),
    Pong,
}

impl SignRequest {
    /// Create a new sign request.
    pub fn new(key_type: KeyType, domain: Vec<u8>, message: Vec<u8>) -> Self {
        Self {
            key_type,
            domain,
            message,
            request_id: generate_request_id(),
        }
    }
}

/// Generate a unique request ID based on timestamp and random component.
fn generate_request_id() -> u64 {
    use rand::Rng;
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    // Mix in some randomness
    let random: u32 = rand::thread_rng().gen();
    timestamp ^ (random as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_request_serialization() {
        let req = SignRequest::new(
            KeyType::Bls,
            b"\x0Dmonad/vote/1\n".to_vec(),
            b"test message".to_vec(),
        );

        let encoded = bincode::serialize(&Request::Sign(req.clone())).unwrap();
        let decoded: Request = bincode::deserialize(&encoded).unwrap();

        match decoded {
            Request::Sign(decoded_req) => {
                assert_eq!(decoded_req.key_type, req.key_type);
                assert_eq!(decoded_req.domain, req.domain);
                assert_eq!(decoded_req.message, req.message);
            }
            _ => panic!("Expected Sign request"),
        }
    }

    #[test]
    fn test_sign_response_serialization() {
        let resp = SignResponse::Success {
            signature: vec![1, 2, 3, 4],
            request_id: 12345,
        };

        let encoded = bincode::serialize(&Response::Sign(resp.clone())).unwrap();
        let decoded: Response = bincode::deserialize(&encoded).unwrap();

        match decoded {
            Response::Sign(SignResponse::Success {
                signature,
                request_id,
            }) => {
                assert_eq!(signature, vec![1, 2, 3, 4]);
                assert_eq!(request_id, 12345);
            }
            _ => panic!("Expected Success response"),
        }
    }
}
