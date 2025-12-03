// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Remote signing support for keystore.
//!
//! This module provides factory functions to create remote keypairs that
//! communicate with a remote signer daemon via Unix socket.
//!
//! ## Usage
//!
//! ```ignore
//! use monad_keystore::remote::{create_remote_bls_keypair, RemoteSignerConfig};
//!
//! let config = RemoteSignerConfig {
//!     socket_path: PathBuf::from("/var/run/monad-signer.sock"),
//!     pubkey_bls: Some("abcd1234...".to_string()),
//!     pubkey_secp: Some("0234...".to_string()),
//! };
//!
//! let bls_keypair = create_remote_bls_keypair(&config)?;
//! // Use bls_keypair with CertificateSignature trait
//! ```

use monad_bls::{BlsPubKey, BlsSigningCallback, RemoteBlsKeyPair};
use monad_crypto::certificate_signature::PubKey;
use monad_secp::{PubKey as SecpPubKey, RemoteSecpKeyPair, SecpSigningCallback};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;

/// Configuration for remote signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSignerConfig {
    /// Path to the Unix socket
    pub socket_path: PathBuf,
    /// Cached BLS public key (hex-encoded, compressed)
    pub pubkey_bls: Option<String>,
    /// Cached secp256k1 public key (hex-encoded, compressed 33 bytes)
    pub pubkey_secp: Option<String>,
}

/// Key type for signing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Bls,
    Secp256k1,
}

/// Request to sign a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignRequest {
    key_type: KeyType,
    domain: Vec<u8>,
    message: Vec<u8>,
    request_id: u64,
}

/// Response from signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum SignResponse {
    Success { signature: Vec<u8>, request_id: u64 },
    Rejected { reason: String, request_id: u64 },
    Error { message: String, request_id: u64 },
}

/// Request types for protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Request {
    Sign(SignRequest),
    GetPubKey { key_type: KeyType },
    Ping,
}

/// Response types for protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Response {
    Sign(SignResponse),
    PubKey { pubkey: Vec<u8> },
    Pong,
}

/// Error from remote signing operations.
#[derive(Debug)]
pub enum RemoteSignError {
    Io(std::io::Error),
    Protocol(String),
    Serialization(bincode::Error),
}

impl std::fmt::Display for RemoteSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteSignError::Io(e) => write!(f, "IO error: {}", e),
            RemoteSignError::Protocol(s) => write!(f, "Protocol error: {}", s),
            RemoteSignError::Serialization(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for RemoteSignError {}

impl From<std::io::Error> for RemoteSignError {
    fn from(e: std::io::Error) -> Self {
        RemoteSignError::Io(e)
    }
}

impl From<bincode::Error> for RemoteSignError {
    fn from(e: bincode::Error) -> Self {
        RemoteSignError::Serialization(e)
    }
}

/// Create a remote BLS keypair from configuration.
///
/// This creates a `RemoteBlsKeyPair` that delegates signing to the remote
/// signer daemon via Unix socket.
pub fn create_remote_bls_keypair(
    config: &RemoteSignerConfig,
) -> Result<RemoteBlsKeyPair, RemoteSignError> {
    let pubkey = if let Some(ref pk_hex) = config.pubkey_bls {
        // Use cached pubkey
        let bytes = hex::decode(pk_hex)
            .map_err(|e| RemoteSignError::Protocol(format!("Invalid pubkey hex: {}", e)))?;
        BlsPubKey::from_bytes(&bytes)
            .map_err(|e| RemoteSignError::Protocol(format!("Invalid pubkey: {}", e)))?
    } else {
        // Fetch from daemon
        fetch_bls_pubkey(&config.socket_path)?
    };

    let socket_path = config.socket_path.clone();
    let callback: BlsSigningCallback = Arc::new(move |domain: &[u8], message: &[u8]| {
        send_sign_request(&socket_path, KeyType::Bls, domain, message)
            .map_err(|e| e.to_string())
    });

    Ok(RemoteBlsKeyPair::new(pubkey, callback))
}

/// Create a remote secp256k1 keypair from configuration.
///
/// This creates a `RemoteSecpKeyPair` that delegates signing to the remote
/// signer daemon via Unix socket.
pub fn create_remote_secp_keypair(
    config: &RemoteSignerConfig,
) -> Result<RemoteSecpKeyPair, RemoteSignError> {
    let pubkey = if let Some(ref pk_hex) = config.pubkey_secp {
        // Use cached pubkey
        let bytes = hex::decode(pk_hex)
            .map_err(|e| RemoteSignError::Protocol(format!("Invalid pubkey hex: {}", e)))?;
        SecpPubKey::from_slice(&bytes)
            .map_err(|e| RemoteSignError::Protocol(format!("Invalid pubkey: {}", e)))?
    } else {
        // Fetch from daemon
        fetch_secp_pubkey(&config.socket_path)?
    };

    let socket_path = config.socket_path.clone();
    let callback: SecpSigningCallback = Arc::new(move |domain: &[u8], message: &[u8]| {
        send_sign_request(&socket_path, KeyType::Secp256k1, domain, message)
            .map_err(|e| e.to_string())
    });

    Ok(RemoteSecpKeyPair::new(pubkey, callback))
}

// Helper functions for socket communication

fn send_request(socket_path: &PathBuf, request: &Request) -> Result<Response, RemoteSignError> {
    let mut stream = UnixStream::connect(socket_path)?;

    // Serialize and send request
    let request_bytes = bincode::serialize(request)?;
    let len_bytes = (request_bytes.len() as u32).to_le_bytes();
    stream.write_all(&len_bytes)?;
    stream.write_all(&request_bytes)?;
    stream.flush()?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let msg_len = u32::from_le_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf)?;

    let response: Response = bincode::deserialize(&msg_buf)?;
    Ok(response)
}

fn send_sign_request(
    socket_path: &PathBuf,
    key_type: KeyType,
    domain: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, RemoteSignError> {
    let request = Request::Sign(SignRequest {
        key_type,
        domain: domain.to_vec(),
        message: message.to_vec(),
        request_id: generate_request_id(),
    });

    let response = send_request(socket_path, &request)?;

    match response {
        Response::Sign(SignResponse::Success { signature, .. }) => Ok(signature),
        Response::Sign(SignResponse::Rejected { reason, .. }) => {
            Err(RemoteSignError::Protocol(format!("Rejected: {}", reason)))
        }
        Response::Sign(SignResponse::Error { message, .. }) => {
            Err(RemoteSignError::Protocol(format!("Error: {}", message)))
        }
        _ => Err(RemoteSignError::Protocol("Unexpected response".to_string())),
    }
}

fn fetch_bls_pubkey(socket_path: &PathBuf) -> Result<BlsPubKey, RemoteSignError> {
    let request = Request::GetPubKey {
        key_type: KeyType::Bls,
    };
    let response = send_request(socket_path, &request)?;

    match response {
        Response::PubKey { pubkey } => BlsPubKey::from_bytes(&pubkey)
            .map_err(|e| RemoteSignError::Protocol(format!("Invalid pubkey: {}", e))),
        _ => Err(RemoteSignError::Protocol("Unexpected response".to_string())),
    }
}

fn fetch_secp_pubkey(socket_path: &PathBuf) -> Result<SecpPubKey, RemoteSignError> {
    let request = Request::GetPubKey {
        key_type: KeyType::Secp256k1,
    };
    let response = send_request(socket_path, &request)?;

    match response {
        Response::PubKey { pubkey } => SecpPubKey::from_slice(&pubkey)
            .map_err(|e| RemoteSignError::Protocol(format!("Invalid pubkey: {}", e))),
        _ => Err(RemoteSignError::Protocol("Unexpected response".to_string())),
    }
}

fn generate_request_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_config_serialization() {
        let config = RemoteSignerConfig {
            socket_path: PathBuf::from("/var/run/signer.sock"),
            pubkey_bls: Some("abcd1234".to_string()),
            pubkey_secp: None,
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: RemoteSignerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.socket_path, config.socket_path);
        assert_eq!(parsed.pubkey_bls, config.pubkey_bls);
    }

    #[test]
    fn test_key_type_serialization() {
        let bls = KeyType::Bls;
        let secp = KeyType::Secp256k1;

        let bls_json = serde_json::to_string(&bls).unwrap();
        let secp_json = serde_json::to_string(&secp).unwrap();

        assert_eq!(serde_json::from_str::<KeyType>(&bls_json).unwrap(), bls);
        assert_eq!(serde_json::from_str::<KeyType>(&secp_json).unwrap(), secp);
    }
}
