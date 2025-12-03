//! Remote signer server implementation.
//!
//! Listens on a Unix socket and handles signing requests.

use crate::protocol::{KeyType, PubKeyResponse, Request, Response, SignRequest, SignResponse};
use crate::security::{DoubleSignError, DoubleSignGuard};
use monad_bls::{BlsKeyPair, BlsSignature};
use monad_crypto::certificate_signature::CertificateSignature;
use monad_crypto::signing_domain::{
    ConsensusMessage, NoEndorsement, RoundSignature, SigningDomain, Timeout, Tip, Vote,
};
use monad_secp::{KeyPair as SecpKeyPair, SecpSignature};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Server configuration.
pub struct ServerConfig {
    /// Path to Unix socket
    pub socket_path: std::path::PathBuf,
    /// BLS keypair for signing votes/certificates
    pub bls_keypair: BlsKeyPair,
    /// Secp256k1 keypair for signing consensus messages
    pub secp_keypair: SecpKeyPair,
    /// Path to double-sign protection state file
    pub state_file: std::path::PathBuf,
}

/// Errors from the signer server.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Double-sign error: {0}")]
    DoubleSgin(#[from] DoubleSignError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}

/// Remote signer server.
pub struct SignerServer {
    listener: UnixListener,
    bls_keypair: BlsKeyPair,
    secp_keypair: SecpKeyPair,
    guard: Arc<Mutex<DoubleSignGuard>>,
}

impl SignerServer {
    /// Create a new signer server.
    pub fn new(config: ServerConfig) -> Result<Self, ServerError> {
        // Remove existing socket file if it exists
        if config.socket_path.exists() {
            std::fs::remove_file(&config.socket_path)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = config.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&config.socket_path)?;
        info!("Signer server listening on {:?}", config.socket_path);

        // Set socket permissions (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&config.socket_path, perms)?;
        }

        let guard = DoubleSignGuard::new(config.state_file)?;

        Ok(Self {
            listener,
            bls_keypair: config.bls_keypair,
            secp_keypair: config.secp_keypair,
            guard: Arc::new(Mutex::new(guard)),
        })
    }

    /// Run the server (blocking).
    pub fn run(&self) -> Result<(), ServerError> {
        info!("Signer server starting...");
        info!(
            "BLS pubkey: 0x{}",
            hex::encode(self.bls_keypair.pubkey().compress())
        );
        info!(
            "Secp256k1 pubkey: 0x{}",
            hex::encode(self.secp_keypair.pubkey().bytes_compressed())
        );

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    debug!("New connection");
                    if let Err(e) = self.handle_connection(stream) {
                        error!("Error handling connection: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle a single connection.
    fn handle_connection(&self, mut stream: UnixStream) -> Result<(), ServerError> {
        // Read length-prefixed message
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let msg_len = u32::from_le_bytes(len_buf) as usize;

        if msg_len > 1024 * 1024 {
            // 1MB max
            return Err(ServerError::Protocol("Message too large".to_string()));
        }

        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf)?;

        // Deserialize request
        let request: Request = bincode::deserialize(&msg_buf)?;

        // Process request
        let response = match request {
            Request::Sign(sign_req) => self.handle_sign(sign_req),
            Request::GetPubKey(pk_req) => self.handle_get_pubkey(pk_req.key_type),
            Request::Ping => Response::Pong,
        };

        // Serialize and send response
        let response_bytes = bincode::serialize(&response)?;
        let len_bytes = (response_bytes.len() as u32).to_le_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&response_bytes)?;
        stream.flush()?;

        Ok(())
    }

    /// Handle a sign request.
    fn handle_sign(&self, req: SignRequest) -> Response {
        debug!(
            "Sign request: key_type={:?}, domain_len={}, msg_len={}, id={}",
            req.key_type,
            req.domain.len(),
            req.message.len(),
            req.request_id
        );

        // Check double-sign protection
        let mut guard = self.guard.lock().unwrap();
        if let Err(e) = guard.check_and_record(&req) {
            warn!("Sign request rejected: {}", e);
            return Response::Sign(SignResponse::Rejected {
                reason: e.to_string(),
                request_id: req.request_id,
            });
        }
        drop(guard);

        // Sign the message
        let result = match req.key_type {
            KeyType::Bls => self.sign_bls(&req.domain, &req.message),
            KeyType::Secp256k1 => self.sign_secp(&req.domain, &req.message),
        };

        match result {
            Ok(signature) => {
                debug!(
                    "Signed successfully: id={}, sig_len={}",
                    req.request_id,
                    signature.len()
                );
                Response::Sign(SignResponse::Success {
                    signature,
                    request_id: req.request_id,
                })
            }
            Err(e) => {
                error!("Signing failed: {}", e);
                Response::Sign(SignResponse::Error {
                    message: e.to_string(),
                    request_id: req.request_id,
                })
            }
        }
    }

    /// Sign with BLS key.
    fn sign_bls(&self, domain: &[u8], message: &[u8]) -> Result<Vec<u8>, ServerError> {
        // Dispatch based on domain prefix
        let sig = match domain {
            d if d == Vote::PREFIX => BlsSignature::sign::<Vote>(message, &self.bls_keypair),
            d if d == Timeout::PREFIX => BlsSignature::sign::<Timeout>(message, &self.bls_keypair),
            d if d == NoEndorsement::PREFIX => {
                BlsSignature::sign::<NoEndorsement>(message, &self.bls_keypair)
            }
            d if d == RoundSignature::PREFIX => {
                BlsSignature::sign::<RoundSignature>(message, &self.bls_keypair)
            }
            _ => {
                return Err(ServerError::Protocol(format!(
                    "Unknown BLS signing domain: {}",
                    hex::encode(domain)
                )));
            }
        };
        Ok(sig.serialize())
    }

    /// Sign with Secp256k1 key.
    fn sign_secp(&self, domain: &[u8], message: &[u8]) -> Result<Vec<u8>, ServerError> {
        // Dispatch based on domain prefix
        let sig = match domain {
            d if d == ConsensusMessage::PREFIX => {
                SecpSignature::sign::<ConsensusMessage>(message, &self.secp_keypair)
            }
            d if d == Tip::PREFIX => SecpSignature::sign::<Tip>(message, &self.secp_keypair),
            _ => {
                return Err(ServerError::Protocol(format!(
                    "Unknown Secp256k1 signing domain: {}",
                    hex::encode(domain)
                )));
            }
        };
        Ok(sig.serialize().to_vec())
    }

    /// Handle get pubkey request.
    fn handle_get_pubkey(&self, key_type: KeyType) -> Response {
        let pubkey = match key_type {
            KeyType::Bls => self.bls_keypair.pubkey().compress().to_vec(),
            KeyType::Secp256k1 => self.secp_keypair.pubkey().bytes_compressed().to_vec(),
        };

        Response::PubKey(PubKeyResponse { pubkey })
    }
}

/// Client for connecting to the remote signer.
pub struct SignerClient {
    socket_path: std::path::PathBuf,
}

impl SignerClient {
    /// Create a new client.
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Connect to the server and send a request.
    fn send_request(&self, request: &Request) -> Result<Response, ServerError> {
        let mut stream = UnixStream::connect(&self.socket_path)?;

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

    /// Sign a message.
    pub fn sign(&self, req: SignRequest) -> Result<Vec<u8>, ServerError> {
        let response = self.send_request(&Request::Sign(req.clone()))?;

        match response {
            Response::Sign(SignResponse::Success { signature, .. }) => Ok(signature),
            Response::Sign(SignResponse::Rejected { reason, .. }) => {
                Err(ServerError::Protocol(format!("Rejected: {}", reason)))
            }
            Response::Sign(SignResponse::Error { message, .. }) => {
                Err(ServerError::Protocol(format!("Error: {}", message)))
            }
            _ => Err(ServerError::Protocol("Unexpected response".to_string())),
        }
    }

    /// Get public key.
    pub fn get_pubkey(&self, key_type: KeyType) -> Result<Vec<u8>, ServerError> {
        let response =
            self.send_request(&Request::GetPubKey(crate::protocol::PubKeyRequest { key_type }))?;

        match response {
            Response::PubKey(PubKeyResponse { pubkey }) => Ok(pubkey),
            _ => Err(ServerError::Protocol("Unexpected response".to_string())),
        }
    }

    /// Ping the server.
    pub fn ping(&self) -> Result<(), ServerError> {
        let response = self.send_request(&Request::Ping)?;

        match response {
            Response::Pong => Ok(()),
            _ => Err(ServerError::Protocol("Unexpected response".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monad_bls::BlsPubKey;
    use monad_consensus_types::timeout::TimeoutInfo;
    use monad_consensus_types::voting::Vote as VoteData;
    use monad_crypto::certificate_signature::PubKey;
    use monad_secp::PubKey as SecpPubKey;
    use monad_types::{BlockId, Epoch, Hash, Round, GENESIS_ROUND};
    use std::thread;
    use tempfile::TempDir;

    // Helper functions for creating RLP-encoded test messages

    /// Create a test Vote and RLP-encode it
    fn encode_vote(epoch: u64, round: u64, block_id_byte: u8) -> Vec<u8> {
        let mut hash = [0u8; 32];
        hash[0] = block_id_byte;
        let vote = VoteData {
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

    fn create_test_keypairs() -> (BlsKeyPair, SecpKeyPair) {
        let mut bls_secret = [127u8; 32];
        let bls_keypair = BlsKeyPair::from_bytes(&mut bls_secret).unwrap();

        let mut secp_secret = [127u8; 32];
        let secp_keypair = SecpKeyPair::from_bytes(&mut secp_secret).unwrap();

        (bls_keypair, secp_keypair)
    }

    fn create_test_server(temp_dir: &TempDir) -> (SignerServer, std::path::PathBuf) {
        let (bls_keypair, secp_keypair) = create_test_keypairs();

        let socket_path = temp_dir.path().join("signer.sock");
        let state_file = temp_dir.path().join("state.json");

        let config = ServerConfig {
            socket_path: socket_path.clone(),
            bls_keypair,
            secp_keypair,
            state_file,
        };

        let server = SignerServer::new(config).unwrap();
        (server, socket_path)
    }

    #[test]
    fn test_server_creation() {
        let temp_dir = TempDir::new().unwrap();
        let (_, socket_path) = create_test_server(&temp_dir);
        assert!(socket_path.exists());
    }

    #[test]
    fn test_sign_bls_vote() {
        let temp_dir = TempDir::new().unwrap();
        let (server, _) = create_test_server(&temp_dir);

        let message = encode_vote(1, 1, 0);
        let result = server.sign_bls(Vote::PREFIX, &message);

        assert!(result.is_ok());
        let sig_bytes = result.unwrap();

        // Verify the signature is valid
        let sig = BlsSignature::deserialize(&sig_bytes).unwrap();
        let (bls_kp, _) = create_test_keypairs();
        assert!(sig.verify::<Vote>(&message, &bls_kp.pubkey()).is_ok());
    }

    #[test]
    fn test_sign_bls_timeout() {
        let temp_dir = TempDir::new().unwrap();
        let (server, _) = create_test_server(&temp_dir);

        let message = encode_timeout_info(1, 1, 0);
        let result = server.sign_bls(Timeout::PREFIX, &message);

        assert!(result.is_ok());
        let sig_bytes = result.unwrap();

        let sig = BlsSignature::deserialize(&sig_bytes).unwrap();
        let (bls_kp, _) = create_test_keypairs();
        assert!(sig.verify::<Timeout>(&message, &bls_kp.pubkey()).is_ok());
    }

    #[test]
    fn test_sign_secp_consensus_message() {
        let temp_dir = TempDir::new().unwrap();
        let (server, _) = create_test_server(&temp_dir);

        let message = b"test consensus message";
        let result = server.sign_secp(ConsensusMessage::PREFIX, message);

        assert!(result.is_ok());
        let sig_bytes = result.unwrap();

        // Verify the signature
        let sig = SecpSignature::deserialize(&sig_bytes).unwrap();
        let (_, secp_kp) = create_test_keypairs();
        assert!(secp_kp
            .pubkey()
            .verify::<ConsensusMessage>(message, &sig)
            .is_ok());
    }

    #[test]
    fn test_sign_unknown_domain_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let (server, _) = create_test_server(&temp_dir);

        let unknown_domain = b"\x10unknown/domain/1\n";
        let message = b"test message";

        let result = server.sign_bls(unknown_domain, message);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_pubkey_bls() {
        let temp_dir = TempDir::new().unwrap();
        let (server, _) = create_test_server(&temp_dir);

        let response = server.handle_get_pubkey(KeyType::Bls);

        match response {
            Response::PubKey(PubKeyResponse { pubkey }) => {
                let pk = BlsPubKey::from_bytes(&pubkey).unwrap();
                let (bls_kp, _) = create_test_keypairs();
                assert_eq!(pk, bls_kp.pubkey());
            }
            _ => panic!("Expected PubKey response"),
        }
    }

    #[test]
    fn test_get_pubkey_secp() {
        let temp_dir = TempDir::new().unwrap();
        let (server, _) = create_test_server(&temp_dir);

        let response = server.handle_get_pubkey(KeyType::Secp256k1);

        match response {
            Response::PubKey(PubKeyResponse { pubkey }) => {
                let pk = SecpPubKey::from_slice(&pubkey).unwrap();
                let (_, secp_kp) = create_test_keypairs();
                assert_eq!(pk, secp_kp.pubkey());
            }
            _ => panic!("Expected PubKey response"),
        }
    }

    #[test]
    fn test_client_server_integration() {
        let temp_dir = TempDir::new().unwrap();
        let (server, socket_path) = create_test_server(&temp_dir);

        // Spawn server in background thread
        let server_handle = thread::spawn(move || {
            // Handle just one connection for the test
            if let Ok((stream, _)) = server.listener.accept() {
                let _ = server.handle_connection(stream);
            }
        });

        // Give server time to start
        thread::sleep(std::time::Duration::from_millis(50));

        // Create client and ping
        let client = SignerClient::new(&socket_path);
        let result = client.ping();
        assert!(result.is_ok());

        server_handle.join().unwrap();
    }

    #[test]
    fn test_client_get_pubkey() {
        let temp_dir = TempDir::new().unwrap();
        let (server, socket_path) = create_test_server(&temp_dir);
        let (bls_kp, _) = create_test_keypairs();

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = server.listener.accept() {
                let _ = server.handle_connection(stream);
            }
        });

        thread::sleep(std::time::Duration::from_millis(50));

        let client = SignerClient::new(&socket_path);
        let pubkey_bytes = client.get_pubkey(KeyType::Bls).unwrap();
        let pubkey = BlsPubKey::from_bytes(&pubkey_bytes).unwrap();

        assert_eq!(pubkey, bls_kp.pubkey());

        server_handle.join().unwrap();
    }

    #[test]
    fn test_client_sign_and_verify() {
        let temp_dir = TempDir::new().unwrap();
        let (server, socket_path) = create_test_server(&temp_dir);
        let (bls_kp, _) = create_test_keypairs();

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = server.listener.accept() {
                let _ = server.handle_connection(stream);
            }
        });

        thread::sleep(std::time::Duration::from_millis(50));

        let client = SignerClient::new(&socket_path);
        let message = encode_vote(1, 1, 0);

        let sig_bytes = client
            .sign(SignRequest {
                key_type: KeyType::Bls,
                domain: Vote::PREFIX.to_vec(),
                message: message.clone(),
                request_id: 1,
            })
            .unwrap();

        // Verify the signature locally
        let sig = BlsSignature::deserialize(&sig_bytes).unwrap();
        assert!(sig.verify::<Vote>(&message, &bls_kp.pubkey()).is_ok());

        server_handle.join().unwrap();
    }

    #[test]
    fn test_full_round_trip_multiple_requests() {
        let temp_dir = TempDir::new().unwrap();
        let (server, socket_path) = create_test_server(&temp_dir);
        let (bls_kp, secp_kp) = create_test_keypairs();

        // Server handles 3 connections
        let server_handle = thread::spawn(move || {
            for _ in 0..3 {
                if let Ok((stream, _)) = server.listener.accept() {
                    let _ = server.handle_connection(stream);
                }
            }
        });

        thread::sleep(std::time::Duration::from_millis(50));

        let client = SignerClient::new(&socket_path);

        // Request 1: Get BLS pubkey
        let bls_pk_bytes = client.get_pubkey(KeyType::Bls).unwrap();
        let bls_pk = BlsPubKey::from_bytes(&bls_pk_bytes).unwrap();
        assert_eq!(bls_pk, bls_kp.pubkey());

        // Request 2: Sign BLS message (properly RLP-encoded Vote)
        let msg1 = encode_vote(1, 1, 0);
        let sig1_bytes = client
            .sign(SignRequest {
                key_type: KeyType::Bls,
                domain: Vote::PREFIX.to_vec(),
                message: msg1.clone(),
                request_id: 1,
            })
            .unwrap();
        let sig1 = BlsSignature::deserialize(&sig1_bytes).unwrap();
        assert!(sig1.verify::<Vote>(&msg1, &bls_pk).is_ok());

        // Request 3: Sign Secp message
        let msg2 = b"consensus message";
        let sig2_bytes = client
            .sign(SignRequest {
                key_type: KeyType::Secp256k1,
                domain: ConsensusMessage::PREFIX.to_vec(),
                message: msg2.to_vec(),
                request_id: 2,
            })
            .unwrap();
        let sig2 = SecpSignature::deserialize(&sig2_bytes).unwrap();
        assert!(secp_kp
            .pubkey()
            .verify::<ConsensusMessage>(msg2, &sig2)
            .is_ok());

        server_handle.join().unwrap();
    }
}
