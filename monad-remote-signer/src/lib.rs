//! Remote Validator Signer for Monad BFT.
//!
//! This crate provides a remote signing daemon that allows validator keys
//! to be stored on a separate, more secure machine. The validator node
//! connects to this daemon via Unix socket for all signing operations.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     Unix Socket     ┌─────────────────┐
//! │  Validator Node │ ◄─────────────────► │  Signer Daemon  │
//! │  (monad-node)   │  SignRequest/Resp   │  (this crate)   │
//! └─────────────────┘                     └─────────────────┘
//! ```
//!
//! ## Features
//!
//! - **Double-sign protection**: Prevents signing conflicting messages
//! - **Low latency**: Unix socket communication, ~1-5ms overhead
//! - **Secure**: Keys never leave the signer daemon
//!
//! ## Usage
//!
//! Start the signer daemon:
//! ```bash
//! monad-signer-daemon \
//!     --socket /var/run/monad-signer.sock \
//!     --bls-keystore /path/to/bls-key.json \
//!     --secp-keystore /path/to/secp-key.json \
//!     --state-file /var/lib/monad-signer/state.json
//! ```
//!
//! Then configure the validator node to use a remote keystore (version 3).

pub mod protocol;
pub mod security;
pub mod server;

pub use protocol::{KeyType, PubKeyRequest, PubKeyResponse, Request, Response, SignRequest, SignResponse};
pub use security::{DoubleSignError, DoubleSignGuard, DoubleSignState};
pub use server::{ServerConfig, ServerError, SignerClient, SignerServer};
