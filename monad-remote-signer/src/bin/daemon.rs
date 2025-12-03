//! Remote signer daemon binary.
//!
//! This binary runs as a standalone process that handles signing requests
//! from validator nodes via Unix socket.

use clap::Parser;
use monad_bls::BlsKeyPair;
use monad_keystore::keystore::Keystore;
use monad_remote_signer::{ServerConfig, SignerServer};
use monad_secp::KeyPair as SecpKeyPair;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// Remote validator signer daemon for Monad BFT.
#[derive(Parser, Debug)]
#[command(name = "monad-signer-daemon")]
#[command(about = "Remote signing daemon for Monad validators")]
#[command(version)]
struct Args {
    /// Path to Unix socket for client connections
    #[arg(long, default_value = "/var/run/monad-signer.sock")]
    socket: PathBuf,

    /// Path to BLS keystore file (encrypted JSON)
    #[arg(long)]
    bls_keystore: PathBuf,

    /// Path to secp256k1 keystore file (encrypted JSON)
    #[arg(long)]
    secp_keystore: PathBuf,

    /// Keystore password (or use MONAD_KEYSTORE_PASSWORD env var)
    #[arg(long, env = "MONAD_KEYSTORE_PASSWORD", default_value = "")]
    keystore_password: String,

    /// Path to double-sign protection state file
    #[arg(long, default_value = "/var/lib/monad-signer/state.json")]
    state_file: PathBuf,
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!("Starting monad-signer-daemon");
    info!("Socket path: {:?}", args.socket);
    info!("BLS keystore: {:?}", args.bls_keystore);
    info!("Secp256k1 keystore: {:?}", args.secp_keystore);
    info!("State file: {:?}", args.state_file);

    // Load BLS keypair
    let bls_keypair = match load_bls_keypair(&args.bls_keystore, &args.keystore_password) {
        Ok(kp) => {
            info!(
                "Loaded BLS keypair, pubkey: 0x{}",
                hex::encode(kp.pubkey().compress())
            );
            kp
        }
        Err(e) => {
            error!("Failed to load BLS keystore: {}", e);
            std::process::exit(1);
        }
    };

    // Load Secp256k1 keypair
    let secp_keypair = match load_secp_keypair(&args.secp_keystore, &args.keystore_password) {
        Ok(kp) => {
            info!(
                "Loaded secp256k1 keypair, pubkey: 0x{}",
                hex::encode(kp.pubkey().bytes_compressed())
            );
            kp
        }
        Err(e) => {
            error!("Failed to load secp256k1 keystore: {}", e);
            std::process::exit(1);
        }
    };

    // Create server config
    let config = ServerConfig {
        socket_path: args.socket,
        bls_keypair,
        secp_keypair,
        state_file: args.state_file,
    };

    // Create and run server
    let server = match SignerServer::new(config) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create server: {}", e);
            std::process::exit(1);
        }
    };

    info!("Signer daemon ready, waiting for connections...");

    if let Err(e) = server.run() {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

fn load_bls_keypair(path: &PathBuf, password: &str) -> Result<BlsKeyPair, String> {
    Keystore::load_bls_key(path, password).map_err(|e| format!("{:?}", e))
}

fn load_secp_keypair(path: &PathBuf, password: &str) -> Result<SecpKeyPair, String> {
    Keystore::load_secp_key(path, password).map_err(|e| format!("{:?}", e))
}
