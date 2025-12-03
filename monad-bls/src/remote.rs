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

//! Remote BLS signing support.
//!
//! This module provides types for delegating BLS signing operations to
//! a remote signer daemon, enabling secure key isolation.
//!
//! ## Usage
//!
//! ```ignore
//! use monad_bls::remote::{RemoteBlsKeyPair, BlsSigningCallback};
//! use std::sync::Arc;
//!
//! // Create a callback that communicates with the remote signer
//! let callback: BlsSigningCallback = Arc::new(|domain, message| {
//!     // Send to remote signer daemon and get signature bytes
//!     todo!("implement socket communication")
//! });
//!
//! let pubkey = /* fetch from remote signer */;
//! let keypair = RemoteBlsKeyPair::new(pubkey, callback);
//!
//! // Use with CertificateSignature trait
//! let sig = RemoteBlsSignature::sign::<Vote>(&message, &keypair);
//! ```

use std::sync::Arc;

use alloy_rlp::{Decodable, Encodable};
use monad_crypto::{
    certificate_signature::{CertificateKeyPair, CertificateSignature, CertificateSignaturePubKey},
    signing_domain::SigningDomain,
};
use serde::{Deserialize, Serialize};

use crate::{BlsError, BlsPubKey, BlsSignature};

/// Error type for remote signing operations.
#[derive(Debug)]
pub enum RemoteBlsError {
    /// BLS cryptographic error
    Bls(BlsError),
    /// Remote signer communication error
    Remote(String),
}

impl std::fmt::Display for RemoteBlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteBlsError::Bls(e) => write!(f, "BLS error: {}", e),
            RemoteBlsError::Remote(s) => write!(f, "Remote error: {}", s),
        }
    }
}

impl std::error::Error for RemoteBlsError {}

impl From<BlsError> for RemoteBlsError {
    fn from(e: BlsError) -> Self {
        RemoteBlsError::Bls(e)
    }
}

/// Callback type for remote BLS signing.
///
/// Takes domain prefix and message bytes, returns serialized signature bytes
/// or an error string.
pub type BlsSigningCallback = Arc<dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

/// Remote BLS keypair that delegates signing to a callback.
///
/// This type implements `CertificateKeyPair` and can be used anywhere
/// a `BlsKeyPair` would be used, but signing operations are delegated
/// to the provided callback (typically communicating with a remote signer).
pub struct RemoteBlsKeyPair {
    pubkey: BlsPubKey,
    sign_callback: BlsSigningCallback,
}

impl RemoteBlsKeyPair {
    /// Create a new remote BLS keypair.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The BLS public key (typically fetched from remote signer)
    /// * `sign_callback` - Callback that performs the actual signing via remote signer
    pub fn new(pubkey: BlsPubKey, sign_callback: BlsSigningCallback) -> Self {
        Self {
            pubkey,
            sign_callback,
        }
    }

    /// Sign a message with the specified signing domain.
    ///
    /// This method delegates to the remote signer callback.
    pub fn sign<SD: SigningDomain>(&self, msg: &[u8]) -> Result<BlsSignature, RemoteBlsError> {
        let sig_bytes = (self.sign_callback)(SD::PREFIX, msg)
            .map_err(RemoteBlsError::Remote)?;
        BlsSignature::deserialize(&sig_bytes).map_err(RemoteBlsError::Bls)
    }

    /// Get the public key.
    pub fn pubkey(&self) -> BlsPubKey {
        self.pubkey
    }
}

impl Clone for RemoteBlsKeyPair {
    fn clone(&self) -> Self {
        Self {
            pubkey: self.pubkey,
            sign_callback: Arc::clone(&self.sign_callback),
        }
    }
}

impl CertificateKeyPair for RemoteBlsKeyPair {
    type PubKeyType = BlsPubKey;
    type Error = RemoteBlsError;

    fn from_bytes(_secret: &mut [u8]) -> Result<Self, Self::Error> {
        // Remote keypairs cannot be created from bytes directly.
        // Use RemoteBlsKeyPair::new() with a callback instead.
        Err(RemoteBlsError::Remote(
            "RemoteBlsKeyPair cannot be created from bytes. Use new() with a callback.".to_string(),
        ))
    }

    fn pubkey(&self) -> Self::PubKeyType {
        self.pubkey
    }
}

/// Remote BLS signature.
///
/// This type wraps a `BlsSignature` and is binary-compatible with it,
/// but its associated keypair type is `RemoteBlsKeyPair`.
///
/// This enables using remote signing with the `CertificateSignature` trait
/// while maintaining full compatibility with existing signature verification.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct RemoteBlsSignature(BlsSignature);

impl RemoteBlsSignature {
    /// Get the inner BLS signature.
    pub fn inner(&self) -> &BlsSignature {
        &self.0
    }

    /// Convert into the inner BLS signature.
    pub fn into_inner(self) -> BlsSignature {
        self.0
    }

    /// Create from a BLS signature.
    pub fn from_inner(sig: BlsSignature) -> Self {
        Self(sig)
    }
}

impl From<BlsSignature> for RemoteBlsSignature {
    fn from(sig: BlsSignature) -> Self {
        Self(sig)
    }
}

impl From<RemoteBlsSignature> for BlsSignature {
    fn from(sig: RemoteBlsSignature) -> Self {
        sig.0
    }
}

impl CertificateSignature for RemoteBlsSignature {
    type KeyPairType = RemoteBlsKeyPair;
    type Error = RemoteBlsError;

    fn sign<SD: SigningDomain>(msg: &[u8], keypair: &Self::KeyPairType) -> Self {
        let sig = keypair
            .sign::<SD>(msg)
            .expect("Remote BLS signing failed");
        RemoteBlsSignature(sig)
    }

    fn verify<SD: SigningDomain>(
        &self,
        msg: &[u8],
        pubkey: &CertificateSignaturePubKey<Self>,
    ) -> Result<(), Self::Error> {
        // Verification is done locally - no need to contact remote signer
        self.0.verify::<SD>(msg, pubkey).map_err(RemoteBlsError::Bls)
    }

    fn validate(&self) -> Result<(), Self::Error> {
        self.0.validate(true).map_err(RemoteBlsError::Bls)
    }

    fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }

    fn deserialize(signature: &[u8]) -> Result<Self, Self::Error> {
        let inner = BlsSignature::deserialize(signature).map_err(RemoteBlsError::Bls)?;
        Ok(RemoteBlsSignature(inner))
    }
}

// Implement RLP encoding/decoding by delegating to inner BlsSignature

impl Encodable for RemoteBlsSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.0.encode(out)
    }
}

impl Decodable for RemoteBlsSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let inner = BlsSignature::decode(buf)?;
        Ok(RemoteBlsSignature(inner))
    }
}

// Implement serde by delegating to inner BlsSignature
// Note: BlsSignature already implements Serialize/Deserialize

impl Serialize for RemoteBlsSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Delegate to BlsSignature's serde Serialize implementation
        Serialize::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for RemoteBlsSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Delegate to BlsSignature's serde Deserialize implementation
        let inner = <BlsSignature as Deserialize>::deserialize(deserializer)?;
        Ok(RemoteBlsSignature(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlsKeyPair;
    use monad_crypto::signing_domain;

    type TestDomain = signing_domain::Vote;

    #[test]
    fn test_remote_keypair_creation() {
        let mut secret = [127u8; 32];
        let local_kp = BlsKeyPair::from_bytes(&mut secret).unwrap();
        let pubkey = local_kp.pubkey();

        // Create a simple mock callback
        let callback: BlsSigningCallback = Arc::new(|_domain, _message| {
            Err("mock callback".to_string())
        });

        let remote_kp = RemoteBlsKeyPair::new(pubkey, callback);
        assert_eq!(remote_kp.pubkey(), pubkey);
    }

    #[test]
    fn test_remote_signature_serialize_roundtrip() {
        let mut secret = [127u8; 32];
        let local_kp = BlsKeyPair::from_bytes(&mut secret).unwrap();

        // Create local signature for testing
        let msg = b"test message";
        let local_sig = local_kp.sign::<TestDomain>(msg);

        // Wrap in remote signature
        let remote_sig = RemoteBlsSignature::from_inner(local_sig);

        // Serialize and deserialize using CertificateSignature trait
        let bytes =
            <RemoteBlsSignature as CertificateSignature>::serialize(&remote_sig);
        let recovered =
            <RemoteBlsSignature as CertificateSignature>::deserialize(&bytes).unwrap();

        assert_eq!(remote_sig, recovered);
    }

    #[test]
    fn test_remote_signature_rlp_roundtrip() {
        let mut secret = [127u8; 32];
        let local_kp = BlsKeyPair::from_bytes(&mut secret).unwrap();

        let msg = b"test message";
        let local_sig = local_kp.sign::<TestDomain>(msg);
        let remote_sig = RemoteBlsSignature::from_inner(local_sig);

        let encoded = alloy_rlp::encode(&remote_sig);
        let decoded: RemoteBlsSignature = alloy_rlp::decode_exact(&encoded).unwrap();

        assert_eq!(remote_sig, decoded);
    }

    #[test]
    fn test_remote_signature_verification() {
        let mut secret = [127u8; 32];
        let local_kp = BlsKeyPair::from_bytes(&mut secret).unwrap();
        let pubkey = local_kp.pubkey();

        let msg = b"test message";
        let local_sig = local_kp.sign::<TestDomain>(msg);
        let remote_sig = RemoteBlsSignature::from_inner(local_sig);

        // Verification should work locally
        assert!(remote_sig.verify::<TestDomain>(msg, &pubkey).is_ok());
    }

    #[test]
    fn test_conversion_between_types() {
        let mut secret = [127u8; 32];
        let local_kp = BlsKeyPair::from_bytes(&mut secret).unwrap();

        let msg = b"test message";
        let local_sig = local_kp.sign::<TestDomain>(msg);

        // Convert to remote and back
        let remote_sig: RemoteBlsSignature = local_sig.into();
        let back_to_local: BlsSignature = remote_sig.into();

        assert_eq!(local_sig, back_to_local);
    }
}
