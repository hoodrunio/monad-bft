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

//! Remote secp256k1 signing support.
//!
//! This module provides types for delegating secp256k1 signing operations to
//! a remote signer daemon, enabling secure key isolation.

use std::sync::Arc;

use alloy_rlp::{Decodable, Encodable};
use monad_crypto::{
    certificate_signature::{
        CertificateKeyPair, CertificateSignature, CertificateSignaturePubKey,
        CertificateSignatureRecoverable,
    },
    signing_domain::SigningDomain,
};
use serde::{Deserialize, Serialize};

use crate::{Error, PubKey, SecpSignature};

/// Error type for remote signing operations.
#[derive(Debug, Clone)]
pub enum RemoteSecpError {
    /// Secp256k1 cryptographic error
    Secp(Error),
    /// Remote signer communication error
    Remote(String),
}

impl std::fmt::Display for RemoteSecpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteSecpError::Secp(e) => write!(f, "Secp error: {}", e),
            RemoteSecpError::Remote(s) => write!(f, "Remote error: {}", s),
        }
    }
}

impl std::error::Error for RemoteSecpError {}

impl From<Error> for RemoteSecpError {
    fn from(e: Error) -> Self {
        RemoteSecpError::Secp(e)
    }
}

/// Callback type for remote secp256k1 signing.
///
/// Takes domain prefix and message bytes, returns serialized signature bytes
/// or an error string.
pub type SecpSigningCallback = Arc<dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

/// Remote secp256k1 keypair that delegates signing to a callback.
///
/// This type implements `CertificateKeyPair` and can be used anywhere
/// a `KeyPair` would be used, but signing operations are delegated
/// to the provided callback (typically communicating with a remote signer).
pub struct RemoteSecpKeyPair {
    pubkey: PubKey,
    sign_callback: SecpSigningCallback,
}

impl RemoteSecpKeyPair {
    /// Create a new remote secp256k1 keypair.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The secp256k1 public key (typically fetched from remote signer)
    /// * `sign_callback` - Callback that performs the actual signing via remote signer
    pub fn new(pubkey: PubKey, sign_callback: SecpSigningCallback) -> Self {
        Self {
            pubkey,
            sign_callback,
        }
    }

    /// Sign a message with the specified signing domain.
    ///
    /// This method delegates to the remote signer callback.
    pub fn sign<SD: SigningDomain>(&self, msg: &[u8]) -> Result<SecpSignature, RemoteSecpError> {
        let sig_bytes =
            (self.sign_callback)(SD::PREFIX, msg).map_err(RemoteSecpError::Remote)?;
        SecpSignature::deserialize(&sig_bytes).map_err(RemoteSecpError::Secp)
    }

    /// Get the public key.
    pub fn pubkey(&self) -> PubKey {
        self.pubkey
    }
}

impl Clone for RemoteSecpKeyPair {
    fn clone(&self) -> Self {
        Self {
            pubkey: self.pubkey,
            sign_callback: Arc::clone(&self.sign_callback),
        }
    }
}

impl CertificateKeyPair for RemoteSecpKeyPair {
    type PubKeyType = PubKey;
    type Error = RemoteSecpError;

    fn from_bytes(_secret: &mut [u8]) -> Result<Self, Self::Error> {
        // Remote keypairs cannot be created from bytes directly.
        // Use RemoteSecpKeyPair::new() with a callback instead.
        Err(RemoteSecpError::Remote(
            "RemoteSecpKeyPair cannot be created from bytes. Use new() with a callback."
                .to_string(),
        ))
    }

    fn pubkey(&self) -> Self::PubKeyType {
        self.pubkey
    }
}

/// Remote secp256k1 signature.
///
/// This type wraps a `SecpSignature` and is binary-compatible with it,
/// but its associated keypair type is `RemoteSecpKeyPair`.
///
/// This enables using remote signing with the `CertificateSignature` trait
/// while maintaining full compatibility with existing signature verification.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct RemoteSecpSignature(SecpSignature);

impl RemoteSecpSignature {
    /// Get the inner secp256k1 signature.
    pub fn inner(&self) -> &SecpSignature {
        &self.0
    }

    /// Convert into the inner secp256k1 signature.
    pub fn into_inner(self) -> SecpSignature {
        self.0
    }

    /// Create from a secp256k1 signature.
    pub fn from_inner(sig: SecpSignature) -> Self {
        Self(sig)
    }
}

impl From<SecpSignature> for RemoteSecpSignature {
    fn from(sig: SecpSignature) -> Self {
        Self(sig)
    }
}

impl From<RemoteSecpSignature> for SecpSignature {
    fn from(sig: RemoteSecpSignature) -> Self {
        sig.0
    }
}

impl CertificateSignature for RemoteSecpSignature {
    type KeyPairType = RemoteSecpKeyPair;
    type Error = RemoteSecpError;

    fn sign<SD: SigningDomain>(msg: &[u8], keypair: &Self::KeyPairType) -> Self {
        let sig = keypair
            .sign::<SD>(msg)
            .expect("Remote secp256k1 signing failed");
        RemoteSecpSignature(sig)
    }

    fn verify<SD: SigningDomain>(
        &self,
        msg: &[u8],
        pubkey: &CertificateSignaturePubKey<Self>,
    ) -> Result<(), Self::Error> {
        // Verification is done locally - no need to contact remote signer
        pubkey.verify::<SD>(msg, &self.0).map_err(RemoteSecpError::Secp)
    }

    fn validate(&self) -> Result<(), Self::Error> {
        // SecpSignature doesn't have explicit validation
        Ok(())
    }

    fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    fn deserialize(signature: &[u8]) -> Result<Self, Self::Error> {
        let inner = SecpSignature::deserialize(signature).map_err(RemoteSecpError::Secp)?;
        Ok(RemoteSecpSignature(inner))
    }
}

impl CertificateSignatureRecoverable for RemoteSecpSignature {
    fn recover_pubkey<SD: SigningDomain>(
        &self,
        msg: &[u8],
    ) -> Result<CertificateSignaturePubKey<Self>, <Self as CertificateSignature>::Error> {
        self.0
            .recover_pubkey::<SD>(msg)
            .map_err(RemoteSecpError::Secp)
    }
}

// Implement RLP encoding/decoding by delegating to inner SecpSignature

impl Encodable for RemoteSecpSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.0.encode(out)
    }
}

impl Decodable for RemoteSecpSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let inner = SecpSignature::decode(buf)?;
        Ok(RemoteSecpSignature(inner))
    }
}

// Implement serde by delegating to inner SecpSignature

impl Serialize for RemoteSecpSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for RemoteSecpSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = <SecpSignature as Deserialize>::deserialize(deserializer)?;
        Ok(RemoteSecpSignature(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use monad_crypto::signing_domain;

    type TestDomain = signing_domain::ConsensusMessage;

    #[test]
    fn test_remote_keypair_creation() {
        let mut secret = [127u8; 32];
        let local_kp = KeyPair::from_bytes(&mut secret).unwrap();
        let pubkey = local_kp.pubkey();

        // Create a simple mock callback
        let callback: SecpSigningCallback = Arc::new(|_domain, _message| {
            Err("mock callback".to_string())
        });

        let remote_kp = RemoteSecpKeyPair::new(pubkey, callback);
        assert_eq!(remote_kp.pubkey(), pubkey);
    }

    #[test]
    fn test_remote_signature_serialize_roundtrip() {
        let mut secret = [127u8; 32];
        let local_kp = KeyPair::from_bytes(&mut secret).unwrap();

        // Create local signature for testing
        let msg = b"test message";
        let local_sig = local_kp.sign::<TestDomain>(msg);

        // Wrap in remote signature
        let remote_sig = RemoteSecpSignature::from_inner(local_sig);

        // Serialize and deserialize using CertificateSignature trait
        let bytes =
            <RemoteSecpSignature as CertificateSignature>::serialize(&remote_sig);
        let recovered =
            <RemoteSecpSignature as CertificateSignature>::deserialize(&bytes).unwrap();

        assert_eq!(remote_sig, recovered);
    }

    #[test]
    fn test_remote_signature_rlp_roundtrip() {
        let mut secret = [127u8; 32];
        let local_kp = KeyPair::from_bytes(&mut secret).unwrap();

        let msg = b"test message";
        let local_sig = local_kp.sign::<TestDomain>(msg);
        let remote_sig = RemoteSecpSignature::from_inner(local_sig);

        let encoded = alloy_rlp::encode(&remote_sig);
        let decoded: RemoteSecpSignature = alloy_rlp::decode_exact(&encoded).unwrap();

        assert_eq!(remote_sig, decoded);
    }

    #[test]
    fn test_remote_signature_verification() {
        let mut secret = [127u8; 32];
        let local_kp = KeyPair::from_bytes(&mut secret).unwrap();
        let pubkey = local_kp.pubkey();

        let msg = b"test message";
        let local_sig = local_kp.sign::<TestDomain>(msg);
        let remote_sig = RemoteSecpSignature::from_inner(local_sig);

        // Verification should work locally
        assert!(remote_sig.verify::<TestDomain>(msg, &pubkey).is_ok());
    }

    #[test]
    fn test_remote_signature_recovery() {
        let mut secret = [127u8; 32];
        let local_kp = KeyPair::from_bytes(&mut secret).unwrap();
        let pubkey = local_kp.pubkey();

        let msg = b"test message";
        let local_sig = local_kp.sign::<TestDomain>(msg);
        let remote_sig = RemoteSecpSignature::from_inner(local_sig);

        // Recovery should work locally
        let recovered = remote_sig.recover_pubkey::<TestDomain>(msg).unwrap();
        assert_eq!(recovered, pubkey);
    }

    #[test]
    fn test_conversion_between_types() {
        let mut secret = [127u8; 32];
        let local_kp = KeyPair::from_bytes(&mut secret).unwrap();

        let msg = b"test message";
        let local_sig = local_kp.sign::<TestDomain>(msg);

        // Convert to remote and back
        let remote_sig: RemoteSecpSignature = local_sig.into();
        let back_to_local: SecpSignature = remote_sig.into();

        assert_eq!(local_sig, back_to_local);
    }
}
