//! Ed25519 signing and verification for WAL commits and page authentication.
//!
//! Each database instance has a signing keypair.  Every COMMIT record is
//! signed so that any external auditor can verify the transaction log without
//! trusting the server.

use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::CryptoError;
use crate::{PublicKey, Signature};

/// An Ed25519 signing keypair.  The private key is zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub struct DbSigningKey {
    inner: SigningKey,
}

impl DbSigningKey {
    /// Generate a fresh random keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let key = SigningKey::generate(&mut OsRng);
        Self { inner: key }
    }

    /// Load from 32 raw bytes (the seed / private scalar).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: SigningKey::from_bytes(bytes),
        })
    }

    /// Export the raw private key bytes.  Handle with care.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// The corresponding public key.
    pub fn public_key(&self) -> DbVerifyingKey {
        DbVerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign arbitrary bytes and return a 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.inner.sign(message).to_bytes()
    }
}

/// An Ed25519 verifying (public) key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbVerifyingKey {
    #[serde(with = "verifying_key_serde")]
    inner: VerifyingKey,
}

impl DbVerifyingKey {
    /// Load from 32 raw bytes.
    pub fn from_bytes(bytes: &PublicKey) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    /// Export the raw public key bytes.
    pub fn to_bytes(&self) -> PublicKey {
        self.inner.to_bytes()
    }

    /// Verify a signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let sig = DalekSig::from_bytes(signature);
        self.inner
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureInvalid)
    }
}

/// A signed commit record — contains both the data being signed and the
/// signature so that verifiers can check authenticity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCommit {
    /// The canonical bytes that were signed (e.g. bincode of CommitPayload).
    pub data: Vec<u8>,
    /// Ed25519 signature over `data` (64 bytes, stored as Vec for serde compat).
    #[serde(with = "signature_serde")]
    pub signature: Signature,
    /// Public key of the signer, embedded for convenience.
    pub public_key: PublicKey,
}

impl SignedCommit {
    /// Create a new signed commit.
    pub fn new(data: Vec<u8>, signing_key: &DbSigningKey) -> Self {
        let signature = signing_key.sign(&data);
        let public_key = signing_key.public_key().to_bytes();
        Self {
            data,
            signature,
            public_key,
        }
    }

    /// Verify that the embedded signature is valid.
    pub fn verify(&self) -> Result<(), CryptoError> {
        let key = DbVerifyingKey::from_bytes(&self.public_key)?;
        key.verify(&self.data, &self.signature)
    }
}

// ── Serde helper for VerifyingKey ─────────────────────────────────────────────

mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(key: &VerifyingKey, ser: S) -> Result<S::Ok, S::Error> {
        key.as_bytes().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<VerifyingKey, D::Error> {
        let bytes = <[u8; 32]>::deserialize(de)?;
        VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = DbSigningKey::generate();
        let message = b"VectorGuard Labs \xE2\x80\x94 commit #42";
        let sig = key.sign(message);
        key.public_key().verify(message, &sig).unwrap();
    }

    #[test]
    fn tampered_message_fails_verification() {
        let key = DbSigningKey::generate();
        let message = b"commit data";
        let sig = key.sign(message);
        let result = key.public_key().verify(b"tampered data", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn signed_commit_roundtrip() {
        let key = DbSigningKey::generate();
        let sc = SignedCommit::new(b"tx payload".to_vec(), &key);
        sc.verify().unwrap();
    }
}

// ── Serde helper for 64-byte Signature ───────────────────────────────────────

mod signature_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        sig.as_slice().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v = Vec::<u8>::deserialize(de)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))
    }
}
