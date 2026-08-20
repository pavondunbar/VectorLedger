//! Argon2id password hashing for database user authentication.
//!
//! Argon2id is the OWASP-recommended algorithm for password hashing as of
//! 2024.  Parameters are set conservatively above the minimum OWASP guidance:
//! - Memory: 64 MiB (OWASP min: 19 MiB)
//! - Iterations: 3 (OWASP min: 1 for 64 MiB)
//! - Parallelism: 4

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

use crate::error::CryptoError;

/// Hash a plaintext password using Argon2id.
///
/// Returns a PHC-format string that includes the algorithm parameters and salt,
/// suitable for storage in the user table.
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(
        64 * 1024, // 64 MiB memory
        3,         // 3 iterations
        4,         // 4 lanes (parallelism)
        None,
    )
    .map_err(|e| CryptoError::PasswordHashFailed(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| CryptoError::PasswordHashFailed(e.to_string()))
}

/// Verify a plaintext password against a stored PHC hash string.
///
/// Returns `Ok(())` on match, `Err(CryptoError::SignatureInvalid)` on mismatch.
/// (We reuse `SignatureInvalid` to avoid leaking whether the user exists.)
pub fn verify_password(password: &str, hash_str: &str) -> Result<(), CryptoError> {
    let parsed_hash =
        PasswordHash::new(hash_str).map_err(|e| CryptoError::PasswordHashFailed(e.to_string()))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| CryptoError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let password = "correct-horse-battery-staple-2024!";
        let hash = hash_password(password).unwrap();
        verify_password(password, &hash).unwrap();
    }

    #[test]
    fn wrong_password_fails() {
        let hash = hash_password("correct-password").unwrap();
        assert!(verify_password("wrong-password", &hash).is_err());
    }

    #[test]
    fn hashes_are_unique() {
        // Same password → different hashes (different salts)
        let h1 = hash_password("same-password").unwrap();
        let h2 = hash_password("same-password").unwrap();
        assert_ne!(h1, h2);
        // But both verify
        verify_password("same-password", &h1).unwrap();
        verify_password("same-password", &h2).unwrap();
    }
}
