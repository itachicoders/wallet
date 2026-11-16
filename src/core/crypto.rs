use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const ARGON2_MEMORY_KIB: u32 = 65536;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;
pub const SALT_LENGTH: usize = 16;
pub const NONCE_LENGTH: usize = 24;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Argon2 KDF error: {0}")]
    KdfError(String),
    #[error("Decryption failed: invalid password or corrupted data")]
    DecryptionFailed,
    #[error("Invalid salt length: expected {0}, got {1}")]
    InvalidSaltLength(usize, usize),
    #[error("Invalid nonce length: expected {0}, got {1}")]
    InvalidNonceLength(usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordStrength {
    TooShort,
    Weak(String),
    Moderate,
    Strong,
}

pub fn check_password_strength(password: &str) -> PasswordStrength {
    if password.len() < 8 {
        return PasswordStrength::TooShort;
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let score = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&b| b)
        .count();

    if password.len() < 12 && score < 3 {
        return PasswordStrength::Weak("Рекомендуется длина от 12 символов и сочетание букв, цифр и спецсимволов".to_string());
    }

    if score >= 3 && password.len() >= 12 {
        PasswordStrength::Strong
    } else {
        PasswordStrength::Moderate
    }
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    Ok(key)
}

#[allow(deprecated)]
pub fn encrypt_data(password: &[u8], plaintext: &[u8]) -> Result<EncryptedPayload, CryptoError> {
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce_bytes);

    let derived_key = derive_key(
        password,
        &salt,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
    )?;

    let cipher_key = Key::from_slice(derived_key.as_ref());
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(EncryptedPayload {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        memory_kib: ARGON2_MEMORY_KIB,
        iterations: ARGON2_ITERATIONS,
        parallelism: ARGON2_PARALLELISM,
    })
}

#[allow(deprecated)]
pub fn decrypt_data(
    password: &[u8],
    payload: &EncryptedPayload,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let salt = hex::decode(&payload.salt).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce_bytes = hex::decode(&payload.nonce).map_err(|_| CryptoError::DecryptionFailed)?;
    let ciphertext = hex::decode(&payload.ciphertext).map_err(|_| CryptoError::DecryptionFailed)?;

    if salt.len() != SALT_LENGTH {
        return Err(CryptoError::InvalidSaltLength(SALT_LENGTH, salt.len()));
    }
    if nonce_bytes.len() != NONCE_LENGTH {
        return Err(CryptoError::InvalidNonceLength(NONCE_LENGTH, nonce_bytes.len()));
    }

    let derived_key = derive_key(
        password,
        &salt,
        payload.memory_kib,
        payload.iterations,
        payload.parallelism,
    )?;

    let cipher_key = Key::from_slice(derived_key.as_ref());
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let result = Zeroizing::new(plaintext.clone());
    plaintext.zeroize();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_xchacha20_roundtrip() {
        let password = b"StrongP@ssw0rd!2026";
        let secret = b"my ultra secret seed phrase and keys";

        let payload = encrypt_data(password, secret).expect("encryption failed");
        assert_eq!(payload.memory_kib, ARGON2_MEMORY_KIB);
        assert_eq!(payload.iterations, ARGON2_ITERATIONS);

        let decrypted = decrypt_data(password, &payload).expect("decryption failed");
        assert_eq!(decrypted.as_slice(), secret);

        let wrong_password = b"WrongP@ssw0rd!2026";
        let fail = decrypt_data(wrong_password, &payload);
        assert!(fail.is_err());
    }

    #[test]
    fn test_password_strength_levels() {
        assert_eq!(check_password_strength("short"), PasswordStrength::TooShort);
        assert!(matches!(
            check_password_strength("simplepass"),
            PasswordStrength::Weak(_)
        ));
        assert_eq!(
            check_password_strength("SimplePass123!@#"),
            PasswordStrength::Strong
        );
    }
}
