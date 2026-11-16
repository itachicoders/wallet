use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use bip39::Mnemonic;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::crypto::{decrypt_data, encrypt_data, CryptoError, EncryptedPayload};
use crate::platform::Storage;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid BIP-39 mnemonic: {0}")]
    InvalidBip39(String),
    #[error("Invalid Monero mnemonic: {0}")]
    InvalidMonero(String),
    #[error("Word confirmation mismatch")]
    WordCheckFailed,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WalletSecrets {
    pub bip39_mnemonic: String,
    pub monero_seed: String,
    #[zeroize(skip)]
    pub monero_restore_height: u64,
    #[zeroize(skip)]
    pub created_at: u64,
}

impl WalletSecrets {
    pub fn new_random(restore_height: u64) -> Result<Self, WalletError> {
        let mut entropy = [0u8; 32];
        rand::rng().fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| WalletError::InvalidBip39(e.to_string()))?;
        let bip39_str = mnemonic.to_string();

        let monero_words = libmonero::keys::generate_seed("en", "original");
        let monero_str = monero_words.join(" ");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            bip39_mnemonic: bip39_str,
            monero_seed: monero_str,
            monero_restore_height: restore_height,
            created_at: now,
        })
    }

    pub fn from_mnemonics(
        bip39_str: &str,
        monero_str: &str,
        restore_height: u64,
    ) -> Result<Self, WalletError> {
        let trimmed_bip39 = bip39_str.trim();
        Mnemonic::parse(trimmed_bip39)
            .map_err(|e| WalletError::InvalidBip39(e.to_string()))?;

        let monero_words: Vec<String> = monero_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if monero_words.len() != 25 {
            return Err(WalletError::InvalidMonero(
                "Monero seed must be exactly 25 words".to_string(),
            ));
        }

        let hex_seed = std::panic::catch_unwind(|| {
            libmonero::keys::derive_hex_seed(monero_words.clone())
        })
        .map_err(|_| WalletError::InvalidMonero("Invalid Monero seed words or checksum".to_string()))?;

        if hex_seed.len() != 64 {
            return Err(WalletError::InvalidMonero(
                "Failed to derive 64-byte hex seed from Monero phrase".to_string(),
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            bip39_mnemonic: trimmed_bip39.to_string(),
            monero_seed: monero_words.join(" "),
            monero_restore_height: restore_height,
            created_at: now,
        })
    }

    pub fn bip39_words(&self) -> Vec<&str> {
        self.bip39_mnemonic.split_whitespace().collect()
    }

    pub fn monero_words(&self) -> Vec<&str> {
        self.monero_seed.split_whitespace().collect()
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P, password: &str) -> Result<(), WalletError> {
        let json_data = serde_json::to_vec(self)?;
        let encrypted_payload = encrypt_data(password.as_bytes(), &json_data)?;
        let file_bytes = serde_json::to_vec_pretty(&encrypted_payload)?;
        Storage::atomic_write_secure(path, &file_bytes)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(
        path: P,
        password: &str,
    ) -> Result<Self, WalletError> {
        let file_bytes = Storage::read_secure(path)?;
        let payload: EncryptedPayload = serde_json::from_slice(&file_bytes)?;
        let decrypted_bytes = decrypt_data(password.as_bytes(), &payload)?;
        let secrets: Self = serde_json::from_slice(&decrypted_bytes)?;
        Ok(secrets)
    }

    pub fn pick_verification_indices(&self, count: usize) -> Vec<usize> {
        use rand::seq::SliceRandom;
        let mut indices: Vec<usize> = (0..self.bip39_words().len()).collect();
        let mut rng = rand::rng();
        indices.shuffle(&mut rng);
        indices.truncate(count);
        indices.sort_unstable();
        indices
    }

    pub fn verify_word(&self, index: usize, word: &str) -> bool {
        let words = self.bip39_words();
        if let Some(expected) = words.get(index) {
            expected.eq_ignore_ascii_case(word.trim())
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_wallet_creation_encryption_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("agy_wallet_test_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);
        let wallet_path = temp_dir.join("wallet.dat");

        let password = "SuperSecretPassword123!";
        let wallet = WalletSecrets::new_random(3200000).expect("failed to create wallet");
        assert_eq!(wallet.bip39_words().len(), 24);
        assert_eq!(wallet.monero_words().len(), 25);

        let indices = wallet.pick_verification_indices(3);
        assert_eq!(indices.len(), 3);
        for &idx in &indices {
            let word = wallet.bip39_words()[idx];
            assert!(wallet.verify_word(idx, word));
            assert!(!wallet.verify_word(idx, "wrongword"));
        }

        wallet.save_to_file(&wallet_path, password).expect("save failed");

        let loaded = WalletSecrets::load_from_file(&wallet_path, password).expect("load failed");
        assert_eq!(loaded.bip39_mnemonic, wallet.bip39_mnemonic);
        assert_eq!(loaded.monero_seed, wallet.monero_seed);
        assert_eq!(loaded.monero_restore_height, 3200000);

        let wrong_load = WalletSecrets::load_from_file(&wallet_path, "WrongPassword");
        assert!(wrong_load.is_err());

        let _ = fs::remove_dir_all(temp_dir);
    }
}
