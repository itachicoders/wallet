use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use reqwest::Client;
use serde_json::json;
use sha3::{Digest, Keccak256};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum MoneroError {
    #[error("Invalid seed phrase: {0}")]
    InvalidSeed(String),
    #[error("Invalid Monero address: {0}")]
    InvalidAddress(String),
    #[error("Node RPC error ({0}): {1}")]
    Rpc(String, String),
    #[error("Tor proxy connection error: {0}")]
    Proxy(String),
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoneroNetworkType {
    Mainnet,
    Stagenet,
    Testnet,
}

impl MoneroNetworkType {
    pub fn standard_prefix(&self) -> u8 {
        match self {
            MoneroNetworkType::Mainnet => 0x12, // '4'
            MoneroNetworkType::Stagenet => 0x18, // '5'
            MoneroNetworkType::Testnet => 0x35,  // '9'
        }
    }

    pub fn subaddress_prefix(&self) -> u8 {
        match self {
            MoneroNetworkType::Mainnet => 0x2a, // '8'
            MoneroNetworkType::Stagenet => 0x24, // '7'
            MoneroNetworkType::Testnet => 0x3f,  // 'B'
        }
    }
}

pub struct MoneroKeys {
    pub private_spend_key: Zeroizing<[u8; 32]>,
    pub private_view_key: Zeroizing<[u8; 32]>,
    pub public_spend_key: [u8; 32],
    pub public_view_key: [u8; 32],
    pub primary_address: String,
    pub stagenet_address: String,
}

impl MoneroKeys {
    pub fn from_mnemonic_words(words: &[String]) -> Result<Self, MoneroError> {
        if words.len() != 25 {
            return Err(MoneroError::InvalidSeed(
                "Electrum Monero seed must be exactly 25 words".to_string(),
            ));
        }

        let hex_seed = std::panic::catch_unwind(|| {
            libmonero::keys::derive_hex_seed(words.to_vec())
        })
        .map_err(|_| MoneroError::InvalidSeed("Checksum or wordlist error".to_string()))?;

        let priv_keys = libmonero::keys::derive_priv_keys(hex_seed);

        let sk_bytes = hex::decode(&priv_keys[0])
            .map_err(|_| MoneroError::InvalidSeed("Invalid private spend key hex".to_string()))?;
        let vk_bytes = hex::decode(&priv_keys[1])
            .map_err(|_| MoneroError::InvalidSeed("Invalid private view key hex".to_string()))?;

        let mut sk_arr = [0u8; 32];
        let mut vk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        vk_arr.copy_from_slice(&vk_bytes);

        let priv_sk = Zeroizing::new(sk_arr);
        let priv_vk = Zeroizing::new(vk_arr);

        // Derive public keys using scalar multiplication on Ed25519 basepoint
        let sk_scalar = Scalar::from_bytes_mod_order(*priv_sk);
        let vk_scalar = Scalar::from_bytes_mod_order(*priv_vk);

        let pub_spend_point = ED25519_BASEPOINT_TABLE * &sk_scalar;
        let pub_view_point = ED25519_BASEPOINT_TABLE * &vk_scalar;

        let pub_sk = pub_spend_point.compress().to_bytes();
        let pub_vk = pub_view_point.compress().to_bytes();

        let mainnet_addr = encode_monero_addr_bytes(&pub_sk, &pub_vk, MoneroNetworkType::Mainnet.standard_prefix())?;
        let stagenet_addr = encode_monero_addr_bytes(&pub_sk, &pub_vk, MoneroNetworkType::Stagenet.standard_prefix())?;

        Ok(Self {
            private_spend_key: priv_sk,
            private_view_key: priv_vk,
            public_spend_key: pub_sk,
            public_view_key: pub_vk,
            primary_address: mainnet_addr,
            stagenet_address: stagenet_addr,
        })
    }

    /// Derive subaddress for account `major` and address index `minor`
    pub fn get_subaddress(&self, net_type: MoneroNetworkType, major: u32, minor: u32) -> Result<String, MoneroError> {
        if major == 0 && minor == 0 {
            let prefix = net_type.standard_prefix();
            return encode_monero_addr_bytes(&self.public_spend_key, &self.public_view_key, prefix);
        }

        // Subaddress derivation:
        // m = Hs("SubAddr\0" || a || major || minor)
        // M = m * G
        // D = B + M
        // C = a * D
        let mut hasher = Keccak256::new();
        hasher.update(b"SubAddr\0");
        hasher.update(*self.private_view_key);
        hasher.update(major.to_le_bytes());
        hasher.update(minor.to_le_bytes());
        let hash = hasher.finalize();

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash);
        let m_scalar = Scalar::from_bytes_mod_order(hash_arr);

        let big_m = ED25519_BASEPOINT_TABLE * &m_scalar;
        let big_b = CompressedEdwardsY(self.public_spend_key)
            .decompress()
            .ok_or_else(|| MoneroError::InvalidAddress("Failed to decompress pub_spend".to_string()))?;

        let big_d = big_b + big_m; // Subaddress spend public key
        let a_scalar = Scalar::from_bytes_mod_order(*self.private_view_key);
        let big_c = big_d * a_scalar; // Subaddress view public key

        let sub_spend = big_d.compress().to_bytes();
        let sub_view = big_c.compress().to_bytes();

        encode_monero_addr_bytes(&sub_spend, &sub_view, net_type.subaddress_prefix())
    }
}

pub fn encode_monero_addr_bytes(pub_spend: &[u8; 32], pub_view: &[u8; 32], net_byte: u8) -> Result<String, MoneroError> {
    let mut data = Vec::with_capacity(69);
    data.push(net_byte);
    data.extend_from_slice(pub_spend);
    data.extend_from_slice(pub_view);

    let hash = Keccak256::digest(&data);
    data.extend_from_slice(&hash[0..4]);

    base58_monero::encode(&data)
        .map_err(|e| MoneroError::InvalidAddress(format!("Base58 encode failed: {e}")))
}

pub fn validate_monero_address(addr: &str) -> Result<(MoneroNetworkType, bool), MoneroError> {
    let decoded = base58_monero::decode(addr)
        .map_err(|e| MoneroError::InvalidAddress(format!("Base58 error: {e}")))?;

    if decoded.len() != 69 {
        return Err(MoneroError::InvalidAddress(format!(
            "Expected 69 bytes, got {}",
            decoded.len()
        )));
    }

    let payload = &decoded[0..65];
    let checksum = &decoded[65..69];
    let hash = Keccak256::digest(payload);

    if &hash[0..4] != checksum {
        return Err(MoneroError::InvalidAddress("Checksum mismatch".to_string()));
    }

    let net_byte = decoded[0];
    match net_byte {
        0x12 => Ok((MoneroNetworkType::Mainnet, false)),
        0x2a => Ok((MoneroNetworkType::Mainnet, true)),
        0x18 => Ok((MoneroNetworkType::Stagenet, false)),
        0x24 => Ok((MoneroNetworkType::Stagenet, true)),
        0x35 => Ok((MoneroNetworkType::Testnet, false)),
        0x3f => Ok((MoneroNetworkType::Testnet, true)),
        other => Err(MoneroError::InvalidAddress(format!("Unknown network byte 0x{:02x}", other))),
    }
}

pub struct ScannedOutput {
    pub tx_hash: String,
    pub output_index: u64,
    pub amount_atomic: u64,
    pub is_subaddress: bool,
}

pub struct MoneroNodeClient {
    client: Client,
    pub daemon_url: String,
    pub is_tor: bool,
}

impl MoneroNodeClient {
    pub fn new(daemon_url: &str, tor_socks5: Option<&str>) -> Result<Self, MoneroError> {
        let is_tor = tor_socks5.is_some();
        let client = crate::chains::create_http_client(20, tor_socks5);
        Ok(Self {
            client,
            daemon_url: daemon_url.trim_end_matches('/').to_string(),
            is_tor,
        })
    }

    pub fn privacy_warning(&self) -> Option<&'static str> {
        if !self.is_tor && !self.daemon_url.starts_with("https://") {
            Some("ВНИМАНИЕ: Подключение к Monero-узлу без TLS и без Tor может раскрывать ваш IP-адрес узлу!")
        } else {
            None
        }
    }

    pub async fn get_daemon_height(&self) -> Result<u64, MoneroError> {
        let endpoint = format!("{}/json_rpc", self.daemon_url);
        let body = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_block_count"
        });

        let resp = self.client.post(&endpoint).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(MoneroError::Rpc("get_block_count".to_string(), err.to_string()));
        }

        let count = json_val["result"]["count"].as_u64().unwrap_or(0);
        Ok(count)
    }

    pub async fn get_fee_estimate(&self) -> Result<u64, MoneroError> {
        let endpoint = format!("{}/json_rpc", self.daemon_url);
        let body = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_fee_estimate",
            "params": {
                "grace_blocks": 10
            }
        });

        let resp = self.client.post(&endpoint).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(MoneroError::Rpc("get_fee_estimate".to_string(), err.to_string()));
        }

        let fee = json_val["result"]["fee"].as_u64().unwrap_or(0);
        Ok(fee)
    }

    /// View-key scanning of a transaction's output keys against wallet spend public key
    pub fn scan_tx_output(
        &self,
        tx_pubkey: &[u8; 32],
        output_pubkey: &[u8; 32],
        output_index: u64,
        view_priv_key: &[u8; 32],
        spend_pub_key: &[u8; 32],
    ) -> bool {
        // Derivation = 8 * a * R
        let r_point = match CompressedEdwardsY(*tx_pubkey).decompress() {
            Some(p) => p,
            None => return false,
        };
        let a_scalar = Scalar::from_bytes_mod_order(*view_priv_key);
        // cofactor 8 * a * R
        let shared_point = (r_point * a_scalar).mul_by_cofactor();
        let shared_bytes = shared_point.compress().to_bytes();

        // Hs(shared_bytes || output_index)
        let mut hasher = Keccak256::new();
        hasher.update(shared_bytes);
        encode_varint(&mut hasher, output_index);
        let hash = hasher.finalize();

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash);
        let hs_scalar = Scalar::from_bytes_mod_order(hash_arr);

        // P_expected = hs * G + B
        let expected_point = ED25519_BASEPOINT_TABLE * &hs_scalar;
        let b_point = match CompressedEdwardsY(*spend_pub_key).decompress() {
            Some(p) => p,
            None => return false,
        };
        let p_expected = (expected_point + b_point).compress().to_bytes();

        &p_expected == output_pubkey
    }
}

fn encode_varint(hasher: &mut Keccak256, mut val: u64) {
    while val >= 0x80 {
        hasher.update([((val as u8) & 0x7f) | 0x80]);
        val >>= 7;
    }
    hasher.update([val as u8]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monero_key_and_address_derivation() {
        let words: Vec<String> = "tissue raking haunted huts afraid volcano howls liar egotistic befit rounded older bluntly imbalance pivot exotic tuxedo amaze mostly lukewarm macro vocal hounded biplane rounded"
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        let keys = MoneroKeys::from_mnemonic_words(&words).expect("keys derived");
        assert!(keys.primary_address.starts_with('4'));
        assert!(keys.stagenet_address.starts_with('5'));

        let (net, is_sub) = validate_monero_address(&keys.primary_address).expect("valid mainnet address");
        assert_eq!(net, MoneroNetworkType::Mainnet);
        assert!(!is_sub);

        let (net_stage, is_sub_stage) = validate_monero_address(&keys.stagenet_address).expect("valid stagenet address");
        assert_eq!(net_stage, MoneroNetworkType::Stagenet);
        assert!(!is_sub_stage);

        // Test subaddress derivation (major 0, minor 1)
        let subaddr_mainnet = keys.get_subaddress(MoneroNetworkType::Mainnet, 0, 1).expect("subaddress derived");
        assert!(subaddr_mainnet.starts_with('8'));
        let (sub_net, is_sub) = validate_monero_address(&subaddr_mainnet).expect("valid subaddress");
        assert_eq!(sub_net, MoneroNetworkType::Mainnet);
        assert!(is_sub);

        let subaddr_stage = keys.get_subaddress(MoneroNetworkType::Stagenet, 0, 1).expect("subaddress stagenet derived");
        assert!(subaddr_stage.starts_with('7'));
        let (sub_net_stage, is_sub_st) = validate_monero_address(&subaddr_stage).expect("valid subaddress stagenet");
        assert_eq!(sub_net_stage, MoneroNetworkType::Stagenet);
        assert!(is_sub_st);
    }

    #[test]
    fn test_view_key_output_scanning() {
        let words: Vec<String> = "tissue raking haunted huts afraid volcano howls liar egotistic befit rounded older bluntly imbalance pivot exotic tuxedo amaze mostly lukewarm macro vocal hounded biplane rounded"
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let keys = MoneroKeys::from_mnemonic_words(&words).unwrap();
        let client = MoneroNodeClient::new("http://127.0.0.1:38081", None).unwrap();

        // Simulate an output sent to this wallet:
        // Ephemeral tx private key r
        let r_scalar = Scalar::from_bytes_mod_order([17u8; 32]);
        let tx_pubkey = (ED25519_BASEPOINT_TABLE * &r_scalar).compress().to_bytes();

        // Sender calculates: shared = 8 * r * A = 8 * a * R
        let a_point = CompressedEdwardsY(keys.public_view_key).decompress().unwrap();
        let shared_point = (a_point * r_scalar).mul_by_cofactor();
        let shared_bytes = shared_point.compress().to_bytes();

        let mut hasher = Keccak256::new();
        hasher.update(&shared_bytes);
        encode_varint(&mut hasher, 0);
        let mut hs_arr = [0u8; 32];
        hs_arr.copy_from_slice(&hasher.finalize());
        let hs_scalar = Scalar::from_bytes_mod_order(hs_arr);

        let b_point = CompressedEdwardsY(keys.public_spend_key).decompress().unwrap();
        let output_pubkey = (ED25519_BASEPOINT_TABLE * &hs_scalar + b_point).compress().to_bytes();

        // Scanner checks if output belongs to keys:
        let is_mine = client.scan_tx_output(
            &tx_pubkey,
            &output_pubkey,
            0,
            &*keys.private_view_key,
            &keys.public_spend_key,
        );
        assert!(is_mine);

        // False output must NOT match
        let fake_pubkey = [99u8; 32];
        let is_fake = client.scan_tx_output(
            &tx_pubkey,
            &fake_pubkey,
            0,
            &*keys.private_view_key,
            &keys.public_spend_key,
        );
        assert!(!is_fake);
    }

    #[test]
    fn test_monero_wallet_crate_scanner() {
        let words: Vec<String> = "tissue raking haunted huts afraid volcano howls liar egotistic befit rounded older bluntly imbalance pivot exotic tuxedo amaze mostly lukewarm macro vocal hounded biplane rounded"
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let keys = MoneroKeys::from_mnemonic_words(&words).unwrap();

        let compressed = monero_wallet::ed25519::CompressedPoint::read(&mut &keys.public_spend_key[..]).unwrap();
        let spend_pt = compressed.decompress().expect("decompressed");
        let view_scalar = monero_wallet::ed25519::Scalar::read(&mut &keys.private_view_key[..]).unwrap();
        let view_pair = monero_wallet::ViewPair::new(spend_pt, zeroize::Zeroizing::new(view_scalar)).expect("view pair");
        let _scanner = monero_wallet::Scanner::new(view_pair);
    }
}
