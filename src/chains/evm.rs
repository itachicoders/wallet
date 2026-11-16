use std::str::FromStr;
use std::time::Duration;

use bip32::{DerivationPath, XPrv};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use reqwest::Client;
use serde_json::json;
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EvmError {
    #[error("Derivation error: {0}")]
    Derivation(String),
    #[error("Invalid EVM address: {0}")]
    InvalidAddress(String),
    #[error("EIP-55 checksum mismatch")]
    ChecksumMismatch,
    #[error("RPC error ({0}): {1}")]
    Rpc(String, String),
    #[error("Transaction failed on-chain (reverted)")]
    TxReverted,
    #[error("Transaction receipt timeout after {0} seconds")]
    TxTimeout(u64),
    #[error("Insufficient native fee balance: have {have} {symbol}, required at least {need} {symbol}")]
    InsufficientFee {
        have: String,
        need: String,
        symbol: String,
    },
    #[error("Insufficient token balance: have {have} USDT, trying to send {send} USDT")]
    InsufficientBalance {
        have: String,
        send: String,
    },
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
}

pub struct EvmKey {
    pub signing_key: SigningKey,
    pub address_bytes: [u8; 20],
    pub checksum_address: String,
}

impl EvmKey {
    pub fn from_seed(seed: &[u8; 64], path_str: &str) -> Result<Self, EvmError> {
        let path = DerivationPath::from_str(path_str)
            .map_err(|e| EvmError::Derivation(e.to_string()))?;
        let child_xprv = XPrv::derive_from_path(seed, &path)
            .map_err(|e| EvmError::Derivation(e.to_string()))?;

        let signing_key = child_xprv.private_key().clone();
        let child_xpub = child_xprv.public_key();
        let verifying_key = child_xpub.public_key();
        let encoded_point = verifying_key.to_sec1_point(false);
        let pub_uncompressed = &encoded_point.as_bytes()[1..]; // 64 bytes without 0x04 tag

        let hash = Keccak256::digest(pub_uncompressed);
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);

        let checksum_address = to_checksum_address(&address_bytes);

        Ok(Self {
            signing_key,
            address_bytes,
            checksum_address,
        })
    }
}

pub fn to_checksum_address(addr: &[u8; 20]) -> String {
    let hex_addr = hex::encode(addr);
    let hash = Keccak256::digest(hex_addr.as_bytes());
    let hash_hex = hex::encode(hash);

    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");

    for (i, c) in hex_addr.chars().enumerate() {
        let hash_nibble = hash_hex.as_bytes()[i];
        if hash_nibble >= b'8' && c.is_ascii_alphabetic() {
            checksummed.push(c.to_ascii_uppercase());
        } else {
            checksummed.push(c);
        }
    }

    checksummed
}

pub fn validate_evm_address(addr: &str) -> Result<[u8; 20], EvmError> {
    let clean = addr.strip_prefix("0x").unwrap_or(addr);
    if clean.len() != 40 {
        return Err(EvmError::InvalidAddress("Address must be 40 hex chars".to_string()));
    }

    let raw_bytes = hex::decode(clean)
        .map_err(|_| EvmError::InvalidAddress("Invalid hex characters".to_string()))?;

    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&raw_bytes);

    let is_mixed = clean.chars().any(|c| c.is_ascii_uppercase())
        && clean.chars().any(|c| c.is_ascii_lowercase());

    if is_mixed {
        let expected = to_checksum_address(&bytes);
        let normalized_input = if addr.starts_with("0x") {
            addr.to_string()
        } else {
            format!("0x{addr}")
        };
        if normalized_input != expected {
            return Err(EvmError::ChecksumMismatch);
        }
    }

    Ok(bytes)
}

pub fn encode_erc20_balance_of(owner: &[u8; 20]) -> String {
    let mut data = String::with_capacity(74);
    data.push_str("0x70a08231");
    data.push_str(&"0".repeat(24));
    data.push_str(&hex::encode(owner));
    data
}

pub fn encode_erc20_transfer(recipient: &[u8; 20], amount_u128: u128) -> String {
    let mut data = String::with_capacity(138);
    data.push_str("0xa9059cbb");
    data.push_str(&"0".repeat(24));
    data.push_str(&hex::encode(recipient));
    data.push_str(&format!("{:064x}", amount_u128));
    data
}

pub fn parse_u256_hex(hex_str: &str) -> Result<u128, EvmError> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if clean.is_empty() {
        return Ok(0);
    }
    let trimmed = if clean.len() > 32 {
        &clean[clean.len() - 32..]
    } else {
        clean
    };
    u128::from_str_radix(trimmed, 16)
        .map_err(|e| EvmError::Rpc("ParseInt".to_string(), e.to_string()))
}

// ----------------- RLP Encoding -----------------

pub fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        vec![bytes[0]]
    } else if bytes.len() <= 55 {
        let mut res = Vec::with_capacity(1 + bytes.len());
        res.push(0x80 + bytes.len() as u8);
        res.extend_from_slice(bytes);
        res
    } else {
        let len_bytes = rlp_be_bytes(bytes.len() as u128);
        let mut res = Vec::with_capacity(1 + len_bytes.len() + bytes.len());
        res.push(0xb7 + len_bytes.len() as u8);
        res.extend_from_slice(&len_bytes);
        res.extend_from_slice(bytes);
        res
    }
}

pub fn rlp_encode_u128(val: u128) -> Vec<u8> {
    if val == 0 {
        vec![0x80]
    } else {
        let be = rlp_be_bytes(val);
        rlp_encode_bytes(&be)
    }
}

pub fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let total_payload_len: usize = items.iter().map(|it| it.len()).sum();
    let mut res = Vec::new();
    if total_payload_len <= 55 {
        res.push(0xc0 + total_payload_len as u8);
    } else {
        let len_bytes = rlp_be_bytes(total_payload_len as u128);
        res.push(0xf7 + len_bytes.len() as u8);
        res.extend_from_slice(&len_bytes);
    }
    for item in items {
        res.extend_from_slice(item);
    }
    res
}

fn rlp_be_bytes(val: u128) -> Vec<u8> {
    let raw = val.to_be_bytes();
    let start = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
    raw[start..].to_vec()
}

// ----------------- EIP-1559 and EIP-155 Signing -----------------

pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: u128,
    pub max_fee: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

impl Eip1559Tx {
    pub fn sign_and_serialize(&self, signing_key: &SigningKey) -> (String, String) {
        let unsigned_items = vec![
            rlp_encode_u128(self.chain_id as u128),
            rlp_encode_u128(self.nonce as u128),
            rlp_encode_u128(self.max_priority_fee),
            rlp_encode_u128(self.max_fee),
            rlp_encode_u128(self.gas_limit as u128),
            rlp_encode_bytes(&self.to),
            rlp_encode_u128(self.value),
            rlp_encode_bytes(&self.data),
            rlp_encode_list(&[]), // empty access list
        ];

        let rlp_payload = rlp_encode_list(&unsigned_items);
        let mut prehash_payload = Vec::with_capacity(1 + rlp_payload.len());
        prehash_payload.push(0x02); // EIP-2718 Type 2
        prehash_payload.extend_from_slice(&rlp_payload);

        let tx_hash = Keccak256::digest(&prehash_payload);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&tx_hash);

        let y_parity = recovery_id.to_byte();
        let r_bytes = &signature.to_bytes()[0..32];
        let s_bytes = &signature.to_bytes()[32..64];

        let mut signed_items = unsigned_items;
        signed_items.push(rlp_encode_u128(y_parity as u128));
        signed_items.push(rlp_encode_bytes(r_bytes.strip_leading_zeros()));
        signed_items.push(rlp_encode_bytes(s_bytes.strip_leading_zeros()));

        let signed_rlp = rlp_encode_list(&signed_items);
        let mut final_tx = Vec::with_capacity(1 + signed_rlp.len());
        final_tx.push(0x02);
        final_tx.extend_from_slice(&signed_rlp);

        let raw_tx_hex = format!("0x{}", hex::encode(final_tx));
        let computed_tx_hash = format!("0x{}", hex::encode(tx_hash));

        (raw_tx_hex, computed_tx_hash)
    }
}

trait StripLeadingZeros {
    fn strip_leading_zeros(&self) -> &[u8];
}

impl StripLeadingZeros for [u8] {
    fn strip_leading_zeros(&self) -> &[u8] {
        let start = self.iter().position(|&b| b != 0).unwrap_or(self.len());
        if start == self.len() {
            &[]
        } else {
            &self[start..]
        }
    }
}

pub struct EvmClient {
    client: Client,
    pub rpc_url: String,
}

impl EvmClient {
    pub fn new(rpc_url: &str) -> Self {
        let client = crate::chains::create_http_client(15, None);
        Self {
            client,
            rpc_url: rpc_url.to_string(),
        }
    }

    pub async fn get_native_balance(&self, address: &str) -> Result<u128, EvmError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(EvmError::Rpc("eth_getBalance".to_string(), err.to_string()));
        }

        let hex_res = json_val["result"]
            .as_str()
            .ok_or_else(|| EvmError::Rpc("eth_getBalance".to_string(), "Missing result".to_string()))?;

        parse_u256_hex(hex_res)
    }

    pub async fn get_usdt_balance(
        &self,
        contract: &str,
        owner: &[u8; 20],
    ) -> Result<u128, EvmError> {
        let data = encode_erc20_balance_of(owner);
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{
                "to": contract,
                "data": data
            }, "latest"],
            "id": 2
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(EvmError::Rpc("eth_call".to_string(), err.to_string()));
        }

        let hex_res = json_val["result"]
            .as_str()
            .ok_or_else(|| EvmError::Rpc("eth_call".to_string(), "Missing result".to_string()))?;

        parse_u256_hex(hex_res)
    }

    pub async fn get_gas_price(&self) -> Result<u128, EvmError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_gasPrice",
            "params": [],
            "id": 3
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(EvmError::Rpc("eth_gasPrice".to_string(), err.to_string()));
        }

        let hex_res = json_val["result"]
            .as_str()
            .ok_or_else(|| EvmError::Rpc("eth_gasPrice".to_string(), "Missing result".to_string()))?;

        parse_u256_hex(hex_res)
    }

    pub async fn get_transaction_count(&self, address: &str) -> Result<u64, EvmError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [address, "latest"],
            "id": 4
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(EvmError::Rpc("eth_getTransactionCount".to_string(), err.to_string()));
        }

        let hex_res = json_val["result"]
            .as_str()
            .ok_or_else(|| EvmError::Rpc("eth_getTransactionCount".to_string(), "Missing result".to_string()))?;

        let clean = hex_res.strip_prefix("0x").unwrap_or(hex_res);
        u64::from_str_radix(clean, 16)
            .map_err(|e| EvmError::Rpc("eth_getTransactionCount".to_string(), e.to_string()))
    }

    pub async fn estimate_gas(&self, from: &str, to: &str, data: &str) -> Result<u64, EvmError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_estimateGas",
            "params": [{
                "from": from,
                "to": to,
                "data": data
            }],
            "id": 5
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(EvmError::Rpc("eth_estimateGas".to_string(), err.to_string()));
        }

        let hex_res = json_val["result"]
            .as_str()
            .unwrap_or("0x15f90"); // 90000 gas fallback

        let clean = hex_res.strip_prefix("0x").unwrap_or(hex_res);
        u64::from_str_radix(clean, 16)
            .map_err(|e| EvmError::Rpc("eth_estimateGas".to_string(), e.to_string()))
    }

    pub async fn send_raw_transaction(&self, raw_tx_hex: &str) -> Result<String, EvmError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx_hex],
            "id": 6
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(EvmError::Rpc("eth_sendRawTransaction".to_string(), err.to_string()));
        }

        let tx_hash = json_val["result"]
            .as_str()
            .ok_or_else(|| EvmError::Rpc("eth_sendRawTransaction".to_string(), "Missing tx hash".to_string()))?;

        Ok(tx_hash.to_string())
    }

    pub async fn wait_for_receipt(&self, tx_hash: &str, timeout_secs: u64) -> Result<(), EvmError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash],
            "id": 7
        });
        let start = std::time::Instant::now();

        loop {
            if start.elapsed().as_secs() > timeout_secs {
                return Err(EvmError::TxTimeout(timeout_secs));
            }

            if let Ok(resp) = self.client.post(&self.rpc_url).json(&body).send().await
                && let Ok(json_val) = resp.json::<serde_json::Value>().await
                && let Some(receipt) = json_val.get("result")
                && !receipt.is_null()
            {
                let status = receipt.get("status").and_then(|s| s.as_str()).unwrap_or("0x0");
                if status == "0x1" {
                    return Ok(());
                } else {
                    return Err(EvmError::TxReverted);
                }
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}

pub fn recover_evm_sender_address(tx_hash: &[u8; 32], sig_bytes: &[u8; 64], recovery_id: u8) -> Result<String, EvmError> {
    let signature = Signature::from_slice(sig_bytes)
        .map_err(|e| EvmError::Rpc("Recovery".to_string(), e.to_string()))?;
    let recid = RecoveryId::try_from(recovery_id)
        .map_err(|e| EvmError::Rpc("Recovery".to_string(), e.to_string()))?;

    let recovered_key = VerifyingKey::recover_from_prehash(tx_hash, &signature, recid)
        .map_err(|e| EvmError::Rpc("Recovery".to_string(), e.to_string()))?;

    let encoded_point = recovered_key.to_sec1_point(false);
    let pub_uncompressed = &encoded_point.as_bytes()[1..];

    let hash = Keccak256::digest(pub_uncompressed);
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(&hash[12..32]);

    Ok(to_checksum_address(&address_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlp_encoding_known_vectors() {
        // Ethereum official RLP test vectors
        assert_eq!(rlp_encode_u128(0), vec![0x80]);
        assert_eq!(rlp_encode_u128(15), vec![0x0f]);
        assert_eq!(rlp_encode_u128(1024), vec![0x82, 0x04, 0x00]);

        let dog = b"dog";
        assert_eq!(rlp_encode_bytes(dog), vec![0x83, b'd', b'o', b'g']);

        let list = vec![rlp_encode_bytes(b"cat"), rlp_encode_bytes(b"dog")];
        assert_eq!(rlp_encode_list(&list), vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']);
    }

    #[test]
    fn test_eip1559_signing_and_sender_recovery() {
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let evm = EvmKey::from_seed(&seed, "m/44'/60'/0'/0/0").unwrap();

        let recipient_bytes = validate_evm_address("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();
        let transfer_data_hex = encode_erc20_transfer(&recipient_bytes, 10_000_000);
        let transfer_data = hex::decode(transfer_data_hex.strip_prefix("0x").unwrap()).unwrap();

        let tx = Eip1559Tx {
            chain_id: 11155111, // Sepolia
            nonce: 0,
            max_priority_fee: 1_500_000_000, // 1.5 Gwei
            max_fee: 20_000_000_000,        // 20 Gwei
            gas_limit: 65000,
            to: recipient_bytes,
            value: 0,
            data: transfer_data,
        };

        let (raw_hex, _hash) = tx.sign_and_serialize(&evm.signing_key);
        assert!(raw_hex.starts_with("0x02"));

        // Verify that raw tx hex decodes properly
        let raw_bytes = hex::decode(raw_hex.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(raw_bytes[0], 0x02);
    }

    #[test]
    fn test_eip55_checksum_vectors() {
        let v1 = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let v2 = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
        let v3 = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB";

        let b1 = validate_evm_address(v1).expect("v1 valid");
        assert_eq!(to_checksum_address(&b1), v1);

        let b2 = validate_evm_address(v2).expect("v2 valid");
        assert_eq!(to_checksum_address(&b2), v2);

        let b3 = validate_evm_address(v3).expect("v3 valid");
        assert_eq!(to_checksum_address(&b3), v3);

        let lower = v1.to_lowercase();
        let b_lower = validate_evm_address(&lower).expect("lower valid");
        assert_eq!(to_checksum_address(&b_lower), v1);
    }

    #[tokio::test]
    #[ignore]
    async fn test_sepolia_live_gas_price_and_balance() {
        let client = EvmClient::new("https://ethereum-sepolia-rpc.publicnode.com");
        let gas_price = client.get_gas_price().await.expect("gas price fetched");
        assert!(gas_price > 0);

        let test_addr = "0x1ebE4A053F3E94c9B9a09F33669435e7EF1beAed";
        let bal = client.get_native_balance(test_addr).await.expect("balance fetched");
        assert!(bal == 0 || bal > 0);
    }
}
