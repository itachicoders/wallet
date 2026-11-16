use std::str::FromStr;
use std::time::Duration;

use bip32::{DerivationPath, XPrv};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use reqwest::Client;
use serde_json::json;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use thiserror::Error;

use crate::networks::registry::NetworkSpec;

#[derive(Error, Debug)]
pub enum TronError {
    #[error("Derivation error: {0}")]
    Derivation(String),
    #[error("Invalid Tron address: {0}")]
    InvalidAddress(String),
    #[error("Base58Check decode failed: {0}")]
    Base58(String),
    #[error("Tron API error ({0}): {1}")]
    Api(String, String),
    #[error("Signature recovery failed: {0}")]
    SignatureRecovery(String),
    #[error("Transaction failed on chain: {0}")]
    TxFailed(String),
    #[error("Transaction confirmation timeout after {0} seconds")]
    TxTimeout(u64),
    #[error("Insufficient TRX balance for energy/fee: have {have} TRX, need at least {need} TRX")]
    InsufficientFee {
        have: String,
        need: String,
    },
    #[error("Insufficient USDT balance: have {have} USDT, trying to send {send} USDT")]
    InsufficientBalance {
        have: String,
        send: String,
    },
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
}

pub struct TronKey {
    pub signing_key: SigningKey,
    pub address_raw: [u8; 21],
    pub base58_address: String,
}

impl TronKey {
    pub fn from_seed(seed: &[u8; 64], path_str: &str) -> Result<Self, TronError> {
        let path = DerivationPath::from_str(path_str)
            .map_err(|e| TronError::Derivation(e.to_string()))?;
        let child_xprv = XPrv::derive_from_path(seed, &path)
            .map_err(|e| TronError::Derivation(e.to_string()))?;

        let signing_key = child_xprv.private_key().clone();
        let child_xpub = child_xprv.public_key();
        let verifying_key = child_xpub.public_key();
        let encoded_point = verifying_key.to_sec1_point(false);
        let pub_uncompressed = &encoded_point.as_bytes()[1..]; // 64 bytes

        let hash = Keccak256::digest(pub_uncompressed);
        let mut address_raw = [0u8; 21];
        address_raw[0] = 0x41; // Tron mainnet / testnet prefix 0x41
        address_raw[1..21].copy_from_slice(&hash[12..32]);

        let base58_address = bs58::encode(&address_raw).with_check().into_string();

        Ok(Self {
            signing_key,
            address_raw,
            base58_address,
        })
    }
}

pub fn validate_tron_address(addr: &str) -> Result<[u8; 21], TronError> {
    if !addr.starts_with('T') {
        return Err(TronError::InvalidAddress("Tron address must start with 'T'".to_string()));
    }
    if addr.len() != 34 {
        return Err(TronError::InvalidAddress(format!("Expected 34 chars, got {}", addr.len())));
    }

    let decoded = bs58::decode(addr)
        .with_check(None)
        .into_vec()
        .map_err(|e| TronError::Base58(e.to_string()))?;

    if decoded.len() != 21 {
        return Err(TronError::InvalidAddress(format!("Expected 21 bytes, got {}", decoded.len())));
    }

    if decoded[0] != 0x41 {
        return Err(TronError::InvalidAddress("Invalid address network prefix (expected 0x41)".to_string()));
    }

    let mut result = [0u8; 21];
    result.copy_from_slice(&decoded);
    Ok(result)
}

pub fn tron_address_to_hex(addr: &str) -> Result<String, TronError> {
    let bytes = validate_tron_address(addr)?;
    Ok(hex::encode(bytes))
}

pub fn hex_to_tron_address(hex_str: &str) -> Result<String, TronError> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|_| TronError::InvalidAddress("Invalid hex".to_string()))?;
    if bytes.len() != 21 || bytes[0] != 0x41 {
        return Err(TronError::InvalidAddress("Invalid Tron raw bytes".to_string()));
    }
    Ok(bs58::encode(&bytes).with_check().into_string())
}

pub fn encode_trc20_balance_of_param(owner_bytes: &[u8; 21]) -> String {
    let mut param = String::with_capacity(64);
    param.push_str(&"0".repeat(24));
    param.push_str(&hex::encode(&owner_bytes[1..21]));
    param
}

pub fn encode_trc20_transfer_param(recipient_bytes: &[u8; 21], amount_raw: u128) -> String {
    let mut param = String::with_capacity(128);
    param.push_str(&"0".repeat(24));
    param.push_str(&hex::encode(&recipient_bytes[1..21]));
    param.push_str(&format!("{:064x}", amount_raw));
    param
}

pub struct TronClient {
    client: Client,
    pub api_url: String,
}

impl TronClient {
    pub fn new(api_url: &str) -> Self {
        let client = crate::chains::create_http_client(15, None);
        Self {
            client,
            api_url: api_url.trim_end_matches('/').to_string(),
        }
    }

    pub async fn get_trx_balance(&self, address: &str) -> Result<u64, TronError> {
        let endpoint = format!("{}/wallet/getaccount", self.api_url);
        let body = json!({
            "address": address,
            "visible": true
        });

        let resp = self.client.post(&endpoint).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        // Balance is in SUN (1 TRX = 1_000_000 SUN)
        let balance = json_val["balance"].as_u64().unwrap_or(0);
        Ok(balance)
    }

    pub async fn get_account_resources(&self, address: &str) -> Result<(u64, u64), TronError> {
        let endpoint = format!("{}/wallet/getaccountresource", self.api_url);
        let body = json!({
            "address": address,
            "visible": true
        });

        let resp = self.client.post(&endpoint).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        let free_net_limit = json_val["freeNetLimit"].as_u64().unwrap_or(0);
        let free_net_used = json_val["freeNetUsed"].as_u64().unwrap_or(0);
        let free_bandwidth = free_net_limit.saturating_sub(free_net_used);

        let energy_limit = json_val["EnergyLimit"].as_u64().unwrap_or(0);
        let energy_used = json_val["EnergyUsed"].as_u64().unwrap_or(0);
        let free_energy = energy_limit.saturating_sub(energy_used);

        Ok((free_bandwidth, free_energy))
    }

    pub async fn get_trc20_usdt_balance(
        &self,
        contract_base58: &str,
        owner_base58: &str,
    ) -> Result<u128, TronError> {
        let endpoint = format!("{}/wallet/triggerconstantcontract", self.api_url);
        let owner_raw = validate_tron_address(owner_base58)?;
        let contract_hex = tron_address_to_hex(contract_base58)?;
        let owner_param = encode_trc20_balance_of_param(&owner_raw);

        let body = json!({
            "owner_address": hex::encode(owner_raw),
            "contract_address": contract_hex,
            "function_selector": "balanceOf(address)",
            "parameter": owner_param,
            "visible": false
        });

        let resp = self.client.post(&endpoint).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(res_arr) = json_val["constant_result"].as_array()
            && let Some(hex_val) = res_arr.first().and_then(|v| v.as_str()) {
                let clean = hex_val.trim_start_matches('0');
                if clean.is_empty() {
                    return Ok(0);
                }
                return u128::from_str_radix(clean, 16)
                    .map_err(|e| TronError::Api("ParseBalance".to_string(), e.to_string()));
            }

        Ok(0)
    }

    pub async fn check_transfer_eligibility(
        &self,
        net: &NetworkSpec,
        owner_base58: &str,
        send_amount_raw: u128,
        min_required_trx_sun: u64,
    ) -> Result<(u64, u128), TronError> {
        let contract = net.usdt_contract.ok_or_else(|| {
            TronError::Api("Config".to_string(), "No Tron USDT contract".to_string())
        })?;

        let trx_sun = self.get_trx_balance(owner_base58).await?;
        let usdt_raw = self.get_trc20_usdt_balance(contract, owner_base58).await?;

        if usdt_raw < send_amount_raw {
            let have_fmt = format!("{:.6}", usdt_raw as f64 / 1_000_000.0);
            let send_fmt = format!("{:.6}", send_amount_raw as f64 / 1_000_000.0);
            return Err(TronError::InsufficientBalance {
                have: have_fmt,
                send: send_fmt,
            });
        }

        if trx_sun < min_required_trx_sun {
            let have_fmt = format!("{:.6}", trx_sun as f64 / 1_000_000.0);
            let need_fmt = format!("{:.6}", min_required_trx_sun as f64 / 1_000_000.0);
            return Err(TronError::InsufficientFee {
                have: have_fmt,
                need: need_fmt,
            });
        }

        Ok((trx_sun, usdt_raw))
    }

    pub async fn create_trc20_transfer_tx(
        &self,
        owner_base58: &str,
        contract_base58: &str,
        recipient_base58: &str,
        amount_raw: u128,
        fee_limit_sun: u64,
    ) -> Result<serde_json::Value, TronError> {
        let endpoint = format!("{}/wallet/triggersmartcontract", self.api_url);
        let recipient_raw = validate_tron_address(recipient_base58)?;
        let parameter = encode_trc20_transfer_param(&recipient_raw, amount_raw);

        let body = json!({
            "owner_address": owner_base58,
            "contract_address": contract_base58,
            "function_selector": "transfer(address,uint256)",
            "parameter": parameter,
            "fee_limit": fee_limit_sun,
            "visible": true
        });

        let resp = self.client.post(&endpoint).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(res) = json_val.get("result")
            && res.get("result").and_then(|v| v.as_bool()) == Some(false) {
                let msg = res.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Trigger contract failed");
                return Err(TronError::Api("TriggerSmartContract".to_string(), msg.to_string()));
            }

        let tx = json_val.get("transaction")
            .ok_or_else(|| TronError::Api("TriggerSmartContract".to_string(), "Missing transaction in response".to_string()))?;

        Ok(tx.clone())
    }

    pub fn sign_transaction_locally(
        &self,
        signing_key: &SigningKey,
        raw_data_hex: &str,
    ) -> Result<String, TronError> {
        let raw_bytes = hex::decode(raw_data_hex)
            .map_err(|_| TronError::Api("DecodeRaw".to_string(), "Invalid raw_data_hex".to_string()))?;
        let hash = Sha256::digest(&raw_bytes);

        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&hash);

        let mut sig_65 = [0u8; 65];
        sig_65[0..64].copy_from_slice(&signature.to_bytes());
        sig_65[64] = recovery_id.to_byte();

        Ok(hex::encode(sig_65))
    }

    pub async fn broadcast_transaction(
        &self,
        mut transaction: serde_json::Value,
        signature_hex: &str,
    ) -> Result<String, TronError> {
        let endpoint = format!("{}/wallet/broadcasttransaction", self.api_url);

        transaction["signature"] = json!([signature_hex]);

        let resp = self.client.post(&endpoint).json(&transaction).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        let success = json_val.get("result").and_then(|v| v.as_bool()).unwrap_or(false);
        if !success {
            let msg = json_val.get("message")
                .and_then(|m| m.as_str())
                .or_else(|| json_val.get("code").and_then(|c| c.as_str()))
                .unwrap_or("Broadcast rejected");
            return Err(TronError::Api("BroadcastTransaction".to_string(), msg.to_string()));
        }

        let txid = transaction.get("txID")
            .and_then(|t| t.as_str())
            .ok_or_else(|| TronError::Api("BroadcastTransaction".to_string(), "Missing txID".to_string()))?;

        Ok(txid.to_string())
    }

    pub async fn wait_for_confirmation(
        &self,
        txid: &str,
        timeout_secs: u64,
    ) -> Result<(), TronError> {
        let endpoint = format!("{}/wallet/gettransactioninfobyid", self.api_url);
        let body = json!({ "value": txid });
        let start = std::time::Instant::now();

        loop {
            if start.elapsed().as_secs() > timeout_secs {
                return Err(TronError::TxTimeout(timeout_secs));
            }

            if let Ok(resp) = self.client.post(&endpoint).json(&body).send().await
                && let Ok(val) = resp.json::<serde_json::Value>().await
                && let Some(block_num) = val.get("blockNumber").and_then(|b| b.as_u64())
                && block_num > 0
            {
                if let Some(receipt) = val.get("receipt")
                    && receipt.get("result").and_then(|r| r.as_str()) == Some("FAILED")
                {
                    return Err(TronError::TxFailed("Transaction reverted on chain".to_string()));
                }
                return Ok(());
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}

pub fn recover_tron_sender_address(hash: &[u8; 32], sig_65_hex: &str) -> Result<String, TronError> {
    let sig_bytes = hex::decode(sig_65_hex)
        .map_err(|_| TronError::SignatureRecovery("Invalid signature hex".to_string()))?;

    if sig_bytes.len() != 65 {
        return Err(TronError::SignatureRecovery(format!(
            "Expected 65-byte signature, got {}",
            sig_bytes.len()
        )));
    }

    let signature = Signature::from_slice(&sig_bytes[0..64])
        .map_err(|e| TronError::SignatureRecovery(e.to_string()))?;
    let recovery_id = RecoveryId::try_from(sig_bytes[64])
        .map_err(|e| TronError::SignatureRecovery(e.to_string()))?;

    let recovered_key = VerifyingKey::recover_from_prehash(hash, &signature, recovery_id)
        .map_err(|e| TronError::SignatureRecovery(e.to_string()))?;

    let encoded_point = recovered_key.to_sec1_point(false);
    let pub_uncompressed = &encoded_point.as_bytes()[1..];

    let hash_keccak = Keccak256::digest(pub_uncompressed);
    let mut address_raw = [0u8; 21];
    address_raw[0] = 0x41;
    address_raw[1..21].copy_from_slice(&hash_keccak[12..32]);

    Ok(bs58::encode(&address_raw).with_check().into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tron_address_validation() {
        let usdt_contract = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
        let raw = validate_tron_address(usdt_contract).expect("contract is valid");
        assert_eq!(raw[0], 0x41);
        let encoded = bs58::encode(&raw).with_check().into_string();
        assert_eq!(encoded, usdt_contract);

        let nile_usdt = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf";
        let raw_nile = validate_tron_address(nile_usdt).expect("nile contract valid");
        assert_eq!(raw_nile[0], 0x41);

        assert!(validate_tron_address("0x7169D38820dfd117C3FA1f22a697dBA58d90BA06").is_err());
        assert!(validate_tron_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X").is_err());
    }

    #[test]
    fn test_tron_derivation_from_seed() {
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let tron = TronKey::from_seed(&seed, "m/44'/195'/0'/0/0").unwrap();
        assert!(tron.base58_address.starts_with('T'));
        assert_eq!(tron.base58_address.len(), 34);
        validate_tron_address(&tron.base58_address).expect("derived address is valid Base58Check");
    }

    #[test]
    fn test_tron_recoverable_signing_recovers_sender_address() {
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let tron = TronKey::from_seed(&seed, "m/44'/195'/0'/0/0").unwrap();

        let client = TronClient::new("https://nile.trongrid.io");
        let dummy_raw_tx = "0a02080112450a31636f6e7472616374";
        let sig_65_hex = client.sign_transaction_locally(&tron.signing_key, dummy_raw_tx).expect("signing succeeds");
        assert_eq!(sig_65_hex.len(), 130); // 65 bytes = 130 hex chars

        let raw_bytes = hex::decode(dummy_raw_tx).unwrap();
        let hash: [u8; 32] = Sha256::digest(&raw_bytes).into();

        let recovered_address = recover_tron_sender_address(&hash, &sig_65_hex).expect("recover succeeds");
        assert_eq!(recovered_address, tron.base58_address);
    }

    #[tokio::test]
    #[ignore]
    async fn test_tron_nile_live_balance_and_eligibility() {
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let tron = TronKey::from_seed(&seed, "m/44'/195'/0'/0/0").unwrap();

        let client = TronClient::new("https://nile.trongrid.io");
        let nile_usdt = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf";
        let usdt_bal = client.get_trc20_usdt_balance(nile_usdt, &tron.base58_address).await.expect("query succeeds");
        assert!(usdt_bal == 0 || usdt_bal > 0);

        let trx_bal = client.get_trx_balance(&tron.base58_address).await.unwrap_or(0);
        let net = crate::networks::registry::get_network(crate::networks::registry::NetworkId::TronNile);
        let check_res = client.check_transfer_eligibility(net, &tron.base58_address, 1_000_000, 15_000_000).await;
        if trx_bal < 15_000_000 {
            assert!(check_res.is_err(), "Must reject when fee is insufficient");
        }
    }
}
