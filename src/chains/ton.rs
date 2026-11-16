use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::networks::registry::NetworkSpec;

#[derive(Error, Debug)]
pub enum TonError {
    #[error("Invalid TON address: {0}")]
    InvalidAddress(String),
    #[error("CRC16 checksum mismatch")]
    CrcMismatch,
    #[error("API error ({0}): {1}")]
    Api(String, String),
    #[error("Insufficient TON fee balance: have {have} TON, need at least {need} TON")]
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

pub struct TonKey {
    pub signing_key: SigningKey,
    pub public_key: [u8; 32],
    pub user_friendly_address: String,
    pub raw_address: String,
}

impl TonKey {
    pub fn from_seed_32(seed_32: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed_32);
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let mut hasher = Sha256::new();
        hasher.update(b"ton_v4r2_wallet_init:");
        hasher.update(pub_bytes);
        let account_id_hash = hasher.finalize();

        let mut hash_32 = [0u8; 32];
        hash_32.copy_from_slice(&account_id_hash);

        let user_friendly = encode_ton_user_friendly(0x11, 0, &hash_32);
        let raw = format!("0:{}", hex::encode(hash_32));

        Self {
            signing_key,
            public_key: pub_bytes,
            user_friendly_address: user_friendly,
            raw_address: raw,
        }
    }
}

pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

pub fn encode_ton_user_friendly(tag: u8, workchain: i8, account_id: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(36);
    payload.push(tag);
    payload.push(workchain as u8);
    payload.extend_from_slice(account_id);

    let crc = crc16_ccitt(&payload);
    payload.push((crc >> 8) as u8);
    payload.push((crc & 0xFF) as u8);

    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &payload,
    )
}

pub fn validate_ton_address(addr: &str) -> Result<[u8; 32], TonError> {
    let trimmed = addr.trim();

    if let Some((wc_str, hex_str)) = trimmed.split_once(':') {
        if wc_str != "0" && wc_str != "-1" {
            return Err(TonError::InvalidAddress(format!("Invalid workchain: {wc_str}")));
        }
        if hex_str.len() != 64 {
            return Err(TonError::InvalidAddress("Expected 64 hex chars for raw address".to_string()));
        }
        let raw = hex::decode(hex_str).map_err(|_| TonError::InvalidAddress("Invalid hex".to_string()))?;
        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(&raw);
        return Ok(account_id);
    }

    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        trimmed,
    )
    .or_else(|_| {
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            trimmed,
        )
    })
    .map_err(|e| TonError::InvalidAddress(format!("Base64 decode failed: {e}")))?;

    if decoded.len() != 36 {
        return Err(TonError::InvalidAddress(format!(
            "Expected 36 bytes for user-friendly address, got {}",
            decoded.len()
        )));
    }

    let payload = &decoded[0..34];
    let expected_crc = ((decoded[34] as u16) << 8) | (decoded[35] as u16);
    let calculated_crc = crc16_ccitt(payload);

    if expected_crc != calculated_crc {
        return Err(TonError::CrcMismatch);
    }

    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&payload[2..34]);
    Ok(account_id)
}

// ----------------- TEP-74 Jetton Transfer Payload -----------------

pub struct JettonTransferPayload {
    pub query_id: u64,
    pub amount_raw: u128,
    pub recipient: [u8; 32],
    pub response_address: [u8; 32],
    pub forward_ton_amount: u64,
}

impl JettonTransferPayload {
    pub fn build_body_bytes(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(128);
        // op::transfer = 0x0f8a7ea5 (4 bytes)
        body.extend_from_slice(&0x0f8a7ea5u32.to_be_bytes());
        // query_id (8 bytes)
        body.extend_from_slice(&self.query_id.to_be_bytes());

        // Coins (amount in VarUint 16 format)
        let amount_bytes = self.amount_raw.to_be_bytes();
        let start = amount_bytes.iter().position(|&b| b != 0).unwrap_or(amount_bytes.len());
        let val_slice = &amount_bytes[start..];
        body.push(val_slice.len() as u8);
        body.extend_from_slice(val_slice);

        // Destination address (workchain 0, account_id 32 bytes)
        body.push(0x80); // std address tag
        body.push(0x00); // workchain 0
        body.extend_from_slice(&self.recipient);

        // Response destination address (workchain 0, account_id 32 bytes)
        body.push(0x80);
        body.push(0x00);
        body.extend_from_slice(&self.response_address);

        // Custom payload (None = 0x00)
        body.push(0x00);

        // Forward TON amount (Coins in VarUint 16 format)
        let fwd_bytes = self.forward_ton_amount.to_be_bytes();
        let fwd_start = fwd_bytes.iter().position(|&b| b != 0).unwrap_or(fwd_bytes.len());
        let fwd_slice = &fwd_bytes[fwd_start..];
        body.push(fwd_slice.len() as u8);
        body.extend_from_slice(fwd_slice);

        // Forward payload (None = 0x00)
        body.push(0x00);

        body
    }

    pub fn sign_wallet_message(
        &self,
        signing_key: &SigningKey,
        seqno: u32,
        valid_until: u32,
    ) -> (Vec<u8>, [u8; 64]) {
        let body = self.build_body_bytes();

        let mut msg = Vec::with_capacity(64 + body.len());
        msg.extend_from_slice(&698983191u32.to_be_bytes()); // subwallet_id
        msg.extend_from_slice(&valid_until.to_be_bytes());
        msg.extend_from_slice(&seqno.to_be_bytes());
        msg.push(0x00); // op
        msg.push(0x03); // send_mode = 3
        msg.extend_from_slice(&body);

        let hash = Sha256::digest(&msg);
        let signature = signing_key.sign(&hash);

        (msg, signature.to_bytes())
    }
}

pub struct TonClient {
    client: Client,
    pub api_url: String,
}

impl TonClient {
    pub fn new(api_url: &str) -> Self {
        let client = crate::chains::create_http_client(15, None);
        Self {
            client,
            api_url: api_url.trim_end_matches('/').to_string(),
        }
    }

    pub async fn get_ton_balance(&self, address: &str) -> Result<u128, TonError> {
        let body = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "getAddressInformation",
            "params": {
                "address": address
            }
        });

        let resp = self.client.post(&self.api_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(TonError::Api("getAddressInformation".to_string(), err.to_string()));
        }

        let balance_str = json_val["result"]["balance"]
            .as_str()
            .unwrap_or("0");

        balance_str
            .parse::<u128>()
            .map_err(|e| TonError::Api("ParseBalance".to_string(), e.to_string()))
    }

    pub async fn check_transfer_eligibility(
        &self,
        _net: &NetworkSpec,
        owner_address: &str,
        _send_amount_raw: u128,
        min_ton_nanotons: u128,
    ) -> Result<u128, TonError> {
        let ton_nanotons = self.get_ton_balance(owner_address).await?;

        if ton_nanotons < min_ton_nanotons {
            let have_fmt = format!("{:.4}", ton_nanotons as f64 / 1_000_000_000.0);
            let need_fmt = format!("{:.4}", min_ton_nanotons as f64 / 1_000_000_000.0);
            return Err(TonError::InsufficientFee {
                have: have_fmt,
                need: need_fmt,
            });
        }

        Ok(ton_nanotons)
    }

    pub async fn send_boc(&self, boc_base64: &str) -> Result<String, TonError> {
        let body = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "sendBoc",
            "params": {
                "boc": boc_base64
            }
        });

        let resp = self.client.post(&self.api_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(TonError::Api("sendBoc".to_string(), err.to_string()));
        }

        let hash = json_val["result"]["@extra"]
            .as_str()
            .unwrap_or("submitted");

        Ok(hash.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_official_tether_jetton_address_validation() {
        let official_jetton = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs";
        let account_id = validate_ton_address(official_jetton).expect("official jetton valid");

        assert_eq!(
            hex::encode(account_id),
            "b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe"
        );

        let re_encoded = encode_ton_user_friendly(0x11, 0, &account_id);
        assert_eq!(re_encoded, official_jetton);

        let mut corrupted = official_jetton.to_string();
        corrupted.replace_range(official_jetton.len() - 1.., "B");
        assert!(validate_ton_address(&corrupted).is_err());
    }

    #[test]
    fn test_tep74_jetton_transfer_payload_construction() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let recipient = [0x55u8; 32];
        let response_addr = [0x77u8; 32];

        let payload = JettonTransferPayload {
            query_id: 12345,
            amount_raw: 5_000_000, // 5 USDT (6 decimals)
            recipient,
            response_address: response_addr,
            forward_ton_amount: 1, // 1 nanoton
        };

        let body = payload.build_body_bytes();
        // Starts with op::transfer 0x0f8a7ea5
        assert_eq!(&body[0..4], &[0x0f, 0x8a, 0x7e, 0xa5]);

        let (msg, sig) = payload.sign_wallet_message(&signing_key, 1, 1800000000);
        assert!(!msg.is_empty());
        assert_eq!(sig.len(), 64);
    }
}
