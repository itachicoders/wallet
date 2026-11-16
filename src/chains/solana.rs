use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::networks::registry::NetworkSpec;

pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

#[derive(Error, Debug)]
pub enum SolanaError {
    #[error("Invalid Solana address: {0}")]
    InvalidAddress(String),
    #[error("Base58 decode error: {0}")]
    Base58(String),
    #[error("Associated Token Account error: {0}")]
    AtaError(String),
    #[error("Solana RPC error ({0}): {1}")]
    Rpc(String, String),
    #[error("Insufficient SOL fee balance: have {have} SOL, need at least {need} SOL")]
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

pub struct SolanaKey {
    pub signing_key: SigningKey,
    pub public_key: [u8; 32],
    pub base58_address: String,
}

impl SolanaKey {
    pub fn from_seed_32(seed_32: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed_32);
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let base58_address = bs58::encode(&pub_bytes).into_string();

        Self {
            signing_key,
            public_key: pub_bytes,
            base58_address,
        }
    }
}

pub fn validate_solana_address(addr: &str) -> Result<[u8; 32], SolanaError> {
    let decoded = bs58::decode(addr)
        .into_vec()
        .map_err(|e| SolanaError::Base58(e.to_string()))?;

    if decoded.len() != 32 {
        return Err(SolanaError::InvalidAddress(format!(
            "Expected 32 bytes for Solana address, got {}",
            decoded.len()
        )));
    }

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&decoded);
    Ok(pub_bytes)
}

pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: &[u8; 32],
) -> Result<([u8; 32], u8), SolanaError> {
    let pda_marker = b"ProgramDerivedAddress";

    for bump in (0..=255u8).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id);
        hasher.update(pda_marker);
        let hash = hasher.finalize();

        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&hash);

        // PDA must NOT be on the Ed25519 curve
        if CompressedEdwardsY(candidate).decompress().is_none() {
            return Ok((candidate, bump));
        }
    }

    Err(SolanaError::AtaError("Unable to find valid PDA nonce".to_string()))
}

pub fn get_associated_token_address(
    wallet_address: &str,
    mint_address: &str,
) -> Result<String, SolanaError> {
    let wallet_bytes = validate_solana_address(wallet_address)?;
    let mint_bytes = validate_solana_address(mint_address)?;
    let token_program_bytes = validate_solana_address(TOKEN_PROGRAM_ID)?;
    let ata_program_bytes = validate_solana_address(ASSOCIATED_TOKEN_PROGRAM_ID)?;

    let seeds: [&[u8]; 3] = [&wallet_bytes, &token_program_bytes, &mint_bytes];
    let (ata_bytes, _bump) = find_program_address(&seeds, &ata_program_bytes)?;

    Ok(bs58::encode(&ata_bytes).into_string())
}

// ----------------- Solana Wire Transaction Construction -----------------

pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

pub struct SolanaTransaction {
    pub payer: [u8; 32],
    pub recent_blockhash: [u8; 32],
    pub account_keys: Vec<[u8; 32]>,
    pub instructions: Vec<CompiledInstruction>,
}

impl SolanaTransaction {
    pub fn build_spl_transfer(
        payer_pubkey: [u8; 32],
        source_ata: [u8; 32],
        destination_ata: [u8; 32],
        amount_raw: u64,
        recent_blockhash: [u8; 32],
        create_recipient_ata: Option<([u8; 32], [u8; 32])>, // (recipient_owner, mint)
    ) -> Self {
        let token_prog_bytes = validate_solana_address(TOKEN_PROGRAM_ID).unwrap();
        let mut account_keys = Vec::new();
        let mut instructions = Vec::new();

        account_keys.push(payer_pubkey);       // 0: payer (signer, writable)
        account_keys.push(source_ata);         // 1: source_ata (writable)
        account_keys.push(destination_ata);    // 2: destination_ata (writable)
        account_keys.push(token_prog_bytes);   // 3: token program

        if let Some((recipient_owner, mint)) = create_recipient_ata {
            let ata_prog_bytes = validate_solana_address(ASSOCIATED_TOKEN_PROGRAM_ID).unwrap();
            let sys_prog_bytes = validate_solana_address(SYSTEM_PROGRAM_ID).unwrap();

            account_keys.push(recipient_owner); // 4
            account_keys.push(mint);            // 5
            account_keys.push(sys_prog_bytes);  // 6
            account_keys.push(ata_prog_bytes);  // 7

            // Instruction to create ATA:
            // accounts: [payer(0), dest_ata(2), recipient_owner(4), mint(5), system(6), token(3)]
            instructions.push(CompiledInstruction {
                program_id_index: 7, // ata_prog_bytes
                accounts: vec![0, 2, 4, 5, 6, 3],
                data: vec![],
            });
        }

        // Token instruction: 3 (transfer) + amount (8 bytes LE)
        let mut transfer_data = Vec::with_capacity(9);
        transfer_data.push(3);
        transfer_data.extend_from_slice(&amount_raw.to_le_bytes());

        instructions.push(CompiledInstruction {
            program_id_index: 3, // token_prog_bytes
            accounts: vec![1, 2, 0], // source_ata, dest_ata, owner (payer)
            data: transfer_data,
        });

        Self {
            payer: payer_pubkey,
            recent_blockhash,
            account_keys,
            instructions,
        }
    }

    pub fn serialize_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        // Header: num_required_signatures (1), num_readonly_signed (0), num_readonly_unsigned (e.g. programs)
        msg.push(1);
        msg.push(0);
        msg.push(1); // at least programs are readonly

        // Account keys
        encode_compact_u16(&mut msg, self.account_keys.len() as u16);
        for key in &self.account_keys {
            msg.extend_from_slice(key);
        }

        // Recent blockhash
        msg.extend_from_slice(&self.recent_blockhash);

        // Instructions
        encode_compact_u16(&mut msg, self.instructions.len() as u16);
        for ix in &self.instructions {
            msg.push(ix.program_id_index);
            encode_compact_u16(&mut msg, ix.accounts.len() as u16);
            msg.extend_from_slice(&ix.accounts);
            encode_compact_u16(&mut msg, ix.data.len() as u16);
            msg.extend_from_slice(&ix.data);
        }

        msg
    }

    pub fn sign_and_serialize(&self, signing_key: &SigningKey) -> (String, String) {
        let message_bytes = self.serialize_message();
        let signature = signing_key.sign(&message_bytes);

        let mut tx_wire = Vec::new();
        // 1 signature
        encode_compact_u16(&mut tx_wire, 1);
        tx_wire.extend_from_slice(&signature.to_bytes());
        tx_wire.extend_from_slice(&message_bytes);

        let tx_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &tx_wire,
        );
        let sig_b58 = bs58::encode(&signature.to_bytes()).into_string();

        (tx_b64, sig_b58)
    }
}

fn encode_compact_u16(buf: &mut Vec<u8>, mut val: u16) {
    loop {
        let mut elem = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(elem);
            break;
        } else {
            elem |= 0x80;
            buf.push(elem);
        }
    }
}

pub struct SolanaClient {
    client: Client,
    pub rpc_url: String,
}

impl SolanaClient {
    pub fn new(rpc_url: &str) -> Self {
        let client = crate::chains::create_http_client(15, None);
        Self {
            client,
            rpc_url: rpc_url.to_string(),
        }
    }

    pub async fn get_latest_blockhash(&self) -> Result<[u8; 32], SolanaError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "confirmed"}]
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(SolanaError::Rpc("getLatestBlockhash".to_string(), err.to_string()));
        }

        let b58_hash = json_val["result"]["value"]["blockhash"]
            .as_str()
            .ok_or_else(|| SolanaError::Rpc("getLatestBlockhash".to_string(), "Missing blockhash".to_string()))?;

        validate_solana_address(b58_hash)
    }

    pub async fn get_sol_balance(&self, address: &str) -> Result<u64, SolanaError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [address]
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(SolanaError::Rpc("getBalance".to_string(), err.to_string()));
        }

        let lamports = json_val["result"]["value"].as_u64().unwrap_or(0);
        Ok(lamports)
    }

    pub async fn get_usdt_token_balance(&self, ata_address: &str) -> Result<u128, SolanaError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getTokenAccountBalance",
            "params": [ata_address]
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            let msg = err.to_string();
            if msg.contains("could not find account") {
                return Ok(0);
            }
            return Err(SolanaError::Rpc("getTokenAccountBalance".to_string(), msg));
        }

        let amount_str = json_val["result"]["value"]["amount"]
            .as_str()
            .unwrap_or("0");

        amount_str
            .parse::<u128>()
            .map_err(|e| SolanaError::Rpc("ParseTokenBalance".to_string(), e.to_string()))
    }

    pub async fn send_transaction_b64(&self, tx_base64: &str) -> Result<String, SolanaError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "sendTransaction",
            "params": [
                tx_base64,
                {"encoding": "base64", "preflightCommitment": "confirmed"}
            ]
        });

        let resp = self.client.post(&self.rpc_url).json(&body).send().await?;
        let json_val: serde_json::Value = resp.json().await?;

        if let Some(err) = json_val.get("error") {
            return Err(SolanaError::Rpc("sendTransaction".to_string(), err.to_string()));
        }

        let sig = json_val["result"]
            .as_str()
            .ok_or_else(|| SolanaError::Rpc("sendTransaction".to_string(), "Missing signature".to_string()))?;

        Ok(sig.to_string())
    }

    pub async fn check_transfer_eligibility(
        &self,
        net: &NetworkSpec,
        owner_address: &str,
        send_amount_raw: u128,
        min_fee_lamports: u64,
    ) -> Result<(u64, u128), SolanaError> {
        let mint = net.usdt_contract.ok_or_else(|| {
            SolanaError::Rpc("Config".to_string(), "No Solana USDT mint address".to_string())
        })?;

        let ata = get_associated_token_address(owner_address, mint)?;
        let lamports = self.get_sol_balance(owner_address).await?;
        let usdt_raw = self.get_usdt_token_balance(&ata).await?;

        if usdt_raw < send_amount_raw {
            let have_fmt = format!("{:.6}", usdt_raw as f64 / 1_000_000.0);
            let send_fmt = format!("{:.6}", send_amount_raw as f64 / 1_000_000.0);
            return Err(SolanaError::InsufficientBalance {
                have: have_fmt,
                send: send_fmt,
            });
        }

        if lamports < min_fee_lamports {
            let have_fmt = format!("{:.6}", lamports as f64 / 1_000_000.0);
            let need_fmt = format!("{:.6}", min_fee_lamports as f64 / 1_000_000.0);
            return Err(SolanaError::InsufficientFee {
                have: have_fmt,
                need: need_fmt,
            });
        }

        Ok((lamports, usdt_raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_official_tether_usdt_mint_validation() {
        let mint = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
        let pub_bytes = validate_solana_address(mint).expect("mint address valid");
        assert_eq!(pub_bytes.len(), 32);
        assert_eq!(bs58::encode(&pub_bytes).into_string(), mint);

        assert!(validate_solana_address("0xdAC17F958D2ee523a2206206994597C13D831ec7").is_err());
    }

    #[test]
    fn test_associated_token_address_derivation() {
        let wallet = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
        let mint = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
        let ata = get_associated_token_address(wallet, mint).expect("ATA derived");
        assert!(!ata.is_empty());
        validate_solana_address(&ata).expect("ATA is valid Base58");
    }

    #[test]
    fn test_solana_spl_transaction_serialization_and_signing() {
        let seed = [99u8; 32];
        let sol = SolanaKey::from_seed_32(&seed);

        let source_ata = validate_solana_address("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin").unwrap();
        let dest_ata = validate_solana_address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let dummy_blockhash = [7u8; 32];

        let tx = SolanaTransaction::build_spl_transfer(
            sol.public_key,
            source_ata,
            dest_ata,
            1_000_000, // 1 USDT
            dummy_blockhash,
            None,
        );

        let (b64, sig_b58) = tx.sign_and_serialize(&sol.signing_key);
        assert!(!b64.is_empty());
        assert!(!sig_b58.is_empty());

        let wire_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &b64,
        ).unwrap();
        assert_eq!(wire_bytes[0], 1); // 1 signature
    }
}
