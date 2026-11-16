use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use qrcode::render::unicode;
use qrcode::QrCode;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::chains::{
    encode_erc20_transfer, get_associated_token_address, validate_evm_address,
    validate_recipient_address, validate_solana_address, validate_ton_address,
    Eip1559Tx, EvmClient, EvmKey, JettonTransferPayload, MoneroKeys,
    MoneroNodeClient, SolanaClient, SolanaKey, SolanaTransaction, TonClient, TonKey, TronClient,
    TronKey,
};
use crate::config::AppSettings;
use crate::core::crypto::{check_password_strength, PasswordStrength};
use crate::core::wallet::WalletSecrets;
use crate::networks::registry::{get_network, NetworkFamily, NetworkId, NetworkSpec, NETWORKS};
use crate::platform::Storage;
use crate::ui::theme::Theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview = 0,
    Usdt = 1,
    Monero = 2,
    Backup = 3,
    Settings = 4,
}

impl Tab {
    pub fn all() -> &'static [Tab] {
        &[
            Tab::Overview,
            Tab::Usdt,
            Tab::Monero,
            Tab::Backup,
            Tab::Settings,
        ]
    }

    pub fn title(&self) -> &'static str {
        match self {
            Tab::Overview => "  Кошелёк  ",
            Tab::Usdt => "  USDT  ",
            Tab::Monero => "  Monero  ",
            Tab::Backup => "  Бэкап  ",
            Tab::Settings => "  Настройки  ",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Welcome,
    CreatePassword,
    ShowNewMnemonic,
    VerifyMnemonic,
    RestoreWallet,
    Unlock,
    Main(Tab),
    ReceiveModal(NetworkId),
    SendModal {
        network_id: NetworkId,
        step: SendStep,
    },
    RevealSeedWarning,
    RevealSeedView,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendStep {
    InputForm,
    ConfirmSummary {
        estimated_fee: String,
        native_balance: String,
        usdt_balance: String,
        can_send: bool,
        fee_check_msg: String,
    },
    Broadcasting,
    ResultSuccess(String),
    ResultError(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkBalanceInfo {
    pub native_balance: Option<String>,
    pub usdt_balance: Option<String>,
    pub is_loading: bool,
    pub error: Option<String>,
}

pub fn get_explorer_tx_url(net: &NetworkSpec, tx_hash: &str) -> String {
    match net.id {
        NetworkId::Sepolia => format!("https://sepolia.etherscan.io/tx/{tx_hash}"),
        NetworkId::Ethereum => format!("https://etherscan.io/tx/{tx_hash}"),
        NetworkId::Bsc => format!("https://bscscan.com/tx/{tx_hash}"),
        NetworkId::Polygon => format!("https://polygonscan.com/tx/{tx_hash}"),
        NetworkId::Arbitrum => format!("https://arbiscan.io/tx/{tx_hash}"),
        NetworkId::Optimism => format!("https://optimistic.etherscan.io/tx/{tx_hash}"),
        NetworkId::Avalanche => format!("https://snowtrace.io/tx/{tx_hash}"),
        NetworkId::TronNile => format!("https://nile.tronscan.org/#/transaction/{tx_hash}"),
        NetworkId::Tron => format!("https://tronscan.org/#/transaction/{tx_hash}"),
        NetworkId::Ton => format!("https://tonscan.org/tx/{tx_hash}"),
        NetworkId::Solana => format!("https://solscan.io/tx/{tx_hash}"),
        NetworkId::MoneroStagenet => format!("https://stagenet.xmrchain.net/tx/{tx_hash}"),
        NetworkId::MoneroMainnet => format!("https://xmrchain.net/tx/{tx_hash}"),
    }
}

pub struct DerivedAddresses {
    pub evm_address: String,
    pub tron_address: String,
    pub ton_address: String,
    pub solana_address: String,
    pub monero_mainnet: String,
    pub monero_stagenet: String,
}

pub struct App {
    pub theme: Theme,
    pub screen: Screen,
    pub wallet_path: PathBuf,
    pub secrets: Option<WalletSecrets>,
    pub pending_secrets: Option<WalletSecrets>,
    pub addresses: Option<DerivedAddresses>,
    pub settings: AppSettings,
    pub balances: std::collections::HashMap<NetworkId, NetworkBalanceInfo>,

    // Form inputs
    pub input_buffer: String,
    pub input_buffer_confirm: String,
    pub input_field_idx: usize,
    pub status_message: Option<(String, bool)>, // (msg, is_error)

    // Send Form inputs
    pub send_recipient_input: String,
    pub send_amount_input: String,
    pub send_cursor: usize,

    // Verification step
    pub verification_indices: Vec<usize>,
    pub verification_inputs: Vec<String>,
    pub verification_cursor: usize,

    // Navigation state in Main
    pub active_tab: Tab,
    pub selected_usdt_idx: usize,

    // Backup screen fields
    pub backup_export_path: String,

    pub should_exit: bool,
}

impl App {
    pub fn new<P: AsRef<Path>>(wallet_path: P) -> Self {
        let path = wallet_path.as_ref().to_path_buf();
        let exists = path.exists();
        let config_path = AppSettings::default_config_path();
        let settings = AppSettings::load_or_default(config_path);

        let screen = if exists {
            Screen::Unlock
        } else {
            Screen::Welcome
        };

        Self {
            theme: Theme::default(),
            screen,
            wallet_path: path,
            secrets: None,
            pending_secrets: None,
            addresses: None,
            settings,
            input_buffer: String::new(),
            input_buffer_confirm: String::new(),
            input_field_idx: 0,
            status_message: None,
            send_recipient_input: String::new(),
            send_amount_input: String::new(),
            send_cursor: 0,
            verification_indices: Vec::new(),
            verification_inputs: Vec::new(),
            verification_cursor: 0,
            active_tab: Tab::Overview,
            selected_usdt_idx: 0,
            backup_export_path: "wallet_backup.dat".to_string(),
            balances: std::collections::HashMap::new(),
            should_exit: false,
        }
    }

    pub fn derive_keys_for_wallet(&mut self) {
        if let Some(secrets) = &self.secrets {
            let mnemonic = bip39::Mnemonic::parse(&secrets.bip39_mnemonic).unwrap();
            let seed = mnemonic.to_seed("");

            let evm = EvmKey::from_seed(&seed, "m/44'/60'/0'/0/0").unwrap();
            let tron = TronKey::from_seed(&seed, "m/44'/195'/0'/0/0").unwrap();
            let ton = TonKey::from_seed_32(&seed[0..32].try_into().unwrap());
            let solana = SolanaKey::from_seed_32(&seed[0..32].try_into().unwrap());

            let words: Vec<String> = secrets.monero_words().iter().map(|s| s.to_string()).collect();
            let monero = MoneroKeys::from_mnemonic_words(&words).unwrap();

            self.addresses = Some(DerivedAddresses {
                evm_address: evm.checksum_address,
                tron_address: tron.base58_address,
                ton_address: ton.user_friendly_address,
                solana_address: solana.base58_address,
                monero_mainnet: monero.primary_address,
                monero_stagenet: monero.stagenet_address,
            });
        }
    }

    pub fn get_address_for_network(&self, net: &NetworkSpec) -> String {
        if let Some(addrs) = &self.addresses {
            match net.family {
                NetworkFamily::Evm => addrs.evm_address.clone(),
                NetworkFamily::Tron => addrs.tron_address.clone(),
                NetworkFamily::Ton => addrs.ton_address.clone(),
                NetworkFamily::Solana => addrs.solana_address.clone(),
                NetworkFamily::Monero => {
                    if net.is_testnet {
                        addrs.monero_stagenet.clone()
                    } else {
                        addrs.monero_mainnet.clone()
                    }
                }
            }
        } else {
            "Кошелёк заблокирован".to_string()
        }
    }

    pub fn set_status(&mut self, msg: &str, is_error: bool) {
        self.status_message = Some((msg.to_string(), is_error));
    }

    pub fn clear_status(&mut self) {
        self.status_message = None;
    }

    pub fn format_balance_for_display(&self, net: &NetworkSpec) -> String {
        if let Some(info) = self.balances.get(&net.id) {
            if info.is_loading {
                return "[Загрузка...]".to_string();
            }
            if let Some(err) = &info.error {
                return format!("[Ошибка: {err}]");
            }
            let native = info.native_balance.as_deref().unwrap_or("0.00");
            let usdt = info.usdt_balance.as_deref().unwrap_or("0.00 USDT");
            format!("{native} • {usdt}")
        } else {
            "[Нажмите 'r' для обновления]".to_string()
        }
    }

    pub async fn refresh_balances(&mut self) {
        if self.addresses.is_none() {
            return;
        }

        for net in NETWORKS {
            let addr = self.get_address_for_network(net);
            let mut info = NetworkBalanceInfo {
                native_balance: None,
                usdt_balance: None,
                is_loading: true,
                error: None,
            };
            self.balances.insert(net.id, info.clone());

            match net.family {
                NetworkFamily::Evm => {
                    let client = EvmClient::new(net.primary_rpc);
                    match client.get_native_balance(&addr).await {
                        Ok(wei) => {
                            let eth = wei as f64 / 1e18;
                            info.native_balance = Some(format!("{:.4} {}", eth, net.native_symbol));
                        }
                        Err(e) => {
                            info.error = Some(format!("{e}"));
                        }
                    }
                    if let Some(contract) = net.usdt_contract
                        && let Ok(owner) = validate_evm_address(&addr)
                        && let Ok(usdt) = client.get_usdt_balance(contract, &owner).await {
                            let dec = 10u128.pow(net.usdt_decimals as u32);
                            info.usdt_balance = Some(format!("{:.2} USDT", usdt as f64 / dec as f64));
                        }
                }
                NetworkFamily::Tron => {
                    let client = TronClient::new(net.primary_rpc);
                    match client.get_trx_balance(&addr).await {
                        Ok(sun) => {
                            let trx = sun as f64 / 1_000_000.0;
                            info.native_balance = Some(format!("{:.2} TRX", trx));
                        }
                        Err(e) => {
                            info.error = Some(format!("{e}"));
                        }
                    }
                    if let Some(contract) = net.usdt_contract
                        && let Ok(usdt) = client.get_trc20_usdt_balance(contract, &addr).await {
                            info.usdt_balance = Some(format!("{:.2} USDT", usdt as f64 / 1_000_000.0));
                        }
                }
                NetworkFamily::Ton => {
                    let client = TonClient::new(net.primary_rpc);
                    match client.get_ton_balance(&addr).await {
                        Ok(nano) => {
                            let ton = nano as f64 / 1_000_000_000.0;
                            info.native_balance = Some(format!("{:.4} TON", ton));
                        }
                        Err(e) => {
                            info.error = Some(format!("{e}"));
                        }
                    }
                }
                NetworkFamily::Solana => {
                    let client = SolanaClient::new(net.primary_rpc);
                    match client.get_sol_balance(&addr).await {
                        Ok(lamports) => {
                            let sol = lamports as f64 / 1_000_000_000.0;
                            info.native_balance = Some(format!("{:.4} SOL", sol));
                        }
                        Err(e) => {
                            info.error = Some(format!("{e}"));
                        }
                    }
                    if let Some(mint) = net.usdt_contract
                        && let Ok(ata) = get_associated_token_address(&addr, mint)
                        && let Ok(usdt) = client.get_usdt_token_balance(&ata).await {
                            info.usdt_balance = Some(format!("{:.2} USDT", usdt as f64 / 1_000_000.0));
                        }
                }
                NetworkFamily::Monero => {
                    if let Ok(client) = MoneroNodeClient::new(net.primary_rpc, None) {
                        if let Ok(h) = client.get_daemon_height().await {
                            info.native_balance = Some(format!("Высота: {h}"));
                        } else {
                            info.error = Some("Узел недоступен".to_string());
                        }
                    }
                }
            }
            info.is_loading = false;
            self.balances.insert(net.id, info);
        }
    }

    pub async fn prepare_send_confirmation(&mut self, net_id: NetworkId) -> Result<SendStep, String> {
        let net = get_network(net_id);
        let amount_f64 = self.send_amount_input.trim().parse::<f64>()
            .map_err(|_| "Некорректная сумма перевода".to_string())?;
        if amount_f64 <= 0.0 {
            return Err("Сумма должна быть больше нуля".to_string());
        }

        let address = self.get_address_for_network(net);
        if address == "Кошелёк заблокирован" {
            return Err("Кошелёк заблокирован".to_string());
        }

        match net.family {
            NetworkFamily::Evm => {
                let client = EvmClient::new(net.primary_rpc);
                let native_bal = client.get_native_balance(&address).await.unwrap_or(0);
                let native_bal_f64 = native_bal as f64 / 1e18;
                let native_str = format!("{:.6} {}", native_bal_f64, net.native_symbol);

                let contract = net.usdt_contract.ok_or_else(|| "Нет контракта USDT".to_string())?;
                let owner_bytes = validate_evm_address(&address).map_err(|e| e.to_string())?;
                let usdt_bal = client.get_usdt_balance(contract, &owner_bytes).await.unwrap_or(0);
                let dec = 10u128.pow(net.usdt_decimals as u32);
                let usdt_bal_f64 = usdt_bal as f64 / dec as f64;
                let usdt_str = format!("{:.2} USDT", usdt_bal_f64);

                let gas_price = client.get_gas_price().await.unwrap_or(20_000_000_000);
                let fee_wei = 65_000u128 * (gas_price + 1_500_000_000);
                let fee_f64 = fee_wei as f64 / 1e18;
                let fee_str = format!("{:.6} {}", fee_f64, net.native_symbol);

                let has_fee = native_bal >= fee_wei;
                let has_balance = usdt_bal_f64 >= amount_f64;
                let can_send = has_fee && has_balance;

                let fee_check_msg = if !has_fee {
                    format!("НЕДОСТАТОЧНО СРЕДСТВ ДЛЯ КОМИССИИ: требуется {}, доступно {}", fee_str, native_str)
                } else if !has_balance {
                    format!("НЕДОСТАТОЧНО USDT: требуется {:.2}, доступно {:.2}", amount_f64, usdt_bal_f64)
                } else {
                    "Баланс комиссии и USDT подтверждён".to_string()
                };

                Ok(SendStep::ConfirmSummary {
                    estimated_fee: fee_str,
                    native_balance: native_str,
                    usdt_balance: usdt_str,
                    can_send,
                    fee_check_msg,
                })
            }
            NetworkFamily::Tron => {
                let client = TronClient::new(net.primary_rpc);
                let trx_sun = client.get_trx_balance(&address).await.unwrap_or(0);
                let trx_f64 = trx_sun as f64 / 1_000_000.0;
                let native_str = format!("{:.6} TRX", trx_f64);

                let contract = net.usdt_contract.ok_or_else(|| "Нет контракта USDT".to_string())?;
                let usdt_bal = client.get_trc20_usdt_balance(contract, &address).await.unwrap_or(0);
                let usdt_bal_f64 = usdt_bal as f64 / 1_000_000.0;
                let usdt_str = format!("{:.2} USDT", usdt_bal_f64);

                let fee_str = "15.000000 TRX (оценка Energy/Bandwidth)".to_string();
                let min_sun = 15_000_000u64;

                let has_fee = trx_sun >= min_sun;
                let has_balance = usdt_bal_f64 >= amount_f64;
                let can_send = has_fee && has_balance;

                let fee_check_msg = if !has_fee {
                    format!("НЕДОСТАТОЧНО TRX: требуется 15.0 TRX на энергию, доступно {}", native_str)
                } else if !has_balance {
                    format!("НЕДОСТАТОЧНО USDT: требуется {:.2}, доступно {:.2}", amount_f64, usdt_bal_f64)
                } else {
                    "Баланс TRX и TRC-20 USDT подтверждён".to_string()
                };

                Ok(SendStep::ConfirmSummary {
                    estimated_fee: fee_str,
                    native_balance: native_str,
                    usdt_balance: usdt_str,
                    can_send,
                    fee_check_msg,
                })
            }
            NetworkFamily::Ton => {
                let client = TonClient::new(net.primary_rpc);
                let ton_nano = client.get_ton_balance(&address).await.unwrap_or(0);
                let ton_f64 = ton_nano as f64 / 1_000_000_000.0;
                let native_str = format!("{:.4} TON", ton_f64);

                let fee_str = "0.0500 TON (Jetton transfer + forward)".to_string();
                let min_nano = 50_000_000u128;
                let has_fee = ton_nano >= min_nano;
                let can_send = has_fee;

                let fee_check_msg = if !has_fee {
                    format!("НЕДОСТАТОЧНО TON: требуется 0.05 TON, доступно {}", native_str)
                } else {
                    "Баланс комиссии подтверждён".to_string()
                };

                Ok(SendStep::ConfirmSummary {
                    estimated_fee: fee_str,
                    native_balance: native_str,
                    usdt_balance: "Jetton USDT".to_string(),
                    can_send,
                    fee_check_msg,
                })
            }
            NetworkFamily::Solana => {
                let client = SolanaClient::new(net.primary_rpc);
                let lamports = client.get_sol_balance(&address).await.unwrap_or(0);
                let sol_f64 = lamports as f64 / 1_000_000_000.0;
                let native_str = format!("{:.6} SOL", sol_f64);

                let mint = net.usdt_contract.ok_or_else(|| "Нет контракта USDT".to_string())?;
                let ata_res = get_associated_token_address(&address, mint);
                let usdt_bal = if let Ok(ata) = &ata_res {
                    client.get_usdt_token_balance(ata).await.unwrap_or(0)
                } else {
                    0
                };
                let usdt_bal_f64 = usdt_bal as f64 / 1_000_000.0;
                let usdt_str = format!("{:.2} USDT", usdt_bal_f64);

                let fee_str = "0.000005 SOL (5000 lamports)".to_string();
                let has_fee = lamports >= 5000;
                let has_balance = usdt_bal_f64 >= amount_f64;
                let can_send = has_fee && has_balance;

                let fee_check_msg = if !has_fee {
                    format!("НЕДОСТАТОЧНО SOL: требуется 0.000005 SOL, доступно {}", native_str)
                } else if !has_balance {
                    format!("НЕДОСТАТОЧНО USDT: требуется {:.2}, доступно {:.2}", amount_f64, usdt_bal_f64)
                } else {
                    "Баланс SOL и SPL USDT подтверждён".to_string()
                };

                Ok(SendStep::ConfirmSummary {
                    estimated_fee: fee_str,
                    native_balance: native_str,
                    usdt_balance: usdt_str,
                    can_send,
                    fee_check_msg,
                })
            }
            NetworkFamily::Monero => {
                let client = MoneroNodeClient::new(net.primary_rpc, None).map_err(|e| e.to_string())?;
                let fee = client.get_fee_estimate().await.unwrap_or(20000);
                let fee_f64 = fee as f64 / 1e12;
                let fee_str = format!("{:.12} XMR", fee_f64);

                Ok(SendStep::ConfirmSummary {
                    estimated_fee: fee_str,
                    native_balance: "Stagenet XMR".to_string(),
                    usdt_balance: "—".to_string(),
                    can_send: false,
                    fee_check_msg: "Для отправки Monero используйте stagenet с пополненными выходами".to_string(),
                })
            }
        }
    }

    pub async fn execute_send_transaction(
        &mut self,
        network_id: NetworkId,
    ) -> Result<String, String> {
        let net = get_network(network_id);
        let amount_f64 = self.send_amount_input.trim().parse::<f64>()
            .map_err(|_| "Некорректная сумма перевода".to_string())?;

        let secrets = self.secrets.as_ref().ok_or("Кошелёк не разблокирован")?;
        let mnemonic = bip39::Mnemonic::parse(&secrets.bip39_mnemonic)
            .map_err(|e| format!("Mnemonic error: {e}"))?;
        let seed = zeroize::Zeroizing::new(mnemonic.to_seed(""));

        match net.family {
            NetworkFamily::Evm => {
                let evm = EvmKey::from_seed(&seed, net.derivation_path).map_err(|e| e.to_string())?;
                let client = EvmClient::new(net.primary_rpc);
                let nonce = client.get_transaction_count(&evm.checksum_address).await
                    .map_err(|e| format!("Ошибка получения nonce: {e}"))?;
                let gas_price = client.get_gas_price().await.unwrap_or(20_000_000_000);
                let priority_fee = 1_500_000_000u128;

                let recipient_bytes = validate_evm_address(&self.send_recipient_input)
                    .map_err(|e| format!("Некорректный получатель: {e}"))?;
                let contract = net.usdt_contract.ok_or("Нет контракта USDT")?;
                let contract_bytes = validate_evm_address(contract)
                    .map_err(|e| format!("Некорректный контракт: {e}"))?;

                let dec = 10u128.pow(net.usdt_decimals as u32);
                let amount_raw = (amount_f64 * dec as f64) as u128;
                let calldata_hex = encode_erc20_transfer(&recipient_bytes, amount_raw);
                let calldata = hex::decode(&calldata_hex[2..])
                    .map_err(|e| format!("Hex decode error: {e}"))?;

                let tx = Eip1559Tx {
                    chain_id: net.chain_id.unwrap_or(1),
                    nonce,
                    max_priority_fee: priority_fee,
                    max_fee: gas_price + priority_fee,
                    gas_limit: 65000,
                    to: contract_bytes,
                    value: 0,
                    data: calldata,
                };

                let (raw_hex, _computed_hash) = tx.sign_and_serialize(&evm.signing_key);
                let tx_hash = client.send_raw_transaction(&raw_hex).await
                    .map_err(|e| format!("{e}"))?;
                Ok(tx_hash)
            }
            NetworkFamily::Tron => {
                let tron = TronKey::from_seed(&seed, net.derivation_path).map_err(|e| e.to_string())?;
                let client = TronClient::new(net.primary_rpc);
                let contract = net.usdt_contract.ok_or("Нет контракта Tron USDT")?;
                let amount_raw = (amount_f64 * 1_000_000.0) as u128;

                let tx_obj = client.create_trc20_transfer_tx(
                    &tron.base58_address,
                    contract,
                    &self.send_recipient_input,
                    amount_raw,
                    30_000_000,
                ).await.map_err(|e| format!("{e}"))?;

                let raw_hex = tx_obj.get("raw_data_hex")
                    .and_then(|h| h.as_str())
                    .ok_or("Узел не вернул raw_data_hex")?;
                let sig_hex = client.sign_transaction_locally(&tron.signing_key, raw_hex)
                    .map_err(|e| format!("{e}"))?;

                let txid = client.broadcast_transaction(tx_obj, &sig_hex).await
                    .map_err(|e| format!("{e}"))?;
                Ok(txid)
            }
            NetworkFamily::Ton => {
                let ton = TonKey::from_seed_32(&seed[0..32].try_into().unwrap());
                let client = TonClient::new(net.primary_rpc);
                let recipient_bytes = validate_ton_address(&self.send_recipient_input)
                    .map_err(|e| format!("{e}"))?;
                let amount_raw = (amount_f64 * 1_000_000.0) as u128;

                let payload = JettonTransferPayload {
                    query_id: rand::random::<u64>(),
                    amount_raw,
                    recipient: recipient_bytes,
                    response_address: ton.signing_key.verifying_key().to_bytes(),
                    forward_ton_amount: 1,
                };

                let (msg, _sig) = payload.sign_wallet_message(&ton.signing_key, 0, 1800000000);
                let boc_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &msg,
                );
                let hash = client.send_boc(&boc_b64).await.map_err(|e| format!("{e}"))?;
                Ok(hash)
            }
            NetworkFamily::Solana => {
                let sol = SolanaKey::from_seed_32(&seed[0..32].try_into().unwrap());
                let client = SolanaClient::new(net.primary_rpc);
                let mint = net.usdt_contract.ok_or("Нет адреса USDT mint")?;

                let src_ata_b58 = get_associated_token_address(&sol.base58_address, mint)
                    .map_err(|e| format!("{e}"))?;
                let src_ata = validate_solana_address(&src_ata_b58).map_err(|e| format!("{e}"))?;

                let dst_ata_b58 = get_associated_token_address(&self.send_recipient_input, mint)
                    .map_err(|e| format!("{e}"))?;
                let dst_ata = validate_solana_address(&dst_ata_b58).map_err(|e| format!("{e}"))?;

                let blockhash = client.get_latest_blockhash().await
                    .map_err(|e| format!("{e}"))?;
                let amount_raw = (amount_f64 * 1_000_000.0) as u64;

                let tx = SolanaTransaction::build_spl_transfer(
                    sol.public_key,
                    src_ata,
                    dst_ata,
                    amount_raw,
                    blockhash,
                    None,
                );

                let (tx_b64, sig_b58) = tx.sign_and_serialize(&sol.signing_key);
                let _ = client.send_transaction_b64(&tx_b64).await
                    .map_err(|e| format!("{e}"))?;
                Ok(sig_b58)
            }
            NetworkFamily::Monero => {
                Err("Прямая рассылка Monero Stagenet требует предварительного сканирования неизрасходованных выходов (UTXO)".to_string())
            }
        }
    }

    pub async fn handle_key(&mut self, key: KeyEvent) {
        match &mut self.screen {
            Screen::Welcome => match key.code {
                KeyCode::Char('1') | KeyCode::Enter => {
                    self.screen = Screen::CreatePassword;
                    self.input_buffer.clear();
                    self.input_buffer_confirm.clear();
                    self.input_field_idx = 0;
                    self.clear_status();
                }
                KeyCode::Char('2') => {
                    self.screen = Screen::RestoreWallet;
                    self.input_buffer.clear();
                    self.input_buffer_confirm.clear();
                    self.input_field_idx = 0;
                    self.clear_status();
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.should_exit = true;
                }
                _ => {}
            },
            Screen::CreatePassword => match key.code {
                KeyCode::Esc => {
                    self.screen = Screen::Welcome;
                    self.clear_status();
                }
                KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                    self.input_field_idx = (self.input_field_idx + 1) % 2;
                }
                KeyCode::Backspace => {
                    if self.input_field_idx == 0 {
                        self.input_buffer.pop();
                    } else {
                        self.input_buffer_confirm.pop();
                    }
                }
                KeyCode::Char(c) => {
                    if self.input_field_idx == 0 {
                        self.input_buffer.push(c);
                    } else {
                        self.input_buffer_confirm.push(c);
                    }
                }
                KeyCode::Enter => {
                    if self.input_buffer != self.input_buffer_confirm {
                        self.set_status("Пароли не совпадают", true);
                        return;
                    }
                    match check_password_strength(&self.input_buffer) {
                        PasswordStrength::TooShort => {
                            self.set_status("Пароль слишком короткий (минимум 8 знаков)", true);
                            return;
                        }
                        PasswordStrength::Weak(reason) => {
                            self.set_status(&format!("Слабый пароль: {reason}"), true);
                        }
                        _ => {}
                    }

                    match WalletSecrets::new_random(3200000) {
                        Ok(secrets) => {
                            let indices = secrets.pick_verification_indices(3);
                            self.verification_indices = indices;
                            self.verification_inputs = vec![String::new(), String::new(), String::new()];
                            self.verification_cursor = 0;
                            self.pending_secrets = Some(secrets);
                            self.screen = Screen::ShowNewMnemonic;
                            self.clear_status();
                        }
                        Err(e) => {
                            self.set_status(&format!("Ошибка создания: {e}"), true);
                        }
                    }
                }
                _ => {}
            },
            Screen::ShowNewMnemonic => match key.code {
                KeyCode::Enter => {
                    self.screen = Screen::VerifyMnemonic;
                    self.clear_status();
                }
                KeyCode::Esc => {
                    self.screen = Screen::Welcome;
                    self.pending_secrets = None;
                    self.clear_status();
                }
                _ => {}
            },
            Screen::VerifyMnemonic => match key.code {
                KeyCode::Esc => {
                    self.screen = Screen::ShowNewMnemonic;
                    self.clear_status();
                }
                KeyCode::Tab | KeyCode::Down => {
                    self.verification_cursor = (self.verification_cursor + 1) % 3;
                }
                KeyCode::Up => {
                    if self.verification_cursor == 0 {
                        self.verification_cursor = 2;
                    } else {
                        self.verification_cursor -= 1;
                    }
                }
                KeyCode::Backspace => {
                    if let Some(buf) = self.verification_inputs.get_mut(self.verification_cursor) {
                        buf.pop();
                    }
                }
                KeyCode::Char(c) => {
                    if let Some(buf) = self.verification_inputs.get_mut(self.verification_cursor) {
                        buf.push(c);
                    }
                }
                KeyCode::Enter => {
                    if let Some(secrets) = &self.pending_secrets {
                        let mut all_correct = true;
                        for (i, &idx) in self.verification_indices.iter().enumerate() {
                            let input = &self.verification_inputs[i];
                            if !secrets.verify_word(idx, input) {
                                all_correct = false;
                                break;
                            }
                        }

                        if !all_correct {
                            self.set_status("Слова не совпали. Проверьте правильность записи.", true);
                        } else {
                            if let Err(e) = secrets.save_to_file(&self.wallet_path, &self.input_buffer) {
                                self.set_status(&format!("Ошибка сохранения: {e}"), true);
                                return;
                            }
                            self.secrets = self.pending_secrets.take();
                            self.derive_keys_for_wallet();
                            self.input_buffer.clear();
                            self.input_buffer_confirm.clear();
                            self.screen = Screen::Main(Tab::Overview);
                            self.clear_status();
                            self.refresh_balances().await;
                        }
                    }
                }
                _ => {}
            },
            Screen::RestoreWallet => match key.code {
                KeyCode::Esc => {
                    self.screen = Screen::Welcome;
                    self.clear_status();
                }
                KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                    self.input_field_idx = (self.input_field_idx + 1) % 2;
                }
                KeyCode::Backspace => {
                    if self.input_field_idx == 0 {
                        self.input_buffer.pop();
                    } else {
                        self.input_buffer_confirm.pop();
                    }
                }
                KeyCode::Char(c) => {
                    if self.input_field_idx == 0 {
                        self.input_buffer.push(c);
                    } else {
                        self.input_buffer_confirm.push(c);
                    }
                }
                KeyCode::Enter => {
                    match WalletSecrets::from_mnemonics(
                        &self.input_buffer,
                        &self.input_buffer_confirm,
                        3200000,
                    ) {
                        Ok(secrets) => {
                            self.pending_secrets = Some(secrets);
                            self.screen = Screen::CreatePassword;
                            self.input_buffer.clear();
                            self.input_buffer_confirm.clear();
                            self.input_field_idx = 0;
                            self.clear_status();
                        }
                        Err(e) => {
                            self.set_status(&format!("Ошибка восстановления: {e}"), true);
                        }
                    }
                }
                _ => {}
            },
            Screen::Unlock => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.should_exit = true;
                }
                KeyCode::Backspace => {
                    self.input_buffer.pop();
                }
                KeyCode::Char(c) => {
                    self.input_buffer.push(c);
                }
                KeyCode::Enter => {
                    match WalletSecrets::load_from_file(&self.wallet_path, &self.input_buffer) {
                        Ok(secrets) => {
                            self.secrets = Some(secrets);
                            self.derive_keys_for_wallet();
                            self.input_buffer.clear();
                            self.screen = Screen::Main(Tab::Overview);
                            self.clear_status();
                            self.refresh_balances().await;
                        }
                        Err(_) => {
                            self.set_status("Неверный пароль или повреждённый файл", true);
                        }
                    }
                }
                _ => {}
            },
            Screen::Main(tab) => match key.code {
                KeyCode::Char('q') => {
                    self.should_exit = true;
                }
                KeyCode::Char('r') => {
                    self.refresh_balances().await;
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    let idx = *tab as usize;
                    if idx > 0 {
                        self.active_tab = Tab::all()[idx - 1];
                        self.screen = Screen::Main(self.active_tab);
                    }
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    let idx = *tab as usize;
                    if idx + 1 < Tab::all().len() {
                        self.active_tab = Tab::all()[idx + 1];
                        self.screen = Screen::Main(self.active_tab);
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if *tab == Tab::Usdt {
                        let total = NETWORKS.iter().filter(|n| n.usdt_contract.is_some()).count();
                        if total > 0 && self.selected_usdt_idx + 1 < total {
                            self.selected_usdt_idx += 1;
                        }
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if *tab == Tab::Usdt && self.selected_usdt_idx > 0 {
                        self.selected_usdt_idx -= 1;
                    }
                }
                KeyCode::Char('g') => {
                    let net_id = match *tab {
                        Tab::Usdt => {
                            let usdt_nets: Vec<_> = NETWORKS.iter().filter(|n| n.usdt_contract.is_some()).collect();
                            usdt_nets.get(self.selected_usdt_idx).map(|n| n.id).unwrap_or(NetworkId::Ethereum)
                        }
                        Tab::Monero => NetworkId::MoneroStagenet,
                        _ => NetworkId::Ethereum,
                    };
                    self.screen = Screen::ReceiveModal(net_id);
                    self.clear_status();
                }
                KeyCode::Char('s') => {
                    let net_id = match *tab {
                        Tab::Usdt => {
                            let usdt_nets: Vec<_> = NETWORKS.iter().filter(|n| n.usdt_contract.is_some()).collect();
                            usdt_nets.get(self.selected_usdt_idx).map(|n| n.id).unwrap_or(NetworkId::Ethereum)
                        }
                        Tab::Monero => NetworkId::MoneroStagenet,
                        _ => NetworkId::Ethereum,
                    };
                    self.send_recipient_input.clear();
                    self.send_amount_input.clear();
                    self.send_cursor = 0;
                    self.screen = Screen::SendModal {
                        network_id: net_id,
                        step: SendStep::InputForm,
                    };
                    self.clear_status();
                }
                KeyCode::Char('e') if *tab == Tab::Backup => {
                    let export_dst = Path::new(&self.backup_export_path);
                    match Storage::backup_wallet(&self.wallet_path, export_dst) {
                        Ok(bytes) => {
                            self.set_status(&format!("Файл экспортирован ({bytes} байт, права 0600)"), false);
                        }
                        Err(e) => {
                            self.set_status(&format!("Ошибка экспорта: {e}"), true);
                        }
                    }
                }
                KeyCode::Char('v') if *tab == Tab::Backup => {
                    self.screen = Screen::RevealSeedWarning;
                    self.clear_status();
                }
                _ => {}
            },
            Screen::ReceiveModal(_) => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.screen = Screen::Main(self.active_tab);
                    self.clear_status();
                }
                _ => {}
            },
            Screen::SendModal { network_id, step } => {
                let net_id = *network_id;
                match step {
                    SendStep::InputForm => match key.code {
                        KeyCode::Esc => {
                            self.screen = Screen::Main(self.active_tab);
                            self.clear_status();
                        }
                        KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                            self.send_cursor = (self.send_cursor + 1) % 2;
                        }
                        KeyCode::Backspace => {
                            if self.send_cursor == 0 {
                                self.send_recipient_input.pop();
                            } else {
                                self.send_amount_input.pop();
                            }
                        }
                        KeyCode::Char(c) => {
                            if self.send_cursor == 0 {
                                self.send_recipient_input.push(c);
                            } else {
                                self.send_amount_input.push(c);
                            }
                        }
                        KeyCode::Enter => {
                            let net = get_network(net_id);
                            match validate_recipient_address(net, &self.send_recipient_input) {
                                Ok(canonical) => {
                                    self.send_recipient_input = canonical;
                                    self.clear_status();
                                    match self.prepare_send_confirmation(net_id).await {
                                        Ok(step) => {
                                            self.screen = Screen::SendModal {
                                                network_id: net_id,
                                                step,
                                            };
                                        }
                                        Err(err) => {
                                            self.set_status(&err, true);
                                        }
                                    }
                                }
                                Err(err) => {
                                    self.set_status(&err, true);
                                }
                            }
                        }
                        _ => {}
                    },
                    SendStep::ConfirmSummary { can_send, .. } => {
                        let can_proceed = *can_send;
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('n') => {
                                self.screen = Screen::SendModal {
                                    network_id: net_id,
                                    step: SendStep::InputForm,
                                };
                                self.clear_status();
                            }
                            KeyCode::Enter | KeyCode::Char('y') => {
                                if !can_proceed {
                                    self.set_status("Недостаточно средств для покрытия баланса или комиссии сети", true);
                                } else {
                                    self.screen = Screen::SendModal {
                                        network_id: net_id,
                                        step: SendStep::Broadcasting,
                                    };
                                    match self.execute_send_transaction(net_id).await {
                                        Ok(tx_hash) => {
                                            self.screen = Screen::SendModal {
                                                network_id: net_id,
                                                step: SendStep::ResultSuccess(tx_hash),
                                            };
                                        }
                                        Err(err) => {
                                            self.screen = Screen::SendModal {
                                                network_id: net_id,
                                                step: SendStep::ResultError(err),
                                            };
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    SendStep::Broadcasting => {}
                    SendStep::ResultSuccess(_) | SendStep::ResultError(_) => match key.code {
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                            self.screen = Screen::Main(self.active_tab);
                            self.clear_status();
                        }
                        _ => {}
                    },
                }
            }
            Screen::RevealSeedWarning => match key.code {
                KeyCode::Enter | KeyCode::Char('y') => {
                    self.screen = Screen::RevealSeedView;
                }
                KeyCode::Esc | KeyCode::Char('n') => {
                    self.screen = Screen::Main(Tab::Backup);
                }
                _ => {}
            },
            Screen::RevealSeedView => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.screen = Screen::Main(Tab::Backup);
                }
                _ => {}
            },
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            let row = mouse.row;
            let col = mouse.column;

            if let Screen::Main(_) = self.screen
                && col < 20
            {
                if (2..4).contains(&row) {
                        self.active_tab = Tab::Overview;
                        self.screen = Screen::Main(Tab::Overview);
                    } else if (4..6).contains(&row) {
                        self.active_tab = Tab::Usdt;
                        self.screen = Screen::Main(Tab::Usdt);
                    } else if (6..8).contains(&row) {
                        self.active_tab = Tab::Monero;
                        self.screen = Screen::Main(Tab::Monero);
                    } else if (8..10).contains(&row) {
                        self.active_tab = Tab::Backup;
                        self.screen = Screen::Main(Tab::Backup);
                    } else if (10..12).contains(&row) {
                        self.active_tab = Tab::Settings;
                        self.screen = Screen::Main(Tab::Settings);
                    }
            }
        }
    }

    pub fn render(&self, frame: &mut Frame) {
        let area = frame.area();

        let bg_block = Block::default().style(Style::default().bg(self.theme.surface));
        frame.render_widget(bg_block, area);

        match &self.screen {
            Screen::Welcome => self.render_welcome(frame, area),
            Screen::CreatePassword => self.render_create_password(frame, area),
            Screen::ShowNewMnemonic => self.render_show_mnemonic(frame, area),
            Screen::VerifyMnemonic => self.render_verify_mnemonic(frame, area),
            Screen::RestoreWallet => self.render_restore_wallet(frame, area),
            Screen::Unlock => self.render_unlock(frame, area),
            Screen::Main(tab) => self.render_main(frame, area, *tab),
            Screen::ReceiveModal(net_id) => self.render_receive_modal(frame, area, *net_id),
            Screen::SendModal { network_id, step } => {
                self.render_send_modal(frame, area, *network_id, step)
            }
            Screen::RevealSeedWarning => self.render_reveal_warning(frame, area),
            Screen::RevealSeedView => self.render_reveal_view(frame, area),
        }
    }

    fn render_welcome(&self, frame: &mut Frame, area: Rect) {
        let card = centered_rect(60, 50, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ AGY Wallet • Non-Custodial ] ", self.theme.header_style()));

        let text = vec![
            Line::from(""),
            Line::from(Span::styled("Добро пожаловать в автономный криптокошелёк", Style::default().add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from("Ключи хранятся исключительно на вашем устройстве."),
            Line::from("Поддержка Monero (XMR) и всех официальных сетей Tether USDT."),
            Line::from(""),
            Line::from(vec![
                Span::styled(" [ 1 ] ", self.theme.pill_active()),
                Span::raw(" Создать новый кошелёк (BIP-39 + Monero 25-word)"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(" [ 2 ] ", self.theme.pill_inactive()),
                Span::raw(" Восстановить кошелёк из мнемонических фраз"),
            ]),
            Line::from(""),
            Line::from(Span::styled("Нажмите [1] или [2], либо [q] для выхода", Style::default().fg(self.theme.text_secondary))),
        ];

        let p = Paragraph::new(text).block(block).alignment(Alignment::Center).wrap(Wrap { trim: true });
        frame.render_widget(p, card);
    }

    fn render_create_password(&self, frame: &mut Frame, area: Rect) {
        let card = centered_rect(65, 55, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.focus_border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ Защита кошелька • Установка пароля ] ", self.theme.header_style()));

        let masked_pass = "*".repeat(self.input_buffer.len());
        let masked_confirm = "*".repeat(self.input_buffer_confirm.len());

        let strength = check_password_strength(&self.input_buffer);
        let strength_span = match strength {
            PasswordStrength::TooShort => Span::styled("Слишком короткий (минимум 8)", Style::default().fg(self.theme.error)),
            PasswordStrength::Weak(msg) => Span::styled(format!("Слабый: {msg}"), Style::default().fg(Color::Yellow)),
            PasswordStrength::Moderate => Span::styled("Средний (приемлемо)", Style::default().fg(Color::Cyan)),
            PasswordStrength::Strong => Span::styled("Надёжный", Style::default().fg(self.theme.primary).add_modifier(Modifier::BOLD)),
        };

        let f0_style = if self.input_field_idx == 0 { self.theme.pill_active() } else { self.theme.pill_inactive() };
        let f1_style = if self.input_field_idx == 1 { self.theme.pill_active() } else { self.theme.pill_inactive() };

        let mut text = vec![
            Line::from(""),
            Line::from("Шифрование: Argon2id (64 MiB, RFC 9106) + XChaCha20-Poly1305."),
            Line::from(""),
            Line::from(vec![
                Span::styled(" Пароль: ", f0_style),
                Span::raw(format!(" [ {masked_pass} ]")),
            ]),
            Line::from(vec![Span::raw("Стойкость: "), strength_span]),
            Line::from(""),
            Line::from(vec![
                Span::styled(" Повтор: ", f1_style),
                Span::raw(format!(" [ {masked_confirm} ]")),
            ]),
            Line::from(""),
            Line::from(Span::styled("[Tab] переключение полей • [Enter] подтвердить • [Esc] назад", Style::default().fg(self.theme.text_secondary))),
        ];

        if let Some((msg, is_err)) = &self.status_message {
            let col = if *is_err { self.theme.error } else { self.theme.primary };
            text.push(Line::from(""));
            text.push(Line::from(Span::styled(msg.as_str(), Style::default().fg(col).add_modifier(Modifier::BOLD))));
        }

        let p = Paragraph::new(text).block(block).alignment(Alignment::Center);
        frame.render_widget(p, card);
    }

    fn render_show_mnemonic(&self, frame: &mut Frame, area: Rect) {
        let card = centered_rect(80, 80, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.primary))
            .style(self.theme.card_style())
            .title(Span::styled(" [ ВНИМАНИЕ: СЕКРЕТНЫЕ ФРАЗЫ КОШЕЛЬКА ] ", self.theme.header_style()));

        let mut lines = vec![
            Line::from(Span::styled("Запишите эти фразы на физический носитель. Никому не показывайте их!", Style::default().fg(self.theme.error).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(Span::styled("1. BIP-39 фраза (USDT: EVM, Tron, TON, Solana):", Style::default().fg(self.theme.primary).add_modifier(Modifier::BOLD))),
        ];

        if let Some(secrets) = &self.pending_secrets {
            let bip_words = secrets.bip39_words();
            for chunk in bip_words.chunks(4) {
                let formatted = chunk.iter().map(|w| format!("{:<14}", w)).collect::<Vec<_>>().join(" ");
                lines.push(Line::from(Span::styled(formatted, Style::default().fg(self.theme.text_primary))));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("2. Monero 25-словная фраза (Electrum Monero seed):", Style::default().fg(self.theme.secondary).add_modifier(Modifier::BOLD))));

            let monero_words = secrets.monero_words();
            for chunk in monero_words.chunks(5) {
                let formatted = chunk.iter().map(|w| format!("{:<12}", w)).collect::<Vec<_>>().join(" ");
                lines.push(Line::from(Span::styled(formatted, Style::default().fg(self.theme.text_primary))));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("После нажатия [Enter] потребуется подтвердить несколько контрольных слов.", Style::default().fg(self.theme.text_secondary))));

        let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
        frame.render_widget(p, card);
    }

    fn render_verify_mnemonic(&self, frame: &mut Frame, area: Rect) {
        let card = centered_rect(70, 60, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.focus_border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ Проверка записи слов BIP-39 ] ", self.theme.header_style()));

        let mut lines = vec![
            Line::from("Введите запрошенные слова из вашей BIP-39 фразы для проверки:"),
            Line::from(""),
        ];

        for (i, &word_idx) in self.verification_indices.iter().enumerate() {
            let is_active = self.verification_cursor == i;
            let val = self.verification_inputs.get(i).map(|s| s.as_str()).unwrap_or("");
            let style = if is_active { self.theme.pill_active() } else { self.theme.pill_inactive() };

            lines.push(Line::from(vec![
                Span::styled(format!(" Слово #{} : ", word_idx + 1), style),
                Span::raw(format!(" [ {val} ]")),
            ]));
            lines.push(Line::from(""));
        }

        lines.push(Line::from(Span::styled("[Tab] переключение • [Enter] подтвердить запись кошелька", Style::default().fg(self.theme.text_secondary))));

        if let Some((msg, is_err)) = &self.status_message {
            let col = if *is_err { self.theme.error } else { self.theme.primary };
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(msg.as_str(), Style::default().fg(col).add_modifier(Modifier::BOLD))));
        }

        let p = Paragraph::new(lines).block(block).alignment(Alignment::Center);
        frame.render_widget(p, card);
    }

    fn render_restore_wallet(&self, frame: &mut Frame, area: Rect) {
        let card = centered_rect(75, 65, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ Восстановление кошелька ] ", self.theme.header_style()));

        let f0_style = if self.input_field_idx == 0 { self.theme.pill_active() } else { self.theme.pill_inactive() };
        let f1_style = if self.input_field_idx == 1 { self.theme.pill_active() } else { self.theme.pill_inactive() };

        let mut lines = vec![
            Line::from("Введите фразы для восстановления:"),
            Line::from(""),
            Line::from(vec![
                Span::styled(" 1. BIP-39 фраза: ", f0_style),
            ]),
            Line::from(Span::raw(format!(" [ {} ]", self.input_buffer))),
            Line::from(""),
            Line::from(vec![
                Span::styled(" 2. Monero (25 слов): ", f1_style),
            ]),
            Line::from(Span::raw(format!(" [ {} ]", self.input_buffer_confirm))),
            Line::from(""),
            Line::from(Span::styled("[Tab] переключение • [Enter] восстановить • [Esc] назад", Style::default().fg(self.theme.text_secondary))),
        ];

        if let Some((msg, is_err)) = &self.status_message {
            let col = if *is_err { self.theme.error } else { self.theme.primary };
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(msg.as_str(), Style::default().fg(col).add_modifier(Modifier::BOLD))));
        }

        let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
        frame.render_widget(p, card);
    }

    fn render_unlock(&self, frame: &mut Frame, area: Rect) {
        let card = centered_rect(60, 40, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.focus_border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ Разблокировка кошелька ] ", self.theme.header_style()));

        let masked = "*".repeat(self.input_buffer.len());

        let mut lines = vec![
            Line::from(""),
            Line::from("Файл кошелька зашифрован (Argon2id + XChaCha20-Poly1305)."),
            Line::from(""),
            Line::from(vec![
                Span::styled(" Пароль: ", self.theme.pill_active()),
                Span::raw(format!(" [ {masked} ]")),
            ]),
            Line::from(""),
            Line::from(Span::styled("Нажмите [Enter] для входа или [q] для выхода", Style::default().fg(self.theme.text_secondary))),
        ];

        if let Some((msg, is_err)) = &self.status_message {
            let col = if *is_err { self.theme.error } else { self.theme.primary };
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(msg.as_str(), Style::default().fg(col))));
        }

        let p = Paragraph::new(lines).block(block).alignment(Alignment::Center);
        frame.render_widget(p, card);
    }

    fn render_main(&self, frame: &mut Frame, area: Rect, tab: Tab) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(22), Constraint::Min(40)])
            .split(area);

        // Sidebar
        let mut sidebar_lines = vec![
            Line::from(""),
            Line::from(Span::styled("  AGY WALLET", self.theme.header_style())),
            Line::from(Span::styled("  v0.1.0 (Termux)", Style::default().fg(self.theme.text_secondary))),
            Line::from(""),
        ];

        for t in Tab::all() {
            let is_selected = *t == tab;
            let style = if is_selected {
                self.theme.pill_active()
            } else {
                self.theme.pill_inactive()
            };
            sidebar_lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(t.title(), style),
            ]));
            sidebar_lines.push(Line::from(""));
        }

        sidebar_lines.push(Line::from(""));
        sidebar_lines.push(Line::from(Span::styled("  [s] Отправить", Style::default().fg(self.theme.primary))));
        sidebar_lines.push(Line::from(Span::styled("  [g] Получить", Style::default().fg(self.theme.secondary))));
        sidebar_lines.push(Line::from(""));
        sidebar_lines.push(Line::from(Span::styled("  [q] Выход", Style::default().fg(self.theme.text_secondary))));

        let sidebar_block = Block::default()
            .borders(Borders::RIGHT)
            .border_style(Style::default().fg(self.theme.border))
            .style(Style::default().bg(self.theme.surface));

        let sidebar_p = Paragraph::new(sidebar_lines).block(sidebar_block);
        frame.render_widget(sidebar_p, chunks[0]);

        // Main content area
        match tab {
            Tab::Overview => self.render_tab_overview(frame, chunks[1]),
            Tab::Usdt => self.render_tab_usdt(frame, chunks[1]),
            Tab::Monero => self.render_tab_monero(frame, chunks[1]),
            Tab::Backup => self.render_tab_backup(frame, chunks[1]),
            Tab::Settings => self.render_tab_settings(frame, chunks[1]),
        }
    }

    fn render_tab_overview(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ Обзор активов и адреса ] ", self.theme.header_style()));

        let mut lines = vec![
            Line::from(Span::styled("Балансы и адреса кошелька", Style::default().add_modifier(Modifier::BOLD))),
            Line::from(""),
        ];

        let overview_nets = [
            NetworkId::Sepolia,
            NetworkId::Ethereum,
            NetworkId::TronNile,
            NetworkId::Tron,
            NetworkId::Ton,
            NetworkId::Solana,
            NetworkId::MoneroStagenet,
        ];

        for &net_id in &overview_nets {
            let net = get_network(net_id);
            let addr = self.get_address_for_network(net);
            let bal = self.format_balance_for_display(net);
            let tag = match net.family {
                NetworkFamily::Evm => "[EVM]",
                NetworkFamily::Tron => "[TRON]",
                NetworkFamily::Ton => "[TON]",
                NetworkFamily::Solana => "[SOL]",
                NetworkFamily::Monero => "[XMR]",
            };

            lines.push(Line::from(vec![
                Span::styled(format!("{:<6} ", tag), Style::default().fg(self.theme.secondary)),
                Span::styled(format!("{:<18} ", net.name), Style::default().fg(self.theme.primary).add_modifier(Modifier::BOLD)),
                Span::raw("Баланс: "),
                Span::styled(bal, Style::default().fg(Color::Yellow)),
            ]));
            lines.push(Line::from(format!("       Адрес: {}", addr)));
            lines.push(Line::from(""));
        }

        lines.push(Line::from(Span::styled("Клавиши: [r] обновить балансы • [s] отправить • [g] QR-код • [←]/[→] разделы", Style::default().fg(self.theme.text_secondary))));

        let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
        frame.render_widget(p, area);
    }

    fn render_tab_usdt(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ USDT — Семейства и реестр Tether ] ", self.theme.header_style()));

        let usdt_nets: Vec<_> = NETWORKS.iter().filter(|n| n.usdt_contract.is_some()).collect();
        let mut lines = vec![
            Line::from("Поддерживаемые сети USDT (источник: https://tether.to/en/supported-protocols):"),
            Line::from(""),
        ];

        for (idx, net) in usdt_nets.iter().enumerate() {
            let is_sel = idx == self.selected_usdt_idx;
            let marker = if is_sel { ">" } else { " " };
            let style = if is_sel {
                self.theme.pill_active()
            } else {
                Style::default().fg(self.theme.text_primary)
            };

            let family_tag = match net.family {
                NetworkFamily::Evm => "[EVM]",
                NetworkFamily::Tron => "[TRON]",
                NetworkFamily::Ton => "[TON]",
                NetworkFamily::Solana => "[SOL]",
                NetworkFamily::Monero => "[XMR]",
            };

            let bal = self.format_balance_for_display(net);

            lines.push(Line::from(vec![
                Span::raw(format!(" {marker} ")),
                Span::styled(format!("{:<7} ", family_tag), Style::default().fg(self.theme.secondary)),
                Span::styled(format!("{:<20} ", net.name), style),
                Span::styled(format!("Баланс: {:<25} ", bal), Style::default().fg(Color::Yellow)),
                Span::styled(format!("(Комиссия: {})", net.native_symbol), Style::default().fg(self.theme.text_secondary)),
            ]));
        }

        if let Some(selected_net) = usdt_nets.get(self.selected_usdt_idx) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(format!("Выбрана: {}", selected_net.name), self.theme.header_style())));
            lines.push(Line::from(format!("Баланс: {}", self.format_balance_for_display(selected_net))));
            lines.push(Line::from(format!("Контракт: {}", selected_net.usdt_contract.unwrap_or("None"))));
            lines.push(Line::from(format!("Ваш адрес: {}", self.get_address_for_network(selected_net))));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("[↑]/[↓] выбор сети • [r] обновить баланс • [s] отправить • [g] получить QR", Style::default().fg(self.theme.text_secondary))));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    }

    fn render_tab_monero(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ Monero (XMR) ] ", self.theme.header_style()));

        let stagenet = get_network(NetworkId::MoneroStagenet);
        let restore_height = self.secrets.as_ref().map(|s| s.monero_restore_height).unwrap_or(0);
        let addr = self.get_address_for_network(stagenet);
        let monero_bal = self.format_balance_for_display(stagenet);

        let mut lines = vec![
            Line::from(Span::styled("Анонимный кошелёк Monero", Style::default().add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from("Режим: Тестовая сеть (Stagenet)"),
            Line::from(format!("Узел RPC: {}", stagenet.primary_rpc)),
            Line::from(format!("Состояние демона: {monero_bal}")),
            Line::from(format!("Высота восстановления (Restore Height): {restore_height}")),
            Line::from(""),
            Line::from(Span::styled("Ваш адрес Stagenet:", Style::default().fg(self.theme.primary))),
            Line::from(addr),
            Line::from(""),
        ];

        let client = MoneroNodeClient::new(stagenet.primary_rpc, None).unwrap();
        if let Some(warning) = client.privacy_warning() {
            lines.push(Line::from(Span::styled(warning, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
            lines.push(Line::from(""));
        }

        lines.push(Line::from(Span::styled("Ключи защищены типом Zeroizing (очистка при drop). Сканирование локально.", Style::default().fg(self.theme.secondary))));
        lines.push(Line::from(Span::styled("[r] опросить узел • [g] показать QR-код • [s] отправить", Style::default().fg(self.theme.text_secondary))));

        let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
        frame.render_widget(p, area);
    }

    fn render_tab_backup(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ Бэкап и безопасность ] ", self.theme.header_style()));

        let mut lines = vec![
            Line::from(Span::styled("Резервное копирование и экспорт", Style::default().add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(vec![
                Span::styled(" [ e ] ", self.theme.pill_active()),
                Span::raw(format!(" Экспорт зашифрованного файла кошелька в {}", self.backup_export_path)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(" [ v ] ", self.theme.pill_inactive()),
                Span::raw(" Показать секретные фразы (BIP-39 и Monero seed)"),
            ]),
            Line::from(""),
            Line::from(Span::styled("Запись файла атомарна, права 0600 на Unix, автоматический .bak бэкап.", Style::default().fg(self.theme.text_secondary))),
        ];

        if let Some((msg, is_err)) = &self.status_message {
            let col = if *is_err { self.theme.error } else { self.theme.primary };
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(msg.as_str(), Style::default().fg(col))));
        }

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    }

    fn render_tab_settings(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style())
            .title(Span::styled(" [ Настройки и сеть ] ", self.theme.header_style()));

        let tor_status = if self.settings.tor_enabled { "Включён" } else { "Отключён (прямое соединение)" };

        let lines = vec![
            Line::from(Span::styled("Сетевые подключения и Tor", Style::default().add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(" • TLS стек: rustls (без OpenSSL)"),
            Line::from(format!(" • Tor статус: {tor_status}")),
            Line::from(format!(" • Tor SOCKS5 прокси: {}", self.settings.tor_socks5_url)),
            Line::from(" • Платформы: Termux (Android aarch64), Linux x64, Windows x64"),
        ];

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(p, area);
    }

    fn render_receive_modal(&self, frame: &mut Frame, area: Rect, net_id: NetworkId) {
        let card = centered_rect(75, 80, area);
        let net = get_network(net_id);
        let address = self.get_address_for_network(net);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.primary))
            .style(self.theme.card_style())
            .title(Span::styled(format!(" [ Получение: {} ] ", net.name), self.theme.header_style()));

        let mut lines = vec![
            Line::from(Span::styled("Отправляйте только активы этой сети!", Style::default().fg(self.theme.error).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(Span::styled(format!("Адрес: {address}"), Style::default().fg(self.theme.text_primary).add_modifier(Modifier::BOLD))),
            Line::from(""),
        ];

        // Render QR Code in Dense1x2 unicode format
        if let Ok(code) = QrCode::new(&address) {
            let qr_string = code.render::<unicode::Dense1x2>().build();
            for qr_line in qr_string.lines() {
                lines.push(Line::from(Span::styled(qr_line.to_string(), Style::default().fg(Color::White).bg(Color::Black))));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Нажмите [Esc] или [Enter] для возврата", Style::default().fg(self.theme.text_secondary))));

        let p = Paragraph::new(lines).block(block).alignment(Alignment::Center);
        frame.render_widget(Clear, card);
        frame.render_widget(p, card);
    }

    fn render_send_modal(
        &self,
        frame: &mut Frame,
        area: Rect,
        net_id: NetworkId,
        step: &SendStep,
    ) {
        let card = centered_rect(75, 70, area);
        let net = get_network(net_id);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.focus_border))
            .style(self.theme.card_style())
            .title(Span::styled(format!(" [ Отправка: {} ] ", net.name), self.theme.header_style()));

        match step {
            SendStep::InputForm => {
                let f0_style = if self.send_cursor == 0 { self.theme.pill_active() } else { self.theme.pill_inactive() };
                let f1_style = if self.send_cursor == 1 { self.theme.pill_active() } else { self.theme.pill_inactive() };

                let mut lines = vec![
                    Line::from(Span::styled("Заполните реквизиты перевода:", Style::default().add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(" Адрес получателя: ", f0_style),
                    ]),
                    Line::from(Span::raw(format!(" [ {} ]", self.send_recipient_input))),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(" Сумма (USDT / монеты): ", f1_style),
                    ]),
                    Line::from(Span::raw(format!(" [ {} ]", self.send_amount_input))),
                    Line::from(""),
                    Line::from(format!("Комиссия сети списывается в: {}", net.native_symbol)),
                    Line::from(""),
                    Line::from(Span::styled("[Tab] переключение • [Enter] далее к проверке • [Esc] отмена", Style::default().fg(self.theme.text_secondary))),
                ];

                if let Some((msg, is_err)) = &self.status_message {
                    let col = if *is_err { self.theme.error } else { self.theme.primary };
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(msg.as_str(), Style::default().fg(col).add_modifier(Modifier::BOLD))));
                }

                let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
                frame.render_widget(Clear, card);
                frame.render_widget(p, card);
            }
            SendStep::ConfirmSummary {
                estimated_fee,
                native_balance,
                usdt_balance,
                can_send,
                fee_check_msg,
            } => {
                let status_style = if *can_send {
                    Style::default().fg(self.theme.primary).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(self.theme.error).add_modifier(Modifier::BOLD)
                };

                let mut lines = vec![
                    Line::from(Span::styled("ПРОВЕРКА И ПОДТВЕРЖДЕНИЕ ОТПРАВКИ", Style::default().fg(self.theme.primary).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from(format!("Сеть: {}", net.name)),
                    Line::from(format!("Получатель: {}", self.send_recipient_input)),
                    Line::from(format!("Сумма перевода: {} USDT", self.send_amount_input)),
                    Line::from(format!("Оценочная комиссия сети: {}", estimated_fee)),
                    Line::from(format!("Баланс монеты комиссии: {}", native_balance)),
                    Line::from(format!("Баланс USDT в сети: {}", usdt_balance)),
                    Line::from(""),
                    Line::from(vec![
                        Span::raw("Статус проверки: "),
                        Span::styled(fee_check_msg.as_str(), status_style),
                    ]),
                    Line::from(""),
                ];

                if *can_send {
                    lines.push(Line::from(Span::styled("Отправка средств необратима. Транзакция будет подписана локально.", Style::default().fg(Color::Yellow))));
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::styled(" [ Enter / y ] ", self.theme.pill_active()),
                        Span::raw(" Подтвердить и отправить транзакцию"),
                    ]));
                } else {
                    lines.push(Line::from(Span::styled("ОТПРАВКА ЗАБЛОКИРОВАНА: недостаточно средств для оплаты комиссии или суммы перевода.", Style::default().fg(self.theme.error).add_modifier(Modifier::BOLD))));
                }

                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled(" [ Esc / n ] ", self.theme.pill_inactive()),
                    Span::raw(" Назад к вводу"),
                ]));

                let p = Paragraph::new(lines).block(block).alignment(Alignment::Center).wrap(Wrap { trim: true });
                frame.render_widget(Clear, card);
                frame.render_widget(p, card);
            }
            SendStep::Broadcasting => {
                let lines = vec![
                    Line::from(""),
                    Line::from(Span::styled("ОТПРАВКА ТРАНЗАКЦИИ В СЕТЬ...", Style::default().fg(self.theme.secondary).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from("1. Локальная сборка и подпись закрытым ключом"),
                    Line::from("2. Зануление ключа в оперативной памяти (Zeroize)"),
                    Line::from("3. Рассылка сырой транзакции через доверенный RPC-узел"),
                    Line::from(""),
                    Line::from(Span::styled("Пожалуйста, подождите ответа узла сети...", Style::default().fg(self.theme.text_secondary))),
                ];

                let p = Paragraph::new(lines).block(block).alignment(Alignment::Center).wrap(Wrap { trim: true });
                frame.render_widget(Clear, card);
                frame.render_widget(p, card);
            }
            SendStep::ResultSuccess(hash) => {
                let explorer_url = get_explorer_tx_url(net, hash);
                let lines = vec![
                    Line::from(""),
                    Line::from(Span::styled("ТРАНЗАКЦИЯ УСПЕШНО ОТПРАВЛЕНА!", Style::default().fg(self.theme.primary).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from("Реальный хеш транзакции (TxID):"),
                    Line::from(Span::styled(hash.as_str(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from("Обозреватель сети (Explorer):"),
                    Line::from(Span::styled(explorer_url, Style::default().fg(Color::Cyan))),
                    Line::from(""),
                    Line::from(Span::styled("Нажмите [Enter] или [Esc] для возврата", Style::default().fg(self.theme.text_secondary))),
                ];

                let p = Paragraph::new(lines).block(block).alignment(Alignment::Center).wrap(Wrap { trim: true });
                frame.render_widget(Clear, card);
                frame.render_widget(p, card);
            }
            SendStep::ResultError(err) => {
                let lines = vec![
                    Line::from(""),
                    Line::from(Span::styled("ОШИБКА ОТПРАВКИ ТРАНЗАКЦИИ!", Style::default().fg(self.theme.error).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from("Ответ узла / Описание ошибки:"),
                    Line::from(Span::styled(err.as_str(), Style::default().fg(self.theme.error).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from(Span::styled("Транзакция не была принята сетью. Средства не списаны.", Style::default().fg(self.theme.text_secondary))),
                    Line::from(""),
                    Line::from(Span::styled("Нажмите [Enter] или [Esc] для возврата", Style::default().fg(self.theme.text_secondary))),
                ];

                let p = Paragraph::new(lines).block(block).alignment(Alignment::Center).wrap(Wrap { trim: true });
                frame.render_widget(Clear, card);
                frame.render_widget(p, card);
            }
        }
    }

    fn render_reveal_warning(&self, frame: &mut Frame, area: Rect) {
        let card = centered_rect(65, 45, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.error))
            .style(self.theme.card_style())
            .title(Span::styled(" [ ВНИМАНИЕ: ПРОСМОТР СЕКРЕТНЫХ ФРАЗ ] ", Style::default().fg(self.theme.error).add_modifier(Modifier::BOLD)));

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled("Убедитесь, что никто не смотрит на ваш экран!", Style::default().fg(self.theme.error).add_modifier(Modifier::BOLD))),
            Line::from("Любой, кто увидит эти слова, получит полный доступ к вашим средствам."),
            Line::from(""),
            Line::from(vec![
                Span::styled(" [ Enter / y ] ", self.theme.pill_active()),
                Span::raw(" Я нахожусь в безопасности, показать фразы"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(" [ Esc / n ] ", self.theme.pill_inactive()),
                Span::raw(" Отмена"),
            ]),
        ];

        let p = Paragraph::new(lines).block(block).alignment(Alignment::Center);
        frame.render_widget(Clear, card);
        frame.render_widget(p, card);
    }

    fn render_reveal_view(&self, frame: &mut Frame, area: Rect) {
        let card = centered_rect(80, 80, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.theme.card_border_type())
            .border_style(Style::default().fg(self.theme.primary))
            .style(self.theme.card_style())
            .title(Span::styled(" [ Секретные фразы ] ", self.theme.header_style()));

        let mut lines = vec![
            Line::from(Span::styled("1. BIP-39 фраза (USDT: EVM, Tron, TON, Solana):", Style::default().fg(self.theme.primary).add_modifier(Modifier::BOLD))),
        ];

        if let Some(secrets) = &self.secrets {
            let bip_words = secrets.bip39_words();
            for chunk in bip_words.chunks(4) {
                let formatted = chunk.iter().map(|w| format!("{:<14}", w)).collect::<Vec<_>>().join(" ");
                lines.push(Line::from(Span::styled(formatted, Style::default().fg(self.theme.text_primary))));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("2. Monero 25-словная фраза:", Style::default().fg(self.theme.secondary).add_modifier(Modifier::BOLD))));

            let monero_words = secrets.monero_words();
            for chunk in monero_words.chunks(5) {
                let formatted = chunk.iter().map(|w| format!("{:<12}", w)).collect::<Vec<_>>().join(" ");
                lines.push(Line::from(Span::styled(formatted, Style::default().fg(self.theme.text_primary))));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Нажмите [Esc] или [Enter], чтобы немедленно скрыть экран", Style::default().fg(self.theme.text_secondary))));

        let p = Paragraph::new(lines).block(block);
        frame.render_widget(Clear, card);
        frame.render_widget(p, card);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
