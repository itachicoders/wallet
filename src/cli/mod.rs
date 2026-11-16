use crate::chains::{
    get_associated_token_address, validate_evm_address, validate_recipient_address, EvmClient,
    EvmKey, MoneroKeys, MoneroNodeClient, SolanaClient, SolanaKey, TonClient, TonKey, TronClient,
    TronKey,
};
use crate::core::wallet::WalletSecrets;
use crate::networks::registry::{get_network, NetworkFamily, NetworkId, NetworkSpec, NETWORKS};
use crate::platform::Storage;

pub async fn handle_cli_args(args: &[String]) -> bool {
    if args.len() <= 1 {
        return false; // Launch interactive TUI
    }

    match args[1].as_str() {
        "list-networks" | "networks" => {
            println!("Поддерживаемые сети (источник: https://tether.to/en/supported-protocols):");
            println!("{:<28} {:<10} {:<10} {:<44}", "Сеть", "Семейство", "Комиссия", "Контракт USDT");
            println!("{}", "-".repeat(95));
            for net in NETWORKS {
                let contract = net.usdt_contract.unwrap_or("Native (XMR)");
                let fam = format!("{:?}", net.family);
                println!("{:<28} {:<10} {:<10} {:<44}", net.name, fam, net.native_symbol, contract);
            }
            true
        }
        "validate-address" => {
            if args.len() < 4 {
                eprintln!("Использование: agy-wallet validate-address <network-id> <address>");
                eprintln!("Пример: agy-wallet validate-address tron TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
                return true;
            }
            let net_id_str = &args[2];
            let addr = &args[3];
            let net = match parse_network_id(net_id_str) {
                Some(id) => get_network(id),
                None => {
                    eprintln!("Неизвестный network-id: {net_id_str}");
                    return true;
                }
            };

            match validate_recipient_address(net, addr) {
                Ok(canonical) => {
                    println!("УСПЕШНО: Адрес валиден для сети {}", net.name);
                    println!("Канонический адрес: {canonical}");
                }
                Err(err) => {
                    eprintln!("ОШИБКА ВАЛИДАЦИИ: {err}");
                }
            }
            true
        }
        "export-backup" => {
            if args.len() < 3 {
                eprintln!("Использование: agy-wallet export-backup <dst_path> [wallet_path]");
                return true;
            }
            let dst = &args[2];
            let src = if args.len() >= 4 {
                &args[3]
            } else {
                "wallet.dat"
            };

            match Storage::backup_wallet(src, dst) {
                Ok(bytes) => {
                    println!("УСПЕШНО: Зашифрованный кошелёк экспортирован в {dst} ({bytes} байт, 0600)");
                }
                Err(e) => {
                    eprintln!("Ошибка экспорта: {e}");
                }
            }
            true
        }
        "show-address" => {
            if args.len() < 5 {
                eprintln!("Использование: agy-wallet show-address <network-id> <wallet_file> <password>");
                return true;
            }
            let net_id_str = &args[2];
            let wallet_file = &args[3];
            let password = &args[4];

            let net = match parse_network_id(net_id_str) {
                Some(id) => get_network(id),
                None => {
                    eprintln!("Неизвестный network-id: {net_id_str}");
                    return true;
                }
            };

            match WalletSecrets::load_from_file(wallet_file, password) {
                Ok(secrets) => {
                    let mnemonic = bip39::Mnemonic::parse(&secrets.bip39_mnemonic).unwrap();
                    let seed = mnemonic.to_seed("");

                    let address = match net.family {
                        NetworkFamily::Evm => {
                            let key = EvmKey::from_seed(&seed, net.derivation_path).unwrap();
                            key.checksum_address
                        }
                        NetworkFamily::Tron => {
                            let key = TronKey::from_seed(&seed, net.derivation_path).unwrap();
                            key.base58_address
                        }
                        NetworkFamily::Ton => {
                            let key = TonKey::from_seed_32(&seed[0..32].try_into().unwrap());
                            key.user_friendly_address
                        }
                        NetworkFamily::Solana => {
                            let key = SolanaKey::from_seed_32(&seed[0..32].try_into().unwrap());
                            key.base58_address
                        }
                        NetworkFamily::Monero => {
                            let words: Vec<String> = secrets.monero_words().iter().map(|s| s.to_string()).collect();
                            let keys = MoneroKeys::from_mnemonic_words(&words).unwrap();
                            if net.is_testnet {
                                keys.stagenet_address
                            } else {
                                keys.primary_address
                            }
                        }
                    };

                    println!("Сеть: {}", net.name);
                    println!("Адрес: {address}");
                }
                Err(e) => {
                    eprintln!("Ошибка загрузки кошелька: {e}");
                }
            }
            true
        }
        "query-balance" | "balance" => {
            if args.len() < 4 {
                eprintln!("Использование: agy-wallet query-balance <network-id> <address>");
                return true;
            }
            let net_id_str = &args[2];
            let addr = &args[3];
            let net = match parse_network_id(net_id_str) {
                Some(id) => get_network(id),
                None => {
                    eprintln!("Неизвестный network-id: {net_id_str}");
                    return true;
                }
            };

            println!("Сеть: {} [{:?}]", net.name, net.family);
            println!("Адрес: {addr}");
            query_network_balance(net, addr).await;
            true
        }
        "--help" | "-h" | "help" => {
            println!("AGY Terminal Non-Custodial Wallet");
            println!();
            println!("Использование:");
            println!("  agy-wallet                             Запуск TUI интерфейса");
            println!("  agy-wallet list-networks               Список сетей и контрактов Tether/Monero");
            println!("  agy-wallet validate-address <net> <addr> Проверка адреса и защита от несовпадения сетей");
            println!("  agy-wallet show-address <net> <file> <pass> Вывод адреса из кошелька");
            println!("  agy-wallet query-balance <net> <addr>  Запрос баланса нативной монеты и USDT через публичные узлы");
            println!("  agy-wallet export-backup <dst> [src]   Резервная копия зашифрованного файла");
            true
        }
        _ => false,
    }
}

fn parse_network_id(s: &str) -> Option<NetworkId> {
    match s.to_lowercase().as_str() {
        "eth" | "ethereum" => Some(NetworkId::Ethereum),
        "bsc" | "binance" => Some(NetworkId::Bsc),
        "polygon" | "matic" => Some(NetworkId::Polygon),
        "arbitrum" | "arb" => Some(NetworkId::Arbitrum),
        "optimism" | "op" => Some(NetworkId::Optimism),
        "avalanche" | "avax" => Some(NetworkId::Avalanche),
        "tron" | "trx" => Some(NetworkId::Tron),
        "ton" => Some(NetworkId::Ton),
        "solana" | "sol" => Some(NetworkId::Solana),
        "xmr" | "monero" => Some(NetworkId::MoneroMainnet),
        "xmr-stagenet" | "stagenet" => Some(NetworkId::MoneroStagenet),
        "sepolia" => Some(NetworkId::Sepolia),
        "nile" => Some(NetworkId::TronNile),
        _ => None,
    }
}

pub async fn query_network_balance(net: &NetworkSpec, address: &str) {
    match net.family {
        NetworkFamily::Evm => {
            let client = EvmClient::new(net.primary_rpc);
            println!("Подключение к RPC: {}", net.primary_rpc);
            match client.get_native_balance(address).await {
                Ok(bal_wei) => {
                    let bal_eth = bal_wei as f64 / 1e18;
                    println!("Баланс нативной монеты ({}) : {:.6}", net.native_symbol, bal_eth);
                }
                Err(e) => eprintln!("Ошибка запроса нативного баланса: {e}"),
            }
            if let Some(contract) = net.usdt_contract
                && let Ok(owner_bytes) = validate_evm_address(address)
            {
                match client.get_usdt_balance(contract, &owner_bytes).await {
                    Ok(usdt_raw) => {
                        let dec = 10u128.pow(net.usdt_decimals as u32);
                        let usdt_fmt = usdt_raw as f64 / dec as f64;
                        println!("Баланс USDT: {:.6} (контракт: {})", usdt_fmt, contract);
                    }
                    Err(e) => eprintln!("Ошибка запроса USDT баланса: {e}"),
                }
            }
        }
        NetworkFamily::Tron => {
            let client = TronClient::new(net.primary_rpc);
            println!("Подключение к Tron API: {}", net.primary_rpc);
            match client.get_trx_balance(address).await {
                Ok(sun) => {
                    let trx = sun as f64 / 1_000_000.0;
                    println!("Баланс TRX: {:.6}", trx);
                }
                Err(e) => eprintln!("Ошибка запроса TRX баланса: {e}"),
            }
            match client.get_account_resources(address).await {
                Ok((bw, energy)) => println!("Ресурсы: Bandwidth = {}, Energy = {}", bw, energy),
                Err(e) => eprintln!("Ошибка запроса ресурсов: {e}"),
            }
            if let Some(contract) = net.usdt_contract {
                match client.get_trc20_usdt_balance(contract, address).await {
                    Ok(usdt_raw) => {
                        let usdt_fmt = usdt_raw as f64 / 1_000_000.0;
                        println!("Баланс USDT (TRC-20): {:.6} (контракт: {})", usdt_fmt, contract);
                    }
                    Err(e) => eprintln!("Ошибка запроса USDT баланса: {e}"),
                }
            }
        }
        NetworkFamily::Ton => {
            let client = TonClient::new(net.primary_rpc);
            println!("Подключение к TON RPC: {}", net.primary_rpc);
            match client.get_ton_balance(address).await {
                Ok(nano) => {
                    let ton = nano as f64 / 1_000_000_000.0;
                    println!("Баланс TON: {:.6}", ton);
                }
                Err(e) => eprintln!("Ошибка запроса TON баланса: {e}"),
            }
        }
        NetworkFamily::Solana => {
            let client = SolanaClient::new(net.primary_rpc);
            println!("Подключение к Solana RPC: {}", net.primary_rpc);
            match client.get_sol_balance(address).await {
                Ok(lamports) => {
                    let sol = lamports as f64 / 1_000_000_000.0;
                    println!("Баланс SOL: {:.6}", sol);
                }
                Err(e) => eprintln!("Ошибка запроса SOL баланса: {e}"),
            }
            if let Some(mint) = net.usdt_contract {
                match get_associated_token_address(address, mint) {
                    Ok(ata) => {
                        match client.get_usdt_token_balance(&ata).await {
                            Ok(usdt_raw) => {
                                let usdt_fmt = usdt_raw as f64 / 1_000_000.0;
                                println!("Баланс USDT (SPL ATA: {}): {:.6}", ata, usdt_fmt);
                            }
                            Err(e) => eprintln!("Ошибка запроса SPL USDT баланса: {e}"),
                        }
                    }
                    Err(e) => eprintln!("Ошибка вычисления ATA: {e}"),
                }
            }
        }
        NetworkFamily::Monero => {
            let client = match MoneroNodeClient::new(net.primary_rpc, None) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Ошибка создания Monero клиента: {e}");
                    return;
                }
            };
            println!("Подключение к Monero daemon: {}", net.primary_rpc);
            if let Some(warn) = client.privacy_warning() {
                println!("Предупреждение о приватности: {}", warn);
            }
            match client.get_daemon_height().await {
                Ok(height) => println!("Высота блокчейна: {height}"),
                Err(e) => eprintln!("Ошибка запроса высоты Monero: {e}"),
            }
            match client.get_fee_estimate().await {
                Ok(fee) => println!("Оценка комиссии: {:.12} XMR ({fee} atomic units)", fee as f64 / 1e12),
                Err(e) => eprintln!("Ошибка оценки комиссии Monero: {e}"),
            }
        }
    }
}
