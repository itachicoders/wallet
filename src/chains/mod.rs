pub mod evm;
pub mod monero;
pub mod solana;
pub mod ton;
pub mod tron;

pub use evm::*;
pub use monero::*;
pub use solana::*;
pub use ton::*;
pub use tron::*;

use crate::networks::registry::{NetworkFamily, NetworkSpec};

pub fn create_http_client(timeout_secs: u64, socks5: Option<&str>) -> reqwest::Client {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut builder = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .timeout(std::time::Duration::from_secs(timeout_secs));

    if let Some(socks_url) = socks5
        && let Ok(proxy) = reqwest::Proxy::all(socks_url) {
            builder = builder.proxy(proxy);
        }

    builder.build().unwrap_or_default()
}

pub fn validate_recipient_address(
    net: &NetworkSpec,
    recipient: &str,
) -> Result<String, String> {
    let trimmed = recipient.trim();
    if trimmed.is_empty() {
        return Err("Адрес получателя не может быть пустым".to_string());
    }

    match net.family {
        NetworkFamily::Evm => {
            if trimmed.starts_with('T') && trimmed.len() == 34 {
                return Err("Ошибка: Введён адрес Tron (TRC-20), но выбрана EVM-сеть. Отправка заблокирована для предотвращения потери средств!".to_string());
            }
            if trimmed.starts_with("EQ") || trimmed.starts_with("UQ") {
                return Err("Ошибка: Введён адрес TON (Jetton), но выбрана EVM-сеть. Отправка заблокирована!".to_string());
            }
            let bytes = validate_evm_address(trimmed)
                .map_err(|e| format!("Некорректный EVM адрес: {e}"))?;
            Ok(to_checksum_address(&bytes))
        }
        NetworkFamily::Tron => {
            if trimmed.starts_with("0x") {
                return Err("Ошибка: Введён адрес EVM (0x...), но выбрана сеть Tron (TRC-20). Отправка заблокирована!".to_string());
            }
            if trimmed.starts_with("EQ") || trimmed.starts_with("UQ") {
                return Err("Ошибка: Введён адрес TON, но выбрана сеть Tron. Отправка заблокирована!".to_string());
            }
            let _bytes = validate_tron_address(trimmed)
                .map_err(|e| format!("Некорректный адрес Tron: {e}"))?;
            Ok(trimmed.to_string())
        }
        NetworkFamily::Ton => {
            if trimmed.starts_with("0x") {
                return Err("Ошибка: Введён адрес EVM (0x...), но выбрана сеть TON. Отправка заблокирована!".to_string());
            }
            if trimmed.starts_with('T') && trimmed.len() == 34 {
                return Err("Ошибка: Введён адрес Tron, но выбрана сеть TON. Отправка заблокирована!".to_string());
            }
            let _account_id = validate_ton_address(trimmed)
                .map_err(|e| format!("Некорректный адрес TON: {e}"))?;
            Ok(trimmed.to_string())
        }
        NetworkFamily::Solana => {
            if trimmed.starts_with("0x") {
                return Err("Ошибка: Введён адрес EVM (0x...), но выбрана сеть Solana. Отправка заблокирована!".to_string());
            }
            if trimmed.starts_with("EQ") || trimmed.starts_with("UQ") {
                return Err("Ошибка: Введён адрес TON, но выбрана сеть Solana. Отправка заблокирована!".to_string());
            }
            let _pub_bytes = validate_solana_address(trimmed)
                .map_err(|e| format!("Некорректный адрес Solana: {e}"))?;
            Ok(trimmed.to_string())
        }
        NetworkFamily::Monero => {
            if !libmonero::utils::is_valid_addr(trimmed) {
                return Err("Некорректный адрес Monero (неверный формат или контрольная сумма)".to_string());
            }
            Ok(trimmed.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networks::registry::{get_network, NetworkId};

    #[test]
    fn test_cross_network_mismatch_prevention() {
        let eth = get_network(NetworkId::Ethereum);
        let tron = get_network(NetworkId::Tron);
        let ton = get_network(NetworkId::Ton);
        let sol = get_network(NetworkId::Solana);

        let tron_addr = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
        let evm_addr = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        let ton_addr = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs";
        let sol_addr = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

        // Sending Tron address to EVM network must be BLOCKED
        assert!(validate_recipient_address(eth, tron_addr).is_err());
        // Sending EVM address to Tron network must be BLOCKED
        assert!(validate_recipient_address(tron, evm_addr).is_err());
        // Sending EVM address to TON network must be BLOCKED
        assert!(validate_recipient_address(ton, evm_addr).is_err());
        // Sending TON address to Solana must be BLOCKED
        assert!(validate_recipient_address(sol, ton_addr).is_err());

        // Valid pairs must PASS
        assert!(validate_recipient_address(eth, evm_addr).is_ok());
        assert!(validate_recipient_address(tron, tron_addr).is_ok());
        assert!(validate_recipient_address(ton, ton_addr).is_ok());
        assert!(validate_recipient_address(sol, sol_addr).is_ok());
    }
}
