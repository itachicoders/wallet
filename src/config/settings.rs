use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::networks::registry::NetworkId;
use crate::platform::Storage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub tor_enabled: bool,
    pub tor_socks5_url: String,
    pub monero_custom_node: Option<String>,
    pub evm_rpc_overrides: HashMap<NetworkId, String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            tor_enabled: false,
            tor_socks5_url: "socks5://127.0.0.1:9050".to_string(),
            monero_custom_node: None,
            evm_rpc_overrides: HashMap::new(),
        }
    }
}

impl AppSettings {
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        if let Ok(bytes) = Storage::read_secure(&path)
            && let Ok(settings) = serde_json::from_slice(&bytes) {
                return settings;
            }
        Self::default()
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error> {
        let json = serde_json::to_vec_pretty(self)?;
        Storage::atomic_write_secure(path, &json)
    }

    pub fn default_config_path() -> PathBuf {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".agy_wallet_config.json")
        } else {
            PathBuf::from("agy_wallet_config.json")
        }
    }
}
