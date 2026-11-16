use std::env;
use std::path::PathBuf;

use agy_wallet::cli::handle_cli_args;
use agy_wallet::ui::{App, Tui};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // If non-interactive CLI arguments are passed, process and exit
    if handle_cli_args(&args).await {
        return Ok(());
    }

    // Otherwise launch the full interactive TUI
    let wallet_path = dirs_wallet_path();
    let app = App::new(wallet_path);
    let mut tui = Tui::new()?;
    tui.run(app).await?;
    Ok(())
}

fn dirs_wallet_path() -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        PathBuf::from(home).join(".agy_wallet.dat")
    } else {
        PathBuf::from("agy_wallet.dat")
    }
}
