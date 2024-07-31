use bittensor_wallet::{Wallet, WalletError};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        #[clap(short, long)]
        name: String,
        #[clap(short, long)]
        path: PathBuf,
        #[clap(short, long, default_value = "12")]
        words: u32,
        #[clap(short, long)]
        password: String,
    },
    AddHotkey {
        #[clap(short, long)]
        name: String,
        #[clap(short, long)]
        wallet_name: String,
        #[clap(short, long)]
        wallet_path: PathBuf,
        #[clap(short, long)]
        password: String,
    },
}

fn main() -> Result<(), WalletError> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Create {
            name,
            path,
            words,
            password,
        } => {
            let mut wallet = Wallet::new(name, path.clone());
            wallet.create_new_wallet(*words, password)?;
            println!("Wallet created successfully");
        }
        Commands::AddHotkey {
            name,
            wallet_name,
            wallet_path,
            password,
        } => {
            let mut wallet = Wallet::new(wallet_name, wallet_path.clone());
            wallet.create_new_hotkey(name, password)?;
            println!("Hotkey added successfully");
        }
    }

    Ok(())
}
