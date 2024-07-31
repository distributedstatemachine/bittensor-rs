use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Bittensor error: {0}")]
    BittensorError(#[from] bittensor_rs::errors::SubtensorError),
    #[error("Wallet error: {0}")]
    WalletError(#[from] bittensor_wallet::WalletError),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
