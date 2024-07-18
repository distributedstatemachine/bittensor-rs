use subxt::error::EncodeError;

/// Documentation for the AppError enum
///
/// This enum represents all possible errors that can occur in the application.
///
/// # Variants
///
/// * `Io` - Standard IO errors
/// * `Crossterm` - Errors from the crossterm library
/// * `InvalidInput` - Errors due to invalid user input
/// * `Network` - Errors related to network operations
/// * `Blockchain` - Errors related to blockchain interactions
///
/// # Example
/// ```
/// use crate::errors::AppError;
///

///
/// - Add more specific error types as needed
/// - Implement custom error handling and recovery strategies
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Blockchain error: {0}")]
    Blockchain(String),
    #[error("Event error")]
    EventError,
    #[error("Invalid seed")]
    InvalidSeed,
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
    #[error("Mnemonic error")]
    MnemonicError,
    #[error("Decode error")]
    DecodeError,
    #[error("Verification error")]
    VerificationError,
    #[error("Wallet creation error")]
    WalletCreationError,
    #[error("Wallet selection error")]
    WalletSelectionError,
    #[error("Wallet balance error")]
    WalletBalanceError,
    #[error("Config error: {0}")]
    ConfigError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Entropy generation error")]
    EntropyGenerationError,
    #[error("IO error: {0}")]
    IoError(std::io::Error),
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Subxt error: {0}")]
    SubxtError(#[from] subxt::Error),
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Decoding error: {0}")]
    DecodingError(String),
    #[error("RPC error: {0}")]
    RpcError(String),
}

// TODO: Implement custom From traits for specific error conversions
// TODO: Add unit tests for error handling scenarios

impl From<EncodeError> for AppError {
    fn from(error: EncodeError) -> Self {
        AppError::EncodingError(error.to_string())
    }
}
