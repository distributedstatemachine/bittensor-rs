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
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
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
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Key derivation error")]
    KeyDerivationError,
    #[error("Mnemonic generation error: {0}")]
    MnemonicGenerationError(bip39::Error),
    #[error("No active hotkey")]
    NoActiveHotkey,
    #[error("Hotkey not found")]
    HotkeyNotFound,
    #[error("Invalid mnemonic phrase")]
    InvalidMnemonicPhrase,
    #[error("Invalid seed phrase")]
    InvalidSeedPhrase,
    #[error("Invalid derivation path")]
    InvalidDerivationPath,
    #[error("Invalid conversion")]
    ConversionError,
    #[error("No encrypted mnemonic")]
    NoEncryptedMnemonic,
    #[error("No hotkey data")]
    NoHotkeyData,
    #[error("Invalid mnemonic")]
    InvalidMnemonic,
    #[error("Invalid seed length")]
    InvalidSeedLength,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("No encrypted private key")]
    NoEncryptedPrivateKey,
    #[error("Signature conversion error")]
    SignatureConversionError,
    #[error("Key generation error")]
    KeyGenerationError,
    #[error("Public key error")]
    PublicKeyError,
}

impl From<EncodeError> for WalletError {
    fn from(error: EncodeError) -> Self {
        WalletError::EncodingError(error.to_string())
    }
}
