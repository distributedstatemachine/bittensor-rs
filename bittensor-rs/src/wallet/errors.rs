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
pub enum WalletError {
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
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
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
}
