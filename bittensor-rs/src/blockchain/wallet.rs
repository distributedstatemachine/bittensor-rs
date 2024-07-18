use crate::errors::AppError;
use aes_gcm::aead::generic_array::{typenum::U12, GenericArray};
use aes_gcm::aead::Aead;
use aes_gcm::AeadCore;
use aes_gcm::KeyInit;
use aes_gcm::{Aes256Gcm, Key};
use base64::{engine::general_purpose, Engine as _};
use bip39::Mnemonic;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sp_application_crypto::RuntimePublic;
use sp_core::crypto::CryptoBytes;
use sp_core::{
    crypto::{Pair as PairT, Ss58Codec},
    sr25519,
};
use std::error::Error;
use std::fs::{self};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use sp_core::crypto_bytes::SignatureTag;
use sp_core::sr25519::{Public, Signature};
use sp_core::ByteArray;

pub type SendableResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
use log::{error, info};

/// Represents a wallet in the Bittensor network
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Wallet {
    /// The name of the wallet
    pub name: String,
    /// The encrypted seed phrase of the wallet
    encrypted_seed: String,
    /// The nonce used for encryption
    nonce: String,
    /// The file path where the wallet is stored
    #[serde(skip)]
    pub path: PathBuf,
    /// The current balance of the wallet
    pub balance: Option<f64>,
    /// Indicates if this wallet is currently selected
    pub selected: bool,
}

impl Wallet {
    /// Creates a new wallet with the given name and password
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the wallet
    /// * `password` - The password to encrypt the wallet
    ///
    /// # Returns
    ///
    /// * `Result<Self, AppError>` - The created wallet or an error
    ///
    /// # Example
    ///
    /// Creates a new wallet with the given name and password
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the wallet
    /// * `password` - The password to encrypt the wallet
    /// * `log_tx` - A channel for sending log messages
    ///
    /// # Returns
    ///
    /// * `Result<Self, AppError>` - The created wallet or an error
    ///
    /// # Example
    ///
    /// ```
    /// use blockchain::wallet::Wallet;
    /// use tokio::sync::mpsc;
    /// use std::sync::Arc;
    /// use parking_lot::Mutex;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let (tx, _rx) = mpsc::channel(100);
    ///     let log_tx = Arc::new(Mutex::new(tx));
    ///     let wallet = Wallet::create("my_wallet", "password123", log_tx).await.unwrap();
    ///     println!("Wallet created: {}", wallet.name);
    /// }
    /// ```
    pub async fn create(
        name: &str,
        password: &str,
        log_tx: Arc<Mutex<mpsc::Sender<String>>>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Send initial log message
        Self::send_log(&log_tx, "Creating wallet...").await;
        info!("Creating wallet: {}", name);

        // Generate random entropy
        Self::send_log(&log_tx, "Generating entropy...").await;
        let mut entropy: [u8; 16] = [0u8; 16];
        if let Err(e) = thread_rng().try_fill(&mut entropy) {
            error!("Failed to generate entropy: {}", e);
            return Err(Box::new(AppError::EntropyGenerationError));
        }

        // Generate a new mnemonic phrase
        Self::send_log(&log_tx, "Creating mnemonic...").await;
        let mnemonic = match Mnemonic::from_entropy(&entropy) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to create mnemonic: {}", e);
                return Err(Box::new(AppError::MnemonicError));
            }
        };

        // Convert mnemonic to seed
        Self::send_log(&log_tx, "Generating seed from mnemonic...").await;
        let seed: [u8; 64] = mnemonic.to_seed(password);

        // Encrypt the seed
        Self::send_log(&log_tx, "Encrypting seed...").await;
        let (encrypted_seed, nonce) = Self::encrypt_seed(&seed, password)?;

        // Generate key pair from seed
        Self::send_log(&log_tx, "Generating key pair...").await;
        let _pair: sr25519::Pair = sr25519::Pair::from_seed_slice(&seed[..32])
            .map_err(|_| AppError::InvalidSeed)?;

        // TODO: Consider adding error handling for specific seed-related errors
        // TODO: Implement key pair validation to ensure it was generated correctly
        // NOTE: The key pair is not currently used in this function. Consider using or storing it.

        // Get the wallet path
        let path: PathBuf = Self::wallet_path(name);

        // Create the wallet instance
        Self::send_log(&log_tx, "Creating wallet instance...").await;
        let mut wallet = Self {
            name: name.to_string(),
            encrypted_seed,
            nonce,
            path: path.clone(),
            balance: None,
            selected: false,
        };

        // Save the wallet to storage
        Self::send_log(&log_tx, "Saving wallet to storage...").await;
        wallet.save().await?;

        // Fetch initial balance
        Self::send_log(&log_tx, "Fetching initial balance...").await;
        wallet.fetch_balance().await?;

        Self::send_log(&log_tx, "Wallet created successfully!").await;
        info!("Wallet created successfully: {}", name);
        Ok(wallet)
    }

    /// Helper function to send log messages
    async fn send_log(log_tx: &Arc<Mutex<mpsc::Sender<String>>>, message: &str) {
        if let Err(e) = log_tx.lock().await.send(message.to_string()).await {
            error!("Failed to send log message: {}", e);
        }
    }

    async fn save(&self) -> Result<(), AppError> {
        info!("Saving wallet: {}", self.name);
        let path = &self.path;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                error!("Failed to create directory for wallet: {}", e);
                AppError::IoError(e)
            })?;
        }
        let json = serde_json::to_string(self).map_err(|e| {
            error!("Failed to serialize wallet: {}", e);
            AppError::SerializationError(e.to_string())
        })?;
        fs::write(path, json).map_err(|e| {
            error!("Failed to write wallet file: {}", e);
            AppError::IoError(e)
        })?;
        info!("Wallet saved successfully: {}", self.name);
        Ok(())
    }

    pub async fn load(name: &str) -> Result<Self, AppError> {
        info!("Loading wallet: {}", name);
        let path = Self::wallet_path(name);
        let contents = fs::read_to_string(&path).map_err(|e| {
            log::error!("Failed to read wallet file: {}", e);
            AppError::IoError(e)
        })?;

        let mut wallet: Self = serde_json::from_str(&contents).map_err(|e| {
            log::error!("Failed to deserialize wallet: {}", e);
            AppError::DeserializationError(e.to_string())
        })?;

        wallet.path = path;
        wallet.balance = None;
        wallet.selected = false;

        log::info!("Wallet loaded successfully: {}", name);
        Ok(wallet)
    }

    fn wallet_path(name: &str) -> PathBuf {
        let home = dirs::home_dir().expect("Unable to get home directory");
        home.join(".bittensor-rs")
            .join("wallets")
            .join(format!("{}.json", name))
    }

    /// Encrypts a seed with a password
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed to encrypt
    /// * `password` - The password to use for encryption
    ///
    /// # Returns
    ///
    /// * `Result<(String, String), AppError>` - The encrypted seed and nonce, or an error
    fn encrypt_seed(seed: &[u8], password: &str) -> Result<(String, String), AppError> {
        let key_bytes = Self::derive_key(password);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, seed.as_ref())
            .map_err(|_| AppError::EncryptionError)?;

        Ok((
            general_purpose::STANDARD_NO_PAD.encode(ciphertext),
            general_purpose::STANDARD_NO_PAD.encode(nonce),
        ))
    }

    /// Decrypts a seed with a password
    ///
    /// # Arguments
    ///
    /// * `encrypted_seed` - The encrypted seed
    /// * `nonce` - The nonce used for encryption
    /// * `password` - The password to use for decryption
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, AppError>` - The decrypted seed or an error
    fn decrypt_seed(
        encrypted_seed: &str,
        nonce: &str,
        password: &str,
    ) -> Result<Vec<u8>, AppError> {
        let key_bytes = Self::derive_key(password);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = general_purpose::STANDARD_NO_PAD
            .decode(nonce)
            .map_err(|_| AppError::DecodeError)?;
        let nonce = GenericArray::<u8, U12>::from_slice(&nonce);
        let ciphertext = general_purpose::STANDARD_NO_PAD
            .decode(encrypted_seed)
            .map_err(|_| AppError::DecodeError)?;

        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| AppError::DecryptionError)
    }

    /// Derives a key from a password
    ///
    /// # Arguments
    ///
    /// * `password` - The password to derive the key from
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - The derived key
    fn derive_key(password: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Gets the address of the wallet
    ///
    /// # Arguments
    ///
    /// * `password` - The password to decrypt the wallet
    ///
    /// # Returns
    ///
    /// * `Result<String, AppError>` - The SS58-encoded address or an error
    ///
    /// # Example
    ///
    /// ```
    /// let address = wallet.get_address("password123")?;
    /// ```
    pub fn get_address(&self, password: &str) -> Result<String, AppError> {
        let seed = Self::decrypt_seed(&self.encrypted_seed, &self.nonce, password)?;
        let pair = sr25519::Pair::from_seed_slice(&seed).map_err(|_| AppError::InvalidSeed)?;
        Ok(pair.public().to_ss58check())
    }

    /// Signs a message with the wallet's private key
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `password` - The password to decrypt the wallet
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, AppError>` - The signature or an error
    ///
    /// # Example
    ///
    /// ```
    /// let signature = wallet.sign("Hello, world!", "password123")?;
    /// ```
    pub fn sign(&self, message: &[u8], password: &str) -> Result<Vec<u8>, AppError> {
        let seed = Self::decrypt_seed(&self.encrypted_seed, &self.nonce, password)?;
        let pair = sr25519::Pair::from_seed_slice(&seed).map_err(|_| AppError::InvalidSeed)?;
        Ok(pair.sign(message).0.to_vec())
    }

    /// Verifies a signature
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    /// * `password` - The password to decrypt the wallet
    ///
    /// # Returns
    ///
    /// * `Result<bool, AppError>` - True if the signature is valid, false otherwise, or an error
    ///
    /// # Example
    ///
    /// ```
    /// let is_valid = wallet.verify("Hello, world!", &signature, "password123")?;
    /// ```

    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        password: &str,
    ) -> Result<bool, AppError> {
        let seed: Vec<u8> = Self::decrypt_seed(&self.encrypted_seed, &self.nonce, password)?;
        let pair: sr25519::Pair =
            sr25519::Pair::from_seed_slice(&seed).map_err(|_| AppError::InvalidSeed)?;
        let public: Public = pair.public();

        let signature: Signature =
            Signature::try_from(signature).map_err(|_| AppError::VerificationError)?;

        // Convert message to CryptoBytes
        let crypto_bytes: CryptoBytes<64, (SignatureTag, sp_core::sr25519::Sr25519Tag)> =
            CryptoBytes::from_slice(message).map_err(|_| AppError::VerificationError)?;

        Ok(public.verify(&signature, &crypto_bytes))
    }

    /// Fetches the balance for this wallet
    pub async fn fetch_balance(&mut self) -> Result<(), AppError> {
        // TODO: Implement actual balance fetching logic
        // This is a placeholder implementation
        self.balance = Some(100.0);
        Ok(())
    }

    /// Refreshes the balance of the wallet
    ///
    /// This function simulates a balance update by incrementing the current balance.
    /// In a real-world scenario, this would involve querying the blockchain for the latest balance.
    ///
    /// # Returns
    ///
    /// * `Result<(), AppError>` - Ok if the balance was successfully refreshed, or an error
    pub async fn refresh_balance(&mut self) -> Result<(), AppError> {
        // TODO: Implement actual balance refresh logic by querying the blockchain
        // For now, we'll just simulate a balance update
        let current_balance: f64 = self.balance.unwrap_or(0.0);
        let updated_balance: f64 = current_balance + 1.0;
        self.balance = Some(updated_balance);

        // Inline comment explaining the functionality
        // We're simulating a balance update by adding 1.0 to the current balance.
        // This is a placeholder and should be replaced with actual blockchain querying logic.

        Ok(())
    }

    /// Changes the password of the wallet
    ///
    /// # Arguments
    ///
    /// * `password` - The new password to set
    ///
    /// # Returns
    ///
    /// * `Result<(), AppError>` - Ok if the password was successfully changed, or an error
    /// Changes the password of the wallet
    ///
    /// # Arguments
    ///
    /// * `password` - The new password to set
    ///
    /// # Returns
    ///
    /// * `Result<(), AppError>` - Ok if the password was successfully changed, or an error
    ///
    /// # Example
    ///
    /// ```
    /// let mut wallet = Wallet::new("my_wallet");
    /// wallet.change_password("new_secure_password").unwrap();
    /// ```
    /// Changes the password of the wallet
    ///
    /// # Arguments
    ///
    /// * `old_password` - The current password of the wallet
    /// * `new_password` - The new password to set
    ///
    /// # Returns
    ///
    /// * `Result<(), AppError>` - Ok if the password was successfully changed, or an error
    ///
    /// # Example
    pub async fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), AppError> {
        // Decrypt the seed using the current password
        let seed: Vec<u8> = Self::decrypt_seed(&self.encrypted_seed, &self.nonce, old_password)?;

        // Encrypt the seed with the new password
        let (new_encrypted_seed, new_nonce) = Self::encrypt_seed(&seed, new_password)?;

        // Update the wallet with the new encrypted seed and nonce
        self.encrypted_seed = new_encrypted_seed;
        self.nonce = new_nonce;

        // Save the updated wallet to storage
        self.save().await?;

        Ok(())
    }
}

/// Detects wallets in the given directory
/// Detects wallets in the given directory
///
/// # Arguments
///
/// * `wallet_dir` - The directory to search for wallet files
///
/// # Returns
///
/// * `Vec<Wallet>` - A vector of detected wallets
///
pub fn detect_wallets(wallet_dir: &PathBuf) -> Vec<Wallet> {
    let mut wallets = Vec::new();
    if let Ok(entries) = std::fs::read_dir(wallet_dir) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_file() {
                    if let Some(file_name) = entry.file_name().to_str() {
                        if file_name.ends_with(".json") {
                            let wallet_name = file_name.trim_end_matches(".json");
                            if let Ok(wallet) = tokio::task::block_in_place(|| {
                                tokio::runtime::Runtime::new()
                                    .unwrap()
                                    .block_on(Wallet::load(wallet_name))
                            }) {
                                wallets.push(wallet);
                            }
                        }
                    }
                }
            }
        }
    }
    wallets
}

// TODO: Implement key derivation (e.g., BIP44) for multiple accounts per wallet
// TODO: Add support for hardware wallets
// NOTE: Consider adding a method to change the wallet password
