use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::Rng;

use bip39::{Language, Mnemonic};
use rand::RngCore;
use schnorrkel::{
    derive::{ChainCode, Derivation},
    ExpansionMode, MiniSecretKey, Signature as SchnorrkelSignature,
};
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use sp_runtime::traits::IdentifyAccount;
use std::collections::HashMap;
use std::path::PathBuf;

pub mod errors;
use errors::WalletError;

#[derive(Clone, Debug)]
pub struct Keypair {
    pub public: sr25519::Public,
    encrypted_private: Vec<u8>,
}

impl Keypair {
    pub fn new(public: sr25519::Public, encrypted_private: Vec<u8>) -> Self {
        Self {
            public,
            encrypted_private,
        }
    }

    /// Decrypts the private key using the provided password.
    ///
    /// # Arguments
    ///
    /// * `password` - The password used to decrypt the private key.
    ///
    /// # Returns
    ///
    /// * `Result<sr25519::Pair, WalletError>` - The decrypted SR25519 key pair or an error.
    ///
    /// # Example
    ///
    /// ```
    /// let keypair = Keypair::new(public_key, encrypted_private_key);
    /// let pair = keypair.decrypt_private_key("secure_password").expect("Decryption failed");
    /// ```
    pub fn decrypt_private_key(&self, password: &str) -> Result<sr25519::Pair, WalletError> {
        // Ensure we have encrypted data to decrypt
        if self.encrypted_private.is_empty() {
            return Err(WalletError::NoEncryptedPrivateKey);
        }

        // Extract salt, nonce, and ciphertext from encrypted_private
        let salt = self
            .encrypted_private
            .get(..16)
            .ok_or(WalletError::DecryptionError)?;
        let nonce = self
            .encrypted_private
            .get(16..28)
            .ok_or(WalletError::DecryptionError)?;
        let ciphertext = self
            .encrypted_private
            .get(28..)
            .ok_or(WalletError::DecryptionError)?;

        // Derive the key from the password using Argon2
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|_| WalletError::DecryptionError)?;

        // Create an AES-256-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| WalletError::DecryptionError)?;

        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| WalletError::DecryptionError)?;

        // Convert plaintext to sr25519::Pair
        sr25519::Pair::from_seed_slice(&plaintext).map_err(|_| WalletError::InvalidPrivateKey)
    }

    pub fn sign(&self, message: &[u8], password: &str) -> Result<SchnorrkelSignature, WalletError> {
        let pair = self.decrypt_private_key(password)?;
        let signature: sr25519::Signature = pair.sign(message);
        SchnorrkelSignature::from_bytes(signature.as_ref())
            .map_err(|_| WalletError::SignatureConversionError)
    }
}

/// Implements the `IdentifyAccount` trait for `Keypair`.
///
/// This implementation allows a `Keypair` to be converted into an `AccountId32`,
/// which is typically used to identify accounts in the Substrate ecosystem.
///
/// # Examples
///
/// ```
/// use sp_runtime::traits::IdentifyAccount;
/// let keypair = Keypair::new(); // Assuming a new() method exists
/// let account_id: sp_runtime::AccountId32 = keypair.into_account();
/// ```
impl IdentifyAccount for Keypair {
    type AccountId = sp_runtime::AccountId32;

    fn into_account(self) -> Self::AccountId {
        // Convert the public key to an AccountId32
        self.public.into()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Wallet {
    /// The name of the wallet
    pub name: String,
    /// The file path where the wallet is stored
    #[serde(skip)]
    pub path: PathBuf,
    /// The current balance of the wallet
    pub balance: Option<f64>,
    /// The encrypted mnemonic for the wallet
    encrypted_mnemonic: Vec<u8>,
    /// The derivation paths for the hotkeys
    hotkey_paths: HashMap<String, Vec<u8>>,
    /// The name of the currently active hotkey
    active_hotkey: Option<String>,
    /// The encrypted private keys for the hotkeys
    hotkey_data: Option<HashMap<String, Vec<u8>>>,
}

impl Wallet {
    pub fn new(name: &str, path: PathBuf) -> Self {
        Wallet {
            name: name.to_string(),
            path,
            balance: None,
            encrypted_mnemonic: Vec::new(),
            hotkey_paths: HashMap::new(),
            active_hotkey: None,
            hotkey_data: None,
        }
    }

    /// Creates a new wallet with a randomly generated mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `n_words` - The number of words in the mnemonic phrase (typically 12, 15, 18, 21, or 24).
    /// * `password` - The password used to encrypt the mnemonic.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// wallet.create_new_wallet(12, "secure_password").expect("Failed to create wallet");
    /// ```
    pub fn create_new_wallet(&mut self, n_words: u32, password: &str) -> Result<(), WalletError> {
        // Generate entropy based on the desired number of words
        let entropy_bytes = (n_words / 3) * 4;
        let entropy_size =
            usize::try_from(entropy_bytes).map_err(|_| WalletError::ConversionError)?;

        let mut entropy = vec![0u8; entropy_size];
        rand::thread_rng().fill_bytes(&mut entropy);

        // Create a new mnemonic from the generated entropy
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| WalletError::MnemonicGenerationError(e))?;

        // Encrypt the mnemonic using the provided password
        self.encrypted_mnemonic = self.encrypt_mnemonic(&mnemonic, password)?;

        // Initialize hotkey_data as an empty HashMap
        self.hotkey_data = Some(HashMap::new());

        Ok(())
    }

    /// Creates a new hotkey with the given name and encrypts it using the provided password.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the new hotkey.
    /// * `password` - The password used to encrypt the hotkey.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// wallet.create_new_hotkey("my_hotkey", "secure_password").expect("Failed to create hotkey");
    /// ```
    pub fn create_new_hotkey(&mut self, name: &str, password: &str) -> Result<(), WalletError> {
        // Generate the derivation path for the new hotkey
        let derivation_path: Vec<u8> = format!("//{}", name).into_bytes();

        // Decrypt the wallet's mnemonic using the provided password
        let mnemonic: Mnemonic = self.decrypt_mnemonic(password)?;

        // Generate the seed from the mnemonic
        let seed: [u8; 32] = mnemonic.to_seed("")[..32]
            .try_into()
            .map_err(|_| WalletError::ConversionError)?;

        // Derive the hotkey pair using the seed and derivation path
        let hotkey_pair: sr25519::Pair = self.derive_sr25519_key(&seed, &derivation_path)?;

        // Encrypt the hotkey's private key using the provided password
        let encrypted_private_key: Vec<u8> = self.encrypt_private_key(&hotkey_pair, password)?;

        // Store the encrypted private key and derivation path
        self.hotkey_paths.insert(name.to_string(), derivation_path);

        // Initialize hotkey_data if it doesn't exist
        if self.hotkey_data.is_none() {
            self.hotkey_data = Some(HashMap::new());
        }

        // Add the new hotkey to hotkey_data
        if let Some(hotkey_data) = &mut self.hotkey_data {
            hotkey_data.insert(name.to_string(), encrypted_private_key);
        }

        Ok(())
    }

    // TODO: Implement a method to rotate or update hotkey passwords
    // TODO: Add a mechanism to verify the integrity of stored hotkeys
    // TODO: Consider implementing a backup system for hotkeys

    pub fn set_active_hotkey(&mut self, name: &str) -> Result<(), WalletError> {
        if self.hotkey_paths.contains_key(name) {
            self.active_hotkey = Some(name.to_string());
            Ok(())
        } else {
            Err(WalletError::HotkeyNotFound)
        }
    }

    pub fn get_coldkey(&self, password: &str) -> Result<Keypair, WalletError> {
        let mnemonic = self.decrypt_mnemonic(password)?;
        let seed = mnemonic.to_seed("");
        let pair = sr25519::Pair::from_seed_slice(&seed[..32])
            .map_err(|_| WalletError::KeyDerivationError)?;
        let encrypted_private = self.encrypt_private_key(&pair, password)?;
        Ok(Keypair {
            public: pair.public(),
            encrypted_private,
        })
    }

    /// Gets the active hotkey as a Keypair.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to decrypt the mnemonic and encrypt the private key.
    ///
    /// # Returns
    ///
    /// * `Result<Keypair, WalletError>` - The active hotkey Keypair or an error.
    pub fn get_active_hotkey(&self, password: &str) -> Result<Keypair, WalletError> {
        let active_hotkey = self
            .active_hotkey
            .as_ref()
            .ok_or(WalletError::NoActiveHotkey)?;

        self.get_hotkey(active_hotkey, password)
    }

    /// Gets a hotkey as a Keypair.
    ///
    /// # Arguments
    ///
    /// * `hotkey_name` - The name of the hotkey to retrieve.
    /// * `password` - The password to decrypt the mnemonic and encrypt the private key.
    ///
    /// # Returns
    ///
    /// * `Result<Keypair, WalletError>` - The hotkey Keypair or an error.
    pub fn get_hotkey(&self, hotkey_name: &str, password: &str) -> Result<Keypair, WalletError> {
        let mnemonic = self.decrypt_mnemonic(password)?;
        let seed = mnemonic.to_seed("");

        // Derive the hotkey path
        let hotkey_path = self
            .hotkey_paths
            .get(hotkey_name)
            .ok_or(WalletError::HotkeyNotFound)?;

        // Derive the hotkey pair
        let pair = self.derive_sr25519_key(&seed, hotkey_path)?;
        let encrypted_private = self.encrypt_private_key(&pair, password)?;

        Ok(Keypair {
            public: pair.public(),
            encrypted_private,
        })
    }

    pub async fn fetch_balance(&mut self) -> Result<(), WalletError> {
        // TODO: Implement actual balance fetching logic
        self.balance = Some(100.0);
        Ok(())
    }

    /// Regenerates the wallet using a provided mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - The mnemonic phrase as a string.
    /// * `password` - The password used to encrypt the mnemonic.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// wallet.regenerate_wallet("your mnemonic phrase here", "secure_password").expect("Failed to regenerate wallet");
    /// ```
    pub fn regenerate_wallet(&mut self, mnemonic: &str, password: &str) -> Result<(), WalletError> {
        // Convert the mnemonic phrase to entropy
        let entropy = Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|e| WalletError::MnemonicGenerationError(e))?
            .to_entropy();

        // Create a new mnemonic from the entropy
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| WalletError::MnemonicGenerationError(e))?;

        // Encrypt the mnemonic using the provided password
        self.encrypted_mnemonic = self.encrypt_mnemonic(&mnemonic, password)?;

        // Clear existing hotkey paths and active hotkey
        self.hotkey_paths.clear();
        self.active_hotkey = None;

        // TODO: Consider adding a check to ensure the mnemonic was successfully encrypted
        // TODO: Implement proper error handling for encryption failures

        Ok(())
    }

    /// Changes the password for the wallet and re-encrypts all sensitive data.
    ///
    /// This function decrypts the mnemonic using the old password, re-encrypts it with the new password,
    /// and updates all hotkeys with the new encryption.
    ///
    /// # Arguments
    ///
    /// * `old_password` - A string slice that holds the current password.
    /// * `new_password` - A string slice that holds the new password to be set.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// wallet.change_password("old_password", "new_password").await.expect("Failed to change password");
    /// ```
    pub async fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), WalletError> {
        // Decrypt the mnemonic using the old password
        let mnemonic: Mnemonic = self.decrypt_mnemonic(old_password).map_err(|e| {
            eprintln!("Error decrypting mnemonic: {:?}", e);
            e
        })?;

        // Re-encrypt the mnemonic with the new password
        let new_encrypted_mnemonic =
            self.encrypt_mnemonic(&mnemonic, new_password)
                .map_err(|e| {
                    eprintln!("Error re-encrypting mnemonic: {:?}", e);
                    e
                })?;

        // Re-encrypt all hotkeys
        let mut new_hotkey_data = HashMap::new();
        if let Some(hotkey_data) = &self.hotkey_data {
            for (name, encrypted_private) in hotkey_data.iter() {
                // Decrypt the private key using the old password
                let pair = sr25519::Pair::from_seed_slice(encrypted_private).map_err(|e| {
                    eprintln!("Error decrypting hotkey {}: {:?}", name, e);
                    WalletError::DecryptionError
                })?;

                // Re-encrypt the private key with the new password
                let new_encrypted_private =
                    self.encrypt_private_key(&pair, new_password).map_err(|e| {
                        eprintln!("Error re-encrypting hotkey {}: {:?}", name, e);
                        e
                    })?;
                new_hotkey_data.insert(name.clone(), new_encrypted_private);
            }
        }

        // Update the wallet with the new encrypted data
        self.encrypted_mnemonic = new_encrypted_mnemonic;
        self.hotkey_data = Some(new_hotkey_data);

        Ok(())
    }

    
    fn encrypt_mnemonic(
        &self,
        mnemonic: &Mnemonic,
        password: &str,
    ) -> Result<Vec<u8>, WalletError> {
        // Generate a random salt
        let salt: [u8; 16] = rand::thread_rng().gen();

        // Derive a key from the password using Argon2
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|_| WalletError::EncryptionError)?;

        // Create an AES-256-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| WalletError::EncryptionError)?;

        // Generate a random nonce
        let nonce = Nonce::from(rand::thread_rng().gen::<[u8; 12]>());

        // Convert mnemonic to string and then to bytes
        let mnemonic_string = mnemonic.to_string();
        let mnemonic_bytes = mnemonic_string.as_bytes();

        // Encrypt the mnemonic
        let ciphertext = cipher
            .encrypt(&nonce, mnemonic_bytes)
            .map_err(|_| WalletError::EncryptionError)?;

        // Combine salt, nonce, and ciphertext
        let mut encrypted = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
        encrypted.extend_from_slice(&salt);
        encrypted.extend_from_slice(nonce.as_slice());
        encrypted.extend_from_slice(&ciphertext);

        Ok(encrypted)
    }

    fn decrypt_mnemonic(&self, password: &str) -> Result<Mnemonic, WalletError> {
        // Ensure we have encrypted data to decrypt
        if self.encrypted_mnemonic.is_empty() {
            return Err(WalletError::NoEncryptedMnemonic);
        }

        // Extract salt, nonce, and ciphertext from encrypted_mnemonic
        let salt = self
            .encrypted_mnemonic
            .get(..16)
            .ok_or(WalletError::DecryptionError)?;
        let nonce = self
            .encrypted_mnemonic
            .get(16..28)
            .ok_or(WalletError::DecryptionError)?;
        let ciphertext = self
            .encrypted_mnemonic
            .get(28..)
            .ok_or(WalletError::DecryptionError)?;

        // Derive the key from the password using Argon2
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|_| WalletError::DecryptionError)?;

        // Create an AES-256-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| WalletError::DecryptionError)?;

        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| WalletError::DecryptionError)?;

        // Convert plaintext to string and parse as Mnemonic
        let mnemonic_str =
            String::from_utf8(plaintext).map_err(|_| WalletError::DecryptionError)?;

        Mnemonic::parse_in_normalized(Language::English, &mnemonic_str)
            .map_err(|_| WalletError::InvalidMnemonic)
    }
    /// Updates the encrypted private key for a specific hotkey.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the hotkey to update.
    /// * `encrypted_private` - The new encrypted private key.
    ///
    /// # Returns
    ///
    /// * `Result<(), WalletError>` - Ok(()) if successful, or an error if the operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// let encrypted_private = vec![1, 2, 3, 4, 5]; // Example encrypted private key
    /// wallet.update_hotkey_encryption("hotkey1", &encrypted_private).expect("Failed to update hotkey encryption");
    /// ```
    fn update_hotkey_encryption(
        &mut self,
        name: &str,
        encrypted_private: &[u8],
    ) -> Result<(), WalletError> {
        // Check if the hotkey exists
        if !self.hotkey_paths.contains_key(name) {
            return Err(WalletError::HotkeyNotFound);
        }

        // Create a new HashMap to store hotkey data
        let mut hotkey_data = HashMap::new();

        // If we already have a hotkey_data HashMap, clone it
        if let Some(existing_data) = self.hotkey_data.as_ref() {
            hotkey_data = existing_data.clone();
        }

        // Update the encrypted private key for the specified hotkey
        hotkey_data.insert(name.to_string(), encrypted_private.to_vec());

        // Update the wallet's hotkey_data
        self.hotkey_data = Some(hotkey_data);

        Ok(())
    }

    /// Derives an SR25519 key pair from a seed and a derivation path.
    ///
    /// # Arguments
    ///
    /// * `seed` - A byte slice containing the seed for key derivation.
    /// * `path` - A byte slice representing the derivation path.
    ///
    /// # Returns
    ///
    /// * `Result<sr25519::Pair, WalletError>` - The derived SR25519 key pair or an error.
    ///
    /// # Example
    ///
    /// ```
    /// let seed: [u8; 32] = [0; 32]; // Example seed
    /// let path: [u8; 4] = [0, 1, 2, 3]; // Example path
    /// let derived_key = wallet.derive_sr25519_key(&seed, &path).expect("Failed to derive key");
    /// ```
    /// Derives an SR25519 key pair from a seed and a derivation path.
    ///
    /// # Arguments
    ///
    /// * `seed` - A byte slice containing the seed for key derivation.
    /// * `path` - A byte slice representing the derivation path.
    ///
    /// # Returns
    ///
    /// * `Result<sr25519::Pair, WalletError>` - The derived SR25519 key pair or an error.
    ///
    /// # Example
    ///
    /// ```
    /// let seed: [u8; 32] = [0; 32]; // Example seed
    /// let path: [u8; 4] = [0, 1, 2, 3]; // Example path
    /// let derived_key = wallet.derive_sr25519_key(&seed, &path).expect("Failed to derive key");
    /// ```
    /// Derives an SR25519 key pair from a seed and a derivation path.
    ///
    /// # Arguments
    ///
    /// * `seed` - A byte slice containing the seed for key derivation.
    /// * `path` - A byte slice representing the derivation path.
    ///
    /// # Returns
    ///
    /// * `Result<sr25519::Pair, WalletError>` - The derived SR25519 key pair or an error.
    ///
    /// # Example
    ///
    /// ```
    /// let seed: [u8; 32] = [0; 32]; // Example seed
    /// let path: [u8; 4] = [0, 1, 2, 3]; // Example path
    /// let derived_key = wallet.derive_sr25519_key(&seed, &path).expect("Failed to derive key");
    /// ```
    fn derive_sr25519_key(&self, seed: &[u8], path: &[u8]) -> Result<sr25519::Pair, WalletError> {
        // Ensure the seed is the correct length
        if seed.len() != 32 {
            return Err(WalletError::InvalidSeedLength);
        }

        // Create the initial mini secret key from the seed
        let mini_secret_key =
            MiniSecretKey::from_bytes(seed).map_err(|_| WalletError::KeyDerivationError)?;

        // Convert to a secret key and derive the initial key pair
        let mut secret_key = mini_secret_key.expand(ExpansionMode::Ed25519);
        let mut pair = sr25519::Pair::from_seed_slice(&secret_key.to_bytes()[..32])
            .map_err(|_| WalletError::KeyDerivationError)?;

        // Initialize the chain code
        let mut chain_code = ChainCode(
            seed.try_into()
                .map_err(|_| WalletError::KeyDerivationError)?,
        );

        // Iteratively derive the key pair using the path
        for junction in path {
            let (derived_key, next_chain_code) =
                secret_key.derived_key_simple(chain_code, &[*junction]);
            secret_key = derived_key;
            pair = sr25519::Pair::from_seed_slice(&secret_key.to_bytes()[..32])
                .map_err(|_| WalletError::KeyDerivationError)?;
            chain_code = next_chain_code;
        }

        Ok(pair)
    }

    /// Encrypts the private key of an sr25519 key pair using the provided password.
    ///
    /// # Arguments
    ///
    /// * `pair` - The sr25519 key pair containing the private key to encrypt.
    /// * `password` - The password used to derive the encryption key.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, WalletError>` - The encrypted private key or an error.
    ///
    /// # Examples
    ///
    /// ```
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// let pair = sr25519::Pair::generate();
    /// let encrypted = wallet.encrypt_private_key(&pair, "secure_password").expect("Encryption failed");
    /// ```
    fn encrypt_private_key(
        &self,
        pair: &sr25519::Pair,
        password: &str,
    ) -> Result<Vec<u8>, WalletError> {
        // Generate a random salt
        let salt: [u8; 16] = rand::thread_rng().gen();

        // Derive a key from the password using Argon2
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|_| WalletError::EncryptionError)?;

        // Create an AES-256-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| WalletError::EncryptionError)?;

        // Generate a random nonce
        let nonce = Nonce::from(rand::thread_rng().gen::<[u8; 12]>());

        // Get the private key bytes
        let private_key_bytes = pair.to_raw_vec();

        // Encrypt the private key
        let ciphertext = cipher
            .encrypt(&nonce, private_key_bytes.as_ref())
            .map_err(|_| WalletError::EncryptionError)?;

        // Combine salt, nonce, and ciphertext
        let mut encrypted = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
        encrypted.extend_from_slice(&salt);
        encrypted.extend_from_slice(nonce.as_slice());
        encrypted.extend_from_slice(&ciphertext);

        Ok(encrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use std::str::FromStr;
    use tempfile::tempdir;

    // Helper function to create a test wallet
    fn create_test_wallet() -> Wallet {
        let dir = tempdir().unwrap();
        Wallet::new("test_wallet", dir.path().to_path_buf())
    }

    #[test]
    fn test_wallet_creation() {
        let wallet = create_test_wallet();
        assert_eq!(wallet.name, "test_wallet");
        assert!(wallet.balance.is_none());
        assert!(wallet.encrypted_mnemonic.is_empty());
        assert!(wallet.hotkey_paths.is_empty());
        assert!(wallet.active_hotkey.is_none());
        assert!(wallet.hotkey_data.is_none());
    }

    #[test]
    fn test_create_new_wallet() {
        let mut wallet = create_test_wallet();
        assert!(wallet.create_new_wallet(12, "password123").is_ok());
        assert!(!wallet.encrypted_mnemonic.is_empty());
    }

    #[test]
    fn test_create_new_hotkey() {
        let mut wallet = create_test_wallet();
        assert!(wallet.create_new_hotkey("hotkey1", "password123").is_ok());
        assert!(wallet.hotkey_paths.contains_key("hotkey1"));
    }

    #[test]
    fn test_set_active_hotkey() {
        let mut wallet = create_test_wallet();
        wallet.create_new_hotkey("hotkey1", "password123").unwrap();
        assert!(wallet.set_active_hotkey("hotkey1").is_ok());
        assert_eq!(wallet.active_hotkey, Some("hotkey1".to_string()));
    }

    #[test]
    fn test_get_coldkey() {
        let mut wallet = create_test_wallet();
        wallet.create_new_wallet(12, "password123").unwrap();
        let coldkey = wallet.get_coldkey("password123");
        assert!(coldkey.is_ok());
    }

    #[test]
    fn test_get_active_hotkey() {
        let mut wallet = create_test_wallet();
        wallet.create_new_wallet(12, "password123").unwrap();
        wallet.create_new_hotkey("hotkey1", "password123").unwrap();
        wallet.set_active_hotkey("hotkey1").unwrap();
        let hotkey = wallet.get_active_hotkey("password123");
        assert!(hotkey.is_ok());
    }

    #[test]
    fn test_regenerate_wallet() {
        let mut wallet = create_test_wallet();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(wallet.regenerate_wallet(mnemonic, "password123").is_ok());
        assert!(!wallet.encrypted_mnemonic.is_empty());
    }

    #[tokio::test]
    async fn test_change_password() {
        let mut wallet = create_test_wallet();
        wallet.create_new_wallet(12, "old_password").unwrap();
        wallet.create_new_hotkey("hotkey1", "old_password").unwrap();

        match wallet.change_password("old_password", "new_password").await {
            Ok(_) => println!("Password changed successfully"),
            Err(e) => panic!("Failed to change password: {:?}", e),
        }
    }

    #[test]
    fn test_encrypt_decrypt_mnemonic() {
        let mut wallet = create_test_wallet();
        let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let encrypted = wallet.encrypt_mnemonic(&mnemonic, "password123").unwrap();

        // Use the encrypted mnemonic to test decryption
        wallet.encrypted_mnemonic = encrypted;

        let decrypted = wallet.decrypt_mnemonic("password123").unwrap();
        assert_eq!(mnemonic.to_string(), decrypted.to_string());
    }

    #[test]
    fn test_update_hotkey_encryption() {
        let mut wallet = create_test_wallet();
        wallet.create_new_hotkey("hotkey1", "password123").unwrap();
        let encrypted_private = vec![1, 2, 3, 4, 5];
        assert!(wallet
            .update_hotkey_encryption("hotkey1", &encrypted_private)
            .is_ok());
        assert!(wallet.hotkey_data.is_some());
    }

    #[test]
    fn test_derive_sr25519_key() {
        let wallet = create_test_wallet();
        let seed = [0u8; 32];
        let path = vec![0, 1, 2, 3];
        let result = wallet.derive_sr25519_key(&seed, &path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_encrypt_private_key() {
        let wallet = create_test_wallet();
        let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
        let result = wallet.encrypt_private_key(&pair, "password123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_keypair_decrypt_private_key() {
        let wallet = create_test_wallet();
        let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
        let encrypted = wallet.encrypt_private_key(&pair, "password123").unwrap();
        let keypair = Keypair::new(pair.public(), encrypted);
        let decrypted = keypair.decrypt_private_key("password123");
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap().public(), pair.public());
    }

    #[test]
    fn test_keypair_sign() {
        let wallet = create_test_wallet();
        let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
        let encrypted = wallet.encrypt_private_key(&pair, "password123").unwrap();
        let keypair = Keypair::new(pair.public(), encrypted);
        let message = b"test message";
        let signature = keypair.sign(message, "password123");
        assert!(signature.is_ok());
    }

    #[test]
    fn test_identify_account() {
        let wallet = create_test_wallet();
        let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
        let encrypted = wallet.encrypt_private_key(&pair, "password123").unwrap();
        let keypair = Keypair::new(pair.public(), encrypted);
        let account_id: sp_runtime::AccountId32 = keypair.into_account();
        assert_eq!(account_id, sp_runtime::AccountId32::from(pair.public()));
    }
}

// pub fn detect_wallets(wallet_dir: &PathBuf) -> Vec<Wallet> {
//     // Implementation remains the same
//     unimplemented!()
// }
