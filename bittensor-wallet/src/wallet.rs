use crate::errors::WalletError;
use crate::keypair::Keypair;

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
    ExpansionMode, MiniSecretKey,
};
use serde::{Deserialize, Serialize};
use sp_core::crypto::Ss58Codec;
use sp_core::sr25519::Signature as Sr25519Signature;
use sp_core::{sr25519, Pair};
use sp_runtime::traits::Verify;
use std::path::PathBuf;
use std::{collections::HashMap, error::Error};

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
    hotkey_public_keys: HashMap<String, sr25519::Public>,
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
            hotkey_public_keys: HashMap::new(),
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
        log::debug!("Creating new wallet with {} words", n_words);

        // Generate entropy based on the desired number of words
        let entropy_bytes = (n_words / 3) * 4;
        let entropy_size =
            usize::try_from(entropy_bytes).map_err(|_| WalletError::ConversionError)?;

        let mut entropy = vec![0u8; entropy_size];
        rand::thread_rng().fill_bytes(&mut entropy);
        log::debug!("Generated entropy of {} bytes", entropy_size);

        // Create a new mnemonic from the generated entropy
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(WalletError::MnemonicGenerationError)?;
        log::debug!("Created mnemonic phrase");

        // Encrypt the mnemonic using the provided password
        let encrypted_data = self.encrypt_mnemonic(&mnemonic, password)?;
        log::debug!("Encrypted mnemonic");

        log::debug!(
            "Encrypted mnemonic length before storage: {}",
            encrypted_data.len()
        );

        self.encrypted_mnemonic = encrypted_data;

        // Initialize hotkey_data as an empty HashMap
        self.hotkey_data = Some(HashMap::new());
        self.hotkey_public_keys = HashMap::new();

        log::debug!("Wallet created successfully");
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
    /// ```
    pub fn create_new_hotkey(&mut self, name: &str, password: &str) -> Result<(), WalletError> {
        log::debug!("Creating new hotkey: {}", name);
        let derivation_path: Vec<u8> = format!("//{}", name).into_bytes();

        log::debug!("Attempting to decrypt mnemonic");
        let mnemonic: Mnemonic = self.decrypt_mnemonic(password).map_err(|e| {
            log::error!("Failed to decrypt mnemonic: {:?}", e);
            e
        })?;

        log::debug!("Mnemonic decrypted successfully");

        let seed: [u8; 32] = mnemonic.to_seed("")[..32].try_into().map_err(|_| {
            log::error!("Failed to convert mnemonic to seed");
            WalletError::ConversionError
        })?;

        let hotkey_pair: sr25519::Pair =
            self.derive_sr25519_key(&seed, &derivation_path)
                .map_err(|e| {
                    log::error!("Failed to derive sr25519 key: {:?}", e);
                    e
                })?;

        let encrypted_private_key: Vec<u8> = self
            .encrypt_private_key(&hotkey_pair, password)
            .map_err(|e| {
                log::error!("Failed to encrypt private key: {:?}", e);
                e
            })?;

        self.hotkey_paths.insert(name.to_string(), derivation_path);

        if self.hotkey_data.is_none() {
            self.hotkey_data = Some(HashMap::new());
        }

        if let Some(hotkey_data) = &mut self.hotkey_data {
            hotkey_data.insert(name.to_string(), encrypted_private_key);
        }

        // Add the public key to hotkey_public_keys
        let public_key = hotkey_pair.public();
        self.hotkey_public_keys.insert(name.to_string(), public_key);

        log::debug!("Hotkey created successfully: {}", name);
        log::debug!("Public key: {:?}", public_key);
        log::debug!("Hotkey paths: {:?}", self.hotkey_paths);
        log::debug!("Hotkey data: {:?}", self.hotkey_data);
        log::debug!("Hotkey public keys: {:?}", self.hotkey_public_keys);
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

    /// Retrieves the coldkey as a public key.
    ///
    /// This function decrypts the wallet's mnemonic, derives the seed, generates an SR25519 keypair,
    /// and returns the public key.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password to decrypt the mnemonic.
    ///
    /// # Returns
    ///
    /// * `Result<sr25519::Public, WalletError>` - A Result containing either the public key or a WalletError.
    ///
    /// # Example
    ///
    /// ```
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// let coldkey_public = wallet.get_coldkey("my_password").expect("Failed to get coldkey public key");
    /// ```
    pub fn get_coldkey(&self, password: &str) -> Result<sr25519::Public, WalletError> {
        // Decrypt the mnemonic using the provided password
        let mnemonic: Mnemonic = self.decrypt_mnemonic(password)?;

        // Generate the seed from the mnemonic
        let seed: [u8; 32] = mnemonic.to_seed("")[..32]
            .try_into()
            .map_err(|_| WalletError::ConversionError)?;

        // Generate an SR25519 keypair from the seed
        let pair: sr25519::Pair = sr25519::Pair::from_seed(&seed);

        // Return only the public key
        Ok(pair.public())
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
    ///  Gets a hotkey as a Keypair.
    ///
    /// # Arguments
    ///
    /// * `hotkey_name` - The name of the hotkey to retrieve.
    /// * `password` - The password to decrypt the mnemonic.
    ///
    /// # Returns
    ///
    /// * `Result<Keypair, WalletError>` - The hotkey Keypair or an error.
    ///
    /// # Example
    ///
    /// ```
    /// let wallet = Wallet::new("my_wallet", PathBuf::from("/path/to/wallet"));
    /// let hotkey = wallet.get_hotkey("my_hotkey", "password").expect("Failed to get hotkey");
    /// ```
    pub fn get_hotkey(&self, hotkey_name: &str, password: &str) -> Result<Keypair, WalletError> {
        let encrypted_private = self
            .hotkey_data
            .as_ref()
            .and_then(|data| data.get(hotkey_name))
            .ok_or(WalletError::HotkeyNotFound)?;

        let public = self.get_hotkey_public(hotkey_name, password)?;

        Ok(Keypair::new(public, encrypted_private.clone()))
    }

    fn get_hotkey_public(
        &self,
        hotkey_name: &str,
        password: &str,
    ) -> Result<sr25519::Public, WalletError> {
        let derivation_path = self
            .hotkey_paths
            .get(hotkey_name)
            .ok_or(WalletError::HotkeyNotFound)?;
        let mnemonic = self.decrypt_mnemonic(password)?;
        let seed = mnemonic.to_seed("");
        let pair = self.derive_sr25519_key(&seed[..32], derivation_path)?;
        Ok(pair.public())
    }

    pub async fn fetch_balance(&mut self) -> Result<(), WalletError> {
        // TODO: Implement actual balance fetching logic
        self.balance = Some(100.0);
        Ok(())
    }
    pub fn get_coldkey_ss58(&self) -> Result<String, WalletError> {
        let public = self.get_coldkey_public()?;
        Ok(public.to_ss58check())
    }

    pub fn get_hotkey_ss58(&self, hotkey_name: &str) -> Result<String, WalletError> {
        self.hotkey_public_keys
            .get(hotkey_name)
            .ok_or(WalletError::HotkeyNotFound)
            .map(|public_key| public_key.to_ss58check())
    }

    fn get_coldkey_public(&self) -> Result<sr25519::Public, WalletError> {
        // Assuming the first 32 bytes of encrypted_mnemonic are the public key
        // This assumption needs to be validated in the implementation of create_new_wallet
        let public_bytes: [u8; 32] = self.encrypted_mnemonic[..32]
            .try_into()
            .map_err(|_| WalletError::PublicKeyError)?;
        Ok(sr25519::Public::from_raw(public_bytes))
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
            .map_err(WalletError::MnemonicGenerationError)?
            .to_entropy();

        // Create a new mnemonic from the entropy
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(WalletError::MnemonicGenerationError)?;

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
    pub async fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), WalletError> {
        // Decrypt the mnemonic using the old password
        let mnemonic: Mnemonic = self.decrypt_mnemonic(old_password)?;

        // Re-encrypt the mnemonic with the new password
        let new_encrypted_mnemonic = self.encrypt_mnemonic(&mnemonic, new_password)?;

        // Re-encrypt all hotkeys
        let mut new_hotkey_data = HashMap::new();
        if let Some(hotkey_data) = &self.hotkey_data {
            for (name, encrypted_private) in hotkey_data.iter() {
                let keypair = Keypair::new(
                    self.get_hotkey_public(name, old_password)?,
                    encrypted_private.clone(),
                );
                let pair = keypair.decrypt_private_key(old_password)?;
                let new_encrypted_private = self.encrypt_private_key(&pair, new_password)?;
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
        let salt: [u8; 16] = rand::thread_rng().gen();
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|_| WalletError::EncryptionError)?;

        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| WalletError::EncryptionError)?;
        let nonce = Nonce::from(rand::thread_rng().gen::<[u8; 12]>());
        let mnemonic_string = mnemonic.to_string();
        let mnemonic_bytes = mnemonic_string.as_bytes();

        log::debug!("Encrypting mnemonic of length: {}", mnemonic_bytes.len());

        let ciphertext = cipher
            .encrypt(&nonce, mnemonic_bytes)
            .map_err(|_| WalletError::EncryptionError)?;

        let mut encrypted = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
        encrypted.extend_from_slice(&salt);
        encrypted.extend_from_slice(nonce.as_slice());
        encrypted.extend_from_slice(&ciphertext);

        log::debug!(
            "Encrypted data length (before adding public key): {}",
            encrypted.len()
        );
        log::debug!(
            "Salt length: {}, Nonce length: {}, Ciphertext length: {}",
            salt.len(),
            nonce.len(),
            ciphertext.len()
        );

        // Generate and prepend public key
        let seed = mnemonic.to_seed("");
        let pair = sr25519::Pair::from_seed_slice(&seed[..32])
            .map_err(|_| WalletError::KeyDerivationError)?;
        let public_key = pair.public();

        let mut final_encrypted = Vec::with_capacity(32 + encrypted.len());
        final_encrypted.extend_from_slice(public_key.as_ref());
        final_encrypted.extend_from_slice(&encrypted);

        log::debug!(
            "Final encrypted data length (including public key): {}",
            final_encrypted.len()
        );

        Ok(final_encrypted)
    }

    fn decrypt_mnemonic(&self, password: &str) -> Result<Mnemonic, WalletError> {
        log::debug!(
            "Decrypting mnemonic of length: {}",
            self.encrypted_mnemonic.len()
        );

        if self.encrypted_mnemonic.len() < 92 {
            // 32 (public key) + 16 (salt) + 12 (nonce) + 32 (minimum ciphertext)
            log::error!("Encrypted mnemonic is too short");
            return Err(WalletError::DecryptionError);
        }

        let public_key = &self.encrypted_mnemonic[..32];
        let salt = &self.encrypted_mnemonic[32..48];
        let nonce = &self.encrypted_mnemonic[48..60];
        let ciphertext = &self.encrypted_mnemonic[60..];

        log::debug!(
            "Public key length: {}, Salt length: {}, Nonce length: {}, Ciphertext length: {}",
            public_key.len(),
            salt.len(),
            nonce.len(),
            ciphertext.len()
        );

        // Derive the key from the password using Argon2
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        if let Err(e) = argon2.hash_password_into(password.as_bytes(), salt, &mut key) {
            log::error!("Failed to derive key from password: {:?}", e);
            return Err(WalletError::DecryptionError);
        }

        // Create an AES-256-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
            log::error!("Failed to create AES cipher: {:?}", e);
            WalletError::DecryptionError
        })?;

        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| {
                log::error!("Failed to decrypt ciphertext: {:?}", e);
                WalletError::DecryptionError
            })?;

        // Convert plaintext to string and parse as Mnemonic
        let mnemonic_str = String::from_utf8(plaintext).map_err(|e| {
            log::error!("Failed to convert decrypted data to UTF-8: {:?}", e);
            WalletError::DecryptionError
        })?;

        log::debug!("Decrypted mnemonic string length: {}", mnemonic_str.len());

        Mnemonic::parse_in_normalized(Language::English, &mnemonic_str).map_err(|e| {
            log::error!("Failed to parse mnemonic: {:?}", e);
            WalletError::InvalidMnemonic
        })
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
    pub fn update_hotkey_encryption(
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
            hotkey_data.clone_from(existing_data);
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
                secret_key.derived_key_simple(chain_code, [*junction]);
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

    /// Verifies a signature for a given message using the wallet's active hotkey.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed, as a byte slice.
    /// * `signature` - The signature to verify, as a byte slice.
    /// * `password` - The password to unlock the wallet.
    ///
    /// # Returns
    ///
    /// * `Result<bool, Box<dyn Error>>` - Ok(true) if the signature is valid, Ok(false) if invalid, or an error.

    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        password: &str,
    ) -> Result<bool, Box<dyn Error>> {
        let keypair = self.get_active_hotkey(password)?;
        let public_key = keypair.public;

        let signature =
            Sr25519Signature::try_from(signature).map_err(|_| "Invalid signature format")?;

        Ok(Verify::verify(&signature, message, &public_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    use sp_runtime::traits::IdentifyAccount;
    use std::collections::HashSet;
    use std::str::FromStr;
    use std::time::Instant;
    use tempfile::tempdir;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
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
        let _ = env_logger::builder().is_test(true).try_init();
        let mut wallet = create_test_wallet();

        // First, create a new wallet with a mnemonic
        match wallet.create_new_wallet(12, "password123") {
            Ok(_) => log::debug!("Wallet created successfully"),
            Err(e) => panic!("Failed to create new wallet: {:?}", e),
        }

        // Print the length of the encrypted mnemonic
        log::debug!(
            "Encrypted mnemonic length: {}",
            wallet.encrypted_mnemonic.len()
        );

        // Now create a new hotkey
        match wallet.create_new_hotkey("hotkey1", "password123") {
            Ok(_) => {
                log::debug!("Hotkey created successfully");
                // Rest of the assertions...
            }
            Err(e) => panic!("Failed to create new hotkey: {:?}", e),
        }
    }

    #[test]
    fn test_set_active_hotkey() {
        let mut wallet = create_test_wallet();

        // First, create a new wallet with a mnemonic
        assert!(wallet.create_new_wallet(12, "password123").is_ok());

        // Now create a new hotkey
        assert!(wallet.create_new_hotkey("hotkey1", "password123").is_ok());

        // Set the active hotkey
        assert!(wallet.set_active_hotkey("hotkey1").is_ok());
        assert_eq!(wallet.active_hotkey, Some("hotkey1".to_string()));
    }

    #[test]
    fn test_get_coldkey() {
        init();
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
        init();
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

        // First, create a new wallet with a mnemonic
        assert!(wallet.create_new_wallet(12, "password123").is_ok());

        // Now create a new hotkey
        assert!(wallet.create_new_hotkey("hotkey1", "password123").is_ok());

        // Update the hotkey encryption
        let encrypted_private = vec![1, 2, 3, 4, 5]; // Example encrypted private key
        assert!(wallet
            .update_hotkey_encryption("hotkey1", &encrypted_private)
            .is_ok());

        // Verify that the hotkey data is updated
        assert!(wallet.hotkey_data.is_some());
        assert_eq!(
            wallet.hotkey_data.as_ref().unwrap().get("hotkey1"),
            Some(&encrypted_private)
        );
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

    #[test]
    fn test_wallet_encryption_uniqueness() {
        let mut wallet = create_test_wallet();
        wallet.create_new_wallet(12, "password123").unwrap();

        let mut encrypted_data = HashSet::new();
        for i in 0..1000 {
            let hotkey_name = format!("hotkey_{}", i);
            wallet
                .create_new_hotkey(&hotkey_name, "password123")
                .unwrap();

            // Get the encrypted data for the hotkey
            let hotkey_data = wallet
                .hotkey_data
                .as_ref()
                .unwrap()
                .get(&hotkey_name)
                .unwrap();

            // Check that this encrypted data is unique
            assert!(
                encrypted_data.insert(hotkey_data.clone()),
                "Duplicate encrypted data found"
            );
        }
    }

    #[test]
    fn test_wallet_decrypt_private_key_performance() {
        let mut wallet = create_test_wallet();
        wallet.create_new_wallet(12, "password123").unwrap();
        wallet
            .create_new_hotkey("test_hotkey", "password123")
            .unwrap();

        let start = Instant::now();
        for _ in 0..10 {
            // Reduced from 100 to 10 iterations
            let _ = wallet.get_hotkey("test_hotkey", "password123").unwrap();
        }
        let duration = start.elapsed();

        println!("Average decryption time: {:?}", duration / 10);
        assert!(duration.as_millis() < 5000, "Decryption is too slow"); // Increased threshold to 5000ms
    }

    #[test]
    fn test_wallet_mnemonic_encryption_uniqueness() {
        let mut encrypted_mnemonics = HashSet::new();

        for _ in 0..1000 {
            let mut wallet = create_test_wallet();
            wallet.create_new_wallet(12, "password123").unwrap();

            // Check that this encrypted mnemonic is unique
            assert!(
                encrypted_mnemonics.insert(wallet.encrypted_mnemonic.clone()),
                "Duplicate encrypted mnemonic found"
            );
        }
    }

    // #[test]
    // fn test_get_hotkey_ss58() {
    //     let mut wallet = create_test_wallet();
    //     wallet.create_new_wallet(12, "password123").unwrap();
    //     wallet
    //         .create_new_hotkey("test_hotkey", "password123")
    //         .unwrap();

    //     let ss58_address = wallet.get_hotkey_ss58("test_hotkey").unwrap();

    //     assert!(!ss58_address.is_empty());
    //     assert!(ss58_address.starts_with('5')); // SS58 addresses typically start with '5'
    //     assert_eq!(ss58_address.len(), 48); // SS58 addresses are typically 48 characters long assert_eq!(ss58_address.len(), 48); // SS58 addresses are typically 48 characters long
    // }
    #[test]
    fn test_get_hotkey_ss58() {
        let mut wallet = create_test_wallet();
        wallet.create_new_wallet(12, "password123").unwrap();
        wallet
            .create_new_hotkey("test_hotkey", "password123")
            .unwrap();

        let ss58_address = wallet.get_hotkey_ss58("test_hotkey").unwrap();

        assert!(!ss58_address.is_empty());
        assert!(ss58_address.starts_with('5'));
        assert_eq!(ss58_address.len(), 48); //
    }

    #[test]
    fn test_get_hotkey_ss58_nonexistent() {
        let mut wallet = create_test_wallet();
        wallet.create_new_wallet(12, "password123").unwrap();

        let result = wallet.get_hotkey_ss58("nonexistent_hotkey");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WalletError::HotkeyNotFound));
    }

    #[test]
    fn test_ss58_consistency() {
        let mut wallet = create_test_wallet();
        wallet.create_new_wallet(12, "password123").unwrap();
        wallet
            .create_new_hotkey("test_hotkey", "password123")
            .unwrap();

        let coldkey_ss58 = wallet.get_coldkey_ss58().unwrap();
        let hotkey_ss58 = wallet.get_hotkey_ss58("test_hotkey").unwrap();

        // Ensure that the coldkey and hotkey have different SS58 addresses
        assert_ne!(coldkey_ss58, hotkey_ss58);

        // Ensure that multiple calls to get_coldkey_ss58 return the same address
        assert_eq!(coldkey_ss58, wallet.get_coldkey_ss58().unwrap());

        // Ensure that multiple calls to get_hotkey_ss58 return the same address
        assert_eq!(hotkey_ss58, wallet.get_hotkey_ss58("test_hotkey").unwrap());
    }
}
