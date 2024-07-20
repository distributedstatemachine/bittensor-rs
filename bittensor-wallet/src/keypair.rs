use crate::errors::WalletError;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;

use schnorrkel::Signature as SchnorrkelSignature;
use sp_core::{sr25519, Pair};
use sp_runtime::traits::IdentifyAccount;

// use errors::WalletError;

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
