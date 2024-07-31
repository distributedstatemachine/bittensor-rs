use crate::errors::WalletError;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;

use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use sp_runtime::traits::IdentifyAccount;

// use errors::WalletError;

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub fn decrypt_private_key(&self, password: &str) -> Result<sr25519::Pair, WalletError> {
        if self.encrypted_private.is_empty() {
            return Err(WalletError::NoEncryptedPrivateKey);
        }

        // Extract salt, nonce, and ciphertext
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

        // Create the sr25519::Pair from the decrypted private key
        sr25519::Pair::from_seed_slice(&plaintext).map_err(|_| WalletError::InvalidPrivateKey)
    }

    // pub fn sign(&self, message: &[u8], password: &str) -> Result<SchnorrkelSignature, WalletError> {
    //     let pair = self.decrypt_private_key(password)?;
    //     let signature: sr25519::Signature = pair.sign(message);
    //     SchnorrkelSignature::from_bytes(signature.as_ref())
    //         .map_err(|_| WalletError::SignatureConversionError)
    // }

    pub fn sign(&self, message: &[u8], password: &str) -> Result<sr25519::Signature, WalletError> {
        let pair = self.decrypt_private_key(password)?;
        Ok(pair.sign(message))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde::Serialize;
    use sp_core::ByteArray;
    use sp_core::Pair as TraitPair;
    use sp_runtime::traits::IdentifyAccount;
    use std::time::Instant;

    // Helper function to create a test keypair
    fn create_test_keypair() -> (Keypair, String) {
        let password = "test_password";
        let (pair, _) = sr25519::Pair::generate();
        let public = pair.public();
        let private = pair.to_raw_vec();

        // Encrypt the private key
        let salt = [0u8; 16];
        let nonce = [0u8; 12];
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), private.as_slice())
            .unwrap();

        let mut encrypted_private = Vec::new();
        encrypted_private.extend_from_slice(&salt);
        encrypted_private.extend_from_slice(&nonce);
        encrypted_private.extend_from_slice(&ciphertext);

        (
            Keypair::new(public, encrypted_private),
            password.to_string(),
        )
    }

    /// Tests the creation of a new keypair with a random password.
    #[test]
    fn test_new_keypair() {
        // Create a new test keypair
        let (keypair, _): (Keypair, String) = create_test_keypair();

        // Assert that the public key is not empty and has the correct length
        assert!(
            !<sp_core::sr25519::Public as AsRef<[u8]>>::as_ref(&keypair.public).is_empty(),
            "Public key should not be empty"
        );
        assert_eq!(
            <sp_core::sr25519::Public as AsRef<[u8]>>::as_ref(&keypair.public).len(),
            32,
            "Public key should be 32 bytes long"
        );

        // Assert that the encrypted private key is not empty and has a minimum expected length
        assert!(
            !keypair.encrypted_private.is_empty(),
            "Encrypted private key should not be empty"
        );
        assert!(
            keypair.encrypted_private.len() > 28,
            "Encrypted private key should be longer than 28 bytes (16 bytes salt + 12 bytes nonce + ciphertext)"
        );

        // Verify that the public key is a valid Sr25519 public key
        assert!(
            sp_core::sr25519::Public::from_slice(
                <sp_core::sr25519::Public as AsRef<[u8]>>::as_ref(&keypair.public)
            )
            .is_ok(),
            "Public key should be a valid Sr25519 public key"
        );
    }
    #[test]
    fn test_decrypt_private_key_empty_encrypted_private() {
        let keypair = Keypair::new(sr25519::Public::from_raw([0u8; 32]), Vec::new());
        let result = keypair.decrypt_private_key("password");
        assert!(result.is_err());

        match result {
            Err(WalletError::NoEncryptedPrivateKey) => {}
            _ => panic!("Expected NoEncryptedPrivateKey error"),
        }
    }

    #[test]
    fn test_decrypt_private_key_wrong_password() {
        let (keypair, _) = create_test_keypair();
        let result = keypair.decrypt_private_key("wrong_password");
        assert!(result.is_err());

        match result {
            Err(WalletError::DecryptionError) => {}
            Err(WalletError::InvalidPrivateKey) => {}
            _ => panic!("Expected DecryptionError or InvalidPrivateKey error"),
        }
    }

    #[test]
    fn test_sign_success() {
        let (keypair, password) = create_test_keypair();
        let message = b"test message";
        let result = keypair.sign(message, &password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_wrong_password() {
        let (keypair, _) = create_test_keypair();
        let message = b"test message";
        let result = keypair.sign(message, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_identify_account() {
        let (keypair, _) = create_test_keypair();
        let account_id: sp_runtime::AccountId32 = keypair.clone().into_account();
        assert_eq!(account_id, sp_runtime::AccountId32::new(keypair.public.0));
    }

    #[test]
    fn test_keypair_debug() {
        let (keypair, _) = create_test_keypair();
        let debug_output = format!("{:?}", keypair);
        assert!(debug_output.contains("Keypair"));
        assert!(debug_output.contains("public"));
        assert!(debug_output.contains("encrypted_private"));
    }

    #[test]
    fn test_keypair_clone() {
        let (keypair, _) = create_test_keypair();
        let cloned_keypair = keypair.clone();
        assert_eq!(keypair.public, cloned_keypair.public);
        assert_eq!(keypair.encrypted_private, cloned_keypair.encrypted_private);
    }

    #[test]
    fn test_invalid_public_key() {
        let invalid_public = [0u8; 31]; // Invalid length (31 bytes instead of 32)
        let mut extended_invalid_public = [0u8; 32];
        extended_invalid_public[..31].copy_from_slice(&invalid_public);
        let result = Keypair::new(sr25519::Public::from_raw(extended_invalid_public), vec![]);

        // The public key will be 32 bytes, but it's not a valid sr25519 public key
        assert_eq!(
            <sp_core::sr25519::Public as AsRef<[u8]>>::as_ref(&result.public).len(),
            32
        );

        // You might want to add additional checks here to ensure the key is actually invalid
        // This depends on how your Keypair::new function handles invalid keys
    }
    #[test]
    fn test_password_length_limits() {
        let (keypair, _) = create_test_keypair();

        // Test empty password
        assert!(keypair.decrypt_private_key("").is_err());

        // Test very long password (e.g., 1MB)
        let long_password = "a".repeat(1_000_000);
        let result = keypair.decrypt_private_key(&long_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_empty_message() {
        let (keypair, password) = create_test_keypair();
        let result = keypair.sign(&[], &password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_large_message() {
        let (keypair, password) = create_test_keypair();
        let large_message = vec![0u8; 1_000_000]; // 1MB message
        let result = keypair.sign(&large_message, &password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_encrypted_private_key_tampering() {
        let (mut keypair, password) = create_test_keypair();

        // Tamper with the encrypted private key
        keypair.encrypted_private[20] ^= 0xFF;

        let result = keypair.decrypt_private_key(&password);
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_serialization() {
        let (keypair, _) = create_test_keypair();

        // Serialize
        let serialized = bincode::serialize(&keypair).expect("Serialization failed");

        // Deserialize
        let deserialized: Keypair =
            bincode::deserialize(&serialized).expect("Deserialization failed");

        assert_eq!(keypair.public, deserialized.public);
        assert_eq!(keypair.encrypted_private, deserialized.encrypted_private);
    }

    #[test]
    fn test_keypair_with_pregenerated_keys() {
        let (pair, _) = sr25519::Pair::generate();
        let public = pair.public();
        let private = pair.to_raw_vec();

        // Encrypt the private key (simplified for brevity)
        let encrypted_private = private.clone(); // In reality, this should be properly encrypted

        let keypair = Keypair::new(public, encrypted_private);

        assert_eq!(keypair.public, public);
        assert_eq!(keypair.encrypted_private, private);
    }

    #[test]
    fn test_sign_various_message_types() {
        let (keypair, password) = create_test_keypair();

        // Sign a string
        let string_message = "Hello, world!";
        assert!(keypair.sign(string_message.as_bytes(), &password).is_ok());

        // Sign an integer
        let int_message = 42u64.to_le_bytes();
        assert!(keypair.sign(&int_message, &password).is_ok());

        // Sign a struct
        #[derive(Default, Serialize, Deserialize)]
        struct TestStruct {
            a: u32,
            b: [u8; 10],
        }
        let struct_message = TestStruct::default();
        let struct_bytes = bincode::serialize(&struct_message).unwrap();
        assert!(keypair.sign(&struct_bytes, &password).is_ok());
    }

    #[test]
    fn test_key_derivation_function_parameters() {
        let password = "test_password";
        let salt = [0u8; 16];
        let mut key = [0u8; 32];

        // Test with default parameters
        let start = Instant::now();
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .unwrap();
        let default_duration = start.elapsed();

        // Test with custom parameters (increase memory and iterations)
        let custom_argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 10, 4, None).unwrap(),
        );
        let start = Instant::now();
        custom_argon2
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .unwrap();
        let custom_duration = start.elapsed();

        // Custom parameters should take longer
        assert!(custom_duration > default_duration);
    }

    #[test]
    fn test_identify_account_with_different_public_key_types() {
        // Test with sr25519 public key
        let (sr25519_keypair, _) = create_test_keypair();
        let sr25519_account_id: sp_runtime::AccountId32 = sr25519_keypair.clone().into_account();
        assert_eq!(
            sr25519_account_id,
            sp_runtime::AccountId32::new(sr25519_keypair.public.0)
        );

        // Test with ed25519 public key
        let ed25519_pair = sp_core::ed25519::Pair::generate().0;
        let ed25519_public = ed25519_pair.public();
        let ed25519_keypair = Keypair::new(sr25519::Public::from_raw(ed25519_public.0), vec![]);
        let ed25519_account_id: sp_runtime::AccountId32 = ed25519_keypair.into_account();
        assert_eq!(
            ed25519_account_id,
            sp_runtime::AccountId32::new(ed25519_public.0)
        );
    }

    #[test]
    fn test_clone_deep_equality() {
        let (original_keypair, _) = create_test_keypair();
        let cloned_keypair = original_keypair.clone();

        assert_eq!(original_keypair.public, cloned_keypair.public);
        assert_eq!(
            original_keypair.encrypted_private,
            cloned_keypair.encrypted_private
        );

        // Ensure modifying the clone doesn't affect the original
        let mut modified_clone = cloned_keypair;
        modified_clone.encrypted_private[0] ^= 0xFF;

        assert_ne!(
            original_keypair.encrypted_private,
            modified_clone.encrypted_private
        );
    }
}
