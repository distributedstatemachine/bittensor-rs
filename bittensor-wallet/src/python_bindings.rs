use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::PathBuf;

use crate::errors::WalletError;
use crate::keypair::Keypair;
use crate::wallet::Wallet;
use pyo3::exceptions::{PyException, PyValueError};
use sp_core::crypto::Ss58Codec;

/// A Python module implemented in Rust.
#[pymodule]
fn bittensor_wallet(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyWallet>()?;
    m.add_class::<PyKeypair>()?;
    Ok(())
}

/// Python wrapper for the Wallet struct
#[pyclass]
struct PyWallet {
    wallet: Wallet,
}

#[pymethods]
impl PyWallet {
    #[new]
    fn new(name: &str, path: &str) -> Self {
        PyWallet {
            wallet: Wallet::new(name, PathBuf::from(path)),
        }
    }

    /// Creates a new wallet with the specified number of words and password.
    fn create_new_wallet(&mut self, n_words: u32, password: &str) -> PyResult<()> {
        self.wallet
            .create_new_wallet(n_words, password)
            .map_err(wallet_error_to_pyerr)
    }

    /// Creates a new hotkey with the specified name and password.
    fn create_new_hotkey(&mut self, name: &str, password: &str) -> PyResult<()> {
        self.wallet
            .create_new_hotkey(name, password)
            .map_err(wallet_error_to_pyerr)
    }

    /// Sets the active hotkey by name.
    fn set_active_hotkey(&mut self, name: &str) -> PyResult<()> {
        self.wallet
            .set_active_hotkey(name)
            .map_err(wallet_error_to_pyerr)
    }

    /// Retrieves the coldkey's public key.
    ///
    /// This function attempts to retrieve the coldkey's public key from the wallet.
    /// It requires the correct password to decrypt the coldkey.
    ///
    /// # Arguments
    ///
    /// * `py` - The Python interpreter's context.
    /// * `password` - A string slice containing the password to decrypt the coldkey.
    ///
    /// # Returns
    ///
    /// * `PyResult<&'py PyBytes>` - On success, returns the public key as PyBytes.
    ///                              On failure, returns a Python exception.
    ///
    /// ```
    fn get_coldkey<'py>(&self, py: Python<'py>, password: &str) -> PyResult<&'py PyBytes> {
        match self.wallet.get_coldkey(password) {
            Ok(public_key) => {
                // Convert the public key to bytes
                let key_bytes = public_key.to_vec();
                Ok(PyBytes::new(py, &key_bytes))
            }
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }

    // fn get_coldkey_ss58(&self) -> PyResult<String> {
    //     match self.wallet.get_coldkey_ss58() {
    //         Ok(ss58) => Ok(ss58),
    //         Err(error) => Err(PyValueError::new_err(error.to_string())),
    //     }
    // }

    /// Retrieves the active hotkey.
    fn get_active_hotkey<'py>(&self, py: Python<'py>, password: &str) -> PyResult<&'py PyBytes> {
        match self.wallet.get_active_hotkey(password) {
            Ok(keypair) => {
                let key_bytes = keypair.public.to_vec();
                Ok(PyBytes::new(py, &key_bytes))
            }
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }

    /// Regenerates the wallet from a mnemonic phrase.
    fn regenerate_wallet(&mut self, mnemonic: &str, password: &str) -> PyResult<()> {
        self.wallet
            .regenerate_wallet(mnemonic, password)
            .map_err(wallet_error_to_pyerr)
    }

    /// Changes the password of the wallet.
    #[pyo3(name = "change_password")]
    fn py_change_password<'py>(
        &mut self,
        py: Python<'py>,
        old_password: &str,
        new_password: &str,
    ) -> PyResult<&'py PyAny> {
        let mut wallet = self.wallet.clone();
        let old_password = old_password.to_string();
        let new_password = new_password.to_string();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            wallet
                .change_password(&old_password, &new_password)
                .await
                .map_err(wallet_error_to_pyerr)
        })
    }

    /// Retrieves the coldkey's SS58 address.
    fn get_coldkey_ss58(&self) -> PyResult<String> {
        self.wallet
            .get_coldkey_ss58()
            .map_err(wallet_error_to_pyerr)
    }

    /// Retrieves a hotkey's SS58 address.
    fn get_hotkey_ss58(&self, hotkey_name: &str) -> PyResult<String> {
        self.wallet
            .get_hotkey_ss58(hotkey_name)
            .map_err(wallet_error_to_pyerr)
    }

    /// Updates the encrypted private key for a specific hotkey.
    fn update_hotkey_encryption(&mut self, name: &str, encrypted_private: Vec<u8>) -> PyResult<()> {
        self.wallet
            .update_hotkey_encryption(name, &encrypted_private)
            .map_err(wallet_error_to_pyerr)
    }

    /// Fetches the balance for the wallet.
    fn fetch_balance<'py>(&mut self, py: Python<'py>) -> PyResult<&'py PyAny> {
        let mut wallet = self.wallet.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            wallet.fetch_balance().await.map_err(wallet_error_to_pyerr)
        })
    }
}

/// Python wrapper for the Keypair struct
#[pyclass]
struct PyKeypair {
    keypair: Keypair,
}

#[pymethods]
impl PyKeypair {
    fn sign(&self, message: &[u8], password: &str) -> PyResult<Vec<u8>> {
        self.keypair
            .sign(message, password)
            .map(|sig| sig.0.to_vec())
            .map_err(wallet_error_to_pyerr)
    }

    fn public_key(&self) -> Vec<u8> {
        self.keypair.public.to_vec()
    }

    fn ss58_address(&self) -> String {
        // Convert the public key to an SS58 address
        self.keypair.public.to_ss58check()
    }
}

impl From<Keypair> for PyKeypair {
    fn from(keypair: Keypair) -> Self {
        PyKeypair { keypair }
    }
}

fn wallet_error_to_pyerr(error: WalletError) -> PyErr {
    PyException::new_err(error.to_string())
}
