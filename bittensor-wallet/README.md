# Bittensor Wallet

Bittensor Wallet is a Rust crate that provides wallet functionality for the Bittensor network. It includes features for managing wallets, keypairs, and integrates with Python through PyO3 bindings.

## Architecture

The crate is structured into several key components:

1. **Wallet**: The main struct that handles wallet operations such as creation, key management, and encryption.
2. **Keypair**: Manages cryptographic keypairs, including signing and encryption.
3. **Error Handling**: Custom error types for wallet-specific errors.
4. **Python Bindings**: Allows the wallet functionality to be used from Python.

Key files:
- `src/wallet.rs`: Contains the `Wallet` struct and its implementations.
- `src/keypair.rs`: Implements the `Keypair` struct for cryptographic operations.
- `src/errors.rs`: Defines custom error types.
- `src/python_bindings.rs`: Implements Python bindings using PyO3.

## Using the Python Bindings

This project uses Maturin to build and manage Python bindings. To use the Bittensor Wallet in Python:

1. Install Maturin:
   ```
   pip install maturin
   ```

2. Build the Python module:
   ```
   maturin develop
   ```

3. In your Python code:
   ```python
   import bittensor_wallet
   
   # Create a new wallet
   wallet = bittensor_wallet.PyWallet("my_wallet", "/path/to/wallet")
   
   # Create a new wallet with a mnemonic
   wallet.create_new_wallet(12, "my_password")
   
   # Create a new hotkey
   wallet.create_new_hotkey("my_hotkey", "my_password")
   
   # Get the coldkey
   coldkey = wallet.get_coldkey("my_password")
   
   # Get a hotkey
   hotkey = wallet.get_hotkey("my_hotkey", "my_password")
   
   # Sign a message
   message = b"Hello, Bittensor!"
   signature = hotkey.sign(message, "my_password")
   ```

## Building and Testing

To build the crate:
```
cargo build
```

To run tests:
```
cargo test
```

## Dependencies

This crate relies on several key dependencies:
- `pyo3`: For Python bindings
- `sp-core` and `sp-runtime`: For Substrate-based cryptography
- `aes-gcm` and `argon2`: For encryption and key derivation
- `bip39`: For mnemonic generation and handling

For a full list of dependencies, please refer to the `Cargo.toml` file.
