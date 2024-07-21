# bittensor-rs

bittensor-rs is a Rust library for interacting with the Bittensor blockchain. It provides a high-level interface for submitting extrinsics, querying storage, and making RPC calls to a Subtensor node.

## Features

- Connect to a Bittensor node
- Submit extrinsics to the blockchain
- Query blockchain storage
- Make runtime API calls
- Perform RPC requests
- Fetch account balances

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
bittensor-rs = "0.1.0"
```

## Usage

Here's a basic example of how to use bittensor-rs:

```rust
use bittensor_rs::{Subtensor, ChainInteraction};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let chain_endpoint = "ws://localhost:9944";
    let coldkey = "your_coldkey_here";

    let subtensor = Subtensor::new(chain_endpoint, coldkey).await?;

    // Fetch balance
    let balance = subtensor.fetch_balance("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").await?;
    println!("Balance: {}", balance);

    // More interactions...

    Ok(())
}
```

## API Reference

For detailed API documentation, please refer to the [docs.rs](https://docs.rs/bittensor-rs) page.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Disclaimer

This project is in early development and may contain bugs or incomplete features. Use at your own risk.
