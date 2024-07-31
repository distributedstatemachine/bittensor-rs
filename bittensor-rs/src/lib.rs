#[macro_use]
extern crate lazy_static;
use log::info;
use scale_info::prelude::vec::Vec;
use sp_std::prelude::*;
use std::str::FromStr;
use std::sync::Arc;
use subxt::utils::AccountId32;

use codec::Decode;
use scale_info::prelude::any::TypeId;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Mutex;
use subxt::backend::rpc::RpcClient;
use subxt::backend::rpc::RpcParams;
use subxt::dynamic::Value as DynamicValue;
use subxt::ext::sp_core::H256;
use subxt::ext::sp_core::{sr25519, Pair};
use subxt::metadata::DecodeWithMetadata;
use subxt::metadata::EncodeWithMetadata;
use subxt::runtime_api::RuntimeApiClient;
use subxt::tx::PairSigner;
use subxt::{OnlineClient, SubstrateConfig};

// pub mod delegates;
pub mod neurons;
pub mod root;
pub mod subnets;

pub mod errors;
use errors::SubtensorError;

lazy_static! {
    static ref TYPE_MAP: Mutex<HashMap<TypeId, u32>> = Mutex::new(HashMap::new());
}

/// Gets or assigns a unique identifier for a given TypeId.
///
/// This function is used internally to manage type identifiers for encoding and decoding
/// purposes. It ensures that each unique TypeId is associated with a unique u32 value.
///
/// # Arguments
///
/// * `type_id` - The TypeId for which to get or assign an identifier.
///
/// # Returns
///
/// A u32 value representing the unique identifier for the given TypeId.
fn get_type_id(type_id: TypeId) -> u32 {
    let mut map = TYPE_MAP.lock().unwrap();
    let len = map.len();
    *map.entry(type_id).or_insert_with(|| len as u32)
}

#[async_trait::async_trait]
/// Trait defining interactions with a blockchain.
///
/// This trait provides methods for submitting extrinsics, fetching storage,
/// calling runtime APIs, and performing RPC calls on a blockchain network.
/// Implementations of this trait should handle the specifics of interacting
/// with  Subtensor.
pub trait ChainInteraction {
    /// Submits an extrinsic to the blockchain.
    ///
    /// This method signs and submits an extrinsic (a call to the blockchain)
    /// and waits for it to be included in a block.
    ///
    /// # Arguments
    ///
    /// * `call` - The payload of the extrinsic to be submitted.
    ///
    /// # Returns
    ///
    /// A Result containing () if successful, or an SubtensorError if the submission fails.
    async fn submit_extrinsic(
        &self,
        call: impl subxt::tx::Payload + Send + Sync + 'static,
    ) -> Result<(), SubtensorError>;

    /// Fetches storage from the blockchain.
    ///
    /// This method retrieves data from the blockchain's storage based on the provided address.
    ///
    /// # Arguments
    ///
    /// * `address` - The storage address to fetch data from.
    ///
    /// # Returns
    ///
    /// A Result containing an Option<T> if successful (None if the storage is empty),
    /// or an SubtensorError if the fetch fails.
    async fn fetch_storage<T>(
        &self,
        address: impl subxt::storage::Address<IsFetchable = subxt::custom_values::Yes, Target = T>
            + Send
            + Sync,
    ) -> Result<Option<T>, SubtensorError>
    where
        T: DecodeWithMetadata + Send + 'static;

    /// Calls a runtime API method on the blockchain.
    ///
    /// This method allows interaction with custom runtime APIs defined in the blockchain.
    ///
    /// # Arguments
    ///
    /// * `method` - The name of the runtime API method to call.
    /// * `params` - A vector of dynamic values representing the parameters for the method call.
    ///
    /// # Returns
    ///
    /// A Result containing the decoded return value of type T if successful,
    /// or an SubtensorError if the call fails.
    async fn call_runtime_api<T>(
        &self,
        method: &str,
        params: Vec<subxt::dynamic::Value>,
    ) -> Result<T, SubtensorError>
    where
        T: DecodeWithMetadata + Decode + Send + 'static;

    /// Performs an RPC call to the blockchain node.
    ///
    /// This method allows making raw RPC calls to the blockchain node.
    ///
    /// # Arguments
    ///
    /// * `method` - The name of the RPC method to call.
    /// * `params` - The parameters for the RPC call.
    ///
    /// # Returns
    ///
    /// A Result containing the deserialized return value of type T if successful,
    /// or an SubtensorError if the call fails.
    async fn call_rpc<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: RpcParams,
    ) -> Result<T, SubtensorError>;
}

/// Represents a connection to the Subtensor blockchain.
///
/// This struct provides methods to interact with the Subtensor blockchain,
/// including submitting transactions, querying storage, and making RPC calls.
/// It encapsulates the necessary components for secure and efficient blockchain interactions.
pub struct Subtensor {
    client: Arc<OnlineClient<SubstrateConfig>>,
    signer: Arc<PairSigner<SubstrateConfig, sr25519::Pair>>,
    api: RuntimeApiClient<SubstrateConfig, OnlineClient<SubstrateConfig>>,
    rpc: RpcClient,
}

impl Subtensor {
    /// Creates a new Subtensor instance.
    ///
    /// This method establishes a connection to the Subtensor blockchain and sets up
    /// the necessary components for interaction.
    ///
    /// # Arguments
    ///
    /// * `chain_endpoint` - The WebSocket URL of the Subtensor node (e.g., "ws://localhost:9944").
    /// * `coldkey` - The coldkey (private key) used for signing transactions. This should be a valid SS58-encoded private key.
    ///
    /// # Returns
    ///
    /// A Result containing a new Subtensor instance if successful,
    /// or a SubtensorError if the connection or setup fails.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The connection to the specified chain_endpoint fails.
    /// - The provided coldkey is invalid or cannot be used to create a signer.
    pub async fn new(chain_endpoint: &str, coldkey: &str) -> Result<Self, SubtensorError> {
        let client = OnlineClient::<SubstrateConfig>::from_url(chain_endpoint)
            .await
            .map_err(|e| SubtensorError::ConnectionError(e.to_string()))?;

        let coldkey_pair = sr25519::Pair::from_string(coldkey, None)
            .map_err(|_| SubtensorError::InvalidInput("Invalid coldkey format".into()))?;

        let signer = PairSigner::new(coldkey_pair);
        let api = client.runtime_api();
        let rpc = RpcClient::from_url(chain_endpoint)
            .await
            .map_err(|e| SubtensorError::ConnectionError(e.to_string()))?;

        Ok(Self {
            client: Arc::new(client),
            signer: Arc::new(signer),
            api,
            rpc,
        })
    }

    /// Fetches the balance for a given SS58 address.
    ///
    /// # Arguments
    ///
    /// * `ss58_address` - The SS58 encoded address to fetch the balance for.
    ///
    /// # Returns
    ///
    /// * `Result<f64, SubtensorError>` - The balance as a f64 representing TAO tokens,
    ///   or an error if the balance couldn't be fetched or decoded.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The provided SS58 address is invalid.
    /// - The account information cannot be fetched from the blockchain.
    /// - The account data cannot be decoded.
    ///
    /// # Example
    ///
    /// ```
    /// let balance = subtensor.fetch_balance("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").await?;
    /// println!("Balance: {} TAO", balance);
    /// ```
    pub async fn fetch_balance(&self, ss58_address: &str) -> Result<f64, SubtensorError> {
        // Convert SS58 address to AccountId32
        let account_id = AccountId32::from_str(ss58_address)
            .map_err(|_| SubtensorError::InvalidInput("Invalid SS58 address".into()))?;

        // Convert AccountId32 to subxt::dynamic::Value
        let account_id_value =
            DynamicValue::from_bytes(<AccountId32 as AsRef<[u8]>>::as_ref(&account_id));

        // Fetch the account info using the existing storage query mechanism
        let account_info = self
            .fetch_storage(subxt::dynamic::storage(
                "System",
                "Account",
                vec![account_id_value],
            ))
            .await?
            .ok_or(SubtensorError::NotFound("Account not found".into()))?;

        // Decode the account info
        let account_data: AccountData<u128> = AccountData::decode(&mut account_info.encoded())
            .map_err(|_| SubtensorError::DecodingError("Failed to decode account data".into()))?;

        // Extract the free balance from the account data
        let free_balance = account_data.free;

        // Convert from Planck to Tao
        let balance = free_balance as f64 / 1_000_000_000_000.0;

        Ok(balance)
    }
}

#[async_trait::async_trait]
impl ChainInteraction for Subtensor {
    /// Submits an extrinsic to the Subtensor blockchain.
    ///
    /// This method signs the provided call with the instance's signer,
    /// submits it to the blockchain, and waits for it to be included in a block.
    ///
    /// # Arguments
    ///
    /// * `call` - The payload of the extrinsic to be submitted.
    ///
    /// # Returns
    ///
    /// A Result containing () if the extrinsic is successfully included in a block,
    /// or an SubtensorError if the submission or inclusion fails.
    async fn submit_extrinsic(
        &self,
        call: impl subxt::tx::Payload + Send + Sync + 'static,
    ) -> Result<(), SubtensorError> {
        let result = self
            .client
            .tx()
            .sign_and_submit_then_watch(&call, &*self.signer, Default::default())
            .await?
            .wait_for_finalized_success()
            .await?;

        info!(
            "🎯 Extrinsic successful at block {}.",
            result.extrinsic_hash()
        );

        Ok(())
    }

    /// Fetches storage from the Subtensor blockchain.
    ///
    /// This method retrieves data from the blockchain's storage at the latest block.
    ///
    /// # Arguments
    ///
    /// * `address` - The storage address to fetch data from.
    ///
    /// # Returns
    ///
    /// A Result containing an Option<T> if successful (None if the storage is empty),
    /// or an SubtensorError if the fetch fails.
    async fn fetch_storage<T>(
        &self,
        address: impl subxt::storage::Address<IsFetchable = subxt::custom_values::Yes, Target = T>
            + Send
            + Sync,
    ) -> Result<Option<T>, SubtensorError>
    where
        T: DecodeWithMetadata + Send + 'static,
    {
        let value = self
            .client
            .storage()
            .at_latest()
            .await?
            .fetch(&address)
            .await?;

        Ok(value)
    }

    /// Calls a runtime API method on the Subtensor blockchain.
    ///
    /// This method encodes the provided parameters, makes a call to the specified
    /// runtime API method, and decodes the result.
    ///
    /// # Arguments
    ///
    /// * `method` - The name of the runtime API method to call.
    /// * `params` - A vector of dynamic values representing the parameters for the method call.
    ///
    /// # Returns
    ///
    /// A Result containing the decoded return value of type T if successful,
    /// or an SubtensorError if the call or decoding fails.
    async fn call_runtime_api<T>(
        &self,
        method: &str,
        params: Vec<subxt::dynamic::Value>,
    ) -> Result<T, SubtensorError>
    where
        T: Decode + Send + 'static,
    {
        let block_hash: H256 = self
            .rpc
            .request("chain_getFinalizedHead", RpcParams::new())
            .await?;

        let runtime_api = self.api.at(block_hash);

        let metadata = self.client.metadata();

        let params_bytes = params
            .iter()
            .map(|v| {
                let type_id = get_type_id(v.type_id());
                let mut buffer = Vec::new();
                v.encode_with_metadata(type_id, &metadata, &mut buffer)?;
                Ok(buffer)
            })
            .collect::<Result<Vec<Vec<u8>>, SubtensorError>>()?;
        let flat_params: Vec<u8> = params_bytes.into_iter().flatten().collect();

        let result_bytes: Vec<u8> = runtime_api.call_raw(method, Some(&flat_params)).await?;

        let result = T::decode(&mut &result_bytes[..])
            .map_err(|e| SubtensorError::DecodingError(e.to_string()))?;

        Ok(result)
    }

    /// Performs an RPC call to the Subtensor blockchain node.
    ///
    /// This method makes a raw RPC call to the connected Subtensor node.
    ///
    /// # Arguments
    ///
    /// * `method` - The name of the RPC method to call.
    /// * `params` - The parameters for the RPC call.
    ///
    /// # Returns
    ///
    /// A Result containing the deserialized return value of type T if successful,
    /// or an SubtensorError if the call fails.
    async fn call_rpc<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: RpcParams,
    ) -> Result<T, SubtensorError> {
        self.rpc
            .request(method, params)
            .await
            .map_err(|e| SubtensorError::RpcError(e.to_string()))
    }
}

// Define the AccountData struct to match the structure of the account info in storage
#[derive(Decode)]
struct AccountData<Balance> {
    free: Balance,
    _reserved: Balance,
    _misc_frozen: Balance,
    _fee_frozen: Balance,
}
