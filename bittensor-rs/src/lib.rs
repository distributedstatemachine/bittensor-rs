#[macro_use]
extern crate lazy_static;
use log::info;
use std::sync::Arc;

use codec::Decode;
use scale_info::prelude::any::TypeId;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Mutex;
use subxt::backend::rpc::RpcClient;
use subxt::backend::rpc::RpcParams;
use subxt::ext::sp_core::H256;
use subxt::ext::sp_core::{sr25519, Pair};
use subxt::metadata::DecodeWithMetadata;
use subxt::metadata::EncodeWithMetadata;
use subxt::runtime_api::RuntimeApiClient;
use subxt::tx::PairSigner;
use subxt::{OnlineClient, SubstrateConfig};

pub mod neurons;
pub mod subnets;
pub mod wallet;

pub mod errors;
use errors::AppError;

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
    /// A Result containing () if successful, or an AppError if the submission fails.
    async fn submit_extrinsic(
        &self,
        call: impl subxt::tx::Payload + Send + Sync + 'static,
    ) -> Result<(), AppError>;

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
    /// or an AppError if the fetch fails.
    async fn fetch_storage<T>(
        &self,
        address: impl subxt::storage::Address<IsFetchable = subxt::custom_values::Yes, Target = T>
            + Send
            + Sync,
    ) -> Result<Option<T>, AppError>
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
    /// or an AppError if the call fails.
    async fn call_runtime_api<T>(
        &self,
        method: &str,
        params: Vec<subxt::dynamic::Value>,
    ) -> Result<T, AppError>
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
    /// or an AppError if the call fails.
    async fn call_rpc<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: RpcParams,
    ) -> Result<T, AppError>;
}

/// Represents a connection to the Subtensor blockchain.
///
/// This struct provides methods to interact with the Subtensor blockchain,
/// including submitting transactions, querying storage, and making RPC calls.
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
    /// * `chain_endpoint` - The WebSocket URL of the Subtensor node.
    /// * `coldkey` - The coldkey (private key) used for signing transactions.
    ///
    /// # Returns
    ///
    /// A Result containing a new Subtensor instance if successful,
    /// or an AppError if the connection or setup fails.
    pub async fn new(chain_endpoint: &str, coldkey: &str) -> Result<Self, AppError> {
        let client = OnlineClient::<SubstrateConfig>::from_url(chain_endpoint)
            .await
            .map_err(|e| AppError::ConnectionError(e.to_string()))?;

        let coldkey_pair = sr25519::Pair::from_string(coldkey, None)
            .map_err(|_| AppError::InvalidInput("Invalid coldkey format".into()))?;

        let signer = PairSigner::new(coldkey_pair);
        let api = client.runtime_api();
        let rpc = RpcClient::from_url(chain_endpoint)
            .await
            .map_err(|e| AppError::ConnectionError(e.to_string()))?;

        Ok(Self {
            client: Arc::new(client),
            signer: Arc::new(signer),
            api,
            rpc,
        })
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
    /// or an AppError if the submission or inclusion fails.
    async fn submit_extrinsic(
        &self,
        call: impl subxt::tx::Payload + Send + Sync + 'static,
    ) -> Result<(), AppError> {
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
    /// or an AppError if the fetch fails.
    async fn fetch_storage<T>(
        &self,
        address: impl subxt::storage::Address<IsFetchable = subxt::custom_values::Yes, Target = T>
            + Send
            + Sync,
    ) -> Result<Option<T>, AppError>
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
    /// or an AppError if the call or decoding fails.
    async fn call_runtime_api<T>(
        &self,
        method: &str,
        params: Vec<subxt::dynamic::Value>,
    ) -> Result<T, AppError>
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
            .collect::<Result<Vec<Vec<u8>>, AppError>>()?;
        let flat_params: Vec<u8> = params_bytes.into_iter().flatten().collect();

        let result_bytes: Vec<u8> = runtime_api.call_raw(method, Some(&flat_params)).await?;

        let result = T::decode(&mut &result_bytes[..])
            .map_err(|e| AppError::DecodingError(e.to_string()))?;

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
    /// or an AppError if the call fails.
    async fn call_rpc<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: RpcParams,
    ) -> Result<T, AppError> {
        self.rpc
            .request(method, params)
            .await
            .map_err(|e| AppError::RpcError(e.to_string()))
    }
}
