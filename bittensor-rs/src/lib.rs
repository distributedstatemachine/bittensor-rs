#[macro_use]
extern crate lazy_static;
use log::info;
use std::sync::Arc;
use subxt::backend::Backend;
use subxt::ext::scale_encode::EncodeAsType;
// use subxt::ext::scale_encode::EncodeError;

use subxt::backend::rpc::RpcClient;
use subxt::backend::rpc::RpcParams;
use subxt::ext::sp_core::H256;
use subxt::ext::sp_core::{sr25519, Pair};
// use subxt::metadata::types::TypeId;
use codec::Decode;
use scale_info::prelude::any::TypeId;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Mutex;
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

fn get_type_id(type_id: TypeId) -> u32 {
    let mut map = TYPE_MAP.lock().unwrap();
    let len = map.len();
    *map.entry(type_id).or_insert_with(|| len as u32)
}

#[async_trait::async_trait]
/// Trait defining interactions with a blockchain.
///
/// This trait provides methods for submitting extrinsics and fetching storage
/// from a blockchain.
///

#[async_trait::async_trait]
pub trait ChainInteraction {
    /// Submits an extrinsic to the blockchain.
    ///
    /// # Arguments
    ///
    /// * `call` - The extrinsic to submit, implementing `subxt::tx::TxPayload`.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an `AppError`.
    async fn submit_extrinsic(
        &self,
        call: impl subxt::tx::Payload + Send + Sync + 'static,
    ) -> Result<(), AppError>;

    /// Fetches storage from the blockchain.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type of data to decode from storage, must implement `codec::Decode`.
    ///
    /// # Arguments
    ///
    /// * `address` - The storage address to fetch from, implementing `subxt::storage::Address<T>`.
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<T>` or an `AppError`.
    async fn fetch_storage<T>(
        &self,
        address: impl subxt::storage::Address<IsFetchable = subxt::custom_values::Yes, Target = T>
            + Send
            + Sync,
    ) -> Result<Option<T>, AppError>
    where
        T: DecodeWithMetadata + Send + 'static;

    /// Calls a runtime API method.
    ///
    /// # Arguments
    ///
    /// * `method` - The name of the runtime API method to call.
    /// * `params` - The parameters to pass to the method.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decoded result or an `AppError`.
    async fn call_runtime_api<T>(
        &self,
        method: &str,
        params: Vec<subxt::dynamic::Value>,
    ) -> Result<T, AppError>
    where
        T: DecodeWithMetadata + Decode + Send + 'static;

    /// Performs an RPC call.
    ///
    /// # Arguments
    ///
    /// * `method` - The name of the RPC method to call.
    /// * `params` - The parameters to pass to the method.
    ///
    /// # Returns
    ///
    /// A `Result` containing the JSON result or an `AppError`.
    async fn call_rpc<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: RpcParams,
    ) -> Result<T, AppError>;
}

// TODO: Consider adding a method for batch transactions to optimize multiple calls.
// TODO: Implement error handling for specific blockchain errors (e.g., out of gas, invalid nonce).

pub struct Subtensor {
    client: Arc<OnlineClient<SubstrateConfig>>,
    signer: Arc<PairSigner<SubstrateConfig, sr25519::Pair>>,
    api: RuntimeApiClient<SubstrateConfig, OnlineClient<SubstrateConfig>>,
    rpc: RpcClient,
}

impl Subtensor {
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

        // Get the metadata
        let metadata = self.client.metadata();

        // Encode parameters using EncodeAsType
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

// // Re-export important structs and traits
// pub use neurons::{AxonInfo, PrometheusInfo};
// pub use subnets::{SubnetHyperparams, SubnetInfo};
// pub use wallet::Wallet;
