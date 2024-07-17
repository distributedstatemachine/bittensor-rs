use std::sync::Arc;

use crate::errors::AppError;
use codec::Encode;
use sp_core::crypto::AccountId32;
use subnets::{SubnetHyperparams, SubnetInfo};
use substrate_api_client::ac_primitives::AssetRuntimeConfig;
use substrate_api_client::rpc::ws_client::WsRpcClient;
use substrate_api_client::runtime_api::RuntimeApi;
use substrate_api_client::runtime_api::RuntimeApiClient;

pub mod neurons;
pub mod root;
pub mod subnets;
pub mod wallet;
pub struct BittensorApi {
    runtime_api: RuntimeApiClient<AssetRuntimeConfig, WsRpcClient>,
}

impl BittensorApi {
    pub fn new(url: &str) -> Result<Self, AppError> {
        let client: WsRpcClient = WsRpcClient::new(url)
            .map_err(|e| AppError::Blockchain(format!("Failed to create WsRpcClient: {:?}", e)))?;

        let runtime_api = RuntimeApiClient::new(Arc::new(client));

        Ok(Self { runtime_api })
    }

    pub async fn get_subnet_info(&self, netuid: u16) -> Result<SubnetInfo<AccountId32>, AppError> {
        let method = "SubtensorModule_get_subnet_info";
        let data = vec![netuid.encode()];

        let subnet_info: SubnetInfo<AccountId32> = self
            .runtime_api
            .runtime_call(method, data, None)
            .map_err(|e| AppError::Blockchain(format!("Failed to fetch subnet info: {:?}", e)))?;

        Ok(subnet_info)
    }

    pub async fn get_subnets_info(&self) -> Result<Vec<SubnetInfo<AccountId32>>, AppError> {
        let method = "SubtensorModule_get_subnets_info";

        let subnets_info: Vec<SubnetInfo<AccountId32>> = self
            .runtime_api
            .runtime_call(method, vec![], None)
            .map_err(|e| AppError::Blockchain(format!("Failed to fetch subnets info: {:?}", e)))?;

        Ok(subnets_info)
    }

    pub async fn get_subnet_hyperparams(&self, netuid: u16) -> Result<SubnetHyperparams, AppError> {
        let method = "SubtensorModule_get_subnet_hyperparams";
        let data = vec![netuid.encode()];

        let hyperparams: SubnetHyperparams = self
            .runtime_api
            .runtime_call(method, data, None)
            .map_err(|e| {
                AppError::Blockchain(format!("Failed to fetch subnet hyperparameters: {:?}", e))
            })?;

        Ok(hyperparams)
    }
}
