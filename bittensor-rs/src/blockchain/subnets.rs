use codec::{Compact, Decode, Encode};
use frame_support::pallet_prelude::Member;

/// Struct representing information about a subnet
#[derive(Decode, Encode, PartialEq, Eq, Clone, Debug)]
pub struct SubnetInfo<AccountId: Member> {
    pub netuid: Compact<u16>,
    pub rho: Compact<u16>,
    pub kappa: Compact<u16>,
    pub difficulty: Compact<u64>,
    pub immunity_period: Compact<u16>,
    pub max_allowed_validators: Compact<u16>,
    pub min_allowed_weights: Compact<u16>,
    pub max_weights_limit: Compact<u16>,
    pub scaling_law_power: Compact<u16>,
    pub subnetwork_n: Compact<u16>,
    pub max_allowed_uids: Compact<u16>,
    pub blocks_since_last_step: Compact<u64>,
    pub tempo: Compact<u16>,
    pub network_modality: Compact<u16>,
    pub network_connect: Vec<[u16; 2]>,
    pub emission_values: Compact<u64>,
    pub burn: Compact<u64>,
    pub owner: AccountId,
}

/// Struct representing hyperparameters for a subnet
#[derive(Decode, Encode, PartialEq, Eq, Clone, Debug)]
pub struct SubnetHyperparams {
    pub rho: Compact<u16>,
    pub kappa: Compact<u16>,
    pub immunity_period: Compact<u16>,
    pub min_allowed_weights: Compact<u16>,
    pub max_weights_limit: Compact<u16>,
    pub tempo: Compact<u16>,
    pub min_difficulty: Compact<u64>,
    pub max_difficulty: Compact<u64>,
    pub weights_version: Compact<u64>,
    pub weights_rate_limit: Compact<u64>,
    pub adjustment_interval: Compact<u16>,
    pub activity_cutoff: Compact<u16>,
    pub registration_allowed: bool,
    pub target_regs_per_interval: Compact<u16>,
    pub min_burn: Compact<u64>,
    pub max_burn: Compact<u64>,
    pub bonds_moving_avg: Compact<u64>,
    pub max_regs_per_block: Compact<u16>,
    pub serving_rate_limit: Compact<u64>,
    pub max_validators: Compact<u16>,
    pub adjustment_alpha: Compact<u64>,
    pub difficulty: Compact<u64>,
    pub commit_reveal_weights_interval: Compact<u64>,
    pub commit_reveal_weights_enabled: bool,
    pub alpha_high: Compact<u16>,
    pub alpha_low: Compact<u16>,
    pub liquid_alpha_enabled: bool,
}
