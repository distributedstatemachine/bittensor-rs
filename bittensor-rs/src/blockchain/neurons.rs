use codec::{Compact, Decode, Encode};
use frame_support::pallet_prelude::{Member, TypeInfo};

#[derive(Encode, Decode, Default, TypeInfo, Clone, PartialEq, Eq, Debug)]
pub struct AxonInfo {
    ///  Axon serving block.
    pub block: u64,
    ///  Axon version
    pub version: u32,
    ///  Axon u128 encoded ip address of type v6 or v4.
    pub ip: u128,
    ///  Axon u16 encoded port.
    pub port: u16,
    ///  Axon ip type, 4 for ipv4 and 6 for ipv6.
    pub ip_type: u8,
    ///  Axon protocol. TCP, UDP, other.
    pub protocol: u8,
    ///  Axon proto placeholder 1.
    pub placeholder1: u8,
    ///  Axon proto placeholder 2.
    pub placeholder2: u8,
}

#[derive(Encode, Decode, Default, TypeInfo, Clone, PartialEq, Eq, Debug)]
pub struct PrometheusInfo {
    /// Prometheus serving block.
    pub block: u64,
    /// Prometheus version.
    pub version: u32,
    ///  Prometheus u128 encoded ip address of type v6 or v4.
    pub ip: u128,
    ///  Prometheus u16 encoded port.
    pub port: u16,
    /// Prometheus ip type, 4 for ipv4 and 6 for ipv6.
    pub ip_type: u8,
}

#[derive(Decode, Encode, PartialEq, Eq, Clone, Debug)]
pub struct NeuronInfo<AccountId: Member> {
    hotkey: AccountId,
    coldkey: AccountId,
    uid: Compact<u16>,
    netuid: Compact<u16>,
    active: bool,
    axon_info: AxonInfo,
    prometheus_info: PrometheusInfo,
    stake: Vec<(AccountId, Compact<u64>)>, // map of coldkey to stake on this neuron/hotkey (includes delegations)
    rank: Compact<u16>,
    emission: Compact<u64>,
    incentive: Compact<u16>,
    consensus: Compact<u16>,
    trust: Compact<u16>,
    validator_trust: Compact<u16>,
    dividends: Compact<u16>,
    last_update: Compact<u64>,
    validator_permit: bool,
    weights: Vec<(Compact<u16>, Compact<u16>)>, // Vec of (uid, weight)
    bonds: Vec<(Compact<u16>, Compact<u16>)>,   // Vec of (uid, bond)
    pruning_score: Compact<u16>,
}

#[derive(Decode, Encode, PartialEq, Eq, Clone, Debug)]
pub struct NeuronInfoLite<AccountId: Member> {
    hotkey: AccountId,
    coldkey: AccountId,
    uid: Compact<u16>,
    netuid: Compact<u16>,
    active: bool,
    axon_info: AxonInfo,
    prometheus_info: PrometheusInfo,
    stake: Vec<(AccountId, Compact<u64>)>, // map of coldkey to stake on this neuron/hotkey (includes delegations)
    rank: Compact<u16>,
    emission: Compact<u64>,
    incentive: Compact<u16>,
    consensus: Compact<u16>,
    trust: Compact<u16>,
    validator_trust: Compact<u16>,
    dividends: Compact<u16>,
    last_update: Compact<u64>,
    validator_permit: bool,
    pruning_score: Compact<u16>,
}
