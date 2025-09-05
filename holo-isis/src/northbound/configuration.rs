//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, LazyLock as Lazy};

use arc_swap::ArcSwap;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, InheritableConfig, Provider,
    ValidationCallbacks, ValidationCallbacksBuilder,
};
use holo_northbound::yang::control_plane_protocol::isis;
use holo_utils::bfd;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::keychain::{Key, Keychains};
use holo_utils::protocol::Protocol;
use holo_utils::yang::DataNodeRefExt;
use holo_yang::{ToYang, TryFromYang};
use ipnetwork::IpNetwork;
use prefix_trie::joint::map::JointPrefixMap;

use crate::collections::InterfaceIndex;
use crate::debug::InterfaceInactiveReason;
use crate::instance::Instance;
use crate::interface::InterfaceType;
use crate::northbound::notification;
use crate::packet::auth::AuthMethod;
use crate::packet::consts::{MtId, PduType};
use crate::packet::{
    AreaAddr, LevelNumber, LevelType, LevelTypeIterator, SystemId,
};
use crate::route::RouteFlags;
use crate::{ibus, spf, sr};

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    Summary(IpNetwork),
    AddressFamily(AddressFamily),
    Redistribution(AddressFamily, LevelNumber, Protocol),
    Topology(MtId),
    NodeTag(u32),
    TraceOption(InstanceTraceOption),
    Interface(InterfaceIndex),
    InterfaceAddressFamily(InterfaceIndex, AddressFamily),
    InterfaceTopology(InterfaceIndex, MtId),
    InterfaceTraceOption(InterfaceIndex, InterfaceTraceOption),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceReset,
    InstanceUpdate,
    InterfaceUpdate(InterfaceIndex),
    InstanceLevelTypeUpdate,
    InstanceTopologyUpdate,
    InterfaceDelete(InterfaceIndex),
    InterfaceReset(InterfaceIndex),
    InterfaceRestartNetwork(InterfaceIndex),
    InterfacePriorityChange(InterfaceIndex, LevelNumber),
    InterfaceUpdateHelloInterval(InterfaceIndex, LevelNumber),
    InterfaceUpdateCsnpInterval(InterfaceIndex),
    InterfaceBfdChange(InterfaceIndex),
    InterfaceUpdateTraceOptions(InterfaceIndex),
    InterfaceIbusSub(InterfaceIndex),
    ReoriginateLsps(LevelNumber),
    RefreshLsps,
    RerunSpf,
    ReinstallRoutes,
    OverloadChange(bool),
    SrEnabledChange(bool),
    RedistributeAdd(AddressFamily, Protocol),
    RedistributeDelete(AddressFamily, LevelNumber, Protocol),
    UpdateTraceOptions,
}

pub static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {
    pub enabled: bool,
    pub level_type: LevelType,
    pub system_id: Option<SystemId>,
    pub area_addrs: BTreeSet<AreaAddr>,
    pub lsp_mtu: u16,
    pub lsp_lifetime: u16,
    pub lsp_refresh: u16,
    pub purge_originator: bool,
    pub node_tags: BTreeSet<u32>,
    pub metric_type: LevelsCfgWithDefault<MetricType>,
    pub default_metric: LevelsCfgWithDefault<u32>,
    pub auth: LevelsCfg<AuthCfg>,
    pub ipv4_router_id: Option<Ipv4Addr>,
    pub ipv6_router_id: Option<Ipv6Addr>,
    pub max_paths: u16,
    pub afs: BTreeMap<AddressFamily, AddressFamilyCfg>,
    pub spf_initial_delay: u32,
    pub spf_short_delay: u32,
    pub spf_long_delay: u32,
    pub spf_hold_down: u32,
    pub spf_time_to_learn: u32,
    pub preference: Preference,
    pub overload_status: bool,
    pub mt: HashMap<MtId, InstanceMtCfg>,
    pub summaries: JointPrefixMap<IpNetwork, SummaryCfg>,
    pub att_suppress: bool,
    pub att_ignore: bool,
    pub sr: InstanceSrCfg,
    pub bier: InstanceBierCfg,
    pub trace_opts: InstanceTraceOptions,
}

#[derive(Debug)]
pub struct InstanceMtCfg {
    pub enabled: bool,
    pub default_metric: LevelsCfgWithDefault<u32>,
}

#[derive(Debug)]
pub struct InstanceSrCfg {
    pub enabled: bool,
}

#[derive(Debug)]
pub struct InstanceBierCfg {
    pub mt_id: u8,
    pub enabled: bool,
    pub advertise: bool,
    pub receive: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum InstanceTraceOption {
    InternalBus,
    Lsdb,
    PacketsAll,
    PacketsHello,
    PacketsPsnp,
    PacketsCsnp,
    PacketsLsp,
    Spf,
}

#[derive(Debug, Default)]
pub struct InstanceTraceOptions {
    pub ibus: bool,
    pub lsdb: bool,
    pub packets: TraceOptionPacket,
    pub spf: bool,
}

#[derive(Debug)]
pub struct AddressFamilyCfg {
    pub enabled: bool,
    pub redistribution: HashMap<(LevelNumber, Protocol), RedistributionCfg>,
}

#[derive(Debug)]
pub struct Preference {
    pub internal: u8,
    pub external: u8,
}

#[derive(Clone, Copy, Debug)]
pub enum MetricType {
    Standard,
    Wide,
    Both,
}

#[derive(Debug, Default)]
pub struct RedistributionCfg {}

#[derive(Clone, Debug, Default)]
pub struct SummaryCfg {
    pub metric: Option<u32>,
}

#[derive(Debug)]
pub struct InterfaceCfg {
    pub enabled: bool,
    pub level_type: InheritableConfig<LevelType>,
    pub lsp_pacing_interval: u32,
    pub lsp_rxmt_interval: u16,
    pub passive: bool,
    pub csnp_interval: u16,
    pub hello_padding: bool,
    pub interface_type: InterfaceType,
    pub node_flag: bool,
    pub hello_auth: LevelsCfg<AuthCfg>,
    pub hello_interval: LevelsCfgWithDefault<u16>,
    pub hello_multiplier: LevelsCfgWithDefault<u16>,
    pub priority: LevelsCfgWithDefault<u8>,
    pub metric: LevelsCfgWithDefault<u32>,
    pub bfd_enabled: bool,
    pub bfd_params: bfd::ClientCfg,
    pub afs: BTreeSet<AddressFamily>,
    pub mt: HashMap<MtId, InterfaceMtCfg>,
    pub ext_seqnum_mode: LevelsCfg<Option<ExtendedSeqNumMode>>,
    pub trace_opts: InterfaceTraceOptions,
}

#[derive(Debug)]
pub struct InterfaceMtCfg {
    pub enabled: bool,
    pub metric: LevelsCfgWithDefault<u32>,
}

#[derive(Clone, Copy, Debug)]
pub enum InterfaceTraceOption {
    PacketsAll,
    PacketsHello,
    PacketsPsnp,
    PacketsCsnp,
    PacketsLsp,
}

#[derive(Debug, Default)]
pub struct InterfaceTraceOptions {
    pub packets: TraceOptionPacket,
    pub packets_resolved: Arc<ArcSwap<TraceOptionPacketResolved>>,
}

#[derive(Debug, Default)]
pub struct AuthCfg {
    pub keychain: Option<String>,
    pub key: Option<String>,
    pub key_id: Option<u16>,
    pub algo: Option<CryptoAlgo>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ExtendedSeqNumMode {
    SendOnly,
    SendAndVerify,
}

#[derive(Debug)]
pub struct LevelsCfgWithDefault<T> {
    all: T,
    l1: Option<T>,
    l2: Option<T>,
}

#[derive(Debug, Default)]
pub struct LevelsCfg<T> {
    pub all: T,
    pub l1: T,
    pub l2: T,
}

#[derive(Debug, Default)]
pub struct TraceOptionPacket {
    pub all: Option<TraceOptionPacketType>,
    pub hello: Option<TraceOptionPacketType>,
    pub psnp: Option<TraceOptionPacketType>,
    pub csnp: Option<TraceOptionPacketType>,
    pub lsp: Option<TraceOptionPacketType>,
}

#[derive(Clone, Copy, Debug)]
pub struct TraceOptionPacketResolved {
    pub hello: TraceOptionPacketType,
    pub psnp: TraceOptionPacketType,
    pub csnp: TraceOptionPacketType,
    pub lsp: TraceOptionPacketType,
}

#[derive(Clone, Copy, Debug)]
pub struct TraceOptionPacketType {
    pub tx: bool,
    pub rx: bool,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(isis::enabled::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
        })
        .path(isis::level_type::PATH)
        .modify_apply(|instance, args| {
            let level_type = args.dnode.get_string();
            let level_type = LevelType::try_from_yang(&level_type).unwrap();
            instance.config.level_type = level_type;

            let event_queue = args.event_queue;
            // TODO: We can do better than a full reset.
            event_queue.insert(Event::InstanceReset);
            event_queue.insert(Event::InstanceLevelTypeUpdate);
        })
        .path(isis::system_id::PATH)
        .modify_apply(|instance, args| {
            let system_id = args.dnode.get_string();
            let system_id = SystemId::try_from_yang(&system_id).unwrap();
            instance.config.system_id = Some(system_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceReset);
            event_queue.insert(Event::InstanceUpdate);
        })
        .delete_apply(|instance, args| {
            instance.config.system_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
        })
        .path(isis::area_address::PATH)
        .create_apply(|instance, args| {
            let area_addr = args.dnode.get_string();
            let area_addr = AreaAddr::try_from_yang(&area_addr).unwrap();
            instance.config.area_addrs.insert(area_addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let area_addr = args.dnode.get_string();
            let area_addr = AreaAddr::try_from_yang(&area_addr).unwrap();
            instance.config.area_addrs.remove(&area_addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::lsp_mtu::PATH)
        .modify_apply(|instance, args| {
            let lsp_mtu = args.dnode.get_u16();
            instance.config.lsp_mtu = lsp_mtu;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::lsp_lifetime::PATH)
        .modify_apply(|instance, args| {
            let lsp_lifetime = args.dnode.get_u16();
            instance.config.lsp_lifetime = lsp_lifetime;

            let event_queue = args.event_queue;
            event_queue.insert(Event::RefreshLsps);
        })
        .path(isis::lsp_refresh::PATH)
        .modify_apply(|instance, args| {
            let lsp_refresh = args.dnode.get_u16();
            instance.config.lsp_refresh = lsp_refresh;

            let event_queue = args.event_queue;
            event_queue.insert(Event::RefreshLsps);
        })
        .path(isis::poi_tlv::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.purge_originator = enabled;
        })
        .path(isis::node_tags::node_tag::PATH)
        .create_apply(|instance, args| {
            let node_tag = args.dnode.get_u32_relative("tag").unwrap();
            instance.config.node_tags.insert(node_tag);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let node_tag = args.list_entry.into_node_tag().unwrap();
            instance.config.node_tags.remove(&node_tag);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .lookup(|_instance, _list_entry, dnode| {
            let node_tag = dnode.get_u32_relative("tag").unwrap();
            ListEntry::NodeTag(node_tag)
        })
        .path(isis::metric_type::value::PATH)
        .modify_apply(|instance, args| {
            let metric_type = args.dnode.get_string();
            let metric_type = MetricType::try_from_yang(&metric_type).unwrap();
            instance.config.metric_type.all = metric_type;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::metric_type::level_1::value::PATH)
        .modify_apply(|instance, args| {
            let metric_type = args.dnode.get_string();
            let metric_type = MetricType::try_from_yang(&metric_type).unwrap();
            instance.config.metric_type.l1 = Some(metric_type);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            instance.config.metric_type.l1 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .path(isis::metric_type::level_2::value::PATH)
        .modify_apply(|instance, args| {
            let metric_type = args.dnode.get_string();
            let metric_type = MetricType::try_from_yang(&metric_type).unwrap();
            instance.config.metric_type.l2 = Some(metric_type);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.metric_type.l2 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::default_metric::value::PATH)
        .modify_apply(|instance, args| {
            let metric = args.dnode.get_u32();
            instance.config.default_metric.all = metric;
        })
        .path(isis::default_metric::level_1::value::PATH)
        .modify_apply(|instance, args| {
            let metric = args.dnode.get_u32();
            instance.config.default_metric.l1 = Some(metric);
        })
        .delete_apply(|instance, _args| {
            instance.config.default_metric.l1 = None;
        })
        .path(isis::default_metric::level_2::value::PATH)
        .modify_apply(|instance, args| {
            let metric = args.dnode.get_u32();
            instance.config.default_metric.l2 = Some(metric);
        })
        .delete_apply(|instance, _args| {
            instance.config.default_metric.l2 = None;
        })
        .path(isis::authentication::key_chain::PATH)
        .modify_apply(|instance, args| {
            let keychain = args.dnode.get_string();
            instance.config.auth.all.keychain = Some(keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.all.keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::authentication::key::PATH)
        .modify_apply(|instance, args| {
            let key = args.dnode.get_string();
            instance.config.auth.all.key = Some(key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.all.key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::authentication::key_id::PATH)
        .modify_apply(|instance, args| {
            let key_id = args.dnode.get_u16();
            instance.config.auth.all.key_id = Some(key_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.all.key_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::authentication::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            instance.config.auth.all.algo = Some(algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.all.algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::authentication::level_1::key_chain::PATH)
        .modify_apply(|instance, args| {
            let keychain = args.dnode.get_string();
            instance.config.auth.l1.keychain = Some(keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.l1.keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .path(isis::authentication::level_1::key::PATH)
        .modify_apply(|instance, args| {
            let key = args.dnode.get_string();
            instance.config.auth.l1.key = Some(key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.l1.key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .path(isis::authentication::level_1::key_id::PATH)
        .modify_apply(|instance, args| {
            let key_id = args.dnode.get_u16();
            instance.config.auth.l1.key_id = Some(key_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.l1.key_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .path(isis::authentication::level_1::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            instance.config.auth.l1.algo = Some(algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.l1.algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .path(isis::authentication::level_2::key_chain::PATH)
        .modify_apply(|instance, args| {
            let keychain = args.dnode.get_string();
            instance.config.auth.l2.keychain = Some(keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.l2.keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::authentication::level_2::key::PATH)
        .modify_apply(|instance, args| {
            let key = args.dnode.get_string();
            instance.config.auth.l2.key = Some(key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.l2.key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::authentication::level_2::key_id::PATH)
        .modify_apply(|instance, args| {
            let key_id = args.dnode.get_u16();
            instance.config.auth.l2.key_id = Some(key_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.l2.key_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::authentication::level_2::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            instance.config.auth.l2.algo = Some(algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.auth.l2.algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::address_families::address_family_list::PATH)
        .create_apply(|instance, args| {
            let af = args.dnode.get_string_relative("address-family").unwrap();
            let af = AddressFamily::try_from_yang(&af).unwrap();
            instance.config.afs.insert(af, AddressFamilyCfg::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let af = args.list_entry.into_address_family().unwrap();
            instance.config.afs.remove(&af);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .lookup(|_instance, _list_entry, dnode| {
            let af = dnode.get_string_relative("address-family").unwrap();
            let af = AddressFamily::try_from_yang(&af).unwrap();
            ListEntry::AddressFamily(af)
        })
        .path(isis::address_families::address_family_list::enabled::PATH)
        .modify_apply(|instance, args| {
            let af = args.list_entry.into_address_family().unwrap();
            let af_cfg = instance.config.afs.get_mut(&af).unwrap();

            let enabled = args.dnode.get_bool();
            af_cfg.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::address_families::address_family_list::redistribution::PATH)
        .create_apply(|instance, args| {
            let af = args.list_entry.into_address_family().unwrap();
            let af_cfg = instance.config.afs.get_mut(&af).unwrap();

            let level = args.dnode.get_string_relative("./level").unwrap();
            let level = LevelNumber::try_from_yang(&level).unwrap();
            let protocol = args.dnode.get_string_relative("./type").unwrap();
            let protocol = Protocol::try_from_yang(&protocol).unwrap();
            af_cfg.redistribution.insert((level, protocol), Default::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::RedistributeAdd(af, protocol));
        })
        .delete_apply(|instance, args| {
            let (af, level, protocol) = args.list_entry.into_redistribution().unwrap();
            let af_cfg = instance.config.afs.get_mut(&af).unwrap();

            af_cfg.redistribution.remove(&(level, protocol));

            let event_queue = args.event_queue;
            event_queue.insert(Event::RedistributeDelete(af, level, protocol));
        })
        .lookup(|_instance, list_entry, dnode| {
            let af = list_entry.into_address_family().unwrap();
            let level = dnode.get_string_relative("./level").unwrap();
            let level = LevelNumber::try_from_yang(&level).unwrap();
            let protocol = dnode.get_string_relative("./type").unwrap();
            let protocol = Protocol::try_from_yang(&protocol).unwrap();
            ListEntry::Redistribution(af, level, protocol)
        })
        .path(isis::mpls::te_rid::ipv4_router_id::PATH)
        .modify_apply(|instance, args| {
            let addr = args.dnode.get_ipv4();
            instance.config.ipv4_router_id = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.ipv4_router_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::mpls::te_rid::ipv6_router_id::PATH)
        .modify_apply(|instance, args| {
            let addr = args.dnode.get_ipv6();
            instance.config.ipv6_router_id = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            instance.config.ipv6_router_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::spf_control::paths::PATH)
        .modify_apply(|instance, args| {
            let max_paths = args.dnode.get_u16();
            instance.config.max_paths = max_paths;

            let event_queue = args.event_queue;
            event_queue.insert(Event::RerunSpf);
        })
        .path(isis::spf_control::ietf_spf_delay::initial_delay::PATH)
        .modify_apply(|instance, args| {
            let initial_delay = args.dnode.get_u32();
            instance.config.spf_initial_delay = initial_delay;
        })
        .path(isis::spf_control::ietf_spf_delay::short_delay::PATH)
        .modify_apply(|instance, args| {
            let short_delay = args.dnode.get_u32();
            instance.config.spf_short_delay = short_delay;
        })
        .path(isis::spf_control::ietf_spf_delay::long_delay::PATH)
        .modify_apply(|instance, args| {
            let long_delay = args.dnode.get_u32();
            instance.config.spf_long_delay = long_delay;
        })
        .path(isis::spf_control::ietf_spf_delay::hold_down::PATH)
        .modify_apply(|instance, args| {
            let hold_down = args.dnode.get_u32();
            instance.config.spf_hold_down = hold_down;
        })
        .path(isis::spf_control::ietf_spf_delay::time_to_learn::PATH)
        .modify_apply(|instance, args| {
            let time_to_learn = args.dnode.get_u32();
            instance.config.spf_time_to_learn = time_to_learn;
        })
        .path(isis::preference::internal::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.internal = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(isis::preference::external::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(isis::preference::default::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.internal = preference;
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(isis::overload::status::PATH)
        .modify_apply(|instance, args| {
            let overload_status = args.dnode.get_bool();
            instance.config.overload_status = overload_status;

            let event_queue = args.event_queue;
            event_queue.insert(Event::OverloadChange(overload_status));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::topologies::topology::PATH)
        .create_apply(|instance, args| {
            let name = args.dnode.get_string_relative("name").unwrap();
            let mt_id = MtId::try_from_yang(&name).unwrap();
            instance.config.mt.insert(mt_id, InstanceMtCfg::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceTopologyUpdate);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let mt_id = args.list_entry.into_topology().unwrap();
            instance.config.mt.remove(&mt_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceTopologyUpdate);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .lookup(|_context, _list_entry, dnode| {
            let name = dnode.get_string_relative("name").unwrap();
            let mt_id = MtId::try_from_yang(&name).unwrap();
            ListEntry::Topology(mt_id)
        })
        .path(isis::topologies::topology::enabled::PATH)
        .modify_apply(|instance, args| {
            let mt_id = args.list_entry.into_topology().unwrap();
            let mt_cfg = instance.config.mt.get_mut(&mt_id).unwrap();

            let enabled = args.dnode.get_bool();
            mt_cfg.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceTopologyUpdate);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::topologies::topology::default_metric::value::PATH)
        .modify_apply(|instance, args| {
            let mt_id = args.list_entry.into_topology().unwrap();
            let mt_cfg = instance.config.mt.get_mut(&mt_id).unwrap();

            let metric = args.dnode.get_u32();
            mt_cfg.default_metric.all = metric;
        })
        .path(isis::topologies::topology::default_metric::level_1::value::PATH)
        .modify_apply(|instance, args| {
            let mt_id = args.list_entry.into_topology().unwrap();
            let mt_cfg = instance.config.mt.get_mut(&mt_id).unwrap();

            let metric = args.dnode.get_u32();
            mt_cfg.default_metric.l1 = Some(metric);
        })
        .delete_apply(|instance, args| {
            let mt_id = args.list_entry.into_topology().unwrap();
            let mt_cfg = instance.config.mt.get_mut(&mt_id).unwrap();

            mt_cfg.default_metric.l1 = None;
        })
        .path(isis::topologies::topology::default_metric::level_2::value::PATH)
        .modify_apply(|instance, args| {
            let mt_id = args.list_entry.into_topology().unwrap();
            let mt_cfg = instance.config.mt.get_mut(&mt_id).unwrap();

            let metric = args.dnode.get_u32();
            mt_cfg.default_metric.l2 = Some(metric);
        })
        .delete_apply(|instance, args| {
            let mt_id = args.list_entry.into_topology().unwrap();
            let mt_cfg = instance.config.mt.get_mut(&mt_id).unwrap();

            mt_cfg.default_metric.l2 = None;
        })
        .path(isis::attached_bit::suppress_advertisement::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.att_suppress = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::attached_bit::ignore_reception::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.att_ignore = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::RerunSpf);
        })
        .path(isis::inter_level_propagation_policies::level1_to_level2::summary_prefixes::PATH)
        .create_apply(|instance, args| {
            let prefix = args.dnode.get_prefix_relative("prefix").unwrap();
            instance.config.summaries.insert(prefix, SummaryCfg::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::RerunSpf);
        })
        .delete_apply(|instance, args| {
            let prefix = args.list_entry.into_summary().unwrap();
            instance.config.summaries.remove(&prefix);

            let event_queue = args.event_queue;
            event_queue.insert(Event::RerunSpf);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let prefix = dnode.get_prefix_relative("prefix").unwrap();
            ListEntry::Summary(prefix)
        })
        .path(isis::inter_level_propagation_policies::level1_to_level2::summary_prefixes::metric::PATH)
        .modify_apply(|instance, args| {
            let prefix = args.list_entry.into_summary().unwrap();
            let summary_cfg = instance.config.summaries.get_mut(&prefix).unwrap();

            let metric = args.dnode.get_u32();
            summary_cfg.metric = Some(metric);

            let event_queue = args.event_queue;
            event_queue.insert(Event::RerunSpf);
        })
        .delete_apply(|instance, args| {
            let prefix = args.list_entry.into_summary().unwrap();
            let summary_cfg = instance.config.summaries.get_mut(&prefix).unwrap();

            summary_cfg.metric = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::RerunSpf);
        })
        .path(isis::trace_options::flag::PATH)
        .create_apply(|instance, args| {
            let trace_opt = args.dnode.get_string_relative("name").unwrap();
            let trace_opt = InstanceTraceOption::try_from_yang(&trace_opt).unwrap();
            let trace_opts = &mut instance.config.trace_opts;
            match trace_opt {
                InstanceTraceOption::InternalBus => trace_opts.ibus = true,
                InstanceTraceOption::PacketsAll => {
                    trace_opts.packets.all.get_or_insert_default();
                }
                InstanceTraceOption::PacketsHello => {
                    trace_opts.packets.hello.get_or_insert_default();
                }
                InstanceTraceOption::PacketsPsnp => {
                    trace_opts.packets.psnp.get_or_insert_default();
                }
                InstanceTraceOption::PacketsCsnp => {
                    trace_opts.packets.csnp.get_or_insert_default();
                }
                InstanceTraceOption::PacketsLsp => {
                    trace_opts.packets.lsp.get_or_insert_default();
                }
                InstanceTraceOption::Lsdb => trace_opts.lsdb = true,
                InstanceTraceOption::Spf => trace_opts.spf = true,
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .delete_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let trace_opts = &mut instance.config.trace_opts;
            match trace_opt {
                InstanceTraceOption::InternalBus => trace_opts.ibus = false,
                InstanceTraceOption::PacketsAll => trace_opts.packets.all = None,
                InstanceTraceOption::PacketsHello => trace_opts.packets.hello = None,
                InstanceTraceOption::PacketsPsnp => trace_opts.packets.psnp = None,
                InstanceTraceOption::PacketsCsnp => trace_opts.packets.csnp = None,
                InstanceTraceOption::PacketsLsp => trace_opts.packets.lsp = None,
                InstanceTraceOption::Lsdb => trace_opts.lsdb = false,
                InstanceTraceOption::Spf => trace_opts.spf = false,
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let trace_opt = dnode.get_string_relative("name").unwrap();
            let trace_opt = InstanceTraceOption::try_from_yang(&trace_opt).unwrap();
            ListEntry::TraceOption(trace_opt)
        })
        .path(isis::trace_options::flag::send::PATH)
        .modify_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let enable = args.dnode.get_bool();
            let trace_opts = &mut instance.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InstanceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InstanceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InstanceTraceOption::PacketsPsnp => trace_opts.packets.psnp.as_mut(),
                InstanceTraceOption::PacketsCsnp => trace_opts.packets.csnp.as_mut(),
                InstanceTraceOption::PacketsLsp => trace_opts.packets.lsp.as_mut(),
                _ => None,
            }) else {
                return;
            };
            trace_opt_packet.tx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .path(isis::trace_options::flag::receive::PATH)
        .modify_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let enable = args.dnode.get_bool();
            let trace_opts = &mut instance.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InstanceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InstanceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InstanceTraceOption::PacketsPsnp => trace_opts.packets.psnp.as_mut(),
                InstanceTraceOption::PacketsCsnp => trace_opts.packets.csnp.as_mut(),
                InstanceTraceOption::PacketsLsp => trace_opts.packets.lsp.as_mut(),
                _ => None,
            }) else {
                return;
            };
            trace_opt_packet.rx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .path(isis::interfaces::interface::PATH)
        .create_apply(|instance, args| {
            let ifname = args.dnode.get_string_relative("name").unwrap();

            let iface = instance.arenas.interfaces.insert(&ifname);
            iface.config.level_type.resolved =
                iface.config.resolved_level_type(&instance.config);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(iface.index));
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface.index));
            event_queue.insert(Event::InterfaceIbusSub(iface.index));
        })
        .delete_apply(|_instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceDelete(iface_idx));
        })
        .lookup(|instance, _list_entry, dnode| {
            let ifname = dnode.get_string_relative("./name").unwrap();
            instance.arenas.interfaces.get_by_name(&ifname).map(|iface| ListEntry::Interface(iface.index)).expect("could not find IS-IS interface")
        })
        .path(isis::interfaces::interface::enabled::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(iface_idx));
        })
        .path(isis::interfaces::interface::level_type::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let level_type = args.dnode.get_string();
            let level_type = LevelType::try_from_yang(&level_type).unwrap();
            iface.config.level_type.explicit = Some(level_type);
            iface.config.level_type.resolved =
                iface.config.resolved_level_type(&instance.config);

            let event_queue = args.event_queue;
            // TODO: We can do better than a full reset.
            event_queue.insert(Event::InterfaceReset(iface_idx));
        })
        .path(isis::interfaces::interface::lsp_pacing_interval::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let lsp_pacing_interval = args.dnode.get_u32();
            iface.config.lsp_pacing_interval = lsp_pacing_interval;
        })
        .path(isis::interfaces::interface::lsp_retransmit_interval::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let lsp_rxmt_interval = args.dnode.get_u16();
            iface.config.lsp_rxmt_interval = lsp_rxmt_interval;
        })
        .path(isis::interfaces::interface::passive::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let passive = args.dnode.get_bool();
            iface.config.passive = passive;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceReset(iface_idx));
        })
        .path(isis::interfaces::interface::csnp_interval::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let csnp_interval = args.dnode.get_u16();
            iface.config.csnp_interval = csnp_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateCsnpInterval(iface_idx));
        })
        .path(isis::interfaces::interface::hello_padding::enabled::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_padding = args.dnode.get_bool();
            iface.config.hello_padding = hello_padding;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::interface_type::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let interface_type = args.dnode.get_string();
            let interface_type = InterfaceType::try_from_yang(&interface_type).unwrap();
            iface.config.interface_type = interface_type;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceReset(iface_idx));
        })
        .path(isis::interfaces::interface::node_flag::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.node_flag = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::interfaces::interface::hello_authentication::key_chain::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let keychain = args.dnode.get_string();
            iface.config.hello_auth.all.keychain = Some(keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.all.keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::key::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let key = args.dnode.get_string();
            iface.config.hello_auth.all.key = Some(key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.all.key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::key_id::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let key_id = args.dnode.get_u16();
            iface.config.hello_auth.all.key_id = Some(key_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.all.key_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            iface.config.hello_auth.all.algo = Some(algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.all.algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::level_1::key_chain::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let keychain = args.dnode.get_string();
            iface.config.hello_auth.l1.keychain = Some(keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l1.keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::level_1::key::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let key = args.dnode.get_string();
            iface.config.hello_auth.l1.key = Some(key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l1.key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::level_1::key_id::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let key_id = args.dnode.get_u16();
            iface.config.hello_auth.l1.key_id = Some(key_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l1.key_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::level_1::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            iface.config.hello_auth.l1.algo = Some(algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l1.algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::level_2::key_chain::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let keychain = args.dnode.get_string();
            iface.config.hello_auth.l2.keychain = Some(keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l2.keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::level_2::key::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let key = args.dnode.get_string();
            iface.config.hello_auth.l2.key = Some(key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l2.key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::level_2::key_id::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let key_id = args.dnode.get_u16();
            iface.config.hello_auth.l2.key_id = Some(key_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l2.key_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_authentication::level_2::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            iface.config.hello_auth.l2.algo = Some(algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l2.algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
        })
        .path(isis::interfaces::interface::hello_interval::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_interval = args.dnode.get_u16();
            iface.config.hello_interval.all = hello_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .path(isis::interfaces::interface::hello_interval::level_1::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_interval = args.dnode.get_u16();
            iface.config.hello_interval.l1 = Some(hello_interval);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_interval.l1 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
        })
        .path(isis::interfaces::interface::hello_interval::level_2::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_interval = args.dnode.get_u16();
            iface.config.hello_interval.l2 = Some(hello_interval);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_interval.l2 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .path(isis::interfaces::interface::hello_multiplier::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_multiplier = args.dnode.get_u16();
            iface.config.hello_multiplier.all = hello_multiplier;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .path(isis::interfaces::interface::hello_multiplier::level_1::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_multiplier = args.dnode.get_u16();
            iface.config.hello_multiplier.l1 = Some(hello_multiplier);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_multiplier.l1 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
        })
        .path(isis::interfaces::interface::hello_multiplier::level_2::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_multiplier = args.dnode.get_u16();
            iface.config.hello_multiplier.l2 = Some(hello_multiplier);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_multiplier.l2 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .path(isis::interfaces::interface::priority::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let priority = args.dnode.get_u8();
            iface.config.priority.all = priority;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfacePriorityChange(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfacePriorityChange(iface_idx, LevelNumber::L2));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .path(isis::interfaces::interface::priority::level_1::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let priority = args.dnode.get_u8();
            iface.config.priority.l1 = Some(priority);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfacePriorityChange(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.priority.l1 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfacePriorityChange(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
        })
        .path(isis::interfaces::interface::priority::level_2::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let priority = args.dnode.get_u8();
            iface.config.priority.l2 = Some(priority);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfacePriorityChange(iface_idx, LevelNumber::L2));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.priority.l2 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfacePriorityChange(iface_idx, LevelNumber::L2));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .path(isis::interfaces::interface::metric::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let metric = args.dnode.get_u32();
            iface.config.metric.all = metric;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::interfaces::interface::metric::level_1::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let metric = args.dnode.get_u32();
            iface.config.metric.l1 = Some(metric);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.metric.l1 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        })
        .path(isis::interfaces::interface::metric::level_2::value::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let metric = args.dnode.get_u32();
            iface.config.metric.l2 = Some(metric);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.metric.l2 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::interfaces::interface::bfd::enabled::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.bfd_enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .path(isis::interfaces::interface::bfd::local_multiplier::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let local_multiplier = args.dnode.get_u8();
            iface.config.bfd_params.local_multiplier = local_multiplier;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .path(isis::interfaces::interface::bfd::desired_min_tx_interval::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let min_tx = args.dnode.get_u32();
            iface.config.bfd_params.min_tx = min_tx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(isis::interfaces::interface::bfd::required_min_rx_interval::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let min_rx = args.dnode.get_u32();
            iface.config.bfd_params.min_rx = min_rx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(isis::interfaces::interface::bfd::min_interval::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let min_interval = args.dnode.get_u32();
            iface.config.bfd_params.min_tx = min_interval;
            iface.config.bfd_params.min_rx = min_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(isis::interfaces::interface::address_families::address_family_list::PATH)
        .create_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let af = args.dnode.get_string_relative("address-family").unwrap();
            let af = AddressFamily::try_from_yang(&af).unwrap();
            iface.config.afs.insert(af);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let (iface_idx, af) = args.list_entry.into_interface_address_family().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.afs.remove(&af);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .lookup(|_instance, list_entry, dnode| {
            let iface_idx = list_entry.into_interface().unwrap();
            let af = dnode.get_string_relative("address-family").unwrap();
            let af = AddressFamily::try_from_yang(&af).unwrap();
            ListEntry::InterfaceAddressFamily(iface_idx, af)
        })
        .path(isis::interfaces::interface::topologies::topology::PATH)
        .create_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let name = args.dnode.get_string_relative("name").unwrap();
            let mt_id = MtId::try_from_yang(&name).unwrap();
            iface.config.mt.insert(mt_id, InterfaceMtCfg::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let (iface_idx, mt_id) = args.list_entry.into_interface_topology().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mt.remove(&mt_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .lookup(|_context, list_entry, dnode| {
            let iface_idx = list_entry.into_interface().unwrap();
            let name = dnode.get_string_relative("name").unwrap();
            let mt_id = MtId::try_from_yang(&name).unwrap();
            ListEntry::InterfaceTopology(iface_idx, mt_id)
        })
        .path(isis::interfaces::interface::topologies::topology::enabled::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, mt_id) = args.list_entry.into_interface_topology().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let iface_mt_cfg = iface.config.mt.get_mut(&mt_id).unwrap();

            let enabled = args.dnode.get_bool();
            iface_mt_cfg.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::interfaces::interface::topologies::topology::metric::value::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, mt_id) = args.list_entry.into_interface_topology().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let iface_mt_cfg = iface.config.mt.get_mut(&mt_id).unwrap();

            let metric = args.dnode.get_u32();
            iface_mt_cfg.metric.all = metric;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::interfaces::interface::topologies::topology::metric::level_1::value::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, mt_id) = args.list_entry.into_interface_topology().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let iface_mt_cfg = iface.config.mt.get_mut(&mt_id).unwrap();

            let metric = args.dnode.get_u32();
            iface_mt_cfg.metric.l1 = Some(metric);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let (iface_idx, mt_id) = args.list_entry.into_interface_topology().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let iface_mt_cfg = iface.config.mt.get_mut(&mt_id).unwrap();

            iface_mt_cfg.metric.l1 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::interfaces::interface::topologies::topology::metric::level_2::value::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, mt_id) = args.list_entry.into_interface_topology().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let iface_mt_cfg = iface.config.mt.get_mut(&mt_id).unwrap();

            let metric = args.dnode.get_u32();
            iface_mt_cfg.metric.l2 = Some(metric);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let (iface_idx, mt_id) = args.list_entry.into_interface_topology().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let iface_mt_cfg = iface.config.mt.get_mut(&mt_id).unwrap();

            iface_mt_cfg.metric.l2 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::interfaces::interface::extended_sequence_number::mode::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let ext_seqnum_mode = args.dnode.get_string();
            let ext_seqnum_mode = ExtendedSeqNumMode::try_from_yang(&ext_seqnum_mode).unwrap();
            iface.config.ext_seqnum_mode.all = Some(ext_seqnum_mode);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.ext_seqnum_mode.all = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .path(isis::interfaces::interface::extended_sequence_number::level_1::mode::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let ext_seqnum_mode = args.dnode.get_string();
            let ext_seqnum_mode = ExtendedSeqNumMode::try_from_yang(&ext_seqnum_mode).unwrap();
            iface.config.ext_seqnum_mode.l1 = Some(ext_seqnum_mode);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.ext_seqnum_mode.l1 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
        })
        .path(isis::interfaces::interface::extended_sequence_number::level_2::mode::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let ext_seqnum_mode = args.dnode.get_string();
            let ext_seqnum_mode = ExtendedSeqNumMode::try_from_yang(&ext_seqnum_mode).unwrap();
            iface.config.ext_seqnum_mode.l2 = Some(ext_seqnum_mode);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.ext_seqnum_mode.l2 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
        })
        .path(isis::interfaces::interface::trace_options::flag::PATH)
        .create_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let trace_opt = args.dnode.get_string_relative("name").unwrap();
            let trace_opt = InterfaceTraceOption::try_from_yang(&trace_opt).unwrap();
            let trace_opts = &mut iface.config.trace_opts;
            match trace_opt {
                InterfaceTraceOption::PacketsAll => {
                    trace_opts.packets.all.get_or_insert_default();
                }
                InterfaceTraceOption::PacketsHello => {
                    trace_opts.packets.hello.get_or_insert_default();
                }
                InterfaceTraceOption::PacketsPsnp => {
                    trace_opts.packets.psnp.get_or_insert_default();
                }
                InterfaceTraceOption::PacketsCsnp => {
                    trace_opts.packets.csnp.get_or_insert_default();
                }
                InterfaceTraceOption::PacketsLsp => {
                    trace_opts.packets.lsp.get_or_insert_default();
                }
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        })
        .delete_apply(|instance, args| {
            let (iface_idx, trace_opt) = args.list_entry.into_interface_trace_option().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let trace_opts = &mut iface.config.trace_opts;
            match trace_opt {
                InterfaceTraceOption::PacketsAll => trace_opts.packets.all = None,
                InterfaceTraceOption::PacketsHello => trace_opts.packets.hello = None,
                InterfaceTraceOption::PacketsPsnp => trace_opts.packets.psnp = None,
                InterfaceTraceOption::PacketsCsnp => trace_opts.packets.csnp = None,
                InterfaceTraceOption::PacketsLsp => trace_opts.packets.lsp = None,
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        })
        .lookup(|_instance, list_entry, dnode| {
            let iface_idx = list_entry.into_interface().unwrap();
            let trace_opt = dnode.get_string_relative("name").unwrap();
            let trace_opt = InterfaceTraceOption::try_from_yang(&trace_opt).unwrap();
            ListEntry::InterfaceTraceOption(iface_idx, trace_opt)
        })
        .path(isis::interfaces::interface::trace_options::flag::send::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, trace_opt) = args.list_entry.into_interface_trace_option().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enable = args.dnode.get_bool();
            let trace_opts = &mut iface.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InterfaceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InterfaceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InterfaceTraceOption::PacketsPsnp => trace_opts.packets.psnp.as_mut(),
                InterfaceTraceOption::PacketsCsnp => trace_opts.packets.csnp.as_mut(),
                InterfaceTraceOption::PacketsLsp => trace_opts.packets.lsp.as_mut(),
            }) else {
                return;
            };
            trace_opt_packet.tx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        })
        .path(isis::interfaces::interface::trace_options::flag::receive::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, trace_opt) = args.list_entry.into_interface_trace_option().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enable = args.dnode.get_bool();
            let trace_opts = &mut iface.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InterfaceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InterfaceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InterfaceTraceOption::PacketsPsnp => trace_opts.packets.psnp.as_mut(),
                InterfaceTraceOption::PacketsCsnp => trace_opts.packets.csnp.as_mut(),
                InterfaceTraceOption::PacketsLsp => trace_opts.packets.lsp.as_mut(),
            }) else {
                return;
            };
            trace_opt_packet.rx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        })
        .path(isis::bier::mt_id::PATH)
        .modify_apply(|instance, args| {
            let mt_id = args.dnode.get_u8();
            instance.config.bier.mt_id = mt_id;

            // TODO: should reoriginate LSP
        })
        .delete_apply(|instance, _args| {
            let mt_id = 0;
            instance.config.bier.mt_id = mt_id;
        })
        .path(isis::bier::bier::enable::PATH)
        .modify_apply(|instance, args| {
            let enable = args.dnode.get_bool();
            instance.config.bier.enabled = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .path(isis::bier::bier::advertise::PATH)
        .modify_apply(|instance, args| {
            let advertise = args.dnode.get_bool();
            instance.config.bier.advertise = advertise;
        })
        .path(isis::bier::bier::receive::PATH)
        .modify_apply(|instance, args| {
            let receive = args.dnode.get_bool();
            instance.config.bier.receive = receive;
       })
        .path(isis::segment_routing::enabled::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.sr.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrEnabledChange(enabled));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(isis::topologies::topology::PATH)
        .validate(|args| {
            let valid_options = [MtId::Ipv6Unicast.to_yang()];

            let name = args.dnode.get_string_relative("name").unwrap();
            if !valid_options.iter().any(|option| *option == name) {
                return Err(format!(
                    "unsupported topology name (valid options: \"{}\")",
                    valid_options.join(", "),
                ));
            }

            Ok(())
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        Some(&VALIDATION_CALLBACKS)
    }

    fn callbacks() -> &'static Callbacks<Instance> {
        &CALLBACKS
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::InstanceReset => self.reset(),
            Event::InstanceUpdate => {
                self.update();
            }
            Event::InstanceLevelTypeUpdate => {
                for iface in self.arenas.interfaces.iter_mut() {
                    iface.config.level_type.resolved =
                        iface.config.resolved_level_type(&self.config);
                }
            }
            Event::InstanceTopologyUpdate => {
                if let Some((instance, arenas)) = self.as_up() {
                    for iface in arenas.interfaces.iter_mut().filter(|iface| {
                        iface.state.active && !iface.is_passive()
                    }) {
                        iface.hello_interval_start(&instance, LevelType::All);
                    }
                }
            }
            Event::InterfaceUpdate(iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];
                    if let Err(error) =
                        iface.update(&mut instance, &mut arenas.adjacencies)
                    {
                        error.log();
                    }
                }
            }
            Event::InterfaceDelete(iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];

                    // Cancel ibus subscription.
                    instance.tx.ibus.interface_unsub(Some(iface.name.clone()));

                    // Stop interface if it's active.
                    let reason = InterfaceInactiveReason::AdminDown;
                    iface.stop(&mut instance, &mut arenas.adjacencies, reason);

                    // Update the routing table to remove nexthops that are no
                    // longer reachable.
                    for route in instance
                        .state
                        .rib_mut(instance.config.level_type)
                        .values_mut()
                    {
                        route.nexthops.retain(|_, nexthop| {
                            nexthop.iface_idx != iface_idx
                        });
                    }
                }

                self.arenas.interfaces.delete(iface_idx);
            }
            Event::InterfaceReset(iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];
                    if let Err(error) =
                        iface.reset(&mut instance, &mut arenas.adjacencies)
                    {
                        error.log();
                    }
                }
            }
            Event::InterfaceRestartNetwork(iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];
                    iface.restart_network_tasks(&mut instance);
                }
            }
            Event::InterfacePriorityChange(iface_idx, level) => {
                let Some((instance, arenas)) = self.as_up() else {
                    return;
                };
                let iface = &mut arenas.interfaces[iface_idx];

                // Schedule new DIS election.
                if iface.state.active
                    && !iface.is_passive()
                    && iface.config.interface_type == InterfaceType::Broadcast
                {
                    instance.tx.protocol_input.dis_election(iface.id, level);
                }
            }
            Event::InterfaceUpdateHelloInterval(iface_idx, level) => {
                let Some((instance, arenas)) = self.as_up() else {
                    return;
                };
                let iface = &mut arenas.interfaces[iface_idx];
                if iface.state.active && !iface.is_passive() {
                    iface.hello_interval_start(&instance, level);
                }
            }
            Event::InterfaceUpdateCsnpInterval(iface_idx) => {
                let Some((instance, arenas)) = self.as_up() else {
                    return;
                };
                let iface = &mut arenas.interfaces[iface_idx];
                iface.csnp_interval_reset(&instance);
            }
            Event::InterfaceBfdChange(iface_idx) => {
                let Some((instance, arenas)) = self.as_up() else {
                    return;
                };
                let iface = &mut arenas.interfaces[iface_idx];
                iface.with_adjacencies(
                    &mut arenas.adjacencies,
                    |iface, adj| {
                        if iface.config.bfd_enabled {
                            adj.bfd_update_sessions(iface, &instance, true);
                        } else {
                            adj.bfd_clear_sessions(&instance);
                        }
                    },
                );
            }
            Event::InterfaceUpdateTraceOptions(iface_idx) => {
                let iface = &mut self.arenas.interfaces[iface_idx];
                iface.config.update_trace_options(&self.config);
            }
            Event::InterfaceIbusSub(iface_idx) => {
                let iface = &self.arenas.interfaces[iface_idx];
                self.tx.ibus.interface_sub(Some(iface.name.clone()), None);
            }
            Event::ReoriginateLsps(level) => {
                if let Some((mut instance, _)) = self.as_up() {
                    instance.schedule_lsp_origination(level);
                }
            }
            Event::RefreshLsps => {
                if let Some((instance, arenas)) = self.as_up() {
                    let system_id = instance.config.system_id.unwrap();
                    for level in [LevelNumber::L1, LevelNumber::L2] {
                        for lse in instance
                            .state
                            .lsdb
                            .get(level)
                            .iter_for_system_id(&arenas.lsp_entries, system_id)
                            .filter(|lse| lse.data.rem_lifetime != 0)
                        {
                            instance
                                .tx
                                .protocol_input
                                .lsp_refresh(level, lse.id);
                        }
                    }
                }
            }
            Event::RerunSpf => {
                if let Some((instance, _)) = self.as_up() {
                    for level in instance.config.levels() {
                        instance.tx.protocol_input.spf_delay_event(
                            level,
                            spf::fsm::Event::ConfigChange,
                        );
                    }
                }
            }
            Event::ReinstallRoutes => {
                if let Some((instance, arenas)) = self.as_up() {
                    for (prefix, route) in instance
                        .state
                        .rib(instance.config.level_type)
                        .iter()
                        .filter(|(_, route)| {
                            route.flags.contains(RouteFlags::INSTALLED)
                        })
                    {
                        let distance = route.distance(instance.config);
                        ibus::tx::route_install(
                            &instance.tx.ibus,
                            prefix,
                            route,
                            None,
                            distance,
                            &arenas.interfaces,
                        );
                    }
                }
            }
            Event::OverloadChange(overload_status) => {
                if let Some((instance, _)) = self.as_up() {
                    // Update system counters.
                    if overload_status {
                        instance.state.counters.l1.database_overload += 1;
                        instance.state.counters.l2.database_overload += 1;
                    }

                    // Send YANG notification.
                    notification::database_overload(&instance, overload_status);
                }
            }
            Event::SrEnabledChange(enabled) => {
                let Some((instance, arenas)) = self.as_up() else {
                    return;
                };

                // Iterate over all existing adjacencies.
                for iface in arenas.interfaces.iter_mut() {
                    iface.with_adjacencies(
                        &mut arenas.adjacencies,
                        |iface, adj| {
                            if enabled {
                                sr::adj_sids_add(&instance, iface, adj);
                            } else {
                                sr::adj_sids_del(&instance, adj);
                            }
                        },
                    );
                }
            }
            Event::RedistributeAdd(af, protocol) => {
                // Subscribe to route redistribution for the given protocol and
                // address family.
                self.tx.ibus.route_redistribute_sub(protocol, Some(af));
            }
            Event::RedistributeDelete(af, level, protocol) => {
                // Unsubscribe from route redistribution for the given protocol
                // and address family.
                self.tx.ibus.route_redistribute_unsub(protocol, Some(af));

                // Remove redistributed routes.
                let routes = self.system.routes.get_mut(level);
                routes.retain(|prefix, route| {
                    prefix.address_family() != af || route.protocol != protocol
                });

                // Schedule LSP reorigination.
                if let Some((mut instance, _)) = self.as_up() {
                    instance.schedule_lsp_origination(level);
                }
            }
            Event::UpdateTraceOptions => {
                for iface in self.arenas.interfaces.iter_mut() {
                    iface.config.update_trace_options(&self.config);
                }
            }
        }
    }
}

// ===== configuration helpers =====

impl InstanceCfg {
    // Checks if the specified address family is enabled.
    pub(crate) fn is_af_enabled(&self, af: AddressFamily) -> bool {
        if let Some(af_cfg) = self.afs.get(&af) {
            return af_cfg.enabled;
        }

        true
    }

    // Checks if the specified topology is enabled.
    pub(crate) fn is_topology_enabled(&self, mt_id: MtId) -> bool {
        if mt_id == MtId::Standard {
            return true;
        }

        if let Some(mt_cfg) = self.mt.get(&mt_id) {
            return mt_cfg.enabled;
        }

        false
    }

    // Returns the levels supported by the instance.
    pub(crate) fn levels(&self) -> LevelTypeIterator {
        self.level_type.into_iter()
    }

    // Returns the set of enabled topology IDs for the instance.
    pub(crate) fn topologies(&self) -> BTreeSet<MtId> {
        let mut topologies = BTreeSet::new();
        topologies.insert(MtId::Standard);
        topologies.extend(
            self.mt
                .iter()
                .filter_map(|(mt_id, mt_cfg)| mt_cfg.enabled.then_some(*mt_id)),
        );
        topologies
    }
}

impl InterfaceCfg {
    // Checks if the specified address family is enabled.
    pub(crate) fn is_af_enabled(
        &self,
        af: AddressFamily,
        instance_cfg: &InstanceCfg,
    ) -> bool {
        if !self.afs.contains(&af) {
            return false;
        }

        if let Some(af_cfg) = instance_cfg.afs.get(&af) {
            return af_cfg.enabled;
        }

        true
    }

    // Checks if the specified topology is enabled.
    pub(crate) fn is_topology_enabled(&self, mt_id: MtId) -> bool {
        if mt_id == MtId::Standard {
            return true;
        }

        if let Some(mt_cfg) = self.mt.get(&mt_id) {
            return mt_cfg.enabled;
        }

        true
    }

    // Returns the levels supported by the interface.
    pub(crate) fn levels(&self) -> LevelTypeIterator {
        self.level_type.resolved.into_iter()
    }

    // Returns the set of enabled topology IDs for the interface.
    pub(crate) fn topologies<T>(
        &self,
        instance_cfg: &InstanceCfg,
    ) -> BTreeSet<T>
    where
        MtId: Into<T>,
        T: Ord,
    {
        instance_cfg
            .topologies()
            .into_iter()
            .filter(|mt_id| self.is_topology_enabled(*mt_id))
            .map(Into::into)
            .collect()
    }

    // Calculates the hello hold time for a given level by multiplying the
    // hello interval and multiplier.
    pub(crate) fn hello_holdtime(&self, level: LevelType) -> u16 {
        self.hello_interval.get(level) * self.hello_multiplier.get(level)
    }

    // Resolves the level type.
    fn resolved_level_type(&self, instance_cfg: &InstanceCfg) -> LevelType {
        match instance_cfg.level_type {
            LevelType::L1 | LevelType::L2 => instance_cfg.level_type,
            LevelType::All => self.level_type.explicit.unwrap(),
        }
    }

    // Returns the metric for a given topology and level, or the default if no
    // specific configuration exists.
    pub(crate) fn topology_metric(
        &self,
        mt_id: MtId,
        level: impl Into<LevelType>,
    ) -> u32 {
        const DFLT_METRIC: u32 = isis::interfaces::interface::topologies::topology::metric::value::DFLT;
        let level = level.into();
        self.mt
            .get(&mt_id)
            .map(|mt_cfg| mt_cfg.metric.get(level))
            .unwrap_or(DFLT_METRIC)
    }

    // Resolves packet trace options by merging interface-specific and
    // instance-level options. Interface options override instance options,
    // and per-packet options override "all" options.
    pub(crate) fn update_trace_options(&mut self, instance_cfg: &InstanceCfg) {
        let iface_trace_opts = &self.trace_opts.packets;
        let instance_trace_opts = &instance_cfg.trace_opts.packets;

        let disabled = TraceOptionPacketType {
            tx: false,
            rx: false,
        };
        let hello = iface_trace_opts
            .hello
            .or(iface_trace_opts.all)
            .or(instance_trace_opts.hello)
            .or(instance_trace_opts.all)
            .unwrap_or(disabled);
        let psnp = iface_trace_opts
            .psnp
            .or(iface_trace_opts.all)
            .or(instance_trace_opts.psnp)
            .or(instance_trace_opts.all)
            .unwrap_or(disabled);
        let csnp = iface_trace_opts
            .csnp
            .or(iface_trace_opts.all)
            .or(instance_trace_opts.csnp)
            .or(instance_trace_opts.all)
            .unwrap_or(disabled);
        let lsp = iface_trace_opts
            .lsp
            .or(iface_trace_opts.all)
            .or(instance_trace_opts.lsp)
            .or(instance_trace_opts.all)
            .unwrap_or(disabled);

        let resolved = Arc::new(TraceOptionPacketResolved {
            hello,
            psnp,
            csnp,
            lsp,
        });
        self.trace_opts.packets_resolved.store(resolved);
    }
}

impl<T> LevelsCfgWithDefault<T>
where
    T: Copy,
{
    // Retrieves the configuration value for the specified level.
    pub(crate) fn get(&self, level: impl Into<LevelType>) -> T {
        let level = level.into();
        match level {
            LevelType::L1 => self.l1.unwrap_or(self.all),
            LevelType::L2 => self.l2.unwrap_or(self.all),
            LevelType::All => self.all,
        }
    }
}

impl<T> LevelsCfg<Option<T>>
where
    T: Copy,
{
    // Retrieves the configuration value for the specified level.
    pub(crate) fn get(&self, level: impl Into<LevelType>) -> Option<T> {
        let level = level.into();
        match level {
            LevelType::L1 => self.l1.or(self.all),
            LevelType::L2 => self.l2.or(self.all),
            LevelType::All => self.all,
        }
    }
}

impl MetricType {
    // Checks if standard metric support is enabled.
    pub(crate) const fn is_standard_enabled(&self) -> bool {
        matches!(self, MetricType::Standard | MetricType::Both)
    }

    // Checks if wide metric support is enabled.
    pub(crate) const fn is_wide_enabled(&self) -> bool {
        matches!(self, MetricType::Wide | MetricType::Both)
    }
}

impl AuthCfg {
    pub(crate) fn method(&self, keychains: &Keychains) -> Option<AuthMethod> {
        if let (Some(key), Some(algo)) = (&self.key, self.algo) {
            let key_id = self.key_id.unwrap_or_default() as u64;
            let key = key.as_bytes().to_vec();
            let auth_key = Key::new(key_id, algo, key);
            return Some(AuthMethod::ManualKey(auth_key));
        }

        if let Some(keychain) = &self.keychain
            && let Some(keychain) = keychains.get(keychain)
        {
            return Some(AuthMethod::Keychain(keychain.clone()));
        }

        None
    }
}

impl TraceOptionPacketResolved {
    pub(crate) fn tx(&self, pdu_type: PduType) -> bool {
        match pdu_type {
            PduType::HelloP2P | PduType::HelloLanL1 | PduType::HelloLanL2 => {
                self.hello.tx
            }
            PduType::LspL1 | PduType::LspL2 => self.lsp.tx,
            PduType::CsnpL1 | PduType::CsnpL2 => self.csnp.tx,
            PduType::PsnpL1 | PduType::PsnpL2 => self.psnp.tx,
        }
    }

    pub(crate) fn rx(&self, pdu_type: PduType) -> bool {
        match pdu_type {
            PduType::HelloP2P | PduType::HelloLanL1 | PduType::HelloLanL2 => {
                self.hello.rx
            }
            PduType::LspL1 | PduType::LspL2 => self.lsp.rx,
            PduType::CsnpL1 | PduType::CsnpL2 => self.csnp.rx,
            PduType::PsnpL1 | PduType::PsnpL2 => self.psnp.rx,
        }
    }
}

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let enabled = isis::enabled::DFLT;
        let level_type = isis::level_type::DFLT;
        let level_type = LevelType::try_from_yang(level_type).unwrap();
        let lsp_mtu = isis::lsp_mtu::DFLT;
        let lsp_lifetime = isis::lsp_lifetime::DFLT;
        let lsp_refresh = isis::lsp_refresh::DFLT;
        let purge_originator = isis::poi_tlv::DFLT;
        let metric_type = isis::metric_type::value::DFLT;
        let metric_type = LevelsCfgWithDefault {
            all: MetricType::try_from_yang(metric_type).unwrap(),
            l1: None,
            l2: None,
        };
        let default_metric = isis::default_metric::value::DFLT;
        let default_metric = LevelsCfgWithDefault {
            all: default_metric,
            l1: None,
            l2: None,
        };
        let max_paths = isis::spf_control::paths::DFLT;
        let spf_initial_delay =
            isis::spf_control::ietf_spf_delay::initial_delay::DFLT;
        let spf_short_delay =
            isis::spf_control::ietf_spf_delay::short_delay::DFLT;
        let spf_long_delay =
            isis::spf_control::ietf_spf_delay::long_delay::DFLT;
        let spf_hold_down = isis::spf_control::ietf_spf_delay::hold_down::DFLT;
        let spf_time_to_learn =
            isis::spf_control::ietf_spf_delay::time_to_learn::DFLT;
        let overload_status = isis::overload::status::DFLT;
        let att_suppress = isis::attached_bit::suppress_advertisement::DFLT;
        let att_ignore = isis::attached_bit::ignore_reception::DFLT;

        InstanceCfg {
            enabled,
            level_type,
            system_id: None,
            area_addrs: Default::default(),
            lsp_mtu,
            lsp_lifetime,
            lsp_refresh,
            purge_originator,
            node_tags: Default::default(),
            metric_type,
            default_metric,
            auth: Default::default(),
            max_paths,
            ipv4_router_id: None,
            ipv6_router_id: None,
            afs: Default::default(),
            spf_initial_delay,
            spf_short_delay,
            spf_long_delay,
            spf_hold_down,
            spf_time_to_learn,
            preference: Default::default(),
            overload_status,
            mt: Default::default(),
            summaries: Default::default(),
            att_suppress,
            att_ignore,
            sr: Default::default(),
            bier: Default::default(),
            trace_opts: Default::default(),
        }
    }
}

impl Default for InstanceMtCfg {
    fn default() -> Self {
        let enabled = isis::topologies::topology::enabled::DFLT;
        let default_metric =
            isis::topologies::topology::default_metric::value::DFLT;
        let default_metric = LevelsCfgWithDefault {
            all: default_metric,
            l1: None,
            l2: None,
        };

        Self {
            enabled,
            default_metric,
        }
    }
}

impl Default for InstanceSrCfg {
    fn default() -> Self {
        let enabled = isis::segment_routing::enabled::DFLT;
        Self { enabled }
    }
}

impl Default for InstanceBierCfg {
    fn default() -> Self {
        let enabled = isis::bier::bier::enable::DFLT;
        let advertise = isis::bier::bier::advertise::DFLT;
        let receive = isis::bier::bier::receive::DFLT;
        Self {
            mt_id: 0,
            enabled,
            advertise,
            receive,
        }
    }
}

impl Default for AddressFamilyCfg {
    fn default() -> AddressFamilyCfg {
        let enabled =
            isis::address_families::address_family_list::enabled::DFLT;

        AddressFamilyCfg {
            enabled,
            redistribution: Default::default(),
        }
    }
}

impl Default for Preference {
    fn default() -> Preference {
        let internal = isis::preference::default::DFLT;
        let external = isis::preference::default::DFLT;

        Preference { internal, external }
    }
}

impl Default for InterfaceCfg {
    fn default() -> InterfaceCfg {
        let enabled = isis::interfaces::interface::enabled::DFLT;
        let level_type = isis::interfaces::interface::level_type::DFLT;
        let level_type = LevelType::try_from_yang(level_type).unwrap();
        let level_type = InheritableConfig {
            explicit: Some(level_type),
            resolved: level_type,
        };
        let lsp_pacing_interval =
            isis::interfaces::interface::lsp_pacing_interval::DFLT;
        let lsp_rxmt_interval =
            isis::interfaces::interface::lsp_retransmit_interval::DFLT;
        let passive = isis::interfaces::interface::passive::DFLT;
        let csnp_interval = isis::interfaces::interface::csnp_interval::DFLT;
        let hello_padding =
            isis::interfaces::interface::hello_padding::enabled::DFLT;
        let interface_type = isis::interfaces::interface::interface_type::DFLT;
        let interface_type =
            InterfaceType::try_from_yang(interface_type).unwrap();
        let node_flag = isis::interfaces::interface::node_flag::DFLT;
        let hello_interval =
            isis::interfaces::interface::hello_interval::value::DFLT;
        let hello_interval = LevelsCfgWithDefault {
            all: hello_interval,
            l1: None,
            l2: None,
        };
        let hello_multiplier =
            isis::interfaces::interface::hello_multiplier::value::DFLT;
        let hello_multiplier = LevelsCfgWithDefault {
            all: hello_multiplier,
            l1: None,
            l2: None,
        };
        let priority = isis::interfaces::interface::priority::value::DFLT;
        let priority = LevelsCfgWithDefault {
            all: priority,
            l1: None,
            l2: None,
        };
        let metric = isis::interfaces::interface::metric::value::DFLT;
        let metric = LevelsCfgWithDefault {
            all: metric,
            l1: None,
            l2: None,
        };
        let bfd_enabled = isis::interfaces::interface::bfd::enabled::DFLT;
        InterfaceCfg {
            enabled,
            level_type,
            lsp_pacing_interval,
            lsp_rxmt_interval,
            passive,
            csnp_interval,
            hello_padding,
            interface_type,
            node_flag,
            hello_auth: Default::default(),
            hello_interval,
            hello_multiplier,
            priority,
            metric,
            bfd_enabled,
            bfd_params: Default::default(),
            afs: Default::default(),
            mt: Default::default(),
            ext_seqnum_mode: Default::default(),
            trace_opts: Default::default(),
        }
    }
}

impl Default for InterfaceMtCfg {
    fn default() -> InterfaceMtCfg {
        let enabled =
            isis::interfaces::interface::topologies::topology::enabled::DFLT;
        let metric = isis::interfaces::interface::topologies::topology::metric::value::DFLT;
        let metric = LevelsCfgWithDefault {
            all: metric,
            l1: None,
            l2: None,
        };
        InterfaceMtCfg { enabled, metric }
    }
}

impl Default for TraceOptionPacketResolved {
    fn default() -> TraceOptionPacketResolved {
        let disabled = TraceOptionPacketType {
            tx: false,
            rx: false,
        };
        TraceOptionPacketResolved {
            hello: disabled,
            psnp: disabled,
            csnp: disabled,
            lsp: disabled,
        }
    }
}

impl Default for TraceOptionPacketType {
    fn default() -> TraceOptionPacketType {
        let tx = isis::trace_options::flag::send::DFLT;
        let rx = isis::trace_options::flag::receive::DFLT;

        TraceOptionPacketType { tx, rx }
    }
}
