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
use std::sync::Arc;

use arc_swap::ArcSwap;
use holo_northbound::configuration::{ConfigOp, InheritableConfig, Provider, YangConfigOps};
use holo_northbound::error::ApplyError;
use holo_utils::bfd;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::keychain::{Key, Keychains};
use holo_utils::mac_addr::MacAddr;
use holo_utils::protocol::Protocol;
use holo_yang::TryFromYang;
use ipnetwork::IpNetwork;
use prefix_trie::joint::map::JointPrefixMap;

use crate::collections::InterfaceIndex;
use crate::debug::InterfaceInactiveReason;
use crate::instance::Instance;
use crate::interface::{Interface, InterfaceType};
use crate::northbound::notification;
use crate::northbound::yang_gen::config::{
    self, AddressFamilyListChange, AddressFamilyListEntryChange, AddressFamilyListRedistributionChange, ConfigChange, InterLevelPropagationPoliciesLevel1ToLevel2SummaryPrefixesChange,
    InterLevelPropagationPoliciesLevel1ToLevel2SummaryPrefixesEntryChange, InterfaceAddressFamilyListChange, InterfaceChange, InterfaceEntryChange, InterfaceIsisAslaInterfaceAslaChange, InterfaceIsisAslaInterfaceAslaEntryChange,
    InterfaceTopologyChange, InterfaceTopologyEntryChange, InterfaceTraceOptionsFlagChange, InterfaceTraceOptionsFlagEntryChange, NodeTagChange, SpbServiceChange, SpbServiceEntryChange, SpbServiceIsidChange, SpbServiceIsidEntryChange,
    TopologyChange, TopologyEntryChange, TraceOptionsFlagChange, TraceOptionsFlagEntryChange,
};
use crate::northbound::yang_gen::isis;
use crate::packet::auth::AuthMethod;
use crate::packet::iana::{AslaSabmFlags, FloodingAlgo, MtId, PduType};
use crate::packet::{AreaAddr, LevelNumber, LevelType, LevelTypeIterator, SystemId};
use crate::route::RouteFlags;
use crate::{ibus, spf, sr};

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
    InstanceUpdateAuth,
    InterfaceUpdateAuth(InterfaceIndex),
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
    pub auth_resolved: Arc<ArcSwap<Option<AuthMethod>>>,
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
    pub flooding_reduction: InstanceFloodingReductionCfg,
    pub att_suppress: bool,
    pub att_ignore: bool,
    pub sr: InstanceSrCfg,
    pub bier: InstanceBierCfg,
    pub spb: InstanceSpbCfg,
    pub trace_opts: InstanceTraceOptions,
}

#[derive(Debug)]
pub struct InstanceMtCfg {
    pub enabled: bool,
    pub default_metric: LevelsCfgWithDefault<u32>,
}

// Standard application using application-specific link attributes (RFC 9479).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StandardApp {
    RsvpTe,
    SrPolicy,
    Lfa,
}

// Per-application application-specific link attributes configuration.
#[derive(Clone, Copy, Debug, Default)]
pub struct InterfaceAslaCfg {
    pub te_metric: Option<u32>,
    pub admin_group: Option<u32>,
}

#[derive(Debug)]
pub struct InstanceFloodingReductionCfg {
    pub algo: FloodingAlgo,
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

#[derive(Debug, Default)]
pub struct InstanceSpbCfg {
    pub enabled: bool,
    pub services: BTreeMap<SpbServiceKey, SpbServiceCfg>,
}

/// Key for SPB service entries (B-MAC + Base VID).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SpbServiceKey {
    pub bmac: MacAddr,
    pub base_vid: u16,
}

/// Configuration for an SPB service entry.
#[derive(Clone, Debug, Default)]
pub struct SpbServiceCfg {
    pub isids: BTreeMap<u32, SpbIsidCfg>,
}

/// Configuration for an I-SID entry.
#[derive(Clone, Copy, Debug)]
pub struct SpbIsidCfg {
    pub transmit: bool,
    pub receive: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum InstanceTraceOption {
    FloodReduction,
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
    pub flood_reduction: bool,
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
    pub csnp_disable: bool,
    pub hello_padding: bool,
    pub interface_type: InterfaceType,
    pub node_flag: bool,
    pub hello_auth: LevelsCfg<AuthCfg>,
    pub hello_auth_resolved: Arc<ArcSwap<Option<AuthMethod>>>,
    pub hello_interval: LevelsCfgWithDefault<u16>,
    pub hello_multiplier: LevelsCfgWithDefault<u16>,
    pub priority: LevelsCfgWithDefault<u8>,
    pub metric: LevelsCfgWithDefault<u32>,
    pub bfd_enabled: bool,
    pub bfd_params: bfd::ClientCfg,
    pub afs: BTreeSet<AddressFamily>,
    pub mt: HashMap<MtId, InterfaceMtCfg>,
    pub asla: BTreeMap<StandardApp, InterfaceAslaCfg>,
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

// ===== helper functions =====

fn apply_instance(instance: &mut Instance, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ConfigChange::Enabled(enabled) => {
            instance.config.enabled = enabled;
            event_queue.insert(Event::InstanceUpdate);
        }
        ConfigChange::LevelType(level_type) => {
            instance.config.level_type = level_type;
            // TODO: We can do better than a full reset.
            event_queue.insert(Event::InstanceReset);
            event_queue.insert(Event::InstanceLevelTypeUpdate);
        }
        ConfigChange::SystemId(system_id) => {
            if system_id.is_some() {
                event_queue.insert(Event::InstanceReset);
            }
            instance.config.system_id = system_id;
            event_queue.insert(Event::InstanceUpdate);
        }
        ConfigChange::AreaAddress(op, area_addr) => {
            match op {
                ConfigOp::Create => {
                    instance.config.area_addrs.insert(area_addr);
                }
                ConfigOp::Delete => {
                    instance.config.area_addrs.remove(&area_addr);
                }
            }
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::LspMtu(lsp_mtu) => {
            instance.config.lsp_mtu = lsp_mtu;
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::LspLifetime(lsp_lifetime) => {
            instance.config.lsp_lifetime = lsp_lifetime;
            event_queue.insert(Event::RefreshLsps);
        }
        ConfigChange::LspRefresh(lsp_refresh) => {
            instance.config.lsp_refresh = lsp_refresh;
            event_queue.insert(Event::RefreshLsps);
        }
        ConfigChange::PoiTlv(enabled) => {
            instance.config.purge_originator = enabled;
        }
        ConfigChange::NodeTag(keys, change) => {
            apply_node_tag(instance, keys.tag, change, event_queue)?;
        }
        ConfigChange::MetricTypeValue(metric_type) => {
            instance.config.metric_type.all = metric_type;
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::MetricTypeLevel1Value(metric_type) => {
            instance.config.metric_type.l1 = metric_type;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        }
        ConfigChange::MetricTypeLevel2Value(metric_type) => {
            instance.config.metric_type.l2 = metric_type;
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        }
        ConfigChange::DefaultMetricValue(metric) => {
            instance.config.default_metric.all = metric;
        }
        ConfigChange::DefaultMetricLevel1Value(metric) => {
            instance.config.default_metric.l1 = metric;
        }
        ConfigChange::DefaultMetricLevel2Value(metric) => {
            instance.config.default_metric.l2 = metric;
        }
        ConfigChange::AuthenticationKeyChain(keychain) => {
            instance.config.auth.all.keychain = keychain;
            event_queue.insert(Event::InstanceUpdateAuth);
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::AuthenticationKey(key) => {
            instance.config.auth.all.key = key;
            event_queue.insert(Event::InstanceUpdateAuth);
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::AuthenticationKeyId(key_id) => {
            instance.config.auth.all.key_id = key_id;
            event_queue.insert(Event::InstanceUpdateAuth);
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::AuthenticationCryptoAlgorithm(algo) => {
            instance.config.auth.all.algo = algo;
            event_queue.insert(Event::InstanceUpdateAuth);
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::AuthenticationLevel1KeyChain(keychain) => {
            instance.config.auth.l1.keychain = keychain;
            event_queue.insert(Event::InstanceUpdateAuth);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        }
        ConfigChange::AuthenticationLevel1Key(key) => {
            instance.config.auth.l1.key = key;
            event_queue.insert(Event::InstanceUpdateAuth);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        }
        ConfigChange::AuthenticationLevel1KeyId(key_id) => {
            instance.config.auth.l1.key_id = key_id;
            event_queue.insert(Event::InstanceUpdateAuth);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        }
        ConfigChange::AuthenticationLevel1CryptoAlgorithm(algo) => {
            instance.config.auth.l1.algo = algo;
            event_queue.insert(Event::InstanceUpdateAuth);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
        }
        ConfigChange::AuthenticationLevel2KeyChain(keychain) => {
            instance.config.auth.l2.keychain = keychain;
            event_queue.insert(Event::InstanceUpdateAuth);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        }
        ConfigChange::AuthenticationLevel2Key(key) => {
            instance.config.auth.l2.key = key;
            event_queue.insert(Event::InstanceUpdateAuth);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        }
        ConfigChange::AuthenticationLevel2KeyId(key_id) => {
            instance.config.auth.l2.key_id = key_id;
            event_queue.insert(Event::InstanceUpdateAuth);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        }
        ConfigChange::AuthenticationLevel2CryptoAlgorithm(algo) => {
            instance.config.auth.l2.algo = algo;
            event_queue.insert(Event::InstanceUpdateAuth);
            event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
        }
        ConfigChange::AddressFamilyList(keys, change) => {
            apply_address_family(instance, keys.address_family, change, event_queue)?;
        }
        ConfigChange::MplsTeRidIpv4RouterId(addr) => {
            instance.config.ipv4_router_id = addr;
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::MplsTeRidIpv6RouterId(addr) => {
            instance.config.ipv6_router_id = addr;
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::SpfControlPaths(max_paths) => {
            instance.config.max_paths = max_paths;
            event_queue.insert(Event::RerunSpf);
        }
        ConfigChange::SpfControlIetfSpfDelayInitialDelay(initial_delay) => {
            instance.config.spf_initial_delay = initial_delay;
        }
        ConfigChange::SpfControlIetfSpfDelayShortDelay(short_delay) => {
            instance.config.spf_short_delay = short_delay;
        }
        ConfigChange::SpfControlIetfSpfDelayLongDelay(long_delay) => {
            instance.config.spf_long_delay = long_delay;
        }
        ConfigChange::SpfControlIetfSpfDelayHoldDown(hold_down) => {
            instance.config.spf_hold_down = hold_down;
        }
        ConfigChange::SpfControlIetfSpfDelayTimeToLearn(time_to_learn) => {
            instance.config.spf_time_to_learn = time_to_learn;
        }
        ConfigChange::PreferenceInternal(preference) => {
            if let Some(preference) = preference {
                instance.config.preference.internal = preference;
                event_queue.insert(Event::ReinstallRoutes);
            }
        }
        ConfigChange::PreferenceExternal(preference) => {
            if let Some(preference) = preference {
                instance.config.preference.external = preference;
                event_queue.insert(Event::ReinstallRoutes);
            }
        }
        ConfigChange::PreferenceDefault(preference) => {
            if let Some(preference) = preference {
                instance.config.preference.internal = preference;
                instance.config.preference.external = preference;
                event_queue.insert(Event::ReinstallRoutes);
            }
        }
        ConfigChange::OverloadStatus(overload_status) => {
            instance.config.overload_status = overload_status;
            event_queue.insert(Event::OverloadChange(overload_status));
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::Topology(keys, change) => {
            apply_topology(instance, keys.name, change, event_queue)?;
        }
        ConfigChange::Interface(keys, change) => {
            apply_interface(instance, &keys.name, change, event_queue)?;
        }
        ConfigChange::BierMtId(mt_id) => {
            instance.config.bier.mt_id = mt_id.unwrap_or(0);
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::BierBierEnable(enable) => {
            instance.config.bier.enabled = enable;
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::BierBierAdvertise(advertise) => {
            instance.config.bier.advertise = advertise;
        }
        ConfigChange::BierBierReceive(receive) => {
            instance.config.bier.receive = receive;
        }
        ConfigChange::AttachedBitSuppressAdvertisement(enabled) => {
            instance.config.att_suppress = enabled;
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        ConfigChange::AttachedBitIgnoreReception(enabled) => {
            instance.config.att_ignore = enabled;
            event_queue.insert(Event::RerunSpf);
        }
        ConfigChange::InterLevelPropagationPoliciesLevel1ToLevel2SummaryPrefixes(keys, change) => {
            apply_summary_prefix(instance, keys.prefix, change, event_queue)?;
        }
        ConfigChange::FloodingReductionAlgorithm(algo) => {
            instance.config.flooding_reduction.algo = algo;
            event_queue.insert(Event::RerunSpf);
        }
        ConfigChange::TraceOptionsFlag(keys, change) => {
            apply_trace_options(instance, keys.name, change, event_queue)?;
        }
        ConfigChange::SpbEnable(enable) => {
            instance.config.spb.enabled = enable;
        }
        ConfigChange::SpbService(keys, change) => {
            let Ok(bmac) = keys.bmac.parse::<MacAddr>() else {
                return Ok(());
            };
            let key = SpbServiceKey {
                bmac,
                base_vid: keys.base_vid,
            };
            apply_spb_service(instance, key, change)?;
        }
        ConfigChange::SegmentRoutingEnabled(enabled) => {
            instance.config.sr.enabled = enabled;
            event_queue.insert(Event::SrEnabledChange(enabled));
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
    }

    Ok(())
}

fn apply_node_tag(instance: &mut Instance, tag: u32, change: NodeTagChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        NodeTagChange::Create => {
            instance.config.node_tags.insert(tag);
        }
        NodeTagChange::Delete => {
            instance.config.node_tags.remove(&tag);
        }
    }
    for level in LevelType::All {
        event_queue.insert(Event::ReoriginateLsps(level));
    }

    Ok(())
}

fn apply_address_family(instance: &mut Instance, af: AddressFamily, change: AddressFamilyListChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        AddressFamilyListChange::Create => {
            instance.config.afs.insert(af, AddressFamilyCfg::default());
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        AddressFamilyListChange::Delete => {
            instance.config.afs.remove(&af);
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        AddressFamilyListChange::Entry(change) => {
            let af_cfg = instance.config.afs.get_mut(&af).ok_or(ApplyError::EntryNotFound)?;
            match change {
                AddressFamilyListEntryChange::Enabled(enabled) => {
                    af_cfg.enabled = enabled;
                    for level in LevelType::All {
                        event_queue.insert(Event::ReoriginateLsps(level));
                    }
                }
                AddressFamilyListEntryChange::Redistribution(keys, change) => {
                    apply_redistribution(af_cfg, af, keys.level, keys.r#type, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_redistribution(af_cfg: &mut AddressFamilyCfg, af: AddressFamily, level: LevelNumber, protocol: Protocol, change: AddressFamilyListRedistributionChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        AddressFamilyListRedistributionChange::Create => {
            af_cfg.redistribution.insert((level, protocol), Default::default());
            event_queue.insert(Event::RedistributeAdd(af, protocol));
        }
        AddressFamilyListRedistributionChange::Delete => {
            af_cfg.redistribution.remove(&(level, protocol));
            event_queue.insert(Event::RedistributeDelete(af, level, protocol));
        }
    }

    Ok(())
}

fn apply_topology(instance: &mut Instance, mt_id: MtId, change: TopologyChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        TopologyChange::Create => {
            instance.config.mt.insert(mt_id, InstanceMtCfg::default());
            event_queue.insert(Event::InstanceTopologyUpdate);
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        TopologyChange::Delete => {
            instance.config.mt.remove(&mt_id);
            event_queue.insert(Event::InstanceTopologyUpdate);
            for level in LevelType::All {
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        TopologyChange::Entry(change) => {
            let mt_cfg = instance.config.mt.get_mut(&mt_id).ok_or(ApplyError::EntryNotFound)?;
            match change {
                TopologyEntryChange::Enabled(enabled) => {
                    mt_cfg.enabled = enabled;
                    event_queue.insert(Event::InstanceTopologyUpdate);
                    for level in LevelType::All {
                        event_queue.insert(Event::ReoriginateLsps(level));
                    }
                }
                TopologyEntryChange::DefaultMetricValue(metric) => {
                    mt_cfg.default_metric.all = metric;
                }
                TopologyEntryChange::DefaultMetricLevel1Value(metric) => {
                    mt_cfg.default_metric.l1 = metric;
                }
                TopologyEntryChange::DefaultMetricLevel2Value(metric) => {
                    mt_cfg.default_metric.l2 = metric;
                }
            }
        }
    }

    Ok(())
}

fn apply_interface(instance: &mut Instance, ifname: &str, change: InterfaceChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        InterfaceChange::Create => {
            let iface = instance.arenas.interfaces.insert(ifname);
            iface.config.level_type.resolved = iface.config.resolved_level_type(&instance.config);

            event_queue.insert(Event::InterfaceUpdate(iface.index));
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface.index));
            event_queue.insert(Event::InterfaceIbusSub(iface.index));
        }
        InterfaceChange::Delete => {
            let iface = instance.arenas.interfaces.get_by_name(ifname).ok_or(ApplyError::EntryNotFound)?;
            event_queue.insert(Event::InterfaceDelete(iface.index));
        }
        InterfaceChange::Entry(change) => {
            let iface = instance.arenas.interfaces.get_mut_by_name(ifname).ok_or(ApplyError::EntryNotFound)?;
            let iface_idx = iface.index;

            match change {
                InterfaceEntryChange::Enabled(enabled) => {
                    iface.config.enabled = enabled;
                    event_queue.insert(Event::InterfaceUpdate(iface_idx));
                }
                InterfaceEntryChange::LevelType(level_type) => {
                    iface.config.level_type.explicit = Some(level_type);
                    iface.config.level_type.resolved = iface.config.resolved_level_type(&instance.config);

                    // TODO: We can do better than a full reset.
                    event_queue.insert(Event::InterfaceReset(iface_idx));
                }
                InterfaceEntryChange::LspPacingInterval(lsp_pacing_interval) => {
                    iface.config.lsp_pacing_interval = lsp_pacing_interval;
                }
                InterfaceEntryChange::LspRetransmitInterval(lsp_rxmt_interval) => {
                    iface.config.lsp_rxmt_interval = lsp_rxmt_interval;
                }
                InterfaceEntryChange::Passive(passive) => {
                    iface.config.passive = passive;
                    event_queue.insert(Event::InterfaceReset(iface_idx));
                }
                InterfaceEntryChange::CsnpInterval(csnp_interval) => {
                    iface.config.csnp_interval = csnp_interval;
                    event_queue.insert(Event::InterfaceUpdateCsnpInterval(iface_idx));
                }
                InterfaceEntryChange::CsnpDisable(csnp_disable) => {
                    if let Some(csnp_disable) = csnp_disable {
                        iface.config.csnp_disable = csnp_disable;
                        event_queue.insert(Event::InterfaceUpdateCsnpInterval(iface_idx));
                    }
                }
                InterfaceEntryChange::HelloPaddingEnabled(hello_padding) => {
                    iface.config.hello_padding = hello_padding;
                    event_queue.insert(Event::InterfaceRestartNetwork(iface_idx));
                }
                InterfaceEntryChange::InterfaceType(interface_type) => {
                    iface.config.interface_type = interface_type;
                    event_queue.insert(Event::InterfaceReset(iface_idx));
                }
                InterfaceEntryChange::NodeFlag(enabled) => {
                    iface.config.node_flag = enabled;
                    for level in LevelType::All {
                        event_queue.insert(Event::ReoriginateLsps(level));
                    }
                }
                InterfaceEntryChange::HelloAuthenticationKeyChain(keychain) => {
                    iface.config.hello_auth.all.keychain = keychain;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationKey(key) => {
                    iface.config.hello_auth.all.key = key;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationKeyId(key_id) => {
                    iface.config.hello_auth.all.key_id = key_id;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationCryptoAlgorithm(algo) => {
                    iface.config.hello_auth.all.algo = algo;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationLevel1KeyChain(keychain) => {
                    iface.config.hello_auth.l1.keychain = keychain;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationLevel1Key(key) => {
                    iface.config.hello_auth.l1.key = key;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationLevel1KeyId(key_id) => {
                    iface.config.hello_auth.l1.key_id = key_id;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationLevel1CryptoAlgorithm(algo) => {
                    iface.config.hello_auth.l1.algo = algo;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationLevel2KeyChain(keychain) => {
                    iface.config.hello_auth.l2.keychain = keychain;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationLevel2Key(key) => {
                    iface.config.hello_auth.l2.key = key;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationLevel2KeyId(key_id) => {
                    iface.config.hello_auth.l2.key_id = key_id;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloAuthenticationLevel2CryptoAlgorithm(algo) => {
                    iface.config.hello_auth.l2.algo = algo;
                    event_queue.insert(Event::InterfaceUpdateAuth(iface_idx));
                }
                InterfaceEntryChange::HelloIntervalValue(hello_interval) => {
                    iface.config.hello_interval.all = hello_interval;
                    for level in LevelType::All {
                        event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, level));
                    }
                }
                InterfaceEntryChange::HelloIntervalLevel1Value(hello_interval) => {
                    iface.config.hello_interval.l1 = hello_interval;
                    event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
                }
                InterfaceEntryChange::HelloIntervalLevel2Value(hello_interval) => {
                    iface.config.hello_interval.l2 = hello_interval;
                    event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
                }
                InterfaceEntryChange::HelloMultiplierValue(hello_multiplier) => {
                    iface.config.hello_multiplier.all = hello_multiplier;
                    for level in LevelType::All {
                        event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, level));
                    }
                }
                InterfaceEntryChange::HelloMultiplierLevel1Value(hello_multiplier) => {
                    iface.config.hello_multiplier.l1 = hello_multiplier;
                    event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
                }
                InterfaceEntryChange::HelloMultiplierLevel2Value(hello_multiplier) => {
                    iface.config.hello_multiplier.l2 = hello_multiplier;
                    event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
                }
                InterfaceEntryChange::PriorityValue(priority) => {
                    iface.config.priority.all = priority;
                    for level in LevelType::All {
                        event_queue.insert(Event::InterfacePriorityChange(iface_idx, level));
                        event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, level));
                    }
                }
                InterfaceEntryChange::PriorityLevel1Value(priority) => {
                    iface.config.priority.l1 = priority;
                    event_queue.insert(Event::InterfacePriorityChange(iface_idx, LevelNumber::L1));
                    event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
                }
                InterfaceEntryChange::PriorityLevel2Value(priority) => {
                    iface.config.priority.l2 = priority;
                    event_queue.insert(Event::InterfacePriorityChange(iface_idx, LevelNumber::L2));
                    event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
                }
                InterfaceEntryChange::MetricValue(metric) => {
                    iface.config.metric.all = metric;
                    for level in LevelType::All {
                        event_queue.insert(Event::ReoriginateLsps(level));
                    }
                }
                InterfaceEntryChange::MetricLevel1Value(metric) => {
                    iface.config.metric.l1 = metric;
                    event_queue.insert(Event::ReoriginateLsps(LevelNumber::L1));
                }
                InterfaceEntryChange::MetricLevel2Value(metric) => {
                    iface.config.metric.l2 = metric;
                    event_queue.insert(Event::ReoriginateLsps(LevelNumber::L2));
                }
                InterfaceEntryChange::BfdEnabled(enabled) => {
                    iface.config.bfd_enabled = enabled;
                    event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                }
                InterfaceEntryChange::BfdLocalMultiplier(local_multiplier) => {
                    iface.config.bfd_params.local_multiplier = local_multiplier;
                    event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                }
                InterfaceEntryChange::BfdDesiredMinTxInterval(min_tx) => {
                    if let Some(min_tx) = min_tx {
                        iface.config.bfd_params.min_tx = min_tx;
                        event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                    }
                }
                InterfaceEntryChange::BfdRequiredMinRxInterval(min_rx) => {
                    if let Some(min_rx) = min_rx {
                        iface.config.bfd_params.min_rx = min_rx;
                        event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                    }
                }
                InterfaceEntryChange::BfdMinInterval(min_interval) => {
                    if let Some(min_interval) = min_interval {
                        iface.config.bfd_params.min_tx = min_interval;
                        iface.config.bfd_params.min_rx = min_interval;
                        event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                    }
                }
                InterfaceEntryChange::AddressFamilyList(keys, change) => {
                    apply_interface_address_family(iface, keys.address_family, change, event_queue)?;
                }
                InterfaceEntryChange::Topology(keys, change) => {
                    apply_interface_topology(iface, keys.name, change, event_queue)?;
                }
                InterfaceEntryChange::IsisAslaInterfaceAsla(keys, change) => {
                    apply_interface_asla(iface, keys.link_attr_app, change, event_queue)?;
                }
                InterfaceEntryChange::ExtendedSequenceNumberMode(mode) => {
                    iface.config.ext_seqnum_mode.all = mode;
                    for level in LevelType::All {
                        event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, level));
                    }
                }
                InterfaceEntryChange::ExtendedSequenceNumberLevel1Mode(mode) => {
                    iface.config.ext_seqnum_mode.l1 = mode;
                    event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
                }
                InterfaceEntryChange::ExtendedSequenceNumberLevel2Mode(mode) => {
                    iface.config.ext_seqnum_mode.l2 = mode;
                    event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
                }
                InterfaceEntryChange::TraceOptionsFlag(keys, change) => {
                    apply_interface_trace_options(iface, keys.name, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_interface_address_family(iface: &mut Interface, af: AddressFamily, change: InterfaceAddressFamilyListChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        InterfaceAddressFamilyListChange::Create => {
            iface.config.afs.insert(af);
        }
        InterfaceAddressFamilyListChange::Delete => {
            iface.config.afs.remove(&af);
        }
    }
    for level in LevelType::All {
        event_queue.insert(Event::ReoriginateLsps(level));
    }

    Ok(())
}

fn apply_interface_topology(iface: &mut Interface, mt_id: MtId, change: InterfaceTopologyChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let iface_idx = iface.index;

    match change {
        InterfaceTopologyChange::Create => {
            iface.config.mt.insert(mt_id, InterfaceMtCfg::default());
            for level in LevelType::All {
                event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, level));
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        InterfaceTopologyChange::Delete => {
            iface.config.mt.remove(&mt_id);
            for level in LevelType::All {
                event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, level));
                event_queue.insert(Event::ReoriginateLsps(level));
            }
        }
        InterfaceTopologyChange::Entry(change) => {
            let iface_mt_cfg = iface.config.mt.get_mut(&mt_id).ok_or(ApplyError::EntryNotFound)?;
            match change {
                InterfaceTopologyEntryChange::Enabled(enabled) => {
                    iface_mt_cfg.enabled = enabled;
                    for level in LevelType::All {
                        event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, level));
                        event_queue.insert(Event::ReoriginateLsps(level));
                    }
                }
                InterfaceTopologyEntryChange::MetricValue(metric) => {
                    iface_mt_cfg.metric.all = metric;
                    for level in LevelType::All {
                        event_queue.insert(Event::ReoriginateLsps(level));
                    }
                }
                InterfaceTopologyEntryChange::MetricLevel1Value(metric) => {
                    iface_mt_cfg.metric.l1 = metric;
                    for level in LevelType::All {
                        event_queue.insert(Event::ReoriginateLsps(level));
                    }
                }
                InterfaceTopologyEntryChange::MetricLevel2Value(metric) => {
                    iface_mt_cfg.metric.l2 = metric;
                    for level in LevelType::All {
                        event_queue.insert(Event::ReoriginateLsps(level));
                    }
                }
            }
        }
    }

    Ok(())
}

fn apply_interface_asla(iface: &mut Interface, app: StandardApp, change: InterfaceIsisAslaInterfaceAslaChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        InterfaceIsisAslaInterfaceAslaChange::Create => {
            iface.config.asla.insert(app, InterfaceAslaCfg::default());
        }
        InterfaceIsisAslaInterfaceAslaChange::Delete => {
            iface.config.asla.remove(&app);
        }
        InterfaceIsisAslaInterfaceAslaChange::Entry(change) => {
            let asla_cfg = iface.config.asla.get_mut(&app).ok_or(ApplyError::EntryNotFound)?;
            match change {
                InterfaceIsisAslaInterfaceAslaEntryChange::TeMetric(metric) => {
                    asla_cfg.te_metric = metric;
                }
                InterfaceIsisAslaInterfaceAslaEntryChange::AdminGroup(admin_group) => {
                    asla_cfg.admin_group = admin_group.map(|admin_group| admin_group.0.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)));
                }
            }
        }
    }
    for level in LevelType::All {
        event_queue.insert(Event::ReoriginateLsps(level));
    }

    Ok(())
}

fn apply_interface_trace_options(iface: &mut Interface, trace_opt: InterfaceTraceOption, change: InterfaceTraceOptionsFlagChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let iface_idx = iface.index;
    let trace_opts = &mut iface.config.trace_opts;
    match change {
        InterfaceTraceOptionsFlagChange::Create => match trace_opt {
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
        },
        InterfaceTraceOptionsFlagChange::Delete => match trace_opt {
            InterfaceTraceOption::PacketsAll => trace_opts.packets.all = None,
            InterfaceTraceOption::PacketsHello => trace_opts.packets.hello = None,
            InterfaceTraceOption::PacketsPsnp => trace_opts.packets.psnp = None,
            InterfaceTraceOption::PacketsCsnp => trace_opts.packets.csnp = None,
            InterfaceTraceOption::PacketsLsp => trace_opts.packets.lsp = None,
        },
        InterfaceTraceOptionsFlagChange::Entry(change) => {
            let trace_opt_packet = match trace_opt {
                InterfaceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InterfaceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InterfaceTraceOption::PacketsPsnp => trace_opts.packets.psnp.as_mut(),
                InterfaceTraceOption::PacketsCsnp => trace_opts.packets.csnp.as_mut(),
                InterfaceTraceOption::PacketsLsp => trace_opts.packets.lsp.as_mut(),
            };
            let Some(trace_opt_packet) = trace_opt_packet else {
                return Ok(());
            };
            match change {
                InterfaceTraceOptionsFlagEntryChange::Send(enable) => {
                    trace_opt_packet.tx = enable;
                }
                InterfaceTraceOptionsFlagEntryChange::Receive(enable) => {
                    trace_opt_packet.rx = enable;
                }
            }
        }
    }
    event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));

    Ok(())
}

fn apply_summary_prefix(instance: &mut Instance, prefix: IpNetwork, change: InterLevelPropagationPoliciesLevel1ToLevel2SummaryPrefixesChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        InterLevelPropagationPoliciesLevel1ToLevel2SummaryPrefixesChange::Create => {
            instance.config.summaries.insert(prefix, SummaryCfg::default());
        }
        InterLevelPropagationPoliciesLevel1ToLevel2SummaryPrefixesChange::Delete => {
            instance.config.summaries.remove(&prefix);
        }
        InterLevelPropagationPoliciesLevel1ToLevel2SummaryPrefixesChange::Entry(InterLevelPropagationPoliciesLevel1ToLevel2SummaryPrefixesEntryChange::Metric(metric)) => {
            let summary_cfg = instance.config.summaries.get_mut(&prefix).ok_or(ApplyError::EntryNotFound)?;
            summary_cfg.metric = metric;
        }
    }
    event_queue.insert(Event::RerunSpf);

    Ok(())
}

fn apply_trace_options(instance: &mut Instance, trace_opt: InstanceTraceOption, change: TraceOptionsFlagChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let trace_opts = &mut instance.config.trace_opts;
    match change {
        TraceOptionsFlagChange::Create => match trace_opt {
            InstanceTraceOption::FloodReduction => trace_opts.flood_reduction = true,
            InstanceTraceOption::InternalBus => trace_opts.ibus = true,
            InstanceTraceOption::Lsdb => trace_opts.lsdb = true,
            InstanceTraceOption::Spf => trace_opts.spf = true,
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
        },
        TraceOptionsFlagChange::Delete => match trace_opt {
            InstanceTraceOption::FloodReduction => trace_opts.flood_reduction = false,
            InstanceTraceOption::InternalBus => trace_opts.ibus = false,
            InstanceTraceOption::Lsdb => trace_opts.lsdb = false,
            InstanceTraceOption::Spf => trace_opts.spf = false,
            InstanceTraceOption::PacketsAll => trace_opts.packets.all = None,
            InstanceTraceOption::PacketsHello => trace_opts.packets.hello = None,
            InstanceTraceOption::PacketsPsnp => trace_opts.packets.psnp = None,
            InstanceTraceOption::PacketsCsnp => trace_opts.packets.csnp = None,
            InstanceTraceOption::PacketsLsp => trace_opts.packets.lsp = None,
        },
        TraceOptionsFlagChange::Entry(change) => {
            let trace_opt_packet = match trace_opt {
                InstanceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InstanceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InstanceTraceOption::PacketsPsnp => trace_opts.packets.psnp.as_mut(),
                InstanceTraceOption::PacketsCsnp => trace_opts.packets.csnp.as_mut(),
                InstanceTraceOption::PacketsLsp => trace_opts.packets.lsp.as_mut(),
                _ => None,
            };
            let Some(trace_opt_packet) = trace_opt_packet else {
                return Ok(());
            };
            match change {
                TraceOptionsFlagEntryChange::Send(enable) => {
                    trace_opt_packet.tx = enable;
                }
                TraceOptionsFlagEntryChange::Receive(enable) => {
                    trace_opt_packet.rx = enable;
                }
            }
        }
    }
    event_queue.insert(Event::UpdateTraceOptions);

    Ok(())
}

fn apply_spb_service(instance: &mut Instance, key: SpbServiceKey, change: SpbServiceChange) -> Result<(), ApplyError> {
    match change {
        SpbServiceChange::Create => {
            instance.config.spb.services.insert(key, SpbServiceCfg::default());
        }
        SpbServiceChange::Delete => {
            instance.config.spb.services.remove(&key);
        }
        SpbServiceChange::Entry(SpbServiceEntryChange::Isid(keys, change)) => {
            let service = instance.config.spb.services.get_mut(&key).ok_or(ApplyError::EntryNotFound)?;
            apply_spb_isid(service, keys.value, change)?;
        }
    }

    Ok(())
}

fn apply_spb_isid(service: &mut SpbServiceCfg, isid: u32, change: SpbServiceIsidChange) -> Result<(), ApplyError> {
    match change {
        SpbServiceIsidChange::Create => {
            service.isids.insert(isid, SpbIsidCfg::default());
        }
        SpbServiceIsidChange::Delete => {
            service.isids.remove(&isid);
        }
        SpbServiceIsidChange::Entry(change) => {
            let isid_cfg = service.isids.get_mut(&isid).ok_or(ApplyError::EntryNotFound)?;
            match change {
                SpbServiceIsidEntryChange::Transmit(transmit) => {
                    isid_cfg.transmit = transmit;
                }
                SpbServiceIsidEntryChange::Receive(receive) => {
                    isid_cfg.receive = receive;
                }
            }
        }
    }

    Ok(())
}

fn process_event(instance: &mut Instance, event: Event) {
    match event {
        Event::InstanceReset => instance.reset(),
        Event::InstanceUpdate => {
            instance.update();
        }
        Event::InstanceLevelTypeUpdate => {
            for iface in instance.arenas.interfaces.iter_mut() {
                iface.config.level_type.resolved = iface.config.resolved_level_type(&instance.config);
            }
        }
        Event::InstanceTopologyUpdate => {
            if let Some((instance, arenas)) = instance.as_up() {
                for iface in arenas.interfaces.iter_mut().filter(|iface| iface.state.active && !iface.is_passive()) {
                    iface.hello_interval_start(&instance, LevelType::All);
                }
            }
        }
        Event::InterfaceUpdate(iface_idx) => {
            if let Some((mut instance, arenas)) = instance.as_up() {
                let iface = &mut arenas.interfaces[iface_idx];
                if let Err(error) = iface.update(&mut instance, &mut arenas.adjacencies) {
                    error.log();
                }
            }
        }
        Event::InterfaceDelete(iface_idx) => {
            if let Some((mut instance, arenas)) = instance.as_up() {
                let iface = &mut arenas.interfaces[iface_idx];

                // Cancel ibus subscription.
                instance.tx.ibus.interface_unsub(Some(iface.name.clone()));

                // Stop interface if it's active.
                let reason = InterfaceInactiveReason::AdminDown;
                iface.stop(&mut instance, &mut arenas.adjacencies, reason);

                // Update the routing table to remove nexthops that are no
                // longer reachable.
                for route in instance.state.rib_mut(instance.config.level_type).values_mut() {
                    route.nexthops.retain(|_, nexthop| nexthop.iface_idx != iface_idx);
                }
            }

            instance.arenas.interfaces.delete(iface_idx);
        }
        Event::InterfaceReset(iface_idx) => {
            if let Some((mut instance, arenas)) = instance.as_up() {
                let iface = &mut arenas.interfaces[iface_idx];
                if let Err(error) = iface.reset(&mut instance, &mut arenas.adjacencies) {
                    error.log();
                }
            }
        }
        Event::InterfaceRestartNetwork(iface_idx) => {
            if let Some((mut instance, arenas)) = instance.as_up() {
                let iface = &mut arenas.interfaces[iface_idx];
                iface.restart_network_tasks(&mut instance);
            }
        }
        Event::InstanceUpdateAuth => {
            let auth = instance.config.auth.all.method(&instance.shared.keychains);
            instance.config.auth_resolved.store(Arc::new(auth));
        }
        Event::InterfaceUpdateAuth(iface_idx) => {
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let auth = iface.config.hello_auth.all.method(&instance.shared.keychains);
            iface.config.hello_auth_resolved.store(Arc::new(auth));
        }
        Event::InterfacePriorityChange(iface_idx, level) => {
            let Some((instance, arenas)) = instance.as_up() else {
                return;
            };
            let iface = &mut arenas.interfaces[iface_idx];

            // Schedule new DIS election.
            if iface.state.active && !iface.is_passive() && iface.config.interface_type == InterfaceType::Broadcast {
                instance.tx.protocol_input.dis_election(iface.id, level);
            }
        }
        Event::InterfaceUpdateHelloInterval(iface_idx, level) => {
            let Some((instance, arenas)) = instance.as_up() else {
                return;
            };
            let iface = &mut arenas.interfaces[iface_idx];
            if iface.state.active && !iface.is_passive() {
                iface.hello_interval_start(&instance, level);
            }
        }
        Event::InterfaceUpdateCsnpInterval(iface_idx) => {
            let Some((instance, arenas)) = instance.as_up() else {
                return;
            };
            let iface = &mut arenas.interfaces[iface_idx];
            if iface.config.csnp_disable {
                iface.csnp_interval_stop(LevelType::All);
            } else {
                iface.csnp_interval_start(&instance, LevelType::All);
            }
        }
        Event::InterfaceBfdChange(iface_idx) => {
            let Some((instance, arenas)) = instance.as_up() else {
                return;
            };
            let iface = &mut arenas.interfaces[iface_idx];
            iface.with_adjacencies(&mut arenas.adjacencies, |iface, adj| {
                if iface.config.bfd_enabled {
                    adj.bfd_update_sessions(iface, &instance, true);
                } else {
                    adj.bfd_clear_sessions(&instance);
                }
            });
        }
        Event::InterfaceUpdateTraceOptions(iface_idx) => {
            let iface = &mut instance.arenas.interfaces[iface_idx];
            iface.config.update_trace_options(&instance.config);
        }
        Event::InterfaceIbusSub(iface_idx) => {
            let iface = &instance.arenas.interfaces[iface_idx];
            instance.tx.ibus.interface_sub(Some(iface.name.clone()), None);
        }
        Event::ReoriginateLsps(level) => {
            if let Some((mut instance, _)) = instance.as_up() {
                instance.schedule_lsp_origination(level);
            }
        }
        Event::RefreshLsps => {
            if let Some((instance, arenas)) = instance.as_up() {
                let system_id = instance.config.system_id.unwrap();
                for level in instance.config.levels() {
                    for lse in instance.state.lsdb.get(level).iter_for_system_id(&arenas.lsp_entries, system_id).filter(|lse| lse.data.rem_lifetime != 0) {
                        instance.tx.protocol_input.lsp_refresh(level, lse.id);
                    }
                }
            }
        }
        Event::RerunSpf => {
            if let Some((instance, _)) = instance.as_up() {
                for level in instance.config.levels() {
                    instance.tx.protocol_input.spf_delay_event(level, spf::fsm::Event::ConfigChange);
                }
            }
        }
        Event::ReinstallRoutes => {
            if let Some((instance, arenas)) = instance.as_up() {
                for (prefix, route) in instance.state.rib(instance.config.level_type).iter().filter(|(_, route)| route.flags.contains(RouteFlags::INSTALLED)) {
                    let distance = route.distance(instance.config);
                    ibus::tx::route_install(&instance.tx.ibus, prefix, route, None, distance, &arenas.interfaces);
                }
            }
        }
        Event::OverloadChange(overload_status) => {
            if let Some((instance, _)) = instance.as_up() {
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
            let Some((instance, arenas)) = instance.as_up() else {
                return;
            };

            // Iterate over all existing adjacencies.
            for iface in arenas.interfaces.iter_mut() {
                iface.with_adjacencies(&mut arenas.adjacencies, |iface, adj| {
                    if enabled {
                        sr::adj_sids_add(&instance, iface, adj);
                    } else {
                        sr::adj_sids_del(&instance, adj);
                    }
                });
            }
        }
        Event::RedistributeAdd(af, protocol) => {
            // Subscribe to route redistribution for the given protocol and
            // address family.
            instance.tx.ibus.route_redistribute_sub(protocol, Some(af));
        }
        Event::RedistributeDelete(af, level, protocol) => {
            // Unsubscribe from route redistribution for the given protocol
            // and address family.
            instance.tx.ibus.route_redistribute_unsub(protocol, Some(af));

            // Remove redistributed routes.
            let routes = instance.system.routes.get_mut(level);
            routes.retain(|prefix, route| prefix.address_family() != af || route.protocol != protocol);

            // Schedule LSP reorigination.
            if let Some((mut instance, _)) = instance.as_up() {
                instance.schedule_lsp_origination(level);
            }
        }
        Event::UpdateTraceOptions => {
            for iface in instance.arenas.interfaces.iter_mut() {
                iface.config.update_trace_options(&instance.config);
            }
        }
    }
}

// ===== impl Instance =====

impl Provider for Instance {
    type Event = Event;
    type Resource = Resource;
    type Change = ConfigChange;

    const YANG_OPS_CONFIG: YangConfigOps<ConfigChange> = config::YANG_OPS_CONFIG;

    fn apply(&mut self, change: ConfigChange, _resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
        apply_instance(self, change, event_queue)
    }

    fn process_event(&mut self, event: Event) {
        process_event(self, event);
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
        topologies.extend(self.mt.iter().filter_map(|(mt_id, mt_cfg)| mt_cfg.enabled.then_some(*mt_id)));
        topologies
    }
}

impl InterfaceCfg {
    // Checks if the specified address family is enabled.
    pub(crate) fn is_af_enabled(&self, af: AddressFamily, instance_cfg: &InstanceCfg) -> bool {
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
    pub(crate) fn topologies<T>(&self, instance_cfg: &InstanceCfg) -> BTreeSet<T>
    where
        MtId: Into<T>,
        T: Ord,
    {
        instance_cfg.topologies().into_iter().filter(|mt_id| self.is_topology_enabled(*mt_id)).map(Into::into).collect()
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
    pub(crate) fn topology_metric(&self, mt_id: MtId, level: impl Into<LevelType>) -> u32 {
        const DFLT_METRIC: u32 = isis::interfaces::interface::topologies::topology::metric::value::DFLT;
        let level = level.into();
        self.mt.get(&mt_id).map(|mt_cfg| mt_cfg.metric.get(level)).unwrap_or(DFLT_METRIC)
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
        let hello = iface_trace_opts.hello.or(iface_trace_opts.all).or(instance_trace_opts.hello).or(instance_trace_opts.all).unwrap_or(disabled);
        let psnp = iface_trace_opts.psnp.or(iface_trace_opts.all).or(instance_trace_opts.psnp).or(instance_trace_opts.all).unwrap_or(disabled);
        let csnp = iface_trace_opts.csnp.or(iface_trace_opts.all).or(instance_trace_opts.csnp).or(instance_trace_opts.all).unwrap_or(disabled);
        let lsp = iface_trace_opts.lsp.or(iface_trace_opts.all).or(instance_trace_opts.lsp).or(instance_trace_opts.all).unwrap_or(disabled);

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

impl StandardApp {
    // Returns the Standard Application Identifier Bit Mask bit associated with
    // this application.
    pub(crate) fn sabm(&self) -> AslaSabmFlags {
        match self {
            StandardApp::RsvpTe => AslaSabmFlags::R,
            StandardApp::SrPolicy => AslaSabmFlags::S,
            StandardApp::Lfa => AslaSabmFlags::F,
        }
    }
}

impl TraceOptionPacketResolved {
    pub(crate) fn tx(&self, pdu_type: PduType) -> bool {
        match pdu_type {
            PduType::HelloP2P | PduType::HelloLanL1 | PduType::HelloLanL2 => self.hello.tx,
            PduType::LspL1 | PduType::LspL2 => self.lsp.tx,
            PduType::CsnpL1 | PduType::CsnpL2 => self.csnp.tx,
            PduType::PsnpL1 | PduType::PsnpL2 => self.psnp.tx,
        }
    }

    pub(crate) fn rx(&self, pdu_type: PduType) -> bool {
        match pdu_type {
            PduType::HelloP2P | PduType::HelloLanL1 | PduType::HelloLanL2 => self.hello.rx,
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
        let spf_initial_delay = isis::spf_control::ietf_spf_delay::initial_delay::DFLT;
        let spf_short_delay = isis::spf_control::ietf_spf_delay::short_delay::DFLT;
        let spf_long_delay = isis::spf_control::ietf_spf_delay::long_delay::DFLT;
        let spf_hold_down = isis::spf_control::ietf_spf_delay::hold_down::DFLT;
        let spf_time_to_learn = isis::spf_control::ietf_spf_delay::time_to_learn::DFLT;
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
            auth_resolved: Default::default(),
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
            flooding_reduction: Default::default(),
            att_suppress,
            att_ignore,
            sr: Default::default(),
            bier: Default::default(),
            spb: Default::default(),
            trace_opts: Default::default(),
        }
    }
}

impl Default for InstanceMtCfg {
    fn default() -> Self {
        let enabled = isis::topologies::topology::enabled::DFLT;
        let default_metric = isis::topologies::topology::default_metric::value::DFLT;
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

impl Default for InstanceFloodingReductionCfg {
    fn default() -> Self {
        let algo = isis::flooding_reduction::algorithm::DFLT;
        let algo = FloodingAlgo::try_from_yang(algo).unwrap();
        Self {
            algo,
        }
    }
}

impl Default for InstanceSrCfg {
    fn default() -> Self {
        let enabled = isis::segment_routing::enabled::DFLT;
        Self {
            enabled,
        }
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

impl Default for SpbIsidCfg {
    fn default() -> Self {
        let transmit = isis::spb::service::isid::transmit::DFLT;
        let receive = isis::spb::service::isid::receive::DFLT;
        Self {
            transmit,
            receive,
        }
    }
}

impl Default for AddressFamilyCfg {
    fn default() -> AddressFamilyCfg {
        let enabled = isis::address_families::address_family_list::enabled::DFLT;

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

        Preference {
            internal,
            external,
        }
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
        let lsp_pacing_interval = isis::interfaces::interface::lsp_pacing_interval::DFLT;
        let lsp_rxmt_interval = isis::interfaces::interface::lsp_retransmit_interval::DFLT;
        let passive = isis::interfaces::interface::passive::DFLT;
        let csnp_interval = isis::interfaces::interface::csnp_interval::DFLT;
        let csnp_disable = isis::interfaces::interface::csnp_disable::DFLT;
        let hello_padding = isis::interfaces::interface::hello_padding::enabled::DFLT;
        let interface_type = isis::interfaces::interface::interface_type::DFLT;
        let interface_type = InterfaceType::try_from_yang(interface_type).unwrap();
        let node_flag = isis::interfaces::interface::node_flag::DFLT;
        let hello_interval = isis::interfaces::interface::hello_interval::value::DFLT;
        let hello_interval = LevelsCfgWithDefault {
            all: hello_interval,
            l1: None,
            l2: None,
        };
        let hello_multiplier = isis::interfaces::interface::hello_multiplier::value::DFLT;
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
            csnp_disable,
            hello_padding,
            interface_type,
            node_flag,
            hello_auth: Default::default(),
            hello_auth_resolved: Default::default(),
            hello_interval,
            hello_multiplier,
            priority,
            metric,
            bfd_enabled,
            bfd_params: Default::default(),
            afs: Default::default(),
            mt: Default::default(),
            asla: Default::default(),
            ext_seqnum_mode: Default::default(),
            trace_opts: Default::default(),
        }
    }
}

impl Default for InterfaceMtCfg {
    fn default() -> InterfaceMtCfg {
        let enabled = isis::interfaces::interface::topologies::topology::enabled::DFLT;
        let metric = isis::interfaces::interface::topologies::topology::metric::value::DFLT;
        let metric = LevelsCfgWithDefault {
            all: metric,
            l1: None,
            l2: None,
        };
        InterfaceMtCfg {
            enabled,
            metric,
        }
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

        TraceOptionPacketType {
            tx,
            rx,
        }
    }
}
