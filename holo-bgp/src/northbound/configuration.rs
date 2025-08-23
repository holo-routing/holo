//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![allow(clippy::derivable_impls)]

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, LazyLock as Lazy};

use arc_swap::ArcSwap;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};
use holo_northbound::yang::control_plane_protocol::bgp;
use holo_utils::bgp::AfiSafi;
use holo_utils::ip::{AddressFamily, IpAddrKind};
use holo_utils::policy::{ApplyPolicyCfg, DefaultPolicyType};
use holo_utils::protocol::Protocol;
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;

use crate::af::{Ipv4Unicast, Ipv6Unicast};
use crate::instance::{Instance, InstanceUpView};
use crate::neighbor::{Neighbor, PeerType, fsm};
use crate::network;
use crate::packet::consts::{CeaseSubcode, ErrorCode};
use crate::packet::message::{Message, NotificationMsg};
use crate::rib::RouteOrigin;

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    AfiSafi(AfiSafi),
    Redistribution(AfiSafi, Protocol),
    TraceOption(InstanceTraceOption),
    Neighbor(IpAddr),
    NeighborAfiSafi(IpAddr, AfiSafi),
    NeighborTraceOption(IpAddr, NeighborTraceOption),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceUpdate,
    NeighborUpdate(IpAddr),
    NeighborDelete(IpAddr),
    NeighborReset(IpAddr, NotificationMsg),
    NeighborUpdateAuth(IpAddr),
    RedistributeIbusSub(Protocol, AddressFamily),
    RedistributeDelete(Protocol, AddressFamily, AfiSafi),
    UpdateTraceOptions,
}

pub static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {
    pub asn: u32,
    pub identifier: Option<Ipv4Addr>,
    pub distance: DistanceCfg,
    pub multipath: MultipathCfg,
    pub route_selection: RouteSelectionCfg,
    pub apply_policy: ApplyPolicyCfg,
    pub afi_safi: BTreeMap<AfiSafi, InstanceAfiSafiCfg>,
    pub reject_as_sets: bool,
    pub trace_opts: InstanceTraceOptions,
}

#[derive(Debug)]
pub struct DistanceCfg {
    pub external: u8,
    pub internal: u8,
}

#[derive(Debug)]
pub struct MultipathCfg {
    pub enabled: bool,
    pub ebgp_allow_multiple_as: bool,
    pub ebgp_max_paths: u32,
    pub ibgp_max_paths: u32,
}

#[derive(Debug)]
pub struct InstanceAfiSafiCfg {
    pub enabled: bool,
    pub multipath: MultipathCfg,
    pub route_selection: RouteSelectionCfg,
    pub prefix_limit: PrefixLimitCfg,
    pub send_default_route: bool,
    pub apply_policy: ApplyPolicyCfg,
    pub redistribution: HashMap<Protocol, RedistributionCfg>,
}

#[derive(Clone, Copy, Debug)]
pub enum InstanceTraceOption {
    Events,
    InternalBus,
    Nht,
    PacketsAll,
    PacketsOpen,
    PacketsUpdate,
    PacketsNotification,
    PacketsKeepalive,
    PacketsRefresh,
    Route,
}

#[derive(Debug, Default)]
pub struct InstanceTraceOptions {
    pub events: bool,
    pub ibus: bool,
    pub nht: bool,
    pub packets: TraceOptionPacket,
    pub route: bool,
}

#[derive(Debug)]
pub struct NeighborCfg {
    pub enabled: bool,
    pub peer_as: u32,
    pub local_as: Option<u32>,
    pub private_as_remove: Option<PrivateAsRemove>,
    pub timers: NeighborTimersCfg,
    pub transport: NeighborTransportCfg,
    pub log_neighbor_state_changes: bool,
    pub as_path_options: AsPathOptions,
    pub apply_policy: ApplyPolicyCfg,
    pub prefix_limit: PrefixLimitCfg,
    pub afi_safi: BTreeMap<AfiSafi, NeighborAfiSafiCfg>,
    pub trace_opts: NeighborTraceOptions,
}

#[derive(Debug)]
pub struct NeighborTimersCfg {
    pub connect_retry_interval: u16,
    pub holdtime: u16,
    pub keepalive: Option<u16>,
    pub min_as_orig_interval: Option<u16>,
    pub min_route_adv_interval: Option<u16>,
}

#[derive(Debug)]
pub struct NeighborTransportCfg {
    // TODO: this can be an interface name too.
    pub local_addr: Option<IpAddr>,
    pub tcp_mss: Option<u16>,
    pub ebgp_multihop_enabled: bool,
    pub ebgp_multihop_ttl: Option<u8>,
    pub passive_mode: bool,
    pub ttl_security: Option<u8>,
    pub secure_session_enabled: bool,
    pub md5_key: Option<String>,
}

#[derive(Debug)]
pub struct NeighborAfiSafiCfg {
    pub enabled: bool,
    pub prefix_limit: PrefixLimitCfg,
    pub send_default_route: bool,
    pub apply_policy: ApplyPolicyCfg,
}

#[derive(Clone, Copy, Debug)]
pub enum NeighborTraceOption {
    Events,
    PacketsAll,
    PacketsOpen,
    PacketsUpdate,
    PacketsNotification,
    PacketsKeepalive,
    PacketsRefresh,
}

#[derive(Debug, Default)]
pub struct NeighborTraceOptions {
    pub events: Option<bool>,
    pub events_resolved: bool,
    pub packets: TraceOptionPacket,
    pub packets_resolved: Arc<ArcSwap<TraceOptionPacketResolved>>,
}

#[derive(Debug)]
pub struct RouteSelectionCfg {
    pub always_compare_med: bool,
    pub ignore_as_path_length: bool,
    pub external_compare_router_id: bool,
    pub ignore_next_hop_igp_metric: bool,
    pub enable_med: bool,
}

#[derive(Debug)]
pub struct PrefixLimitCfg {
    pub max_prefixes: Option<u32>,
    pub warning_threshold_pct: Option<u8>,
    pub teardown: bool,
    pub idle_time: Option<u32>,
}

#[derive(Debug, Default)]
pub struct RedistributionCfg {}

#[derive(Debug)]
pub struct AsPathOptions {
    pub allow_own_as: u8,
    pub replace_peer_as: bool,
    pub disable_peer_as_filter: bool,
}

#[derive(Debug)]
pub enum PrivateAsRemove {
    RemoveAll,
    ReplaceAll,
}

#[derive(Debug, Default)]
pub struct TraceOptionPacket {
    pub all: Option<TraceOptionPacketType>,
    pub open: Option<TraceOptionPacketType>,
    pub update: Option<TraceOptionPacketType>,
    pub notification: Option<TraceOptionPacketType>,
    pub keepalive: Option<TraceOptionPacketType>,
    pub refresh: Option<TraceOptionPacketType>,
}

#[derive(Clone, Copy, Debug)]
pub struct TraceOptionPacketResolved {
    pub open: TraceOptionPacketType,
    pub update: TraceOptionPacketType,
    pub notification: TraceOptionPacketType,
    pub keepalive: TraceOptionPacketType,
    pub refresh: TraceOptionPacketType,
}

#[derive(Clone, Copy, Debug)]
pub struct TraceOptionPacketType {
    pub tx: bool,
    pub rx: bool,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(bgp::global::PATH)
        .create_apply(|_instance, _args| {
        })
        .delete_apply(|_instance, _args| {
        })
        .path(bgp::global::r#as::PATH)
        .modify_apply(|instance, args| {
            let asn = args.dnode.get_u32();
            instance.config.asn = asn;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
        })
        .path(bgp::global::identifier::PATH)
        .modify_apply(|instance, args| {
            let identifier = args.dnode.get_ipv4();
            instance.config.identifier = Some(identifier);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
        })
        .delete_apply(|instance, args| {
            instance.config.identifier = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
        })
        .path(bgp::global::distance::external::PATH)
        .modify_apply(|instance, args| {
            let distance = args.dnode.get_u8();
            instance.config.distance.external = distance;
        })
        .path(bgp::global::distance::internal::PATH)
        .modify_apply(|instance, args| {
            let distance = args.dnode.get_u8();
            instance.config.distance.internal = distance;
        })
        .path(bgp::global::use_multiple_paths::enabled::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.multipath.enabled = enabled;
        })
        .path(bgp::global::use_multiple_paths::ebgp::allow_multiple_as::PATH)
        .modify_apply(|instance, args| {
            let allow = args.dnode.get_bool();
            instance.config.multipath.ebgp_allow_multiple_as = allow;
        })
        .path(bgp::global::use_multiple_paths::ebgp::maximum_paths::PATH)
        .modify_apply(|instance, args| {
            let max = args.dnode.get_u32();
            instance.config.multipath.ebgp_max_paths = max;
        })
        .path(bgp::global::use_multiple_paths::ibgp::maximum_paths::PATH)
        .modify_apply(|instance, args| {
            let max = args.dnode.get_u32();
            instance.config.multipath.ibgp_max_paths = max;
        })
        .path(bgp::global::route_selection_options::always_compare_med::PATH)
        .modify_apply(|instance, args| {
            let compare = args.dnode.get_bool();
            instance.config.route_selection.always_compare_med = compare;
        })
        .path(bgp::global::route_selection_options::ignore_as_path_length::PATH)
        .modify_apply(|instance, args| {
            let ignore = args.dnode.get_bool();
            instance.config.route_selection.ignore_as_path_length = ignore;
        })
        .path(bgp::global::route_selection_options::external_compare_router_id::PATH)
        .modify_apply(|instance, args| {
            let compare = args.dnode.get_bool();
            instance.config.route_selection.external_compare_router_id = compare;
        })
        .path(bgp::global::route_selection_options::ignore_next_hop_igp_metric::PATH)
        .modify_apply(|instance, args| {
            let ignore = args.dnode.get_bool();
            instance.config.route_selection.ignore_next_hop_igp_metric = ignore;
        })
        .path(bgp::global::route_selection_options::enable_med::PATH)
        .modify_apply(|instance, args| {
            let enable = args.dnode.get_bool();
            instance.config.route_selection.enable_med = enable;
        })
        .path(bgp::global::afi_safis::afi_safi::PATH)
        .create_apply(|instance, args| {
            let afi_safi = args.dnode.get_string_relative("./name").unwrap();
            let afi_safi = AfiSafi::try_from_yang(&afi_safi).unwrap();
            instance.config.afi_safi.insert(afi_safi, Default::default());
        })
        .delete_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();

            instance.config.afi_safi.remove(&afi_safi);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let afi_safi = dnode.get_string_relative("./name").unwrap();
            let afi_safi = AfiSafi::try_from_yang(&afi_safi).unwrap();
            ListEntry::AfiSafi(afi_safi)
        })
        .path(bgp::global::afi_safis::afi_safi::enabled::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let enabled = args.dnode.get_bool();
            afi_safi.enabled = enabled;
        })
        .path(bgp::global::afi_safis::afi_safi::route_selection_options::always_compare_med::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let compare = args.dnode.get_bool();
            afi_safi.route_selection.always_compare_med = compare;
        })
        .path(bgp::global::afi_safis::afi_safi::route_selection_options::ignore_as_path_length::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let ignore = args.dnode.get_bool();
            afi_safi.route_selection.ignore_as_path_length = ignore;
        })
        .path(bgp::global::afi_safis::afi_safi::route_selection_options::external_compare_router_id::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let compare = args.dnode.get_bool();
            afi_safi.route_selection.external_compare_router_id = compare;
        })
        .path(bgp::global::afi_safis::afi_safi::route_selection_options::ignore_next_hop_igp_metric::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let ignore = args.dnode.get_bool();
            afi_safi.route_selection.ignore_next_hop_igp_metric = ignore;
        })
        .path(bgp::global::afi_safis::afi_safi::route_selection_options::enable_med::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let enable = args.dnode.get_bool();
            afi_safi.route_selection.enable_med = enable;
        })
        .path(bgp::global::afi_safis::afi_safi::use_multiple_paths::enabled::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let enabled = args.dnode.get_bool();
            afi_safi.multipath.enabled = enabled;
        })
        .path(bgp::global::afi_safis::afi_safi::use_multiple_paths::ebgp::allow_multiple_as::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let allow = args.dnode.get_bool();
            afi_safi.multipath.ebgp_allow_multiple_as = allow;
        })
        .path(bgp::global::afi_safis::afi_safi::use_multiple_paths::ebgp::maximum_paths::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let max = args.dnode.get_u32();
            afi_safi.multipath.ebgp_max_paths = max;
        })
        .path(bgp::global::afi_safis::afi_safi::use_multiple_paths::ibgp::maximum_paths::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let max = args.dnode.get_u32();
            afi_safi.multipath.ibgp_max_paths = max;
        })
        .path(bgp::global::afi_safis::afi_safi::apply_policy::import_policy::PATH)
        .create_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let policy = args.dnode.get_string();
            afi_safi.apply_policy.import_policy.insert(policy);
        })
        .delete_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let policy = args.dnode.get_string();
            afi_safi.apply_policy.import_policy.remove(&policy);
        })
        .path(bgp::global::afi_safis::afi_safi::apply_policy::default_import_policy::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let default = args.dnode.get_string();
            let default = DefaultPolicyType::try_from_yang(&default).unwrap();
            afi_safi.apply_policy.default_import_policy = default;
        })
        .path(bgp::global::afi_safis::afi_safi::apply_policy::export_policy::PATH)
        .create_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let policy = args.dnode.get_string();
            afi_safi.apply_policy.export_policy.insert(policy);
        })
        .delete_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let policy = args.dnode.get_string();
            afi_safi.apply_policy.export_policy.remove(&policy);
        })
        .path(bgp::global::afi_safis::afi_safi::apply_policy::default_export_policy::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let default = args.dnode.get_string();
            let default = DefaultPolicyType::try_from_yang(&default).unwrap();
            afi_safi.apply_policy.default_export_policy = default;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv4_unicast::prefix_limit::max_prefixes::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let max = args.dnode.get_u32();
            afi_safi.prefix_limit.max_prefixes = Some(max);
        })
        .delete_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.max_prefixes = None;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv4_unicast::prefix_limit::warning_threshold_pct::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let threshold = args.dnode.get_u8();
            afi_safi.prefix_limit.warning_threshold_pct = Some(threshold);
        })
        .delete_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.warning_threshold_pct = None;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv4_unicast::prefix_limit::teardown::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let teardown = args.dnode.get_bool();
            afi_safi.prefix_limit.teardown = teardown;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv4_unicast::prefix_limit::idle_time::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let idle_time = args.dnode.get_string();
            let idle_time: u32 = idle_time.parse().unwrap();
            afi_safi.prefix_limit.idle_time = Some(idle_time);
        })
        .delete_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.idle_time = None;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv4_unicast::send_default_route::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let send = args.dnode.get_bool();
            afi_safi.send_default_route = send;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv4_unicast::redistribution::PATH)
        .create_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let protocol = args.dnode.get_string_relative("./type").unwrap();
            let protocol = Protocol::try_from_yang(&protocol).unwrap();
            afi_safi.redistribution.insert(protocol, Default::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::RedistributeIbusSub(protocol, AddressFamily::Ipv4));
        })
        .delete_apply(|instance, args| {
            let (afi_safi, protocol) = args.list_entry.into_redistribution().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.redistribution.remove(&protocol);

            let event_queue = args.event_queue;
            event_queue.insert(Event::RedistributeDelete(protocol, AddressFamily::Ipv4, AfiSafi::Ipv4Unicast));
        })
        .lookup(|_instance, list_entry, dnode| {
            let afi_safi = list_entry.into_afi_safi().unwrap();
            let protocol = dnode.get_string_relative("./type").unwrap();
            let protocol = Protocol::try_from_yang(&protocol).unwrap();
            ListEntry::Redistribution(afi_safi, protocol)
        })
        .path(bgp::global::afi_safis::afi_safi::ipv6_unicast::prefix_limit::max_prefixes::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let max = args.dnode.get_u32();
            afi_safi.prefix_limit.max_prefixes = Some(max);
        })
        .delete_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.max_prefixes = None;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv6_unicast::prefix_limit::warning_threshold_pct::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let threshold = args.dnode.get_u8();
            afi_safi.prefix_limit.warning_threshold_pct = Some(threshold);
        })
        .delete_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.warning_threshold_pct = None;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv6_unicast::prefix_limit::teardown::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let teardown = args.dnode.get_bool();
            afi_safi.prefix_limit.teardown = teardown;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv6_unicast::prefix_limit::idle_time::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let idle_time = args.dnode.get_string();
            let idle_time: u32 = idle_time.parse().unwrap();
            afi_safi.prefix_limit.idle_time = Some(idle_time);
        })
        .delete_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.idle_time = None;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv6_unicast::send_default_route::PATH)
        .modify_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let send = args.dnode.get_bool();
            afi_safi.send_default_route = send;
        })
        .path(bgp::global::afi_safis::afi_safi::ipv6_unicast::redistribution::PATH)
        .create_apply(|instance, args| {
            let afi_safi = args.list_entry.into_afi_safi().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            let protocol = args.dnode.get_string_relative("./type").unwrap();
            let protocol = Protocol::try_from_yang(&protocol).unwrap();
            afi_safi.redistribution.insert(protocol, Default::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::RedistributeIbusSub(protocol, AddressFamily::Ipv6));
        })
        .delete_apply(|instance, args| {
            let (afi_safi, protocol) = args.list_entry.into_redistribution().unwrap();
            let afi_safi = instance.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.redistribution.remove(&protocol);

            let event_queue = args.event_queue;
            event_queue.insert(Event::RedistributeDelete(protocol, AddressFamily::Ipv6, AfiSafi::Ipv6Unicast));
        })
        .lookup(|_instance, list_entry, dnode| {
            let afi_safi = list_entry.into_afi_safi().unwrap();
            let protocol = dnode.get_string_relative("./type").unwrap();
            let protocol = Protocol::try_from_yang(&protocol).unwrap();
            ListEntry::Redistribution(afi_safi, protocol)
        })
        .path(bgp::global::apply_policy::import_policy::PATH)
        .create_apply(|instance, args| {
            let policy = args.dnode.get_string();
            instance.config.apply_policy.import_policy.insert(policy);
        })
        .delete_apply(|instance, args| {
            let policy = args.dnode.get_string();
            instance.config.apply_policy.import_policy.remove(&policy);
        })
        .path(bgp::global::apply_policy::default_import_policy::PATH)
        .modify_apply(|instance, args| {
            let default = args.dnode.get_string();
            let default = DefaultPolicyType::try_from_yang(&default).unwrap();
            instance.config.apply_policy.default_import_policy = default;
        })
        .path(bgp::global::apply_policy::export_policy::PATH)
        .create_apply(|instance, args| {
            let policy = args.dnode.get_string();
            instance.config.apply_policy.export_policy.insert(policy);
        })
        .delete_apply(|instance, args| {
            let policy = args.dnode.get_string();
            instance.config.apply_policy.export_policy.remove(&policy);
        })
        .path(bgp::global::apply_policy::default_export_policy::PATH)
        .modify_apply(|instance, args| {
            let default = args.dnode.get_string();
            let default = DefaultPolicyType::try_from_yang(&default).unwrap();
            instance.config.apply_policy.default_export_policy = default;
        })
        .path(bgp::global::reject_as_sets::PATH)
        .modify_apply(|instance, args| {
            let reject = args.dnode.get_bool();
            instance.config.reject_as_sets = reject;
        })
        .path(bgp::global::trace_options::flag::PATH)
        .create_apply(|instance, args| {
            let trace_opt = args.dnode.get_string_relative("name").unwrap();
            let trace_opt = InstanceTraceOption::try_from_yang(&trace_opt).unwrap();
            let trace_opts = &mut instance.config.trace_opts;
            match trace_opt {
                InstanceTraceOption::InternalBus => trace_opts.ibus = true,
                InstanceTraceOption::Nht => trace_opts.nht = true,
                InstanceTraceOption::Events => trace_opts.events = true,
                InstanceTraceOption::PacketsAll => {
                    trace_opts.packets.all.get_or_insert_default();
                }
                InstanceTraceOption::PacketsOpen => {
                    trace_opts.packets.open.get_or_insert_default();
                }
                InstanceTraceOption::PacketsUpdate => {
                    trace_opts.packets.update.get_or_insert_default();
                }
                InstanceTraceOption::PacketsNotification => {
                    trace_opts.packets.notification.get_or_insert_default();
                }
                InstanceTraceOption::PacketsKeepalive => {
                    trace_opts.packets.keepalive.get_or_insert_default();
                }
                InstanceTraceOption::PacketsRefresh => {
                    trace_opts.packets.refresh.get_or_insert_default();
                }
                InstanceTraceOption::Route => trace_opts.route = true,
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .delete_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let trace_opts = &mut instance.config.trace_opts;
            match trace_opt {
                InstanceTraceOption::Events => trace_opts.events = false,
                InstanceTraceOption::InternalBus => trace_opts.ibus = false,
                InstanceTraceOption::Nht => trace_opts.nht = false,
                InstanceTraceOption::PacketsAll => trace_opts.packets.all = None,
                InstanceTraceOption::PacketsOpen => trace_opts.packets.open = None,
                InstanceTraceOption::PacketsUpdate => trace_opts.packets.update = None,
                InstanceTraceOption::PacketsNotification => trace_opts.packets.notification = None,
                InstanceTraceOption::PacketsKeepalive => trace_opts.packets.keepalive = None,
                InstanceTraceOption::PacketsRefresh => trace_opts.packets.refresh = None,
                InstanceTraceOption::Route => trace_opts.route = false,
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let trace_opt = dnode.get_string_relative("name").unwrap();
            let trace_opt = InstanceTraceOption::try_from_yang(&trace_opt).unwrap();
            ListEntry::TraceOption(trace_opt)
        })
        .path(bgp::global::trace_options::flag::send::PATH)
        .modify_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let enable = args.dnode.get_bool();
            let trace_opts = &mut instance.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InstanceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InstanceTraceOption::PacketsOpen => trace_opts.packets.open.as_mut(),
                InstanceTraceOption::PacketsUpdate => trace_opts.packets.update.as_mut(),
                InstanceTraceOption::PacketsNotification => trace_opts.packets.notification.as_mut(),
                InstanceTraceOption::PacketsKeepalive => trace_opts.packets.keepalive.as_mut(),
                InstanceTraceOption::PacketsRefresh => trace_opts.packets.refresh.as_mut(),
                _ => None,
            }) else {
                return;
            };
            trace_opt_packet.tx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .path(bgp::global::trace_options::flag::receive::PATH)
        .modify_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let enable = args.dnode.get_bool();
            let trace_opts = &mut instance.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InstanceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InstanceTraceOption::PacketsOpen => trace_opts.packets.open.as_mut(),
                InstanceTraceOption::PacketsUpdate => trace_opts.packets.update.as_mut(),
                InstanceTraceOption::PacketsNotification => trace_opts.packets.notification.as_mut(),
                InstanceTraceOption::PacketsKeepalive => trace_opts.packets.keepalive.as_mut(),
                InstanceTraceOption::PacketsRefresh => trace_opts.packets.refresh.as_mut(),
                _ => None,
            }) else {
                return;
            };
            trace_opt_packet.rx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .path(bgp::neighbors::neighbor::PATH)
        .create_apply(|instance, args| {
            let nbr_addr = args.dnode.get_ip_relative("./remote-address").unwrap();
            let peer_as = args.dnode.get_u32_relative("./peer-as").unwrap();

            let peer_type = if instance.config.asn == peer_as {
                PeerType::Internal
            } else {
                PeerType::External
            };
            let nbr = Neighbor::new(nbr_addr, peer_type);
            instance.neighbors.insert(nbr_addr, nbr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::NeighborUpdate(nbr_addr));
        })
        .delete_apply(|_instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::NeighborDelete(nbr_addr));
        })
        .lookup(|_instance, _list_entry, dnode| {
            let nbr_addr = dnode.get_ip_relative("./remote-address").unwrap();
            ListEntry::Neighbor(nbr_addr)
        })
        .path(bgp::neighbors::neighbor::enabled::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let enabled = args.dnode.get_bool();
            nbr.config.enabled = enabled;
        })
        .path(bgp::neighbors::neighbor::peer_as::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let asn = args.dnode.get_u32();
            nbr.config.peer_as = asn;
            nbr.peer_type = if instance.config.asn == nbr.config.peer_as {
                PeerType::Internal
            } else {
                PeerType::External
            };

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
        })
        .path(bgp::neighbors::neighbor::local_as::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let asn = args.dnode.get_u32();
            nbr.config.local_as = Some(asn);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.local_as = None;
        })
        .path(bgp::neighbors::neighbor::remove_private_as::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let private_as_remove = args.dnode.get_string();
            let private_as_remove = PrivateAsRemove::try_from_yang(&private_as_remove).unwrap();
            nbr.config.private_as_remove = Some(private_as_remove);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.private_as_remove = None;
        })
        .path(bgp::neighbors::neighbor::description::PATH)
        .modify_apply(|_instance, _args| {
            // Nothing to do.
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(bgp::neighbors::neighbor::timers::connect_retry_interval::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let interval = args.dnode.get_u16();
            nbr.config.timers.connect_retry_interval = interval;
        })
        .path(bgp::neighbors::neighbor::timers::hold_time::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let holdtime = args.dnode.get_u16();
            nbr.config.timers.holdtime = holdtime;
        })
        .path(bgp::neighbors::neighbor::timers::keepalive::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let keepalive = args.dnode.get_u16();
            nbr.config.timers.keepalive = Some(keepalive);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.timers.keepalive = None;
        })
        .path(bgp::neighbors::neighbor::timers::min_as_origination_interval::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let interval = args.dnode.get_u16();
            nbr.config.timers.min_as_orig_interval = Some(interval);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.timers.min_as_orig_interval = None;
        })
        .path(bgp::neighbors::neighbor::timers::min_route_advertisement_interval::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let interval = args.dnode.get_u16();
            nbr.config.timers.min_route_adv_interval = Some(interval);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.timers.min_route_adv_interval = None;
        })
        .path(bgp::neighbors::neighbor::transport::local_address::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let addr = args.dnode.get_ip();
            nbr.config.transport.local_addr = Some(addr);

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.transport.local_addr = None;

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
        })
        .path(bgp::neighbors::neighbor::transport::tcp_mss::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let tcp_mss = args.dnode.get_u16();
            nbr.config.transport.tcp_mss = Some(tcp_mss);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.transport.tcp_mss = None;
        })
        .path(bgp::neighbors::neighbor::transport::ebgp_multihop::enabled::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let enabled = args.dnode.get_bool();
            nbr.config.transport.ebgp_multihop_enabled = enabled;

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
        })
        .path(bgp::neighbors::neighbor::transport::ebgp_multihop::multihop_ttl::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let ttl = args.dnode.get_u8();
            nbr.config.transport.ebgp_multihop_ttl = Some(ttl);

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.transport.ebgp_multihop_ttl = None;

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
        })
        .path(bgp::neighbors::neighbor::transport::passive_mode::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let passive_mode = args.dnode.get_bool();
            nbr.config.transport.passive_mode = passive_mode;
        })
        .path(bgp::neighbors::neighbor::transport::ttl_security::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let ttl_security = args.dnode.get_u8();
            nbr.config.transport.ttl_security = Some(ttl_security);

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
        })
        .path(bgp::neighbors::neighbor::transport::secure_session::enabled::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let enabled = args.dnode.get_bool();
            nbr.config.transport.secure_session_enabled = enabled;

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
            event_queue.insert(Event::NeighborUpdateAuth(nbr.remote_addr));
        })
        .path(bgp::neighbors::neighbor::transport::secure_session::options::md5_key_string::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let keychain = args.dnode.get_string();
            nbr.config.transport.md5_key = Some(keychain);

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
            event_queue.insert(Event::NeighborUpdateAuth(nbr.remote_addr));
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.transport.md5_key = None;

            let event_queue = args.event_queue;
            let msg = NotificationMsg::new(
                ErrorCode::Cease,
                CeaseSubcode::OtherConfigurationChange,
            );
            event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
            event_queue.insert(Event::NeighborUpdateAuth(nbr.remote_addr));
        })
        .path(bgp::neighbors::neighbor::logging_options::log_neighbor_state_changes::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let log = args.dnode.get_bool();
            nbr.config.log_neighbor_state_changes = log;
        })
        .path(bgp::neighbors::neighbor::as_path_options::allow_own_as::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let allow = args.dnode.get_u8();
            nbr.config.as_path_options.allow_own_as = allow;
        })
        .path(bgp::neighbors::neighbor::as_path_options::replace_peer_as::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let replace = args.dnode.get_bool();
            nbr.config.as_path_options.replace_peer_as = replace;
        })
        .path(bgp::neighbors::neighbor::as_path_options::disable_peer_as_filter::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let disable = args.dnode.get_bool();
            nbr.config.as_path_options.disable_peer_as_filter = disable;
        })
        .path(bgp::neighbors::neighbor::apply_policy::import_policy::PATH)
        .create_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let policy = args.dnode.get_string();
            nbr.config.apply_policy.import_policy.insert(policy);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let policy = args.dnode.get_string();
            nbr.config.apply_policy.import_policy.remove(&policy);
        })
        .path(bgp::neighbors::neighbor::apply_policy::default_import_policy::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let default = args.dnode.get_string();
            let default = DefaultPolicyType::try_from_yang(&default).unwrap();
            nbr.config.apply_policy.default_import_policy = default;
        })
        .path(bgp::neighbors::neighbor::apply_policy::export_policy::PATH)
        .create_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let policy = args.dnode.get_string();
            nbr.config.apply_policy.export_policy.insert(policy);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let policy = args.dnode.get_string();
            nbr.config.apply_policy.export_policy.remove(&policy);
        })
        .path(bgp::neighbors::neighbor::apply_policy::default_export_policy::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let default = args.dnode.get_string();
            let default = DefaultPolicyType::try_from_yang(&default).unwrap();
            nbr.config.apply_policy.default_export_policy = default;
        })
        .path(bgp::neighbors::neighbor::prefix_limit::max_prefixes::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let max = args.dnode.get_u32();
            nbr.config.prefix_limit.max_prefixes = Some(max);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.prefix_limit.max_prefixes = None;
        })
        .path(bgp::neighbors::neighbor::prefix_limit::warning_threshold_pct::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let threshold = args.dnode.get_u8();
            nbr.config.prefix_limit.warning_threshold_pct = Some(threshold);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.prefix_limit.warning_threshold_pct = None;
        })
        .path(bgp::neighbors::neighbor::prefix_limit::teardown::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let teardown = args.dnode.get_bool();
            nbr.config.prefix_limit.teardown = teardown;
        })
        .path(bgp::neighbors::neighbor::prefix_limit::idle_time::PATH)
        .modify_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let idle_time = args.dnode.get_string();
            let idle_time: u32 = idle_time.parse().unwrap();
            nbr.config.prefix_limit.idle_time = Some(idle_time);
        })
        .delete_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            nbr.config.prefix_limit.idle_time = None;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::PATH)
        .create_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let afi_safi = args.dnode.get_string_relative("./name").unwrap();
            let afi_safi = AfiSafi::try_from_yang(&afi_safi).unwrap();
            nbr.config.afi_safi.insert(afi_safi, Default::default());
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            nbr.config.afi_safi.remove(&afi_safi);
        })
        .lookup(|_instance, list_entry, dnode| {
            let nbr_addr = list_entry.into_neighbor().unwrap();
            let afi_safi = dnode.get_string_relative("./name").unwrap();
            let afi_safi = AfiSafi::try_from_yang(&afi_safi).unwrap();
            ListEntry::NeighborAfiSafi(nbr_addr, afi_safi)
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::enabled::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let enabled = args.dnode.get_bool();
            afi_safi.enabled = enabled;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::apply_policy::import_policy::PATH)
        .create_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let policy = args.dnode.get_string();
            afi_safi.apply_policy.import_policy.insert(policy);
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let policy = args.dnode.get_string();
            afi_safi.apply_policy.import_policy.remove(&policy);
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::apply_policy::default_import_policy::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let default = args.dnode.get_string();
            let default = DefaultPolicyType::try_from_yang(&default).unwrap();
            afi_safi.apply_policy.default_import_policy = default;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::apply_policy::export_policy::PATH)
        .create_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let policy = args.dnode.get_string();
            afi_safi.apply_policy.export_policy.insert(policy);
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let policy = args.dnode.get_string();
            afi_safi.apply_policy.export_policy.remove(&policy);
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::apply_policy::default_export_policy::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let default = args.dnode.get_string();
            let default = DefaultPolicyType::try_from_yang(&default).unwrap();
            afi_safi.apply_policy.default_export_policy = default;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv4_unicast::prefix_limit::max_prefixes::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let max = args.dnode.get_u32();
            afi_safi.prefix_limit.max_prefixes = Some(max);
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.max_prefixes = None;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv4_unicast::prefix_limit::warning_threshold_pct::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let threshold = args.dnode.get_u8();
            afi_safi.prefix_limit.warning_threshold_pct = Some(threshold);
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.warning_threshold_pct = None;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv4_unicast::prefix_limit::teardown::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let teardown = args.dnode.get_bool();
            afi_safi.prefix_limit.teardown = teardown;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv4_unicast::prefix_limit::idle_time::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let idle_time = args.dnode.get_string();
            let idle_time: u32 = idle_time.parse().unwrap();
            afi_safi.prefix_limit.idle_time = Some(idle_time);
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.idle_time = None;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv4_unicast::send_default_route::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let send = args.dnode.get_bool();
            afi_safi.send_default_route = send;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv6_unicast::prefix_limit::max_prefixes::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let max = args.dnode.get_u32();
            afi_safi.prefix_limit.max_prefixes = Some(max);
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.max_prefixes = None;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv6_unicast::prefix_limit::warning_threshold_pct::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let threshold = args.dnode.get_u8();
            afi_safi.prefix_limit.warning_threshold_pct = Some(threshold);
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.warning_threshold_pct = None;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv6_unicast::prefix_limit::teardown::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let teardown = args.dnode.get_bool();
            afi_safi.prefix_limit.teardown = teardown;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv6_unicast::prefix_limit::idle_time::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let idle_time = args.dnode.get_string();
            let idle_time: u32 = idle_time.parse().unwrap();
            afi_safi.prefix_limit.idle_time = Some(idle_time);
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            afi_safi.prefix_limit.idle_time = None;
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv6_unicast::send_default_route::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, afi_safi) = args.list_entry.into_neighbor_afi_safi().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();
            let afi_safi = nbr.config.afi_safi.get_mut(&afi_safi).unwrap();

            let send = args.dnode.get_bool();
            afi_safi.send_default_route = send;
        })
        .path(bgp::neighbors::neighbor::trace_options::flag::PATH)
        .create_apply(|instance, args| {
            let nbr_addr = args.list_entry.into_neighbor().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let trace_opt = args.dnode.get_string_relative("name").unwrap();
            let trace_opt = NeighborTraceOption::try_from_yang(&trace_opt).unwrap();
            let trace_opts = &mut nbr.config.trace_opts;
            match trace_opt {
                NeighborTraceOption::Events => trace_opts.events = Some(true),
                NeighborTraceOption::PacketsAll => {
                    trace_opts.packets.all.get_or_insert_default();
                }
                NeighborTraceOption::PacketsOpen => {
                    trace_opts.packets.open.get_or_insert_default();
                }
                NeighborTraceOption::PacketsUpdate => {
                    trace_opts.packets.update.get_or_insert_default();
                }
                NeighborTraceOption::PacketsNotification => {
                    trace_opts.packets.notification.get_or_insert_default();
                }
                NeighborTraceOption::PacketsKeepalive => {
                    trace_opts.packets.keepalive.get_or_insert_default();
                }
                NeighborTraceOption::PacketsRefresh => {
                    trace_opts.packets.refresh.get_or_insert_default();
                }
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .delete_apply(|instance, args| {
            let (nbr_addr, trace_opt) = args.list_entry.into_neighbor_trace_option().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let trace_opts = &mut nbr.config.trace_opts;
            match trace_opt {
                NeighborTraceOption::Events => trace_opts.events = None,
                NeighborTraceOption::PacketsAll => trace_opts.packets.all = None,
                NeighborTraceOption::PacketsOpen => trace_opts.packets.open = None,
                NeighborTraceOption::PacketsUpdate => trace_opts.packets.update = None,
                NeighborTraceOption::PacketsNotification => trace_opts.packets.notification = None,
                NeighborTraceOption::PacketsKeepalive => trace_opts.packets.keepalive = None,
                NeighborTraceOption::PacketsRefresh => trace_opts.packets.refresh = None,
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .lookup(|_instance, list_entry, dnode| {
            let nbr_addr = list_entry.into_neighbor().unwrap();
            let trace_opt = dnode.get_string_relative("name").unwrap();
            let trace_opt = NeighborTraceOption::try_from_yang(&trace_opt).unwrap();
            ListEntry::NeighborTraceOption(nbr_addr, trace_opt)
        })
        .path(bgp::neighbors::neighbor::trace_options::flag::send::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, trace_opt) = args.list_entry.into_neighbor_trace_option().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let enable = args.dnode.get_bool();
            let trace_opts = &mut nbr.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                NeighborTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                NeighborTraceOption::PacketsOpen => trace_opts.packets.open.as_mut(),
                NeighborTraceOption::PacketsUpdate => trace_opts.packets.update.as_mut(),
                NeighborTraceOption::PacketsNotification => trace_opts.packets.notification.as_mut(),
                NeighborTraceOption::PacketsKeepalive => trace_opts.packets.keepalive.as_mut(),
                NeighborTraceOption::PacketsRefresh => trace_opts.packets.refresh.as_mut(),
                _ => None,
            }) else {
                return;
            };
            trace_opt_packet.tx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .path(bgp::neighbors::neighbor::trace_options::flag::receive::PATH)
        .modify_apply(|instance, args| {
            let (nbr_addr, trace_opt) = args.list_entry.into_neighbor_trace_option().unwrap();
            let nbr = instance.neighbors.get_mut(&nbr_addr).unwrap();

            let enable = args.dnode.get_bool();
            let trace_opts = &mut nbr.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                NeighborTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                NeighborTraceOption::PacketsOpen => trace_opts.packets.open.as_mut(),
                NeighborTraceOption::PacketsUpdate => trace_opts.packets.update.as_mut(),
                NeighborTraceOption::PacketsNotification => trace_opts.packets.notification.as_mut(),
                NeighborTraceOption::PacketsKeepalive => trace_opts.packets.keepalive.as_mut(),
                NeighborTraceOption::PacketsRefresh => trace_opts.packets.refresh.as_mut(),
                _ => None,
            }) else {
                return;
            };
            trace_opt_packet.rx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default().build()
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
            Event::InstanceUpdate => self.update(),
            Event::NeighborUpdate(nbr_addr) => {
                let Some((mut instance, neighbors)) = self.as_up() else {
                    return;
                };
                let nbr = neighbors.get_mut(&nbr_addr).unwrap();

                if nbr.config.enabled {
                    nbr.fsm_event(&mut instance, fsm::Event::Start);
                } else {
                    let error_code = ErrorCode::Cease;
                    let error_subcode = CeaseSubcode::AdministrativeShutdown;
                    let msg = NotificationMsg::new(error_code, error_subcode);
                    nbr.fsm_event(&mut instance, fsm::Event::Stop(Some(msg)));
                }
            }
            Event::NeighborDelete(nbr_addr) => {
                let Some((mut instance, neighbors)) = self.as_up() else {
                    return;
                };
                let nbr = neighbors.get_mut(&nbr_addr).unwrap();

                // Unset neighbor's password in the listening sockets.
                for listener in
                    instance.state.listening_sockets.iter().filter(|listener| {
                        listener.af == nbr_addr.address_family()
                    })
                {
                    network::listen_socket_md5sig_update(
                        &listener.socket,
                        &nbr_addr,
                        None,
                    );
                }

                // Delete neighbor.
                let error_code = ErrorCode::Cease;
                let error_subcode = CeaseSubcode::PeerDeConfigured;
                let msg = NotificationMsg::new(error_code, error_subcode);
                nbr.fsm_event(&mut instance, fsm::Event::Stop(Some(msg)));
                neighbors.remove(&nbr_addr);
            }
            Event::NeighborReset(nbr_addr, msg) => {
                let Some((mut instance, neighbors)) = self.as_up() else {
                    return;
                };
                let nbr = neighbors.get_mut(&nbr_addr).unwrap();

                nbr.fsm_event(&mut instance, fsm::Event::Stop(Some(msg)));
            }
            Event::NeighborUpdateAuth(nbr_addr) => {
                let Some((instance, neighbors)) = self.as_up() else {
                    return;
                };
                let nbr = neighbors.get_mut(&nbr_addr).unwrap();

                // Get neighbor password.
                let key = if nbr.config.transport.secure_session_enabled
                    && let Some(key) = &nbr.config.transport.md5_key
                {
                    Some(key.clone())
                } else {
                    None
                };

                // Set/unset password in the listening sockets.
                for listener in
                    instance.state.listening_sockets.iter().filter(|listener| {
                        listener.af == nbr_addr.address_family()
                    })
                {
                    network::listen_socket_md5sig_update(
                        &listener.socket,
                        &nbr_addr,
                        key.as_deref(),
                    );
                }
            }
            Event::RedistributeIbusSub(protocol, af) => {
                self.tx.ibus.route_redistribute_sub(protocol, Some(af));
            }
            Event::RedistributeDelete(protocol, af, afi_safi) => {
                self.tx.ibus.route_redistribute_unsub(protocol, Some(af));

                if let Some((mut instance, _)) = self.as_up() {
                    match afi_safi {
                        AfiSafi::Ipv4Unicast => {
                            redistribute_delete::<Ipv4Unicast>(
                                &mut instance,
                                protocol,
                            );
                        }
                        AfiSafi::Ipv6Unicast => {
                            redistribute_delete::<Ipv6Unicast>(
                                &mut instance,
                                protocol,
                            );
                        }
                    }
                }
            }
            Event::UpdateTraceOptions => {
                for nbr in self.neighbors.values_mut() {
                    let nbr_trace_opts = &nbr.config.trace_opts;
                    let instance_trace_opts = &self.config.trace_opts;

                    let disabled = TraceOptionPacketType {
                        tx: false,
                        rx: false,
                    };
                    let open = nbr_trace_opts
                        .packets
                        .open
                        .or(nbr_trace_opts.packets.all)
                        .or(instance_trace_opts.packets.open)
                        .or(instance_trace_opts.packets.all)
                        .unwrap_or(disabled);
                    let update = nbr_trace_opts
                        .packets
                        .update
                        .or(nbr_trace_opts.packets.all)
                        .or(instance_trace_opts.packets.update)
                        .or(instance_trace_opts.packets.all)
                        .unwrap_or(disabled);
                    let notification = nbr_trace_opts
                        .packets
                        .notification
                        .or(nbr_trace_opts.packets.all)
                        .or(instance_trace_opts.packets.notification)
                        .or(instance_trace_opts.packets.all)
                        .unwrap_or(disabled);
                    let keepalive = nbr_trace_opts
                        .packets
                        .keepalive
                        .or(nbr_trace_opts.packets.all)
                        .or(instance_trace_opts.packets.keepalive)
                        .or(instance_trace_opts.packets.all)
                        .unwrap_or(disabled);
                    let refresh = nbr_trace_opts
                        .packets
                        .refresh
                        .or(nbr_trace_opts.packets.all)
                        .or(instance_trace_opts.packets.refresh)
                        .or(instance_trace_opts.packets.all)
                        .unwrap_or(disabled);

                    nbr.config.trace_opts.events_resolved = nbr_trace_opts
                        .events
                        .unwrap_or(instance_trace_opts.events);
                    nbr.config.trace_opts.packets_resolved.store(Arc::new(
                        TraceOptionPacketResolved {
                            open,
                            update,
                            notification,
                            keepalive,
                            refresh,
                        },
                    ));
                }
            }
        }
    }
}

// ===== configuration helpers =====

impl TraceOptionPacketResolved {
    pub(crate) fn tx(&self, msg: &Message) -> bool {
        match msg {
            Message::Open(_) => self.open.tx,
            Message::Update(_) => self.update.tx,
            Message::Notification(_) => self.notification.tx,
            Message::Keepalive(_) => self.keepalive.tx,
            Message::RouteRefresh(_) => self.refresh.tx,
        }
    }

    pub(crate) fn rx(&self, msg: &Message) -> bool {
        match msg {
            Message::Open(_) => self.open.rx,
            Message::Update(_) => self.update.rx,
            Message::Notification(_) => self.notification.rx,
            Message::Keepalive(_) => self.keepalive.rx,
            Message::RouteRefresh(_) => self.refresh.rx,
        }
    }
}

// ===== helper functions =====

fn redistribute_delete<A>(instance: &mut InstanceUpView<'_>, protocol: Protocol)
where
    A: crate::af::AddressFamily,
{
    let table = A::table(&mut instance.state.rib.tables);
    for (prefix, dest) in table.prefixes.iter_mut() {
        let Some(route) = &dest.redistribute else {
            continue;
        };
        if route.origin != RouteOrigin::Protocol(protocol) {
            continue;
        }

        // Remove redistributed route.
        dest.redistribute = None;

        // Enqueue prefix for the BGP Decision Process.
        table.queued_prefixes.insert(*prefix);
    }

    // Schedule the BGP Decision Process.
    instance.state.schedule_decision_process(instance.tx);
}

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let reject_as_sets = bgp::global::reject_as_sets::DFLT;

        InstanceCfg {
            asn: 0,
            identifier: None,
            distance: Default::default(),
            multipath: Default::default(),
            route_selection: Default::default(),
            apply_policy: Default::default(),
            afi_safi: Default::default(),
            reject_as_sets,
            trace_opts: Default::default(),
        }
    }
}

impl Default for DistanceCfg {
    fn default() -> DistanceCfg {
        let external = bgp::global::distance::external::DFLT;
        let internal = bgp::global::distance::internal::DFLT;

        DistanceCfg { external, internal }
    }
}

impl Default for MultipathCfg {
    fn default() -> MultipathCfg {
        let enabled = bgp::global::use_multiple_paths::enabled::DFLT;
        let ebgp_allow_multiple_as =
            bgp::global::use_multiple_paths::ebgp::allow_multiple_as::DFLT;
        let ebgp_max_paths =
            bgp::global::use_multiple_paths::ebgp::maximum_paths::DFLT;
        let ibgp_max_paths =
            bgp::global::use_multiple_paths::ibgp::maximum_paths::DFLT;

        MultipathCfg {
            enabled,
            ebgp_allow_multiple_as,
            ebgp_max_paths,
            ibgp_max_paths,
        }
    }
}

impl Default for InstanceAfiSafiCfg {
    fn default() -> InstanceAfiSafiCfg {
        // TODO: fetch defaults from YANG module
        InstanceAfiSafiCfg {
            enabled: false,
            multipath: Default::default(),
            route_selection: Default::default(),
            prefix_limit: Default::default(),
            send_default_route: false,
            apply_policy: Default::default(),
            redistribution: Default::default(),
        }
    }
}

impl Default for NeighborCfg {
    fn default() -> NeighborCfg {
        let enabled = bgp::neighbors::neighbor::enabled::DFLT;
        let log_neighbor_state_changes =
            bgp::neighbors::neighbor::logging_options::log_neighbor_state_changes::DFLT;

        NeighborCfg {
            enabled,
            peer_as: 0,
            local_as: None,
            private_as_remove: None,
            timers: Default::default(),
            transport: Default::default(),
            log_neighbor_state_changes,
            as_path_options: Default::default(),
            apply_policy: Default::default(),
            prefix_limit: Default::default(),
            afi_safi: Default::default(),
            trace_opts: Default::default(),
        }
    }
}

impl Default for NeighborTimersCfg {
    fn default() -> NeighborTimersCfg {
        let connect_retry_interval =
            bgp::neighbors::neighbor::timers::connect_retry_interval::DFLT;
        let holdtime = bgp::neighbors::neighbor::timers::hold_time::DFLT;

        NeighborTimersCfg {
            connect_retry_interval,
            holdtime,
            keepalive: None,
            min_as_orig_interval: None,
            min_route_adv_interval: None,
        }
    }
}

impl Default for NeighborTransportCfg {
    fn default() -> NeighborTransportCfg {
        let ebgp_multihop_enabled =
            bgp::neighbors::neighbor::transport::ebgp_multihop::enabled::DFLT;
        let passive_mode =
            bgp::neighbors::neighbor::transport::passive_mode::DFLT;
        let secure_session_enabled =
            bgp::neighbors::neighbor::transport::secure_session::enabled::DFLT;

        NeighborTransportCfg {
            local_addr: None,
            tcp_mss: None,
            ebgp_multihop_enabled,
            ebgp_multihop_ttl: None,
            passive_mode,
            ttl_security: None,
            secure_session_enabled,
            md5_key: None,
        }
    }
}

impl Default for NeighborAfiSafiCfg {
    fn default() -> NeighborAfiSafiCfg {
        let enabled =
            bgp::neighbors::neighbor::afi_safis::afi_safi::enabled::DFLT;

        NeighborAfiSafiCfg {
            enabled,
            prefix_limit: Default::default(),
            send_default_route: false,
            apply_policy: Default::default(),
        }
    }
}

impl Default for RouteSelectionCfg {
    fn default() -> RouteSelectionCfg {
        // TODO: fetch defaults from YANG module
        RouteSelectionCfg {
            always_compare_med: false,
            ignore_as_path_length: false,
            external_compare_router_id: true,
            ignore_next_hop_igp_metric: false,
            enable_med: false,
        }
    }
}

impl Default for PrefixLimitCfg {
    fn default() -> PrefixLimitCfg {
        // TODO: fetch defaults from YANG module
        PrefixLimitCfg {
            max_prefixes: None,
            warning_threshold_pct: None,
            teardown: false,
            idle_time: None,
        }
    }
}

impl Default for AsPathOptions {
    fn default() -> AsPathOptions {
        // TODO: fetch defaults from YANG module
        AsPathOptions {
            allow_own_as: 0,
            replace_peer_as: false,
            disable_peer_as_filter: false,
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
            open: disabled,
            update: disabled,
            notification: disabled,
            keepalive: disabled,
            refresh: disabled,
        }
    }
}

impl Default for TraceOptionPacketType {
    fn default() -> TraceOptionPacketType {
        let tx = bgp::global::trace_options::flag::send::DFLT;
        let rx = bgp::global::trace_options::flag::receive::DFLT;

        TraceOptionPacketType { tx, rx }
    }
}
