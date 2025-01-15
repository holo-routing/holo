//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock as Lazy;

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, InheritableConfig, Provider,
    ValidationCallbacks, ValidationCallbacksBuilder,
};
use holo_northbound::yang::control_plane_protocol::isis;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::AddressFamily;
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;
use smallvec::SmallVec;

use crate::collections::InterfaceIndex;
use crate::debug::InterfaceInactiveReason;
use crate::instance::Instance;
use crate::interface::InterfaceType;
use crate::northbound::notification;
use crate::packet::{AreaAddr, LevelNumber, LevelType, SystemId};
use crate::spf;
use crate::tasks::messages::input::DisElectionMsg;

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    AddressFamily(AddressFamily),
    Interface(InterfaceIndex),
    InterfaceAddressFamily(InterfaceIndex, AddressFamily),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceReset,
    InstanceUpdate,
    InterfaceUpdate(InterfaceIndex),
    InstanceLevelTypeUpdate,
    InterfaceDelete(InterfaceIndex),
    InterfaceReset(InterfaceIndex),
    InterfacePriorityChange(InterfaceIndex, LevelNumber),
    InterfaceUpdateHelloInterval(InterfaceIndex, LevelNumber),
    InterfaceUpdateCsnpInterval(InterfaceIndex),
    InterfaceQuerySouthbound(InterfaceIndex),
    ReoriginateLsps(LevelNumber),
    RefreshLsps,
    RerunSpf,
    OverloadChange(bool),
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
    pub metric_type: LevelsCfg<MetricType>,
    pub default_metric: LevelsCfg<u32>,
    pub auth: LevelsOptCfg<AuthCfg>,
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
}

#[derive(Debug)]
pub struct AddressFamilyCfg {
    pub enabled: bool,
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
    pub hello_auth: LevelsOptCfg<AuthCfg>,
    pub hello_interval: LevelsCfg<u16>,
    pub hello_multiplier: LevelsCfg<u16>,
    pub priority: LevelsCfg<u8>,
    pub metric: LevelsCfg<u32>,
    pub afs: BTreeSet<AddressFamily>,
}

#[derive(Debug, Default)]
pub struct AuthCfg {
    pub keychain: Option<String>,
    pub key: Option<String>,
    pub algo: Option<CryptoAlgo>,
}

#[derive(Debug)]
pub struct LevelsCfg<T> {
    all: T,
    l1: Option<T>,
    l2: Option<T>,
}

#[derive(Debug, Default)]
pub struct LevelsOptCfg<T> {
    pub all: T,
    pub l1: T,
    pub l2: T,
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
        })
        .delete_apply(|instance, _args| {
            instance.config.auth.all.keychain = None;
        })
        .path(isis::authentication::key::PATH)
        .modify_apply(|instance, args| {
            let key = args.dnode.get_string();
            instance.config.auth.all.key = Some(key);
        })
        .delete_apply(|instance, _args| {
            instance.config.auth.all.key = None;
        })
        .path(isis::authentication::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            instance.config.auth.all.algo = Some(algo);
        })
        .delete_apply(|instance, _args| {
            instance.config.auth.all.algo = None;
        })
        .path(isis::authentication::level_1::key_chain::PATH)
        .modify_apply(|instance, args| {
            let keychain = args.dnode.get_string();
            instance.config.auth.l1.keychain = Some(keychain);
        })
        .delete_apply(|instance, _args| {
            instance.config.auth.l1.keychain = None;
        })
        .path(isis::authentication::level_1::key::PATH)
        .modify_apply(|instance, args| {
            let key = args.dnode.get_string();
            instance.config.auth.l1.key = Some(key);
        })
        .delete_apply(|instance, _args| {
            instance.config.auth.l1.key = None;
        })
        .path(isis::authentication::level_1::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            instance.config.auth.l1.algo = Some(algo);
        })
        .delete_apply(|instance, _args| {
            instance.config.auth.l1.algo = None;
        })
        .path(isis::authentication::level_2::key_chain::PATH)
        .modify_apply(|instance, args| {
            let keychain = args.dnode.get_string();
            instance.config.auth.l2.keychain = Some(keychain);
        })
        .delete_apply(|instance, _args| {
            instance.config.auth.l2.keychain = None;
        })
        .path(isis::authentication::level_2::key::PATH)
        .modify_apply(|instance, args| {
            let key = args.dnode.get_string();
            instance.config.auth.l2.key = Some(key);
        })
        .delete_apply(|instance, _args| {
            instance.config.auth.l2.key = None;
        })
        .path(isis::authentication::level_2::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            instance.config.auth.l2.algo = Some(algo);
        })
        .delete_apply(|instance, _args| {
            instance.config.auth.l2.algo = None;
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
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(isis::preference::external::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.external = preference;
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(isis::preference::default::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.internal = preference;
            instance.config.preference.external = preference;
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
        .path(isis::interfaces::interface::PATH)
        .create_apply(|instance, args| {
            let ifname = args.dnode.get_string_relative("name").unwrap();

            let iface = instance.arenas.interfaces.insert(&ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(iface.index));
            event_queue.insert(Event::InterfaceQuerySouthbound(iface.index));
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
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L1));
            event_queue.insert(Event::InterfaceUpdateHelloInterval(iface_idx, LevelNumber::L2));
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
        .path(isis::interfaces::interface::hello_authentication::key_chain::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let keychain = args.dnode.get_string();
            iface.config.hello_auth.all.keychain = Some(keychain);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.all.keychain = None;
        })
        .path(isis::interfaces::interface::hello_authentication::key::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let key = args.dnode.get_string();
            iface.config.hello_auth.all.key = Some(key);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.all.key = None;
        })
        .path(isis::interfaces::interface::hello_authentication::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            iface.config.hello_auth.all.algo = Some(algo);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.all.algo = None;
        })
        .path(isis::interfaces::interface::hello_authentication::level_1::key_chain::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let keychain = args.dnode.get_string();
            iface.config.hello_auth.l1.keychain = Some(keychain);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l1.keychain = None;
        })
        .path(isis::interfaces::interface::hello_authentication::level_1::key::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let key = args.dnode.get_string();
            iface.config.hello_auth.l1.key = Some(key);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l1.key = None;
        })
        .path(isis::interfaces::interface::hello_authentication::level_1::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            iface.config.hello_auth.l1.algo = Some(algo);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l1.algo = None;
        })
        .path(isis::interfaces::interface::hello_authentication::level_2::key_chain::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let keychain = args.dnode.get_string();
            iface.config.hello_auth.l2.keychain = Some(keychain);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l2.keychain = None;
        })
        .path(isis::interfaces::interface::hello_authentication::level_2::key::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let key = args.dnode.get_string();
            iface.config.hello_auth.l2.key = Some(key);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l2.key = None;
        })
        .path(isis::interfaces::interface::hello_authentication::level_2::crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            iface.config.hello_auth.l2.algo = Some(algo);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.hello_auth.l2.algo = None;
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
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default().build()
}

// ===== impl Instance =====

#[async_trait]
impl Provider for Instance {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        Some(&VALIDATION_CALLBACKS)
    }

    fn callbacks() -> Option<&'static Callbacks<Instance>> {
        Some(&CALLBACKS)
    }

    async fn process_event(&mut self, event: Event) {
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
            Event::InterfaceUpdate(iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];
                    if let Err(error) =
                        iface.update(&mut instance, &mut arenas.adjacencies)
                    {
                        error.log(arenas);
                    }
                }
            }
            Event::InterfaceDelete(iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];

                    // Stop interface if it's active.
                    let reason = InterfaceInactiveReason::AdminDown;
                    iface.stop(&mut instance, &mut arenas.adjacencies, reason);
                }

                self.arenas.interfaces.delete(iface_idx);
            }
            Event::InterfaceReset(iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];
                    if let Err(error) =
                        iface.reset(&mut instance, &mut arenas.adjacencies)
                    {
                        error.log(arenas);
                    }
                }
            }
            Event::InterfacePriorityChange(iface_idx, level) => {
                let Some((instance, arenas)) = self.as_up() else {
                    return;
                };
                let iface = &mut arenas.interfaces[iface_idx];

                if iface.state.active && !iface.is_passive() {
                    // Schedule new DIS election.
                    if iface.config.interface_type == InterfaceType::Broadcast {
                        let msg = DisElectionMsg {
                            iface_key: iface.id.into(),
                            level,
                        };
                        let _ =
                            instance.tx.protocol_input.dis_election.send(msg);
                    }
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
            Event::InterfaceQuerySouthbound(iface_idx) => {
                if self.is_active() {
                    let iface = &self.arenas.interfaces[iface_idx];
                    iface.query_southbound(&self.tx.ibus);
                }
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

    // Returns the levels supported by the instance.
    pub(crate) fn levels(&self) -> SmallVec<[LevelNumber; 2]> {
        [LevelNumber::L1, LevelNumber::L2]
            .into_iter()
            .filter(|level| self.level_type.intersects(level))
            .collect()
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

    // Returns the levels supported by the interface.
    pub(crate) fn levels(&self) -> SmallVec<[LevelNumber; 2]> {
        [LevelNumber::L1, LevelNumber::L2]
            .into_iter()
            .filter(|level| self.level_type.resolved.intersects(level))
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
}

impl<T> LevelsCfg<T>
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

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let enabled = isis::enabled::DFLT;
        let level_type = isis::level_type::DFLT;
        let level_type = LevelType::try_from_yang(level_type).unwrap();
        let lsp_mtu = isis::lsp_mtu::DFLT;
        let lsp_lifetime = isis::lsp_lifetime::DFLT;
        let lsp_refresh = isis::lsp_refresh::DFLT;
        let metric_type = isis::metric_type::value::DFLT;
        let metric_type = LevelsCfg {
            all: MetricType::try_from_yang(metric_type).unwrap(),
            l1: None,
            l2: None,
        };
        let default_metric = isis::default_metric::value::DFLT;
        let default_metric = LevelsCfg {
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

        InstanceCfg {
            enabled,
            level_type,
            system_id: None,
            area_addrs: Default::default(),
            lsp_mtu,
            lsp_lifetime,
            lsp_refresh,
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
        }
    }
}

impl Default for AddressFamilyCfg {
    fn default() -> AddressFamilyCfg {
        let enabled =
            isis::address_families::address_family_list::enabled::DFLT;

        AddressFamilyCfg { enabled }
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
        let hello_interval =
            isis::interfaces::interface::hello_interval::value::DFLT;
        let hello_interval = LevelsCfg {
            all: hello_interval,
            l1: None,
            l2: None,
        };
        let hello_multiplier =
            isis::interfaces::interface::hello_multiplier::value::DFLT;
        let hello_multiplier = LevelsCfg {
            all: hello_multiplier,
            l1: None,
            l2: None,
        };
        let priority = isis::interfaces::interface::priority::value::DFLT;
        let priority = LevelsCfg {
            all: priority,
            l1: None,
            l2: None,
        };
        let metric = isis::interfaces::interface::metric::value::DFLT;
        let metric = LevelsCfg {
            all: metric,
            l1: None,
            l2: None,
        };
        InterfaceCfg {
            enabled,
            level_type,
            lsp_pacing_interval,
            lsp_rxmt_interval,
            passive,
            csnp_interval,
            hello_padding,
            interface_type,
            hello_auth: Default::default(),
            hello_interval,
            hello_multiplier,
            priority,
            metric,
            afs: Default::default(),
        }
    }
}
