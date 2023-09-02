//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::LazyLock as Lazy;

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};
use holo_northbound::paths::control_plane_protocol::ospf;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::yang::DataNodeRefExt;
use holo_yang::{ToYang, TryFromYang};
use yang2::data::Data;

use crate::area::{self, AreaType};
use crate::collections::{AreaIndex, InterfaceIndex};
use crate::debug::InterfaceInactiveReason;
use crate::instance::Instance;
use crate::interface::{ism, InterfaceType};
use crate::lsdb::LsaOriginateEvent;
use crate::neighbor::nsm;
use crate::route::RouteNetFlags;
use crate::version::{Ospfv2, Ospfv3, Version};
use crate::{gr, spf, sr};

#[derive(Debug, EnumAsInner)]
pub enum ListEntry<V: Version> {
    None,
    Area(AreaIndex),
    AreaRange(AreaIndex, V::IpNetwork),
    Interface(AreaIndex, InterfaceIndex),
    StaticNbr(InterfaceIndex, V::NetIpAddr),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceReset,
    InstanceUpdate,
    InstanceIdUpdate,
    AreaCreate(AreaIndex),
    AreaDelete(AreaIndex),
    AreaTypeChange(AreaIndex),
    AreaSyncHelloTx(AreaIndex),
    InterfaceUpdate(AreaIndex, InterfaceIndex),
    InterfaceDelete(AreaIndex, InterfaceIndex),
    InterfaceReset(AreaIndex, InterfaceIndex),
    InterfaceResetHelloInterval(AreaIndex, InterfaceIndex),
    InterfaceResetDeadInterval(AreaIndex, InterfaceIndex),
    InterfacePriorityChange(AreaIndex, InterfaceIndex),
    InterfaceCostChange(AreaIndex),
    InterfaceSyncHelloTx(AreaIndex, InterfaceIndex),
    InterfaceUpdateAuth(AreaIndex, InterfaceIndex),
    InterfaceBfdChange(InterfaceIndex),
    StubRouterChange,
    GrHelperChange,
    SrEnableChange(bool),
    RerunSpf,
    UpdateSummaries,
    ReinstallRoutes,
    SbRequestInterfaceInfo,
}

pub static VALIDATION_CALLBACKS_OSPFV2: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks_ospfv2);
pub static VALIDATION_CALLBACKS_OSPFV3: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks_ospfv3);
pub static CALLBACKS_OSPFV2: Lazy<Callbacks<Instance<Ospfv2>>> =
    Lazy::new(load_callbacks_ospfv2);
pub static CALLBACKS_OSPFV3: Lazy<Callbacks<Instance<Ospfv3>>> =
    Lazy::new(load_callbacks_ospfv3);

// ===== callbacks =====

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::<Instance<V>>::default()
        .path(ospf::address_family::PATH)
        .modify_apply(|instance, args| {
            let af = args.dnode.get_af();
            instance.config.af = Some(af);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceReset);
        })
        .delete_apply(|instance, args| {
            instance.config.af = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceReset);
        })
        .path(ospf::enabled::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
        })
        .path(ospf::explicit_router_id::PATH)
        .modify_apply(|instance, args| {
            let router_id = args.dnode.get_ipv4();
            let old_router_id = instance.get_router_id();
            instance.config.router_id = Some(router_id);

            // NOTE: apply the new Router-ID immediately.
            if instance.get_router_id() != old_router_id {
                let event_queue = args.event_queue;
                event_queue.insert(Event::InstanceReset);
                event_queue.insert(Event::InstanceUpdate);
            }
        })
        .delete_apply(|instance, args| {
            let old_router_id = instance.get_router_id();
            instance.config.router_id = None;

            if instance.get_router_id() != old_router_id {
                let event_queue = args.event_queue;
                event_queue.insert(Event::InstanceReset);
                event_queue.insert(Event::InstanceUpdate);
            }
        })
        .path(ospf::preference::all::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::preference::intra_area::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.intra_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.intra_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::preference::inter_area::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.inter_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.inter_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::preference::internal::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::preference::external::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::graceful_restart::helper_enabled::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.gr.helper_enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::GrHelperChange);
        })
        .path(ospf::graceful_restart::helper_strict_lsa_checking::PATH)
        .modify_apply(|instance, args| {
            let strict_lsa_checking = args.dnode.get_bool();
            instance.config.gr.helper_strict_lsa_checking = strict_lsa_checking;
        })
        .path(ospf::spf_control::paths::PATH)
        .modify_apply(|instance, args| {
            let max_paths = args.dnode.get_u16();
            instance.config.max_paths = max_paths;

            let event_queue = args.event_queue;
            event_queue.insert(Event::RerunSpf);
        })
        .path(ospf::spf_control::ietf_spf_delay::initial_delay::PATH)
        .modify_apply(|instance, args| {
            let initial_delay = args.dnode.get_u32();
            instance.config.spf_initial_delay = initial_delay;
        })
        .path(ospf::spf_control::ietf_spf_delay::short_delay::PATH)
        .modify_apply(|instance, args| {
            let short_delay = args.dnode.get_u32();
            instance.config.spf_short_delay = short_delay;
        })
        .path(ospf::spf_control::ietf_spf_delay::long_delay::PATH)
        .modify_apply(|instance, args| {
            let long_delay = args.dnode.get_u32();
            instance.config.spf_long_delay = long_delay;
        })
        .path(ospf::spf_control::ietf_spf_delay::hold_down::PATH)
        .modify_apply(|instance, args| {
            let hold_down = args.dnode.get_u32();
            instance.config.spf_hold_down = hold_down;
        })
        .path(ospf::spf_control::ietf_spf_delay::time_to_learn::PATH)
        .modify_apply(|instance, args| {
            let time_to_learn = args.dnode.get_u32();
            instance.config.spf_time_to_learn = time_to_learn;
        })
        .path(ospf::stub_router::always::PATH)
        .create_apply(|instance, args| {
            instance.config.stub_router = true;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StubRouterChange);
        })
        .delete_apply(|instance, args| {
            instance.config.stub_router = false;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StubRouterChange);
        })
        .path(ospf::extended_lsa_support::PATH)
        .modify_apply(|instance, args| {
            let extended_lsa = args.dnode.get_bool();
            instance.config.extended_lsa = extended_lsa;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceReset);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::segment_routing::enabled::PATH)
        .modify_apply(|instance, args| {
            let sr_enabled = args.dnode.get_bool();
            instance.config.sr_enabled = sr_enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrEnableChange(sr_enabled));
        })
        .path(ospf::areas::area::PATH)
        .create_apply(|instance, args| {
            let area_id = args.dnode.get_ipv4_relative("area-id").unwrap();
            let (area_idx, _) = instance.arenas.areas.insert(area_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AreaCreate(area_idx));
        })
        .delete_apply(|_instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::AreaDelete(area_idx));
            event_queue.insert(Event::RerunSpf);
        })
        .lookup(|instance, _list_entry, dnode| {
            let area_id = dnode.get_ipv4_relative("./area-id").unwrap();
            instance
                .arenas
                .areas
                .get_mut_by_area_id(area_id)
                .map(|(area_idx, _)| ListEntry::Area(area_idx))
                .expect("could not find OSPF area")
        })
        .path(ospf::areas::area::area_type::PATH)
        .modify_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let area_type = args.dnode.get_string();
            let area_type = AreaType::try_from_yang(&area_type).unwrap();
            area.config.area_type = area_type;
            area.config.summary = ospf::areas::area::summary::DFLT;
            area.config.default_cost = ospf::areas::area::default_cost::DFLT;

            let event_queue = args.event_queue;
            event_queue.insert(Event::AreaTypeChange(area_idx));
            event_queue.insert(Event::AreaSyncHelloTx(area_idx));
        })
        .path(ospf::areas::area::summary::PATH)
        .modify_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let summary = args.dnode.get_bool();
            area.config.summary = summary;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::default_cost::PATH)
        .modify_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let default_cost = args.dnode.get_u32();
            area.config.default_cost = default_cost;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::ranges::range::PATH)
        .create_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let prefix = args.dnode.get_prefix_relative("prefix").unwrap();
            let prefix = V::IpNetwork::get(prefix).unwrap();
            area.ranges.insert(prefix, Default::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .delete_apply(|instance, args| {
            let (area_idx, prefix) = args.list_entry.into_area_range().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            area.ranges.remove(&prefix);

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .lookup(|_instance, list_entry, dnode| {
            let area_idx = list_entry.into_area().unwrap();

            let prefix = dnode.get_prefix_relative("./prefix").unwrap();
            let prefix = V::IpNetwork::get(prefix).unwrap();
            ListEntry::AreaRange(area_idx, prefix)
        })
        .path(ospf::areas::area::ranges::range::advertise::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, prefix) = args.list_entry.into_area_range().unwrap();
            let area = &mut instance.arenas.areas[area_idx];
            let range = area.ranges.get_mut(&prefix).unwrap();

            let advertise = args.dnode.get_bool();
            range.config.advertise = advertise;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .path(ospf::areas::area::ranges::range::cost::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, prefix) = args.list_entry.into_area_range().unwrap();
            let area = &mut instance.arenas.areas[area_idx];
            let range = area.ranges.get_mut(&prefix).unwrap();

            let cost = args.dnode.get_u32();
            range.config.cost = Some(cost);

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .delete_apply(|instance, args| {
            let (area_idx, prefix) = args.list_entry.into_area_range().unwrap();
            let area = &mut instance.arenas.areas[area_idx];
            let range = area.ranges.get_mut(&prefix).unwrap();

            range.config.cost = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .path(ospf::areas::area::interfaces::interface::PATH)
        .create_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let ifname = args.dnode.get_string_relative("name").unwrap();
            let (iface_idx, _) = area
                .interfaces
                .insert(&mut instance.arenas.interfaces, &ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::InterfaceUpdate(area_idx, iface_idx));
            event_queue.insert(Event::SbRequestInterfaceInfo);
        })
        .delete_apply(|_instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::InterfaceDelete(area_idx, iface_idx));
        })
        .lookup(|instance, list_entry, dnode| {
            let area_idx = list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let ifname = dnode.get_string_relative("./name").unwrap();
            area.interfaces
                .get_mut_by_name(&mut instance.arenas.interfaces, &ifname)
                .map(|(iface_idx, _)| ListEntry::Interface(area_idx, iface_idx))
                .expect("could not find OSPF interface")
        })
        .path(ospf::areas::area::interfaces::interface::interface_type::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let if_type = args.dnode.get_string();
            let if_type = InterfaceType::try_from_yang(&if_type).unwrap();
            iface.config.if_type = if_type;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceReset(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::passive::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let passive = args.dnode.get_bool();
            iface.config.passive = passive;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceReset(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::priority::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let priority = args.dnode.get_u8();
            iface.config.priority = priority;

            let event_queue = args.event_queue;
            event_queue
                .insert(Event::InterfacePriorityChange(area_idx, iface_idx));
            event_queue
                .insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::static_neighbors::neighbor::PATH)
        .create_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let identifier = args.dnode.get_ip_relative("identifier").unwrap();
            let identifier = V::NetIpAddr::get(identifier).unwrap();
            iface
                .config
                .static_nbrs
                .insert(identifier, Default::default());
        })
        .delete_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.static_nbrs.remove(&addr);
        })
        .lookup(|_instance, list_entry, dnode| {
            let (_, iface_idx) = list_entry.into_interface().unwrap();

            let identifier = dnode.get_ip_relative("./identifier").unwrap();
            let identifier = V::NetIpAddr::get(identifier).unwrap();
            ListEntry::StaticNbr(iface_idx, identifier)
        })
        .path(ospf::areas::area::interfaces::interface::static_neighbors::neighbor::cost::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let snbr = iface.config.static_nbrs.get_mut(&addr).unwrap();

            let cost = args.dnode.get_u16();
            snbr.cost = Some(cost);
        })
        .delete_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let snbr = iface.config.static_nbrs.get_mut(&addr).unwrap();

            snbr.cost = None;
        })
        .path(ospf::areas::area::interfaces::interface::static_neighbors::neighbor::poll_interval::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let snbr = iface.config.static_nbrs.get_mut(&addr).unwrap();

            let poll_interval = args.dnode.get_u16();
            snbr.poll_interval = poll_interval;
        })
        .path(ospf::areas::area::interfaces::interface::static_neighbors::neighbor::priority::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let snbr = iface.config.static_nbrs.get_mut(&addr).unwrap();

            let priority = args.dnode.get_u8();
            snbr.priority = priority;
        })
        .path(ospf::areas::area::interfaces::interface::bfd::enabled::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.bfd_enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::bfd::local_multiplier::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let local_multiplier = args.dnode.get_u8();
            iface.config.bfd_params.local_multiplier = local_multiplier;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::bfd::desired_min_tx_interval::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let min_tx = args.dnode.get_u32();
            iface.config.bfd_params.min_tx = min_tx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::interfaces::interface::bfd::required_min_rx_interval::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let min_rx = args.dnode.get_u32();
            iface.config.bfd_params.min_rx = min_rx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::interfaces::interface::bfd::min_interval::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
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
        .path(ospf::areas::area::interfaces::interface::hello_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_interval = args.dnode.get_u16();
            iface.config.hello_interval = hello_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceResetHelloInterval(
                area_idx, iface_idx,
            ));
            event_queue
                .insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::dead_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let dead_interval = args.dnode.get_u16();
            iface.config.dead_interval = dead_interval;

            let event_queue = args.event_queue;
            event_queue
                .insert(Event::InterfaceResetDeadInterval(area_idx, iface_idx));
            event_queue
                .insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(
            ospf::areas::area::interfaces::interface::retransmit_interval::PATH,
        )
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let retransmit_interval = args.dnode.get_u16();
            iface.config.retransmit_interval = retransmit_interval;
        })
        .path(ospf::areas::area::interfaces::interface::transmit_delay::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let transmit_delay = args.dnode.get_u16();
            iface.config.transmit_delay = transmit_delay;
        })
        .path(ospf::areas::area::interfaces::interface::enabled::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::cost::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let cost = args.dnode.get_u16();
            iface.config.cost = cost;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceCostChange(area_idx));
        })
        .path(ospf::areas::area::interfaces::interface::mtu_ignore::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let mtu_ignore = args.dnode.get_bool();
            iface.config.mtu_ignore = mtu_ignore;
        })
        .build()
}

fn load_callbacks_ospfv2() -> Callbacks<Instance<Ospfv2>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::<Instance<Ospfv2>>::new(core_cbs)
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_key_chain::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keychain = args.dnode.get_string();
            iface.config.auth_keychain = Some(auth_keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_key_id::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keyid = args.dnode.get_u32();
            iface.config.auth_keyid = Some(auth_keyid);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keyid = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_key::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_key = args.dnode.get_string();
            iface.config.auth_key = Some(auth_key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_algo = args.dnode.get_string();
            let auth_algo = CryptoAlgo::try_from_yang(&auth_algo).unwrap();
            iface.config.auth_algo = Some(auth_algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .build()
}

fn load_callbacks_ospfv3() -> Callbacks<Instance<Ospfv3>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::<Instance<Ospfv3>>::new(core_cbs)
        .path(ospf::instance_id::PATH)
        .modify_apply(|instance, args| {
            let instance_id = args.dnode.get_u8();
            instance.config.instance_id = instance_id;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceIdUpdate);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::interfaces::interface::instance_id::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let instance_id = args.dnode.get_u8();
            iface.config.instance_id.explicit = Some(instance_id);
            iface.config.instance_id.resolved = instance_id;

            let event_queue = args.event_queue;
            event_queue
                .insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.instance_id.explicit = None;
            iface.config.instance_id.resolved = instance.config.instance_id;

            let event_queue = args.event_queue;
            event_queue
                .insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_key_chain::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keychain = args.dnode.get_string();
            iface.config.auth_keychain = Some(auth_keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_sa_id::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keyid = args.dnode.get_u16();
            iface.config.auth_keyid = Some(auth_keyid as u32);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keyid = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_key::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_key = args.dnode.get_string();
            iface.config.auth_key = Some(auth_key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_algo = args.dnode.get_string();
            let auth_algo = CryptoAlgo::try_from_yang(&auth_algo).unwrap();
            iface.config.auth_algo = Some(auth_algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) =
                args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(ospf::areas::PATH)
        .validate(|args| {
            // Ensure no interface is configured in more than one area.
            let mut ifnames = HashSet::new();
            for dnode in args
                .dnode
                .find_xpath("./area/interfaces/interface/name")
                .unwrap()
            {
                if !ifnames.insert(dnode.get_string()) {
                    return Err(format!(
                        "interface '{}' configured in more than one area",
                        dnode.get_string()
                    ));
                }
            }

            Ok(())
        })
        .path(ospf::areas::area::area_type::PATH)
        .validate(|args| {
            let area_type = args.dnode.get_string();
            let area_type = AreaType::try_from_yang(&area_type).unwrap();
            if area_type == AreaType::Nssa {
                return Err("unsupported area type".to_string());
            }

            let area_id = args.dnode.get_ipv4_relative("../area-id").unwrap();
            if area_type != AreaType::Normal && area_id == Ipv4Addr::UNSPECIFIED
            {
                return Err(
                    "can't change type of the backbone area".to_string()
                );
            }

            Ok(())
        })
        .build()
}

fn load_validation_callbacks_ospfv2() -> ValidationCallbacks {
    let core_cbs = load_validation_callbacks();
    ValidationCallbacksBuilder::new(core_cbs)
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_crypto_algorithm::PATH)
        .validate(|args| {
            let valid_options = [
                CryptoAlgo::Md5.to_yang(),
                CryptoAlgo::HmacSha1.to_yang(),
                CryptoAlgo::HmacSha256.to_yang(),
                CryptoAlgo::HmacSha384.to_yang(),
                CryptoAlgo::HmacSha512.to_yang(),
            ];

            let algo = args.dnode.get_string();
            if !valid_options.iter().any(|option| *option == algo) {
                return Err(format!(
                    "unsupported cryptographic algorithm (valid options: \"{}\")",
                    valid_options.join(", "),
                ));
            }

            Ok(())
        })
        .build()
}

fn load_validation_callbacks_ospfv3() -> ValidationCallbacks {
    let core_cbs = load_validation_callbacks();
    ValidationCallbacksBuilder::new(core_cbs)
        .path(ospf::instance_id::PATH)
        .validate(|args| {
            let instance_id = args.dnode.get_u8();
            let af = args
                .dnode
                .get_af_relative("../address-family")
                .unwrap_or(AddressFamily::Ipv6);

            // Validate interface Instance ID based on RFC5838's address-family
            // Instance ID ranges.
            let range = match af {
                AddressFamily::Ipv6 => 0..=31,
                AddressFamily::Ipv4 => 64..=95,
            };
            if !range.contains(&instance_id) {
                return Err(format!(
                    "Instance ID {} isn't valid for the {} address family",
                    instance_id, af
                ));
            }

            Ok(())
        })
        .path(ospf::areas::area::interfaces::interface::instance_id::PATH)
        .validate(|args| {
            let instance_id = args.dnode.get_u8();
            let af = args
                .dnode
                .get_af_relative("../../../../../address-family")
                .unwrap_or(AddressFamily::Ipv6);

            // Validate interface Instance ID based on RFC5838's
            // address-family Instance ID ranges.
            let range = match af {
                AddressFamily::Ipv6 => 0..=31,
                AddressFamily::Ipv4 => 64..=95,
            };
            if !range.contains(&instance_id) {
                return Err(format!(
                    "Instance ID {} isn't valid for the {} address family",
                    instance_id, af
                ));
            }

            Ok(())
        })
        .path(ospf::segment_routing::enabled::PATH)
        .validate(|args| {
            let sr_enabled = args.dnode.get_bool();
            let extended_lsa = args
                .dnode
                .get_bool_relative("../../extended-lsa-support")
                .unwrap();

            if sr_enabled && !extended_lsa {
                return Err(
                    "Segment Routing for OSPFv3 requires extended LSA support enabled".to_string()
                );
            }

            Ok(())
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_crypto_algorithm::PATH)
        .validate(|args| {
            let valid_options = [
                CryptoAlgo::HmacSha1.to_yang(),
                CryptoAlgo::HmacSha256.to_yang(),
                CryptoAlgo::HmacSha384.to_yang(),
                CryptoAlgo::HmacSha512.to_yang(),
            ];

            let algo = args.dnode.get_string();
            if !valid_options.iter().any(|option| *option == algo) {
                return Err(format!(
                    "unsupported cryptographic algorithm (valid options: \"{}\")",
                    valid_options.join(", "),
                ));
            }

            Ok(())
        })
        .build()
}

// ===== impl Instance =====

#[async_trait]
impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry = ListEntry<V>;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        V::validation_callbacks()
    }

    fn callbacks() -> Option<&'static Callbacks<Instance<V>>> {
        V::configuration_callbacks()
    }

    async fn process_event(&mut self, event: Event) {
        match event {
            Event::InstanceReset => self.reset(),
            Event::InstanceUpdate => self.update(),
            Event::InstanceIdUpdate => {
                for area_idx in self.arenas.areas.indexes().collect::<Vec<_>>()
                {
                    let area = &mut self.arenas.areas[area_idx];
                    for iface_idx in
                        area.interfaces.indexes().collect::<Vec<_>>()
                    {
                        let iface = &mut self.arenas.interfaces[iface_idx];
                        iface.config.instance_id.resolved = iface
                            .config
                            .instance_id
                            .explicit
                            .unwrap_or(self.config.instance_id);
                    }

                    self.process_event(Event::AreaSyncHelloTx(area_idx)).await;
                }
            }
            Event::AreaCreate(area_idx) => {
                let area = &mut self.arenas.areas[area_idx];

                // Originate Router Information LSA(s).
                self.tx.protocol_input.lsa_orig_event(
                    LsaOriginateEvent::AreaStart { area_id: area.id },
                );
            }
            Event::AreaDelete(area_idx) => {
                let area = &mut self.arenas.areas[area_idx];

                // Delete area's interfaces.
                for iface_idx in area.interfaces.indexes().collect::<Vec<_>>() {
                    self.process_event(Event::InterfaceDelete(
                        area_idx, iface_idx,
                    ))
                    .await;
                }

                // Delete area.
                self.arenas.areas.delete(area_idx);
            }
            Event::AreaTypeChange(area_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];

                    // Kill all neighbors in the area to speed-up reconvergence.
                    for iface_idx in area.interfaces.indexes() {
                        let iface = &mut arenas.interfaces[iface_idx];

                        for nbr in iface.state.neighbors.iter(&arenas.neighbors)
                        {
                            instance.tx.protocol_input.nsm_event(
                                area.id,
                                iface.id,
                                nbr.id,
                                nsm::Event::Kill,
                            );
                        }
                    }

                    // Purge all AS-scoped LSAs in the absence of at least one
                    // active normal area.
                    if !arenas.areas.iter().any(|area| {
                        area.config.area_type == AreaType::Normal
                            && area.is_active(&arenas.interfaces)
                    }) {
                        instance.state.lsdb = Default::default();
                    }
                }
            }
            Event::AreaSyncHelloTx(area_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];

                    for iface_idx in area.interfaces.indexes() {
                        let iface = &mut arenas.interfaces[iface_idx];

                        iface.sync_hello_tx(area, &instance);
                    }
                }
            }
            Event::InterfaceUpdate(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    iface.update(
                        area,
                        &instance,
                        &mut arenas.neighbors,
                        &arenas.lsa_entries,
                    );
                }
            }
            Event::InterfaceDelete(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    // Stop interface if it's active.
                    let reason = InterfaceInactiveReason::AdminDown;
                    iface.fsm(
                        area,
                        &instance,
                        &mut arenas.neighbors,
                        &arenas.lsa_entries,
                        ism::Event::InterfaceDown(reason),
                    );

                    // Update the routing table to remove nexthops that are no
                    // longer reachable.
                    for route in instance.state.rib.values_mut() {
                        route.nexthops.retain(|_, nexthop| {
                            nexthop.iface_idx != iface_idx
                        });
                    }
                }

                let area = &mut self.arenas.areas[area_idx];
                area.interfaces
                    .delete(&mut self.arenas.interfaces, iface_idx);
            }
            Event::InterfaceReset(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    if !iface.is_down() {
                        iface.reset(
                            area,
                            &instance,
                            &mut arenas.neighbors,
                            &arenas.lsa_entries,
                        );
                    }
                }
            }
            Event::InterfaceResetHelloInterval(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    if iface.state.tasks.hello_interval.is_some() {
                        iface.hello_interval_start(area, &instance);
                    }
                }
            }
            Event::InterfaceResetDeadInterval(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    for nbr_idx in iface.state.neighbors.indexes() {
                        let nbr = &mut arenas.neighbors[nbr_idx];

                        if nbr.tasks.inactivity_timer.is_some() {
                            nbr.inactivity_timer_start(iface, area, &instance);
                        }
                    }
                }
            }
            Event::InterfacePriorityChange(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &arenas.interfaces[iface_idx];

                    // Rerun the DR election algorithm if necessary.
                    if !iface.is_down() && iface.is_broadcast_or_nbma() {
                        instance.tx.protocol_input.ism_event(
                            area.id,
                            iface.id,
                            ism::Event::NbrChange,
                        );
                    }
                }
            }
            Event::InterfaceCostChange(area_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];

                    instance.tx.protocol_input.lsa_orig_event(
                        LsaOriginateEvent::InterfaceCostChange {
                            area_id: area.id,
                        },
                    );
                }
            }
            Event::InterfaceSyncHelloTx(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    iface.sync_hello_tx(area, &instance);
                }
            }
            Event::InterfaceUpdateAuth(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    // Update interface authentication keys.
                    iface.auth_update(area, &instance);
                }
            }
            Event::InterfaceBfdChange(iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];

                    for nbr in iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .filter(|nbr| nbr.state >= nsm::State::TwoWay)
                    {
                        if iface.config.bfd_enabled {
                            nbr.bfd_register(iface, &instance);
                        } else {
                            nbr.bfd_unregister(iface, &instance);
                        }
                    }
                }
            }
            Event::StubRouterChange => {
                if let Some((instance, _)) = self.as_up() {
                    // (Re)originate Router-LSAs.
                    instance
                        .tx
                        .protocol_input
                        .lsa_orig_event(LsaOriginateEvent::StubRouterChange);
                }
            }
            Event::GrHelperChange => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    // Exit from the helper mode for all neighbors.
                    if !instance.config.gr.helper_enabled {
                        gr::helper_process_topology_change(
                            None,
                            &mut instance,
                            arenas,
                        );
                    }

                    // (Re)originate Router Information LSAs.
                    instance
                        .tx
                        .protocol_input
                        .lsa_orig_event(LsaOriginateEvent::GrHelperChange);
                }
            }
            Event::SrEnableChange(sr_enabled) => {
                if let Some((instance, arenas)) = self.as_up() {
                    // (Re)originate LSAs that might have been affected.
                    instance
                        .tx
                        .protocol_input
                        .lsa_orig_event(LsaOriginateEvent::SrEnableChange);

                    // Iterate over all existing adjacencies.
                    for area in arenas.areas.iter_mut() {
                        for iface in area.interfaces.iter(&arenas.interfaces) {
                            for nbr_idx in iface.state.neighbors.indexes() {
                                let nbr = &mut arenas.neighbors[nbr_idx];
                                if nbr.state < nsm::State::TwoWay {
                                    continue;
                                }

                                if sr_enabled {
                                    // Add SR Adj-SID.
                                    sr::adj_sid_add(nbr, iface, &instance);
                                } else {
                                    // Delete SR Adj-SIDs.
                                    sr::adj_sid_del_all(nbr, &instance);
                                }
                            }
                        }
                    }
                }
            }
            Event::RerunSpf => {
                if let Some((instance, _)) = self.as_up() {
                    instance
                        .tx
                        .protocol_input
                        .spf_delay_event(spf::fsm::Event::ConfigChange);
                }
            }
            Event::UpdateSummaries => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    area::update_summary_lsas(
                        &mut instance,
                        &mut arenas.areas,
                        &arenas.interfaces,
                        &arenas.lsa_entries,
                    );
                }
            }
            Event::ReinstallRoutes => {
                if let Some((instance, arenas)) = self.as_up() {
                    for (dest, route) in
                        instance.state.rib.iter().filter(|(_, route)| {
                            route.flags.contains(RouteNetFlags::INSTALLED)
                        })
                    {
                        let distance = route.distance(instance.config);
                        instance.tx.sb.route_install(
                            dest,
                            route,
                            None,
                            distance,
                            &arenas.interfaces,
                        );
                    }
                }
            }
            Event::SbRequestInterfaceInfo => {
                if self.is_active() {
                    self.tx.sb.request_interface_info();
                }
            }
        }
    }
}

// ===== impl ListEntry =====

#[allow(clippy::derivable_impls)]
impl<V> Default for ListEntry<V>
where
    V: Version,
{
    fn default() -> ListEntry<V> {
        ListEntry::None
    }
}
