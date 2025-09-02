//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, LazyLock as Lazy};

use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    self, Callbacks, CallbacksBuilder, ConfigChanges, Provider,
    ValidationCallbacks, ValidationCallbacksBuilder,
};
use holo_northbound::yang::control_plane_protocol;
use holo_northbound::yang::routing::segment_routing::sr_mpls;
use holo_northbound::yang::routing::{bier, ribs};
use holo_northbound::{CallbackKey, NbDaemonSender};
use holo_utils::bier::{
    BfrId, BierBift, BierBiftCfg, BierCfgEvent, BierEncapsulation,
    BierEncapsulationType, BierInBiftId, BierOutBiftId, BierSubDomainCfg,
    BiftNbr, Bsl, SubDomainId, UnderlayProtocolType,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::mpls::LabelRange;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    Nexthop, RouteKeyMsg, RouteKind, RouteMsg, RouteOpaqueAttrs,
};
use holo_utils::sr::{
    IgpAlgoType, SidLastHopBehavior, SrCfgEvent, SrCfgPrefixSid,
};
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;

use crate::interface::Interfaces;
use crate::northbound::REGEX_PROTOCOLS;
use crate::{InstanceHandle, InstanceId, Master};

static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
static CALLBACKS: Lazy<configuration::Callbacks<Master>> =
    Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    ProtocolInstance(InstanceId),
    StaticRoute(IpNetwork),
    StaticRouteNexthop(IpNetwork, String),
    SrCfgPrefixSid(IpNetwork, IgpAlgoType),
    BierCfgSubDomain(SubDomainId, AddressFamily),
    BierCfgEncapsulation(
        SubDomainId,
        AddressFamily,
        Bsl,
        BierEncapsulationType,
    ),
    BierCfgBift(BfrId),
    BierCfgBiftBsl(BfrId, Bsl),
    BierCfgBiftNbr(BfrId, Bsl, IpAddr),
}

#[derive(Debug, EnumAsInner)]
pub enum Resource {
    SrLabelRange(LabelRange),
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceStart { protocol: Protocol, name: String },
    StaticRouteInstall(IpNetwork),
    StaticRouteUninstall(IpNetwork),
    SrCfgUpdate,
    SrCfgLabelRangeUpdate,
    SrCfgPrefixSidUpdate(AddressFamily),
    BierCfgUpdate,
    BierCfgEncapUpdate(SubDomainId, AddressFamily, Bsl, BierEncapsulationType),
    BierCfgSubDomainUpdate(AddressFamily),
    BierCfgBiftUpdate(BfrId),
}

// ===== configuration structs =====

#[derive(Debug, Default)]
pub struct StaticRoute {
    pub nexthop_single: StaticRouteNexthop,
    pub nexthop_special: Option<NexthopSpecial>,
    pub nexthop_list: HashMap<String, StaticRouteNexthop>,
}

#[derive(Clone, Debug, Default)]
pub struct StaticRouteNexthop {
    pub ifname: Option<String>,
    pub addr: Option<IpAddr>,
}

#[derive(Clone, Debug)]
pub enum NexthopSpecial {
    Blackhole,
    Unreachable,
    Prohibit,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(control_plane_protocol::PATH)
        .create_prepare(|_master, args| {
            let ptype = args.dnode.get_string_relative("./type").unwrap();
            let name = args.dnode.get_string_relative("./name").unwrap();

            // Parse protocol type.
            let protocol = match Protocol::try_from_yang(&ptype) {
                Some(Protocol::DIRECT) => {
                    return Err("invalid protocol type".to_owned());
                }
                Some(value) => value,
                None => {
                    return Err("unknown protocol type".to_owned());
                }
            };

            // The BFD task runs permanently.
            if protocol == Protocol::BFD {
                return Ok(());
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceStart { protocol, name });

            Ok(())
        })
        .create_abort(|master, args| {
            let instance_id = args.list_entry.into_protocol_instance().unwrap();

            // The BFD task runs permanently.
            if instance_id.protocol == Protocol::BFD {
                return;
            }

            // Remove protocol instance.
            master.instances.remove(&instance_id);
        })
        .delete_apply(|master, args| {
            let instance_id = args.list_entry.into_protocol_instance().unwrap();

            // The BFD task runs permanently.
            if instance_id.protocol == Protocol::BFD {
                return;
            }

            // Remove protocol instance.
            master.instances.remove(&instance_id);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let ptype = dnode.get_string_relative("./type").unwrap();
            let name = dnode.get_string_relative("./name").unwrap();
            let protocol = Protocol::try_from_yang(&ptype).unwrap();
            let instance_id = InstanceId::new(protocol, name);
            ListEntry::ProtocolInstance(instance_id)
        })
        .path(control_plane_protocol::description::PATH)
        .modify_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(control_plane_protocol::static_routes::ipv4::route::PATH)
        .create_apply(|master, args| {
            let prefix = args.dnode.get_prefix_relative("./destination-prefix").unwrap();

            master.static_routes.insert(prefix, StaticRoute::default());
        })
        .delete_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();

            master.static_routes.remove(&prefix);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteUninstall(prefix));
        })
        .lookup(|_master, _list_entry, dnode| {
            let prefix = dnode.get_prefix_relative("./destination-prefix").unwrap();
            ListEntry::StaticRoute(prefix)
        })
        .path(control_plane_protocol::static_routes::ipv4::route::description::PATH)
        .modify_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::outgoing_interface::PATH)
        .modify_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            let ifname = args.dnode.get_string();
            route.nexthop_single.ifname = Some(ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            route.nexthop_single.ifname = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::ipv4_next_hop_address::PATH)
        .modify_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            let addr = args.dnode.get_ip();
            route.nexthop_single.addr = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            route.nexthop_single.addr = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::special_next_hop::PATH)
        .modify_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            let special = args.dnode.get_string();
            let special = NexthopSpecial::try_from_yang(&special).unwrap();
            route.nexthop_special = Some(special);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            route.nexthop_special = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::next_hop_list::next_hop::PATH)
        .create_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            let index = args.dnode.get_string_relative("./index").unwrap();
            route.nexthop_list.insert(index, StaticRouteNexthop::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            route.nexthop_list.remove(&nh_index);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .lookup(|_master, list_entry, dnode| {
            let prefix = list_entry.into_static_route().unwrap();

            let index = dnode.get_string_relative("./index").unwrap();
            ListEntry::StaticRouteNexthop(prefix, index)
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::next_hop_list::next_hop::outgoing_interface::PATH)
        .modify_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            let ifname = args.dnode.get_string();
            nexthop.ifname = Some(ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            nexthop.ifname = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::next_hop_list::next_hop::ipv4_next_hop_address::PATH)
        .modify_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            let addr = args.dnode.get_ip();
            nexthop.addr = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            nexthop.addr = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::PATH)
        .create_apply(|master, args| {
            let prefix = args.dnode.get_prefix_relative("./destination-prefix").unwrap();

            master.static_routes.insert(prefix, StaticRoute::default());
        })
        .delete_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();

            master.static_routes.remove(&prefix);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteUninstall(prefix));
        })
        .lookup(|_master, _list_entry, dnode| {
            let prefix = dnode.get_prefix_relative("./destination-prefix").unwrap();
            ListEntry::StaticRoute(prefix)
        })
        .path(control_plane_protocol::static_routes::ipv6::route::description::PATH)
        .modify_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::outgoing_interface::PATH)
        .modify_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            let ifname = args.dnode.get_string();
            route.nexthop_single.ifname = Some(ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            route.nexthop_single.ifname = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::ipv6_next_hop_address::PATH)
        .modify_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            let addr = args.dnode.get_ip();
            route.nexthop_single.addr = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            route.nexthop_single.addr = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::special_next_hop::PATH)
        .modify_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            let special = args.dnode.get_string();
            let special = NexthopSpecial::try_from_yang(&special).unwrap();
            route.nexthop_special = Some(special);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            route.nexthop_special = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::next_hop_list::next_hop::PATH)
        .create_apply(|master, args| {
            let prefix = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            let index = args.dnode.get_string_relative("./index").unwrap();
            route.nexthop_list.insert(index, StaticRouteNexthop::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();

            route.nexthop_list.remove(&nh_index);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .lookup(|_master, list_entry, dnode| {
            let prefix = list_entry.into_static_route().unwrap();

            let index = dnode.get_string_relative("./index").unwrap();
            ListEntry::StaticRouteNexthop(prefix, index)
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::next_hop_list::next_hop::outgoing_interface::PATH)
        .modify_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            let ifname = args.dnode.get_string();
            nexthop.ifname = Some(ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            nexthop.ifname = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::next_hop_list::next_hop::ipv6_next_hop_address::PATH)
        .modify_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            let addr = args.dnode.get_ip();
            nexthop.addr = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .delete_apply(|master, args| {
            let (prefix, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&prefix).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            nexthop.addr = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(prefix));
        })
        .path(sr_mpls::bindings::connected_prefix_sid_map::connected_prefix_sid::PATH)
        .create_apply(|master, args| {
            let prefix = args.dnode.get_prefix_relative("./prefix").unwrap();
            let algo = args.dnode.get_string_relative("./algorithm").unwrap();
            let algo = IgpAlgoType::try_from_yang(&algo).unwrap();
            let index = args.dnode.get_u32_relative("./start-sid").unwrap();
            let last_hop = args.dnode.get_string_relative("./last-hop-behavior").unwrap();
            let last_hop = SidLastHopBehavior::try_from_yang(&last_hop).unwrap();
            let psid = SrCfgPrefixSid::new(index, last_hop);
            master.sr_config.prefix_sids.insert((prefix, algo), psid);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgPrefixSidUpdate(prefix.address_family()));
        })
        .delete_apply(|master, args| {
            let prefix = args.dnode.get_prefix_relative("./prefix").unwrap();
            let algo = args.dnode.get_string_relative("./algorithm").unwrap();
            let algo = IgpAlgoType::try_from_yang(&algo).unwrap();
            master.sr_config.prefix_sids.remove(&(prefix, algo));

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgPrefixSidUpdate(prefix.address_family()));
        })
        .lookup(|_master, _list_entry, dnode| {
            let prefix = dnode.get_prefix_relative("./prefix").unwrap();
            let algo = dnode.get_string_relative("./algorithm").unwrap();
            let algo = IgpAlgoType::try_from_yang(&algo).unwrap();
            ListEntry::SrCfgPrefixSid(prefix, algo)
        })
        .path(sr_mpls::bindings::connected_prefix_sid_map::connected_prefix_sid::start_sid::PATH)
        .modify_apply(|master, args| {
            let (prefix, algo) = args.list_entry.into_sr_cfg_prefix_sid().unwrap();
            let psid = master.sr_config.prefix_sids.get_mut(&(prefix, algo)).unwrap();

            let index = args.dnode.get_u32();
            psid.index = index;

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgPrefixSidUpdate(prefix.address_family()));
        })
        .path(sr_mpls::bindings::connected_prefix_sid_map::connected_prefix_sid::last_hop_behavior::PATH)
        .modify_apply(|master, args| {
            let (prefix, algo) = args.list_entry.into_sr_cfg_prefix_sid().unwrap();
            let psid = master.sr_config.prefix_sids.get_mut(&(prefix, algo)).unwrap();

            let last_hop = args.dnode.get_string();
            let last_hop = SidLastHopBehavior::try_from_yang(&last_hop).unwrap();
            psid.last_hop = last_hop;

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgPrefixSidUpdate(prefix.address_family()));
        })
        .path(sr_mpls::srgb::srgb::PATH)
        .create_prepare(|master, args| {
            let lower_bound = args.dnode.get_u32_relative("./lower-bound").unwrap();
            let upper_bound = args.dnode.get_u32_relative("./upper-bound").unwrap();
            let range = LabelRange::new(lower_bound, upper_bound);

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager
                .range_reserve(range)
                .map_err(|error| error.to_string())?;
            *args.resource = Some(Resource::SrLabelRange(range));

            Ok(())
        })
        .create_abort(|master, args| {
            let resource = args.resource.take().unwrap();
            let range = resource.into_sr_label_range().unwrap();

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
        })
        .create_apply(|master, args| {
            let resource = args.resource.take().unwrap();
            let range = resource.into_sr_label_range().unwrap();
            master.sr_config.srgb.insert(range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgLabelRangeUpdate);
        })
        .delete_apply(|master, args| {
            let lower_bound = args.dnode.get_u32_relative("./lower-bound").unwrap();
            let upper_bound = args.dnode.get_u32_relative("./upper-bound").unwrap();
            let range = LabelRange::new(lower_bound, upper_bound);

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
            master.sr_config.srgb.remove(&range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgLabelRangeUpdate);
        })
        .lookup(|_master, _list_entry, _dnode| {
            ListEntry::None
        })
        .path(sr_mpls::srlb::srlb::PATH)
        .create_prepare(|master, args| {
            let lower_bound = args.dnode.get_u32_relative("./lower-bound").unwrap();
            let upper_bound = args.dnode.get_u32_relative("./upper-bound").unwrap();
            let range = LabelRange::new(lower_bound, upper_bound);

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager
                .range_reserve(range)
                .map_err(|error| error.to_string())?;
            *args.resource = Some(Resource::SrLabelRange(range));

            Ok(())
        })
        .create_abort(|master, args| {
            let resource = args.resource.take().unwrap();
            let range = resource.into_sr_label_range().unwrap();

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
        })
        .create_apply(|master, args| {
            let resource = args.resource.take().unwrap();
            let range = resource.into_sr_label_range().unwrap();
            master.sr_config.srlb.insert(range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgLabelRangeUpdate);
        })
        .delete_apply(|master, args| {
            let lower_bound = args.dnode.get_u32_relative("./lower-bound").unwrap();
            let upper_bound = args.dnode.get_u32_relative("./upper-bound").unwrap();
            let range = LabelRange::new(lower_bound, upper_bound);

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
            master.sr_config.srlb.remove(&range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgLabelRangeUpdate);
        })
        .lookup(|_master, _list_entry, _dnode| {
            ListEntry::None
        })
        .path(ribs::rib::PATH)
        .create_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .lookup(|_master, _list_entry, _dnode| {
            ListEntry::None
        })
        .path(ribs::rib::address_family::PATH)
        .modify_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(ribs::rib::description::PATH)
        .modify_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(bier::sub_domain::PATH)
        .create_apply(|master, args| {
            let sd_id = args.dnode.get_u8_relative("./sub-domain-id").unwrap();
            let af = args.dnode.get_af_relative("./address-family").unwrap();
            let bfr_prefix = args.dnode.get_prefix_relative("./bfr-prefix").unwrap();
            let underlay_protocol = args.dnode.get_string_relative("./underlay-protocol-type").unwrap();
            let underlay_protocol = UnderlayProtocolType::try_from_yang(&underlay_protocol).unwrap();
            let bfr_id = args.dnode.get_u16_relative("./bfr-id").unwrap();
            let bsl = args.dnode.get_string_relative("./bsl").unwrap();
            let bsl = Bsl::try_from_yang(&bsl).unwrap();
            let sd_cfg = BierSubDomainCfg {
                sd_id,
                af,
                bfr_prefix,
                underlay_protocol,
                mt_id: bier::sub_domain::mt_id::DFLT,
                bfr_id,
                bsl,
                ipa: bier::sub_domain::igp_algorithm::DFLT,
                bar: bier::sub_domain::bier_algorithm::DFLT,
                load_balance_num: bier::sub_domain::load_balance_num::DFLT,
                encap: Default::default(),
            };
            master.bier_config.sd_cfg.insert((sd_id, af), sd_cfg);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .delete_apply(|master, args| {
            let sd_id = args.dnode.get_u8_relative("./sub-domain-id").unwrap();
            let af = args.dnode.get_af_relative("./address-family").unwrap();
            master.bier_config.sd_cfg.remove(&(sd_id, af));

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .lookup(|_master, _list_entry, dnode| {
            let sd_id = dnode.get_u8_relative("./sub-domain-id").unwrap();
            let af = dnode.get_af_relative("./address-family").unwrap();
            ListEntry::BierCfgSubDomain(sd_id, af)
        })
        .path(bier::sub_domain::bfr_prefix::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let bfr_prefix = args.dnode.get_prefix();
            sd_cfg.bfr_prefix = bfr_prefix;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .path(bier::sub_domain::underlay_protocol_type::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let underlay_protocol = args.dnode.get_string();
            let underlay_protocol = UnderlayProtocolType::try_from_yang(&underlay_protocol).unwrap();
            sd_cfg.underlay_protocol = underlay_protocol;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .path(bier::sub_domain::mt_id::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let mt_id = args.dnode.get_u8();
            sd_cfg.mt_id = mt_id;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .path(bier::sub_domain::bfr_id::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let bfr_id = args.dnode.get_u16();
            sd_cfg.bfr_id = bfr_id;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .path(bier::sub_domain::bsl::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let bsl = args.dnode.get_string();
            let bsl = Bsl::try_from_yang(&bsl).unwrap();
            sd_cfg.bsl = bsl;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .path(bier::sub_domain::igp_algorithm::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let ipa = args.dnode.get_u8();
            sd_cfg.ipa = ipa;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .path(bier::sub_domain::bier_algorithm::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let bar = args.dnode.get_u8();
            sd_cfg.bar = bar;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .path(bier::sub_domain::load_balance_num::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let load_balance_num = args.dnode.get_u8();
            sd_cfg.load_balance_num = load_balance_num;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        })
        .path(bier::sub_domain::encapsulation::PATH)
        .create_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let bsl = args.dnode.get_string_relative("./bsl").unwrap();
            let bsl = Bsl::try_from_yang(&bsl).unwrap();
            let encap_type = args.dnode.get_string_relative("./encapsulation-type").unwrap();
            let encap_type = BierEncapsulationType::try_from_yang(&encap_type).unwrap();
            let max_si = args.dnode.get_u8_relative("./max-si").unwrap();
            let in_bift_id_base = args.dnode.get_u32_relative("./in-bift-id/in-bift-id-base");
            let in_bift_id_encoding = args.dnode.get_bool_relative("./in-bift-id/in-bift-id-encoding");
            let in_bift_id = in_bift_id_base
                .map_or(in_bift_id_encoding.map(BierInBiftId::Encoding), |v| {
                    Some(BierInBiftId::Base(v))
                })
                .unwrap();
            let encap_cfg = BierEncapsulation::new(bsl, encap_type, max_si, in_bift_id);
            sd_cfg.encap.insert((bsl, encap_type), encap_cfg);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgEncapUpdate(sd_id, af, bsl, encap_type));
        })
        .delete_apply(|context, args| {
            let (sd_id, af) = args.list_entry.into_bier_cfg_sub_domain().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();

            let bsl = args.dnode.get_string_relative("./bsl").unwrap();
            let bsl = Bsl::try_from_yang(&bsl).unwrap();
            let encap_type = args.dnode.get_string_relative("./encapsulation-type").unwrap();
            let encap_type = BierEncapsulationType::try_from_yang(&encap_type).unwrap();
            sd_cfg.encap.remove(&(bsl, encap_type));

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
        })
        .lookup(|_context, list_entry, dnode| {
            let (sd_id, af) = list_entry.into_bier_cfg_sub_domain().unwrap();
            let bsl = dnode.get_string_relative("./bsl").unwrap();
            let bsl = Bsl::try_from_yang(&bsl).unwrap();
            let encap_type = dnode.get_string_relative("./encapsulation-type").unwrap();
            let encap_type = BierEncapsulationType::try_from_yang(&encap_type).unwrap();
            ListEntry::BierCfgEncapsulation(sd_id, af, bsl, encap_type)
        })
        .path(bier::sub_domain::encapsulation::max_si::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af, bsl, encap_type) = args.list_entry.into_bier_cfg_encapsulation().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();
            let encap = sd_cfg.encap.get_mut(&(bsl, encap_type)).unwrap();

            let max_si = args.dnode.get_u8();
            encap.max_si = max_si;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgEncapUpdate(sd_id, af, bsl, encap_type));
        })
        .path(bier::sub_domain::encapsulation::in_bift_id::in_bift_id_base::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af, bsl, encap_type) = args.list_entry.into_bier_cfg_encapsulation().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();
            let encap = sd_cfg.encap.get_mut(&(bsl, encap_type)).unwrap();

            let in_bift_id_base = args.dnode.get_u32();
            encap.in_bift_id = BierInBiftId::Base(in_bift_id_base);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgEncapUpdate(sd_id, af, bsl, encap_type));
        })
        .delete_apply(|_context, _args| {
            // Nothing to do.
        })
        .path(bier::sub_domain::encapsulation::in_bift_id::in_bift_id_encoding::PATH)
        .modify_apply(|context, args| {
            let (sd_id, af, bsl, encap_type) = args.list_entry.into_bier_cfg_encapsulation().unwrap();
            let sd_cfg = context.bier_config.sd_cfg.get_mut(&(sd_id, af)).unwrap();
            let encap = sd_cfg.encap.get_mut(&(bsl, encap_type)).unwrap();

            let in_bift_id_encoding = args.dnode.get_bool();
            encap.in_bift_id = BierInBiftId::Encoding(in_bift_id_encoding);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgEncapUpdate(sd_id, af, bsl, encap_type));
        })
        .delete_apply(|_context, _args| {
            // Nothing to do.
        })
        .path(bier::bift::PATH)
        .create_apply(|master, args| {
            let bfr_id = args.dnode.get_u16_relative("./bfr-id").unwrap();

            let bift_cfg = BierBiftCfg {
                bfr_id,
                birt: Default::default()
            };

            master.bier_config.bift_cfg.insert(bfr_id, bift_cfg);
            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgBiftUpdate(bfr_id));
        })
        .delete_apply(|master, args| {
            let bfr_id = args.dnode.get_u16_relative("./bfr-id").unwrap();
            master.bier_config.bift_cfg.remove(&bfr_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgBiftUpdate(bfr_id));
        })
        .lookup(|_master, _list_entry, dnode| {
            let bfr_id = dnode.get_u16_relative("./bfr-id").unwrap();
            ListEntry::BierCfgBift(bfr_id)
        })
        .path(bier::bift::birt_bitstringlength::PATH)
        .create_apply(|context, args| {
            let bfr_id = args.list_entry.into_bier_cfg_bift().unwrap();
            let bift_cfg = context.bier_config.bift_cfg.get_mut(&bfr_id).unwrap();

            let bsl = args.dnode.get_string_relative("./bsl").unwrap();
            let bsl = Bsl::try_from_yang(&bsl).unwrap();

            let bift = BierBift {
                bsl,
                nbr: Default::default()
            };

            bift_cfg.birt.insert(bsl, bift);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Create custom event?
        })
        .delete_apply(|context, args| {
            let bfr_id = args.list_entry.into_bier_cfg_bift().unwrap();
            let bift_cfg = context.bier_config.bift_cfg.get_mut(&bfr_id).unwrap();

            let bsl = args.dnode.get_string_relative("./bsl").unwrap();
            let bsl = Bsl::try_from_yang(&bsl).unwrap();

            bift_cfg.birt.remove(&bsl);
            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Create custom event?
        })
        .lookup(|_master, list_entry, dnode| {
            let bfr_id = list_entry.into_bier_cfg_bift().unwrap();

            let bsl = dnode.get_string_relative("./bsl").unwrap();
            let bsl = Bsl::try_from_yang(&bsl).unwrap();

            ListEntry::BierCfgBiftBsl(bfr_id, bsl)
        })
        .path(bier::bift::birt_bitstringlength::bfr_nbr::PATH)
        .create_apply(|context, args| {
            let (bfr_id, bsl) = args.list_entry.into_bier_cfg_bift_bsl().unwrap();
            let bift_config = context.bier_config.bift_cfg.get_mut(&bfr_id).unwrap();
            let birt = bift_config.birt.get_mut(&bsl).unwrap();

            let bfr_nbr = args.dnode.get_ip_relative("./bfr-nbr").unwrap();
            let encap_type = args.dnode.get_string_relative("./encapsulation-type").unwrap();
            let encap_type = BierEncapsulationType::try_from_yang(&encap_type).unwrap();
            let out_bift_id = args.dnode.get_u32_relative("./out-bift-id/out-bift-id");
            let out_bift_encoding = args.dnode.get_bool_relative("./out-bift-id/out-bift-id-encoding");
            let out_bift_id = out_bift_id.map_or(out_bift_encoding.map(BierOutBiftId::Encoding), |v| Some(BierOutBiftId::Defined(v))).unwrap();

            let nbr = BiftNbr {
                bfr_nbr,
                encap_type,
                out_bift_id
            };

            birt.nbr.insert(bfr_nbr, nbr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Custom event?
        })
        .delete_apply(|context, args| {
            let (bfr_id, bsl) = args.list_entry.into_bier_cfg_bift_bsl().unwrap();
            let bift_config = context.bier_config.bift_cfg.get_mut(&bfr_id).unwrap();
            let birt = bift_config.birt.get_mut(&bsl).unwrap();

            let bfr_nbr = args.dnode.get_ip_relative("./bfr-nbr").unwrap();

            birt.nbr.remove(&bfr_nbr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Custom event?
        })
        .lookup(|_context, list_entry, dnode| {
            let (bfr_id, bsl) = list_entry.into_bier_cfg_bift_bsl().unwrap();
            let nbr = dnode.get_ip_relative("./bfr-nbr").unwrap();

            ListEntry::BierCfgBiftNbr(bfr_id, bsl, nbr)
        })
        .path(bier::bift::birt_bitstringlength::bfr_nbr::encapsulation_type::PATH)
        .modify_apply(|context, args| {
            let (bfr_id, bsl, nbr) = args.list_entry.into_bier_cfg_bift_nbr().unwrap();

            let bift_config = context.bier_config.bift_cfg.get_mut(&bfr_id).unwrap();
            let birt = bift_config.birt.get_mut(&bsl).unwrap();
            let nbr = birt.nbr.get_mut(&nbr).unwrap();

            let encap_type = args.dnode.get_string_relative("./encapsulation-type").unwrap();
            nbr.encap_type = BierEncapsulationType::try_from_yang(&encap_type).unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Custom event?
        })
        .delete_apply(|_context, _args| {
            // Nothing to do.
        })
        .path(bier::bift::birt_bitstringlength::bfr_nbr::out_bift_id::out_bift_id::PATH)
        .modify_apply(|context, args| {
            let (bfr_id, bsl, nbr) = args.list_entry.into_bier_cfg_bift_nbr().unwrap();

            let bift_config = context.bier_config.bift_cfg.get_mut(&bfr_id).unwrap();
            let birt = bift_config.birt.get_mut(&bsl).unwrap();
            let nbr = birt.nbr.get_mut(&nbr).unwrap();

            let out_bift_id = args.dnode.get_u32_relative("./out-bift-id/out-bift-id").unwrap();
            nbr.out_bift_id = BierOutBiftId::Defined(out_bift_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Custom event?
        })
        .delete_apply(|_context, _args| {
            // Nothing to do.
        })
        .path(bier::bift::birt_bitstringlength::bfr_nbr::out_bift_id::out_bift_id_encoding::PATH)
        .modify_apply(|context, args| {
            let (bfr_id, bsl, nbr) = args.list_entry.into_bier_cfg_bift_nbr().unwrap();

            let bift_config = context.bier_config.bift_cfg.get_mut(&bfr_id).unwrap();
            let birt = bift_config.birt.get_mut(&bsl).unwrap();
            let nbr = birt.nbr.get_mut(&nbr).unwrap();

            let out_bift_id_encoding = args.dnode.get_bool_relative("./out-bift-id/out-bift-id-encoding").unwrap();
            nbr.out_bift_id = BierOutBiftId::Encoding(out_bift_id_encoding);

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Custom event?
        })
        .delete_apply(|_context, _args| {
            // Nothing to do.
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(control_plane_protocol::PATH)
        .validate(|args| {
            let ptype = args.dnode.get_string_relative("./type").unwrap();
            let name = args.dnode.get_string_relative("./name").unwrap();

            // Parse protocol name.
            let protocol = match Protocol::try_from_yang(&ptype) {
                Some(value) => value,
                None => {
                    return Err("unknown protocol name".to_owned());
                }
            };

            // Validate BFD protocol instance name.
            if protocol == Protocol::BFD && name != "main" {
                return Err(
                    "BFD protocol instance should be named \"main\"".to_owned()
                );
            }

            Ok(())
        })
        .path(bier::sub_domain::PATH)
        .validate(|args| {
            let af = args.dnode.get_af_relative("./address-family").unwrap();
            let mt_id = args.dnode.get_u8_relative("./mt-id");

            // Enforce configured address family.
            if let Some(bfr_prefix) =
                args.dnode.get_prefix_relative("./bfr-prefix")
                && bfr_prefix.address_family() != af
            {
                return Err("Configured address family differs from BFR prefix address family.".to_owned());
            }

            // Enforce MT-ID value per RFC4915.
            if let Some(mt_id) = mt_id && mt_id > 128 {
                return Err("Invalid MT-ID per RFC4915".to_owned());
            }

            Ok(())
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        Some(&VALIDATION_CALLBACKS)
    }

    fn callbacks() -> &'static Callbacks<Master> {
        &CALLBACKS
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        let keys: Vec<Vec<CallbackKey>> = vec![
            #[cfg(feature = "bfd")]
            holo_bfd::northbound::configuration::CALLBACKS.keys(),
            #[cfg(feature = "bgp")]
            holo_bgp::northbound::configuration::CALLBACKS.keys(),
            #[cfg(feature = "isis")]
            holo_isis::northbound::configuration::CALLBACKS.keys(),
            #[cfg(feature = "ldp")]
            holo_ldp::northbound::configuration::CALLBACKS.keys(),
            #[cfg(feature = "ospf")]
            holo_ospf::northbound::configuration::CALLBACKS_OSPFV2.keys(),
            #[cfg(feature = "ospf")]
            holo_ospf::northbound::configuration::CALLBACKS_OSPFV3.keys(),
            #[cfg(feature = "rip")]
            holo_rip::northbound::configuration::CALLBACKS_RIPV2.keys(),
            #[cfg(feature = "rip")]
            holo_rip::northbound::configuration::CALLBACKS_RIPNG.keys(),
        ];

        Some(keys.concat())
    }

    fn relay_changes(
        &self,
        changes: ConfigChanges,
    ) -> Vec<(ConfigChanges, NbDaemonSender)> {
        // Create hash table that maps changes to the appropriate child
        // instances.
        let mut changes_map: HashMap<InstanceId, ConfigChanges> =
            HashMap::new();
        for change in changes {
            // HACK: parse protocol type and instance name.
            let caps = REGEX_PROTOCOLS.captures(&change.1).unwrap();
            let ptype = caps.get(1).unwrap().as_str();
            let name = caps.get(2).unwrap().as_str();

            // Move configuration change to the appropriate instance bucket.
            let protocol = Protocol::try_from_yang(ptype).unwrap();
            let instance_id = InstanceId::new(protocol, name.to_owned());
            changes_map.entry(instance_id).or_default().push(change);
        }
        changes_map
            .into_iter()
            .filter_map(|(instance_id, changes)| {
                self.instances
                    .get(&instance_id)
                    .map(|instance| (changes, instance.nb_tx.clone()))
            })
            .collect::<Vec<_>>()
    }

    fn relay_validation(&self) -> Vec<NbDaemonSender> {
        self.instances
            .values()
            .map(|instance| instance.nb_tx.clone())
            .collect()
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::InstanceStart { protocol, name } => {
                instance_start(self, protocol, name);
            }
            Event::StaticRouteInstall(prefix) => {
                let route = self.static_routes.get(&prefix).unwrap();

                // Get nexthops.
                let mut kind = RouteKind::Unicast;
                let mut nexthops = BTreeSet::default();
                if let Some(nexthop) =
                    static_nexthop_get(&self.interfaces, &route.nexthop_single)
                {
                    nexthops.insert(nexthop);
                }
                if let Some(special) = &route.nexthop_special {
                    kind = match special {
                        NexthopSpecial::Blackhole => RouteKind::Blackhole,
                        NexthopSpecial::Unreachable => RouteKind::Unreachable,
                        NexthopSpecial::Prohibit => RouteKind::Prohibit,
                    };
                }
                for nexthop in
                    route.nexthop_list.values().filter_map(|nexthop| {
                        static_nexthop_get(&self.interfaces, nexthop)
                    })
                {
                    nexthops.insert(nexthop);
                }

                // Prepare message.
                let msg = RouteMsg {
                    protocol: Protocol::STATIC,
                    kind,
                    prefix,
                    distance: 1,
                    metric: 0,
                    tag: None,
                    opaque_attrs: RouteOpaqueAttrs::None,
                    nexthops,
                };

                // Send message.
                self.ibus_tx.route_ip_add(msg);
            }
            Event::StaticRouteUninstall(prefix) => {
                // Prepare message.
                let msg = RouteKeyMsg {
                    protocol: Protocol::STATIC,
                    prefix,
                };

                // Send message.
                self.ibus_tx.route_ip_del(msg);
            }
            Event::SrCfgUpdate => {
                // Update the shared SR configuration by creating a new reference-counted copy.
                self.shared.sr_config = Arc::new(self.sr_config.clone());

                // Notify protocol instances about the updated SR configuration.
                for instance in self.instances.values() {
                    let _ = instance
                        .ibus_tx
                        .send(IbusMsg::SrCfgUpd(self.shared.sr_config.clone()));
                }
            }
            Event::SrCfgLabelRangeUpdate => {
                // Notify protocol instances about the updated SRGB/SRLB configuration.
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::SrCfgEvent(
                        SrCfgEvent::LabelRangeUpdate,
                    ));
                }
            }
            Event::SrCfgPrefixSidUpdate(af) => {
                // Notify protocol instances about the updated Prefix-SID configuration.
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::SrCfgEvent(
                        SrCfgEvent::PrefixSidUpdate(af),
                    ));
                }
            }
            Event::BierCfgUpdate => {
                // Update the shared BIER configuration by creating a new reference-counted copy.
                self.shared.bier_config = Arc::new(self.bier_config.clone());

                // Notify protocol instances about the updated BIER configuration.
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::BierCfgUpd(
                        self.shared.bier_config.clone(),
                    ));
                }
            }
            Event::BierCfgEncapUpdate(_sd_id, af, _bsl, _encap_type) => {
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::BierCfgEvent(
                        BierCfgEvent::EncapUpdate(af),
                    ));
                }
            }
            Event::BierCfgSubDomainUpdate(af) => {
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::BierCfgEvent(
                        BierCfgEvent::SubDomainUpdate(af),
                    ));
                }
            }
            Event::BierCfgBiftUpdate(_bfr_id) => {
                // TODO
            }
        }
    }
}

// ===== helper functions =====

#[allow(unreachable_code, unused_imports, unused_variables)]
fn instance_start(master: &mut Master, protocol: Protocol, name: String) {
    use holo_protocol::spawn_protocol_task;

    let instance_id = InstanceId::new(protocol, name.clone());
    let (ibus_instance_tx, ibus_instance_rx) = mpsc::unbounded_channel();

    // Start protocol instance.
    let nb_daemon_tx = match protocol {
        Protocol::BFD => {
            // Nothing to do, the BFD task runs permanently.
            return;
        }
        #[cfg(feature = "bgp")]
        Protocol::BGP => {
            use holo_bgp::instance::Instance;

            spawn_protocol_task::<Instance>(
                name,
                &master.nb_tx,
                &master.ibus_tx,
                ibus_instance_tx.clone(),
                ibus_instance_rx,
                Default::default(),
                master.shared.clone(),
            )
        }
        Protocol::DIRECT => {
            // This protocol type can not be configured.
            unreachable!()
        }
        #[cfg(feature = "isis")]
        Protocol::ISIS => {
            use holo_isis::instance::Instance;

            spawn_protocol_task::<Instance>(
                name,
                &master.nb_tx,
                &master.ibus_tx,
                ibus_instance_tx.clone(),
                ibus_instance_rx,
                Default::default(),
                master.shared.clone(),
            )
        }
        #[cfg(feature = "ldp")]
        Protocol::LDP => {
            use holo_ldp::instance::Instance;

            spawn_protocol_task::<Instance>(
                name,
                &master.nb_tx,
                &master.ibus_tx,
                ibus_instance_tx.clone(),
                ibus_instance_rx,
                Default::default(),
                master.shared.clone(),
            )
        }
        #[cfg(feature = "ospf")]
        Protocol::OSPFV2 => {
            use holo_ospf::instance::Instance;
            use holo_ospf::version::Ospfv2;

            spawn_protocol_task::<Instance<Ospfv2>>(
                name,
                &master.nb_tx,
                &master.ibus_tx,
                ibus_instance_tx.clone(),
                ibus_instance_rx,
                Default::default(),
                master.shared.clone(),
            )
        }
        #[cfg(feature = "ospf")]
        Protocol::OSPFV3 => {
            use holo_ospf::instance::Instance;
            use holo_ospf::version::Ospfv3;

            spawn_protocol_task::<Instance<Ospfv3>>(
                name,
                &master.nb_tx,
                &master.ibus_tx,
                ibus_instance_tx.clone(),
                ibus_instance_rx,
                Default::default(),
                master.shared.clone(),
            )
        }
        #[cfg(feature = "rip")]
        Protocol::RIPV2 => {
            use holo_rip::instance::Instance;
            use holo_rip::version::Ripv2;

            spawn_protocol_task::<Instance<Ripv2>>(
                name,
                &master.nb_tx,
                &master.ibus_tx,
                ibus_instance_tx.clone(),
                ibus_instance_rx,
                Default::default(),
                master.shared.clone(),
            )
        }
        #[cfg(feature = "rip")]
        Protocol::RIPNG => {
            use holo_rip::instance::Instance;
            use holo_rip::version::Ripng;

            spawn_protocol_task::<Instance<Ripng>>(
                name,
                &master.nb_tx,
                &master.ibus_tx,
                ibus_instance_tx.clone(),
                ibus_instance_rx,
                Default::default(),
                master.shared.clone(),
            )
        }
        _ => {
            // Nothing to do.
            return;
        }
    };

    // Keep track of northbound and ibus channels associated to the protocol
    // type and name.
    let instance = InstanceHandle::new(nb_daemon_tx, ibus_instance_tx);
    master.instances.insert(instance_id, instance);
}

fn static_nexthop_get(
    interfaces: &Interfaces,
    nexthop: &StaticRouteNexthop,
) -> Option<Nexthop> {
    let ifname = nexthop.ifname.as_ref()?;
    let iface = interfaces.get_by_name(ifname)?;
    let ifindex = iface.ifindex;
    let nexthop = match nexthop.addr {
        Some(addr) => Nexthop::Address {
            ifindex,
            addr,
            labels: Default::default(),
        },
        None => Nexthop::Interface { ifindex },
    };
    Some(nexthop)
}
