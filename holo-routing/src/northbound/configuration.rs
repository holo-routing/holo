//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, LazyLock as Lazy};

use enum_as_inner::EnumAsInner;
use holo_northbound::NbDaemonSender;
use holo_northbound::configuration::{self, CallbackKey, Callbacks, CallbacksBuilder, ConfigChanges, Provider, ValidationCallbacks, ValidationCallbacksBuilder};
use holo_protocol::{VpnExport, VpnImport};
use holo_utils::bgp::{RouteDistinguisher, RouteTarget};
use holo_utils::bier::{BfrId, BierBift, BierBiftCfg, BierCfgEvent, BierEncapsulation, BierEncapsulationType, BierInBiftId, BierOutBiftId, BierSubDomainCfg, BiftNbr, Bsl, SubDomainId, UnderlayProtocolType};
use holo_utils::ibus::IbusMsg;
use holo_utils::ip::{AddressFamily, IpNetworkKind, JointPrefixMapExt};
use holo_utils::mpls::{Label, LabelRange};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{LabelInstallMsg, LabelUninstallMsg, Nexthop, RouteKeyMsg, RouteKind, RouteMsg, RouteOpaqueAttrs};
use holo_utils::sr::{IgpAlgoType, SidLastHopBehavior, SrCfgEvent, SrCfgPrefixSid};
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;
use tracing::warn;
use yang5::data::Data;

use crate::interface::Interfaces;
use crate::northbound::REGEX_PROTOCOLS;
use crate::northbound::yang_gen::routing::segment_routing::sr_mpls;
use crate::northbound::yang_gen::routing::{bier, ribs};
use crate::northbound::yang_gen::{control_plane_protocol, network_instances};
use crate::rib::{Route, RouteFlags, RouteKey};
use crate::{InstanceHandle, InstanceId, Master};

pub static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> = Lazy::new(load_validation_callbacks);
static CALLBACKS: Lazy<configuration::Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Clone, Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    ProtocolInstance(InstanceId),
    NetworkInstance(String),
    StaticRoute(StaticRouteKey),
    StaticRouteNexthop(StaticRouteKey, String),
    SrCfgPrefixSid(IpNetwork, IgpAlgoType),
    BierCfgSubDomain(SubDomainId, AddressFamily),
    BierCfgEncapsulation(SubDomainId, AddressFamily, Bsl, BierEncapsulationType),
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
    InstanceStart { protocol: Protocol, name: String, network_instance: String },
    StaticRouteInstall(StaticRouteKey),
    StaticRouteUninstall(StaticRouteKey),
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
pub struct NetworkInstance {
    pub enabled: bool,
    pub description: Option<String>,
    pub rd: Option<RouteDistinguisher>,
    pub import_rts: BTreeSet<RouteTarget>,
    pub export_rts: BTreeSet<RouteTarget>,
    pub export_label: Option<Label>,
    pub export_label_installed: Option<(Label, u32)>,
    // Kernel VRF table id, resolved from the learned VRF device of the same
    // name (None until the VRF device is learned). Consumed by per-VRF
    // routing.
    pub table_id: Option<u32>,
}

#[derive(Debug, Default)]
pub struct StaticRoute {
    pub nexthop_single: StaticRouteNexthop,
    pub nexthop_special: Option<NexthopSpecial>,
    pub nexthop_list: HashMap<String, StaticRouteNexthop>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StaticRouteKey {
    pub instance_id: InstanceId,
    pub prefix: IpNetwork,
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
        .create_prepare(|master, args| {
            let ptype = args.dnode.get_string_relative("./type").unwrap();
            let name = args.dnode.get_string_relative("./name").unwrap();
            let network_instance = args.dnode.get_string_relative("./network-instance").unwrap_or_else(|| InstanceId::DEFAULT_NETWORK_INSTANCE.to_owned());

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

            let base_id = InstanceId::new(protocol, name.clone());
            master.instance_ni.insert(base_id, network_instance.clone());

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceStart {
                protocol,
                name,
                network_instance,
            });

            Ok(())
        })
        .create_abort(|master, args| {
            let instance_id = args.list_entry.into_protocol_instance().unwrap();

            // The BFD task runs permanently.
            if instance_id.protocol == Protocol::BFD {
                return;
            }

            // Remove protocol instance.
            remove_instance(master, &instance_id);
            let base_id = InstanceId::new(instance_id.protocol, instance_id.name);
            master.instance_ni.remove(&base_id);
        })
        .delete_apply(|master, args| {
            let instance_id = args.list_entry.into_protocol_instance().unwrap();

            // The BFD task runs permanently.
            if instance_id.protocol == Protocol::BFD {
                return;
            }

            // Remove protocol instance.
            remove_instance(master, &instance_id);
            let base_id = InstanceId::new(instance_id.protocol, instance_id.name);
            master.instance_ni.remove(&base_id);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let ptype = dnode.get_string_relative("./type").unwrap();
            let name = dnode.get_string_relative("./name").unwrap();
            let protocol = Protocol::try_from_yang(&ptype).unwrap();
            let network_instance = dnode.get_string_relative("./network-instance").unwrap_or_else(|| InstanceId::DEFAULT_NETWORK_INSTANCE.to_owned());
            let instance_id = InstanceId::new_with_network_instance(protocol, name, network_instance);
            ListEntry::ProtocolInstance(instance_id)
        })
        .path(control_plane_protocol::description::PATH)
        .modify_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(control_plane_protocol::network_instance::PATH)
        .modify_apply(|master, args| {
            let instance_id = args.list_entry.into_protocol_instance().unwrap();
            let ni = args.dnode.get_string();
            let base_id = InstanceId::new(instance_id.protocol, instance_id.name);
            master.instance_ni.insert(base_id, ni);
        })
        .delete_apply(|master, args| {
            let instance_id = args.list_entry.into_protocol_instance().unwrap();
            let base_id = InstanceId::new(instance_id.protocol, instance_id.name);
            master.instance_ni.remove(&base_id);
        })
        .path(network_instances::network_instance::PATH)
        .create_apply(|master, args| {
            let name = args.dnode.get_string_relative("name").unwrap();
            network_instance_create(master, name.clone());
            let ni = master.network_instances.get_mut(&name).unwrap();
            if let Some(rd) = args.dnode.get_string_relative("./holo-network-instance:l3vpn/route-distinguisher").and_then(|rd| RouteDistinguisher::try_from_yang(&rd)) {
                ni.rd = Some(rd);
            }
            for dnode in args.dnode.find_xpath("./holo-network-instance:l3vpn/import-route-target").unwrap() {
                if let Some(rt) = RouteTarget::try_from_yang(&dnode.get_string()) {
                    ni.import_rts.insert(rt);
                }
            }
            for dnode in args.dnode.find_xpath("./holo-network-instance:l3vpn/export-route-target").unwrap() {
                if let Some(rt) = RouteTarget::try_from_yang(&dnode.get_string()) {
                    ni.export_rts.insert(rt);
                }
            }
            let ensure_export_label = ni.rd.is_some() || !ni.export_rts.is_empty();
            if ensure_export_label {
                vpn_export_label_ensure(master, &name);
            }
            vpn_imports_update(master);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            vpn_export_label_uninstall(master, &name);
            master.network_instances.remove(&name);
            vpn_imports_update(master);
        })
        .lookup(|_master, _list_entry, dnode| {
            let name = dnode.get_string_relative("name").unwrap();
            ListEntry::NetworkInstance(name)
        })
        .path(network_instances::network_instance::enabled::PATH)
        .modify_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            let ni = master.network_instances.get_mut(&name).unwrap();
            ni.enabled = args.dnode.get_bool();
            vpn_imports_update(master);
        })
        .path(network_instances::network_instance::description::PATH)
        .modify_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            let ni = master.network_instances.get_mut(&name).unwrap();
            ni.description = Some(args.dnode.get_string());
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            let ni = master.network_instances.get_mut(&name).unwrap();
            ni.description = None;
        })
        .path(network_instances::network_instance::l3vpn::route_distinguisher::PATH)
        .modify_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            let rd = args.dnode.get_string();
            let rd = RouteDistinguisher::try_from_yang(&rd).unwrap();
            vpn_export_label_ensure(master, &name);
            let ni = master.network_instances.get_mut(&name).unwrap();
            ni.rd = Some(rd);
            vpn_imports_update(master);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            let ni = master.network_instances.get_mut(&name).unwrap();
            ni.rd = None;
            vpn_imports_update(master);
        })
        .path(network_instances::network_instance::l3vpn::import_route_target::PATH)
        .create_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            let rt = args.dnode.get_string();
            let rt = RouteTarget::try_from_yang(&rt).unwrap();
            let ni = master.network_instances.get_mut(&name).unwrap();
            ni.import_rts.insert(rt);
            vpn_imports_update(master);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            let rt = args.dnode.get_string();
            let rt = RouteTarget::try_from_yang(&rt).unwrap();
            let ni = master.network_instances.get_mut(&name).unwrap();
            ni.import_rts.remove(&rt);
            vpn_imports_update(master);
        })
        .path(network_instances::network_instance::l3vpn::export_route_target::PATH)
        .create_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            let rt = args.dnode.get_string();
            let rt = RouteTarget::try_from_yang(&rt).unwrap();
            let rd = args.dnode.get_string_relative("../route-distinguisher").and_then(|rd| RouteDistinguisher::try_from_yang(&rd));
            vpn_export_label_ensure(master, &name);
            let ni = master.network_instances.get_mut(&name).unwrap();
            if ni.rd.is_none() {
                ni.rd = rd;
            }
            ni.export_rts.insert(rt);
            vpn_imports_update(master);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_network_instance().unwrap();
            let rt = args.dnode.get_string();
            let rt = RouteTarget::try_from_yang(&rt).unwrap();
            let ni = master.network_instances.get_mut(&name).unwrap();
            ni.export_rts.remove(&rt);
            vpn_imports_update(master);
        })
        .path(control_plane_protocol::static_routes::ipv4::route::PATH)
        .create_apply(|master, args| {
            let prefix = args.dnode.get_prefix_relative("./destination-prefix").unwrap();
            let instance_id = args.list_entry.clone().into_protocol_instance().unwrap();
            let route_key = StaticRouteKey {
                instance_id,
                prefix,
            };

            master.static_routes.insert(route_key, StaticRoute::default());
        })
        .delete_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();

            master.static_routes.remove(&route_key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteUninstall(route_key));
        })
        .lookup(|_master, list_entry, dnode| {
            let prefix = dnode.get_prefix_relative("./destination-prefix").unwrap();
            let instance_id = list_entry.into_protocol_instance().unwrap();
            ListEntry::StaticRoute(StaticRouteKey {
                instance_id,
                prefix,
            })
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
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            let ifname = args.dnode.get_string();
            route.nexthop_single.ifname = Some(ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            route.nexthop_single.ifname = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::next_hop_address::PATH)
        .modify_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            let addr = args.dnode.get_ip();
            route.nexthop_single.addr = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            route.nexthop_single.addr = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::special_next_hop::PATH)
        .modify_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            let special = args.dnode.get_string();
            let special = NexthopSpecial::try_from_yang(&special).unwrap();
            route.nexthop_special = Some(special);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            route.nexthop_special = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::next_hop_list::next_hop::PATH)
        .create_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            let index = args.dnode.get_string_relative("./index").unwrap();
            route.nexthop_list.insert(index, StaticRouteNexthop::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            route.nexthop_list.remove(&nh_index);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .lookup(|_master, list_entry, dnode| {
            let route_key = list_entry.into_static_route().unwrap();

            let index = dnode.get_string_relative("./index").unwrap();
            ListEntry::StaticRouteNexthop(route_key, index)
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::next_hop_list::next_hop::outgoing_interface::PATH)
        .modify_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            let ifname = args.dnode.get_string();
            nexthop.ifname = Some(ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            nexthop.ifname = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::next_hop_list::next_hop::next_hop_address::PATH)
        .modify_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            let addr = args.dnode.get_ip();
            nexthop.addr = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            nexthop.addr = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::PATH)
        .create_apply(|master, args| {
            let prefix = args.dnode.get_prefix_relative("./destination-prefix").unwrap();
            let instance_id = args.list_entry.clone().into_protocol_instance().unwrap();
            let route_key = StaticRouteKey {
                instance_id,
                prefix,
            };

            master.static_routes.insert(route_key, StaticRoute::default());
        })
        .delete_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();

            master.static_routes.remove(&route_key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteUninstall(route_key));
        })
        .lookup(|_master, list_entry, dnode| {
            let prefix = dnode.get_prefix_relative("./destination-prefix").unwrap();
            let instance_id = list_entry.into_protocol_instance().unwrap();
            ListEntry::StaticRoute(StaticRouteKey {
                instance_id,
                prefix,
            })
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
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            let ifname = args.dnode.get_string();
            route.nexthop_single.ifname = Some(ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            route.nexthop_single.ifname = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::next_hop_address::PATH)
        .modify_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            let addr = args.dnode.get_ip();
            route.nexthop_single.addr = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            route.nexthop_single.addr = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::special_next_hop::PATH)
        .modify_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            let special = args.dnode.get_string();
            let special = NexthopSpecial::try_from_yang(&special).unwrap();
            route.nexthop_special = Some(special);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            route.nexthop_special = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::next_hop_list::next_hop::PATH)
        .create_apply(|master, args| {
            let route_key = args.list_entry.into_static_route().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            let index = args.dnode.get_string_relative("./index").unwrap();
            route.nexthop_list.insert(index, StaticRouteNexthop::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();

            route.nexthop_list.remove(&nh_index);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .lookup(|_master, list_entry, dnode| {
            let route_key = list_entry.into_static_route().unwrap();

            let index = dnode.get_string_relative("./index").unwrap();
            ListEntry::StaticRouteNexthop(route_key, index)
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::next_hop_list::next_hop::outgoing_interface::PATH)
        .modify_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            let ifname = args.dnode.get_string();
            nexthop.ifname = Some(ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            nexthop.ifname = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::next_hop_list::next_hop::next_hop_address::PATH)
        .modify_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            let addr = args.dnode.get_ip();
            nexthop.addr = Some(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
        })
        .delete_apply(|master, args| {
            let (route_key, nh_index) = args.list_entry.into_static_route_nexthop().unwrap();
            let route = master.static_routes.get_mut(&route_key).unwrap();
            let nexthop = route.nexthop_list.get_mut(&nh_index).unwrap();

            nexthop.addr = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StaticRouteInstall(route_key));
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
            label_manager.range_reserve(range).map_err(|error| error.to_string())?;
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
        .lookup(|_master, _list_entry, _dnode| ListEntry::None)
        .path(sr_mpls::srlb::srlb::PATH)
        .create_prepare(|master, args| {
            let lower_bound = args.dnode.get_u32_relative("./lower-bound").unwrap();
            let upper_bound = args.dnode.get_u32_relative("./upper-bound").unwrap();
            let range = LabelRange::new(lower_bound, upper_bound);

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_reserve(range).map_err(|error| error.to_string())?;
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
        .lookup(|_master, _list_entry, _dnode| ListEntry::None)
        .path(ribs::rib::PATH)
        .create_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .lookup(|_master, _list_entry, _dnode| ListEntry::None)
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
            let in_bift_id = in_bift_id_base.map_or(in_bift_id_encoding.map(BierInBiftId::Encoding), |v| Some(BierInBiftId::Base(v))).unwrap();
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
                birt: Default::default(),
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
                nbr: Default::default(),
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
                out_bift_id,
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
            let Some(protocol) = Protocol::try_from_yang(&ptype) else {
                return Err("unknown protocol name".to_owned());
            };

            // Validate BFD protocol instance name.
            if protocol == Protocol::BFD && name != "main" {
                return Err("BFD protocol instance should be named \"main\"".to_owned());
            }

            Ok(())
        })
        .path(bier::sub_domain::PATH)
        .validate(|args| {
            let af = args.dnode.get_af_relative("./address-family").unwrap();
            let mt_id = args.dnode.get_u8_relative("./mt-id");

            // Enforce configured address family.
            if let Some(bfr_prefix) = args.dnode.get_prefix_relative("./bfr-prefix")
                && bfr_prefix.address_family() != af
            {
                return Err("Configured address family differs from BFR prefix address family.".to_owned());
            }

            // Enforce MT-ID value per RFC4915.
            if let Some(mt_id) = mt_id
                && mt_id > 128
            {
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

    fn callbacks() -> &'static Callbacks<Master> {
        &CALLBACKS
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        let keys: Vec<Vec<CallbackKey>> = vec![
            #[cfg(feature = "bfd")]
            holo_bfd::northbound::configuration::CALLBACKS.keys(),
            #[cfg(feature = "bgp")]
            holo_bgp::northbound::configuration::CALLBACKS.keys(),
            #[cfg(feature = "igmp")]
            holo_igmp::northbound::configuration::CALLBACKS.keys(),
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

    fn relay_changes(&self, changes: ConfigChanges) -> Vec<(ConfigChanges, NbDaemonSender)> {
        // Create hash table that maps changes to the appropriate child
        // instances.
        let mut changes_map: HashMap<InstanceId, ConfigChanges> = HashMap::new();
        for change in changes {
            // HACK: parse protocol type and instance name.
            let caps = REGEX_PROTOCOLS.captures(&change.1).unwrap();
            let ptype = caps.get(1).unwrap().as_str();
            let name = caps.get(2).unwrap().as_str();

            // Move configuration change to the appropriate instance bucket.
            let protocol = Protocol::try_from_yang(ptype).unwrap();
            let base_id = InstanceId::new(protocol, name.to_owned());
            let network_instance = self.instance_ni.get(&base_id).cloned().unwrap_or_else(|| InstanceId::DEFAULT_NETWORK_INSTANCE.to_owned());
            let instance_id = InstanceId::new_with_network_instance(protocol, name.to_owned(), network_instance);
            changes_map.entry(instance_id).or_default().push(change);
        }
        changes_map
            .into_iter()
            .filter_map(|(instance_id, changes)| self.instances.get(&instance_id).map(|instance| (changes, instance.nb_tx.clone())))
            .collect::<Vec<_>>()
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::InstanceStart {
                protocol,
                name,
                network_instance,
            } => {
                let base_id = InstanceId::new(protocol, name.clone());
                let network_instance = self.instance_ni.get(&base_id).cloned().unwrap_or(network_instance);
                instance_start(self, protocol, name, network_instance);
            }
            Event::StaticRouteInstall(route_key) => {
                static_route_install(self, route_key);
            }
            Event::StaticRouteUninstall(route_key) => {
                // Prepare message.
                let msg = RouteKeyMsg {
                    protocol: Protocol::STATIC,
                    table_id: static_route_table_id(self, &route_key).unwrap_or(None),
                    prefix: route_key.prefix,
                };

                // Send message.
                self.ibus_tx.route_ip_del(msg);
            }
            Event::SrCfgUpdate => {
                // Update the shared SR configuration by creating a new reference-counted copy.
                self.shared.sr_config = Arc::new(self.sr_config.clone());

                // Notify protocol instances about the updated SR configuration.
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::SrCfgUpd(self.shared.sr_config.clone()));
                }
            }
            Event::SrCfgLabelRangeUpdate => {
                // Notify protocol instances about the updated SRGB/SRLB configuration.
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::SrCfgEvent(SrCfgEvent::LabelRangeUpdate));
                }
            }
            Event::SrCfgPrefixSidUpdate(af) => {
                // Notify protocol instances about the updated Prefix-SID configuration.
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::SrCfgEvent(SrCfgEvent::PrefixSidUpdate(af)));
                }
            }
            Event::BierCfgUpdate => {
                // Update the shared BIER configuration by creating a new reference-counted copy.
                self.shared.bier_config = Arc::new(self.bier_config.clone());

                // Notify protocol instances about the updated BIER configuration.
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::BierCfgUpd(self.shared.bier_config.clone()));
                }
            }
            Event::BierCfgEncapUpdate(_sd_id, af, _bsl, _encap_type) => {
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::BierCfgEvent(BierCfgEvent::EncapUpdate(af)));
                }
            }
            Event::BierCfgSubDomainUpdate(af) => {
                for instance in self.instances.values() {
                    let _ = instance.ibus_tx.send(IbusMsg::BierCfgEvent(BierCfgEvent::SubDomainUpdate(af)));
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
fn instance_start(master: &mut Master, protocol: Protocol, name: String, network_instance: String) {
    use holo_protocol::spawn_protocol_task;

    let instance_id = InstanceId::new_with_network_instance(protocol, name.clone(), network_instance.clone());
    let mut shared = master.shared.clone();
    shared.network_instance = network_instance;
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

            spawn_protocol_task::<Instance>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), shared)
        }
        Protocol::DIRECT => {
            // This protocol type can not be configured.
            unreachable!()
        }
        #[cfg(feature = "igmp")]
        Protocol::IGMP => {
            use holo_igmp::instance::Instance;

            spawn_protocol_task::<Instance>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), shared)
        }
        #[cfg(feature = "isis")]
        Protocol::ISIS => {
            use holo_isis::instance::Instance;

            spawn_protocol_task::<Instance>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), shared)
        }
        #[cfg(feature = "ldp")]
        Protocol::LDP => {
            use holo_ldp::instance::Instance;

            spawn_protocol_task::<Instance>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), shared)
        }
        #[cfg(feature = "ospf")]
        Protocol::OSPFV2 => {
            use holo_ospf::instance::Instance;
            use holo_ospf::version::Ospfv2;

            spawn_protocol_task::<Instance<Ospfv2>>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), shared)
        }
        #[cfg(feature = "ospf")]
        Protocol::OSPFV3 => {
            use holo_ospf::instance::Instance;
            use holo_ospf::version::Ospfv3;

            spawn_protocol_task::<Instance<Ospfv3>>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), shared)
        }
        #[cfg(feature = "rip")]
        Protocol::RIPV2 => {
            use holo_rip::instance::Instance;
            use holo_rip::version::Ripv2;

            spawn_protocol_task::<Instance<Ripv2>>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), shared)
        }
        #[cfg(feature = "rip")]
        Protocol::RIPNG => {
            use holo_rip::instance::Instance;
            use holo_rip::version::Ripng;

            spawn_protocol_task::<Instance<Ripng>>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), shared)
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

fn network_instance_create(master: &mut Master, name: String) {
    // Resolve the kernel table id if the VRF device was already learned from
    // the kernel (otherwise resolved on InterfaceUpd).
    let table_id = master.interfaces.vrf_table_id(&name);
    master.network_instances.insert(
        name,
        NetworkInstance {
            enabled: true,
            table_id,
            ..Default::default()
        },
    );
}

#[cfg(test)]
mod tests {
    use holo_protocol::InstanceShared;
    use holo_utils::ibus::{IbusMsg, ibus_channels};
    use holo_utils::southbound::{InterfaceFlags, InterfaceUpdateMsg};
    use tokio::sync::mpsc;

    use super::network_instance_create;
    use crate::birt::Birt;
    use crate::netlink::NetlinkRequest;
    use crate::rib::Rib;
    use crate::{Master, ibus};

    fn test_master() -> Master {
        let (nb_tx, _nb_rx) = mpsc::unbounded_channel();
        let (ibus_tx, _ibus_rx) = ibus_channels();
        let (netlink_tx, _netlink_rx) = mpsc::unbounded_channel::<NetlinkRequest>();
        let (rib_update_tx, _rib_update_rx) = mpsc::unbounded_channel();
        let (birt_update_tx, _birt_update_rx) = mpsc::unbounded_channel();

        Master {
            nb_tx,
            ibus_tx,
            netlink_tx,
            shared: InstanceShared::default(),
            interfaces: Default::default(),
            rib: Rib::new(rib_update_tx),
            network_instances: Default::default(),
            instance_ni: Default::default(),
            static_routes: Default::default(),
            sr_config: Default::default(),
            bier_config: Default::default(),
            instances: Default::default(),
            birt: Birt::new(birt_update_tx),
        }
    }

    #[test]
    fn network_instance_create_resolves_prelearned_vrf_table() {
        let mut master = test_master();
        master.interfaces.update("blue".to_owned(), 10, InterfaceFlags::OPERATIVE, None, Some(1001));

        network_instance_create(&mut master, "blue".to_owned());

        assert_eq!(master.network_instances["blue"].table_id, Some(1001));
    }

    #[test]
    fn interface_update_resolves_existing_network_instance_table() {
        let mut master = test_master();
        network_instance_create(&mut master, "red".to_owned());
        assert_eq!(master.network_instances["red"].table_id, None);

        ibus::process_notification_msg(
            &mut master,
            IbusMsg::InterfaceUpd(InterfaceUpdateMsg {
                ifname: "red".to_owned(),
                ifindex: 11,
                mtu: 1500,
                flags: InterfaceFlags::OPERATIVE,
                mac_address: Default::default(),
                msd: Default::default(),
                master_ifindex: None,
                vrf_table_id: Some(1002),
            }),
        );

        assert_eq!(master.network_instances["red"].table_id, Some(1002));
    }
}

fn remove_instance(master: &mut Master, instance_id: &InstanceId) {
    if master.instances.remove(instance_id).is_some() {
        return;
    }

    let Some(instance_id) = master.instances.keys().find(|key| key.protocol == instance_id.protocol && key.name == instance_id.name).cloned() else {
        return;
    };
    master.instances.remove(&instance_id);
}

pub(crate) fn static_route_install(master: &mut Master, route_key: StaticRouteKey) {
    let Some(table_id) = static_route_table_id(master, &route_key) else {
        return;
    };
    let Some(route) = master.static_routes.get(&route_key) else {
        return;
    };

    // Get nexthops.
    let mut kind = RouteKind::Unicast;
    let mut nexthops = BTreeSet::default();
    if let Some(nexthop) = static_nexthop_get(&master.interfaces, &route.nexthop_single) {
        nexthops.insert(nexthop);
    }
    if let Some(special) = &route.nexthop_special {
        kind = match special {
            NexthopSpecial::Blackhole => RouteKind::Blackhole,
            NexthopSpecial::Unreachable => RouteKind::Unreachable,
            NexthopSpecial::Prohibit => RouteKind::Prohibit,
        };
    }
    for nexthop in route.nexthop_list.values().filter_map(|nexthop| static_nexthop_get(&master.interfaces, nexthop)) {
        nexthops.insert(nexthop);
    }

    master.ibus_tx.route_ip_add(RouteMsg {
        protocol: Protocol::STATIC,
        kind,
        table_id,
        prefix: route_key.prefix,
        distance: 1,
        metric: 0,
        tag: None,
        opaque_attrs: RouteOpaqueAttrs::None,
        nexthops,
    });
}

fn static_route_table_id(master: &Master, route_key: &StaticRouteKey) -> Option<Option<u32>> {
    let network_instance = &route_key.instance_id.network_instance;
    if network_instance == InstanceId::DEFAULT_NETWORK_INSTANCE {
        return Some(None);
    }

    let Some(ni) = master.network_instances.get(network_instance) else {
        warn!(
            network_instance,
            prefix = %route_key.prefix,
            "static route deferred: network-instance is not configured"
        );
        return None;
    };
    let Some(table_id) = ni.table_id else {
        warn!(
            network_instance,
            prefix = %route_key.prefix,
            "static route deferred: VRF table id is not resolved"
        );
        return None;
    };
    Some(Some(table_id))
}

pub(crate) fn vpn_imports_update(master: &mut Master) {
    let names = master.network_instances.keys().cloned().collect::<Vec<_>>();
    for name in names {
        vpn_export_label_update(master, &name);
    }

    let imports = master
        .network_instances
        .iter()
        .filter(|(_, ni)| ni.enabled && !ni.import_rts.is_empty())
        .map(|(name, ni)| {
            (
                name.clone(),
                VpnImport {
                    table_id: ni.table_id,
                    import_rts: ni.import_rts.clone(),
                },
            )
        })
        .collect();
    *master.shared.vpn_imports.lock().unwrap() = imports;

    let exports: BTreeMap<u32, VpnExport> = master
        .network_instances
        .values()
        .filter(|ni| ni.enabled && !ni.export_rts.is_empty())
        .filter_map(|ni| {
            Some((
                ni.table_id?,
                VpnExport {
                    rd: ni.rd?,
                    export_rts: ni.export_rts.clone(),
                    label: ni.export_label?,
                },
            ))
        })
        .collect();
    let export_table_ids = exports.keys().copied().collect::<BTreeSet<_>>();
    *master.shared.vpn_exports.lock().unwrap() = exports;
    vpn_exports_replay(master, &export_table_ids);
}

fn vpn_export_label_ensure(master: &mut Master, name: &str) {
    let Some(ni) = master.network_instances.get(name) else {
        return;
    };
    if ni.export_label.is_some() {
        return;
    }

    let Ok(label) = master.shared.label_manager.lock().unwrap().label_request() else {
        return;
    };
    let ni = master.network_instances.get_mut(name).unwrap();
    ni.export_label = Some(label);
}

fn vpn_export_label_update(master: &mut Master, name: &str) {
    let desired = master.network_instances.get(name).and_then(|ni| {
        if !ni.enabled || ni.rd.is_none() || ni.export_rts.is_empty() || ni.table_id.is_none() {
            return None;
        }
        let label = ni.export_label?;
        let ifindex = master.interfaces.get_by_name(name)?.ifindex;
        Some((label, ifindex))
    });
    let installed = master.network_instances.get(name).and_then(|ni| ni.export_label_installed);

    if let Some((label, _)) = installed
        && installed != desired
    {
        master.ibus_tx.route_mpls_del(LabelUninstallMsg {
            protocol: Protocol::BGP,
            label,
            nexthops: Default::default(),
            route: None,
        });
        let ni = master.network_instances.get_mut(name).unwrap();
        ni.export_label_installed = None;
    }

    if let Some((label, ifindex)) = desired
        && installed != Some((label, ifindex))
    {
        master.ibus_tx.route_mpls_add(LabelInstallMsg {
            protocol: Protocol::BGP,
            label,
            nexthops: BTreeSet::from([Nexthop::Interface {
                ifindex,
            }]),
            route: None,
            replace: true,
        });
        let ni = master.network_instances.get_mut(name).unwrap();
        ni.export_label_installed = Some((label, ifindex));
    }
}

fn vpn_export_label_uninstall(master: &mut Master, name: &str) {
    let Some((label, _)) = master.network_instances.get_mut(name).and_then(|ni| ni.export_label_installed.take()) else {
        return;
    };

    master.ibus_tx.route_mpls_del(LabelUninstallMsg {
        protocol: Protocol::BGP,
        label,
        nexthops: Default::default(),
        route: None,
    });
}

fn vpn_exports_replay(master: &Master, table_ids: &BTreeSet<u32>) {
    if table_ids.is_empty() {
        return;
    }

    let redistribute_prefix = |prefix, routes: &BTreeMap<RouteKey, Route>| {
        for route in routes
            .values()
            .filter(|route| route.table_id.is_some_and(|table_id| table_ids.contains(&table_id)) && route.flags.contains(RouteFlags::ACTIVE) && !route.flags.contains(RouteFlags::REMOVED))
        {
            for sub in master.rib.subscriptions.values() {
                crate::ibus::notify_redistribute_add(sub, prefix, route);
            }
        }
    };

    for (prefix, routes) in master.rib.ip.ipv4().iter() {
        redistribute_prefix(prefix.into(), routes);
    }
    for (prefix, routes) in master.rib.ip.ipv6().iter() {
        redistribute_prefix(prefix.into(), routes);
    }
}

fn static_nexthop_get(interfaces: &Interfaces, nexthop: &StaticRouteNexthop) -> Option<Nexthop> {
    let iface = match &nexthop.ifname {
        Some(ifname) => interfaces.get_by_name(ifname)?,
        // No outgoing interface configured: resolve the nexthop address
        // against the connected prefixes.
        None => {
            let addr = nexthop.addr?;
            interfaces.iter().find(|iface| iface.addresses.keys().any(|prefix| prefix.contains(addr)))?
        }
    };
    let ifindex = iface.ifindex;
    let nexthop = match nexthop.addr {
        Some(addr) => Nexthop::Address {
            ifindex,
            addr,
            labels: Default::default(),
        },
        None => Nexthop::Interface {
            ifindex,
        },
    };
    Some(nexthop)
}
