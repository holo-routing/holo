//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use holo_northbound::NbDaemonSender;
use holo_northbound::configuration::{ConfigChanges, Provider, ValidateFn, YangConfigOps};
use holo_northbound::error::{ApplyError, PrepareError, ValidationError};
use holo_utils::bier::{BfrId, BierBift, BierBiftCfg, BierCfgEvent, BierEncapsulation, BierEncapsulationType, BierInBiftId, BierOutBiftId, BierSubDomainCfg, BiftNbr, Bsl, SubDomainId, UnderlayProtocolType};
use holo_utils::ibus::IbusMsg;
use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::mpls::LabelRange;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{Nexthop, RouteKeyMsg, RouteKind, RouteMsg, RouteOpaqueAttrs};
use holo_utils::sr::{PrefixSidAlgo, SidLastHopBehavior, SrCfgEvent, SrCfgPrefixSid};
use holo_utils::yang::{DataNodeRefExt, DataTreeExt};
use holo_yang::TryFromYang;
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;
use yang5::data::DataTree;

use crate::interface::Interfaces;
use crate::northbound::REGEX_PROTOCOLS;
use crate::northbound::yang_gen::config::{
    self, BierBiftBirtBitstringlengthBfrNbrChange, BierBiftBirtBitstringlengthBfrNbrEntryChange, BierBiftBirtBitstringlengthChange, BierBiftBirtBitstringlengthEntryChange, BierBiftChange, BierBiftEntryChange, BierSubDomainChange,
    BierSubDomainEncapsulationChange, BierSubDomainEncapsulationEntryChange, BierSubDomainEntryChange, ConfigChange, ControlPlaneProtocolChange, ControlPlaneProtocolEntryChange, ControlPlaneProtocolStaticRoutesIpv4RouteChange,
    ControlPlaneProtocolStaticRoutesIpv4RouteEntryChange, ControlPlaneProtocolStaticRoutesIpv4RouteNextHopNextHopListNextHopChange, ControlPlaneProtocolStaticRoutesIpv4RouteNextHopNextHopListNextHopEntryChange,
    ControlPlaneProtocolStaticRoutesIpv6RouteChange, ControlPlaneProtocolStaticRoutesIpv6RouteEntryChange, ControlPlaneProtocolStaticRoutesIpv6RouteNextHopNextHopListNextHopChange,
    ControlPlaneProtocolStaticRoutesIpv6RouteNextHopNextHopListNextHopEntryChange, RibChange, RibEntryChange, SegmentRoutingSrMplsBindingsConnectedPrefixSidMapConnectedPrefixSidChange,
    SegmentRoutingSrMplsBindingsConnectedPrefixSidMapConnectedPrefixSidEntryChange, SegmentRoutingSrMplsSrgbChange, SegmentRoutingSrMplsSrlbChange,
};
use crate::northbound::yang_gen::routing::bier;
use crate::{InstanceHandle, InstanceId, Master};

#[derive(Debug)]
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

#[derive(Clone, Copy, Debug)]
pub enum NexthopSpecial {
    Blackhole,
    Unreachable,
    Prohibit,
}

// ===== helper functions =====

fn prepare_master(master: &mut Master, change: &ConfigChange, resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), PrepareError> {
    match change {
        ConfigChange::ControlPlaneProtocol(keys, ControlPlaneProtocolChange::Create) => {
            let protocol = keys.r#type;

            // The BFD task runs permanently.
            if protocol == Protocol::BFD {
                return Ok(());
            }

            event_queue.insert(Event::InstanceStart {
                protocol,
                name: keys.name.clone(),
            });
        }
        ConfigChange::SegmentRoutingSrMplsSrgb(keys, SegmentRoutingSrMplsSrgbChange::Create) => {
            let range = LabelRange::new(keys.lower_bound, keys.upper_bound);
            let mut label_manager = master.shared.label_manager.lock().unwrap();
            if let Err(error) = label_manager.range_reserve(range) {
                return Err(PrepareError::from(error.to_string()));
            }
            *resource = Some(Resource::SrLabelRange(range));
        }
        ConfigChange::SegmentRoutingSrMplsSrlb(keys, SegmentRoutingSrMplsSrlbChange::Create) => {
            let range = LabelRange::new(keys.lower_bound, keys.upper_bound);
            let mut label_manager = master.shared.label_manager.lock().unwrap();
            if let Err(error) = label_manager.range_reserve(range) {
                return Err(PrepareError::from(error.to_string()));
            }
            *resource = Some(Resource::SrLabelRange(range));
        }
        _ => (),
    }

    Ok(())
}

fn abort_master(master: &mut Master, change: ConfigChange, resource: &mut Option<Resource>) {
    match change {
        ConfigChange::ControlPlaneProtocol(keys, ControlPlaneProtocolChange::Create) => {
            let protocol = keys.r#type;

            // The BFD task runs permanently.
            if protocol == Protocol::BFD {
                return;
            }

            // Remove protocol instance.
            let instance_id = InstanceId::new(protocol, keys.name);
            master.instances.remove(&instance_id);
        }
        ConfigChange::SegmentRoutingSrMplsSrgb(_, SegmentRoutingSrMplsSrgbChange::Create) | ConfigChange::SegmentRoutingSrMplsSrlb(_, SegmentRoutingSrMplsSrlbChange::Create) => {
            if let Some(Resource::SrLabelRange(range)) = resource.take() {
                let mut label_manager = master.shared.label_manager.lock().unwrap();
                label_manager.range_release(range);
            }
        }
        _ => (),
    }
}

fn apply_master(master: &mut Master, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ConfigChange::ControlPlaneProtocol(keys, change) => {
            apply_control_plane_protocol(master, keys.r#type, keys.name, change, event_queue)?;
        }
        ConfigChange::Rib(_keys, change) => match change {
            RibChange::Create | RibChange::Delete | RibChange::Entry(RibEntryChange::AddressFamily(..) | RibEntryChange::Description(..)) => {
                // Nothing to do.
            }
        },
        ConfigChange::BierSubDomain(keys, change) => {
            apply_bier_sub_domain(master, keys.sub_domain_id, keys.address_family, change, event_queue)?;
        }
        ConfigChange::BierBift(keys, change) => {
            apply_bier_bift(master, keys.bfr_id, change, event_queue)?;
        }
        ConfigChange::SegmentRoutingSrMplsBindingsConnectedPrefixSidMapConnectedPrefixSid(keys, change) => {
            apply_connected_prefix_sid(master, keys.prefix, keys.algorithm, change, event_queue)?;
        }
        ConfigChange::SegmentRoutingSrMplsSrgb(keys, change) => {
            let range = LabelRange::new(keys.lower_bound, keys.upper_bound);
            apply_srgb(master, range, change, event_queue)?;
        }
        ConfigChange::SegmentRoutingSrMplsSrlb(keys, change) => {
            let range = LabelRange::new(keys.lower_bound, keys.upper_bound);
            apply_srlb(master, range, change, event_queue)?;
        }
    }

    Ok(())
}

fn apply_control_plane_protocol(master: &mut Master, protocol: Protocol, name: String, change: ControlPlaneProtocolChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        // Handled during the Prepare phase.
        ControlPlaneProtocolChange::Create => (),
        ControlPlaneProtocolChange::Delete => {
            // The BFD task runs permanently.
            if protocol == Protocol::BFD {
                return Ok(());
            }

            // Remove protocol instance.
            let instance_id = InstanceId::new(protocol, name);
            master.instances.remove(&instance_id);
        }
        ControlPlaneProtocolChange::Entry(change) => match change {
            ControlPlaneProtocolEntryChange::Description(_description) => {
                // Nothing to do.
            }
            ControlPlaneProtocolEntryChange::StaticRoutesIpv4Route(keys, change) => {
                apply_ipv4_route(master, IpNetwork::V4(keys.destination_prefix), change, event_queue)?;
            }
            ControlPlaneProtocolEntryChange::StaticRoutesIpv6Route(keys, change) => {
                apply_ipv6_route(master, IpNetwork::V6(keys.destination_prefix), change, event_queue)?;
            }
        },
    }

    Ok(())
}

fn apply_ipv4_route(master: &mut Master, prefix: IpNetwork, change: ControlPlaneProtocolStaticRoutesIpv4RouteChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ControlPlaneProtocolStaticRoutesIpv4RouteChange::Create => {
            master.static_routes.insert(prefix, StaticRoute::default());
        }
        ControlPlaneProtocolStaticRoutesIpv4RouteChange::Delete => {
            master.static_routes.remove(&prefix);
            event_queue.insert(Event::StaticRouteUninstall(prefix));
        }
        ControlPlaneProtocolStaticRoutesIpv4RouteChange::Entry(change) => {
            let route = master.static_routes.get_mut(&prefix).ok_or(ApplyError::EntryNotFound)?;
            match change {
                ControlPlaneProtocolStaticRoutesIpv4RouteEntryChange::Description(_description) => {
                    // Nothing to do.
                }
                ControlPlaneProtocolStaticRoutesIpv4RouteEntryChange::NextHopOutgoingInterface(ifname) => {
                    route.nexthop_single.ifname = ifname;
                    event_queue.insert(Event::StaticRouteInstall(prefix));
                }
                ControlPlaneProtocolStaticRoutesIpv4RouteEntryChange::NextHopNextHopAddress(addr) => {
                    route.nexthop_single.addr = addr.map(IpAddr::from);
                    event_queue.insert(Event::StaticRouteInstall(prefix));
                }
                ControlPlaneProtocolStaticRoutesIpv4RouteEntryChange::NextHopSpecialNextHop(special) => {
                    route.nexthop_special = special;
                    event_queue.insert(Event::StaticRouteInstall(prefix));
                }
                ControlPlaneProtocolStaticRoutesIpv4RouteEntryChange::NextHopNextHopListNextHop(keys, change) => {
                    apply_ipv4_route_next_hop(route, prefix, keys.index, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_ipv4_route_next_hop(route: &mut StaticRoute, prefix: IpNetwork, index: String, change: ControlPlaneProtocolStaticRoutesIpv4RouteNextHopNextHopListNextHopChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ControlPlaneProtocolStaticRoutesIpv4RouteNextHopNextHopListNextHopChange::Create => {
            route.nexthop_list.insert(index, StaticRouteNexthop::default());
        }
        ControlPlaneProtocolStaticRoutesIpv4RouteNextHopNextHopListNextHopChange::Delete => {
            route.nexthop_list.remove(&index);
        }
        ControlPlaneProtocolStaticRoutesIpv4RouteNextHopNextHopListNextHopChange::Entry(change) => {
            let nexthop = route.nexthop_list.get_mut(&index).ok_or(ApplyError::EntryNotFound)?;
            match change {
                ControlPlaneProtocolStaticRoutesIpv4RouteNextHopNextHopListNextHopEntryChange::OutgoingInterface(ifname) => {
                    nexthop.ifname = ifname;
                }
                ControlPlaneProtocolStaticRoutesIpv4RouteNextHopNextHopListNextHopEntryChange::NextHopAddress(addr) => {
                    nexthop.addr = addr.map(IpAddr::from);
                }
            }
        }
    }
    event_queue.insert(Event::StaticRouteInstall(prefix));

    Ok(())
}

fn apply_ipv6_route(master: &mut Master, prefix: IpNetwork, change: ControlPlaneProtocolStaticRoutesIpv6RouteChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ControlPlaneProtocolStaticRoutesIpv6RouteChange::Create => {
            master.static_routes.insert(prefix, StaticRoute::default());
        }
        ControlPlaneProtocolStaticRoutesIpv6RouteChange::Delete => {
            master.static_routes.remove(&prefix);
            event_queue.insert(Event::StaticRouteUninstall(prefix));
        }
        ControlPlaneProtocolStaticRoutesIpv6RouteChange::Entry(change) => {
            let route = master.static_routes.get_mut(&prefix).ok_or(ApplyError::EntryNotFound)?;
            match change {
                ControlPlaneProtocolStaticRoutesIpv6RouteEntryChange::Description(_description) => {
                    // Nothing to do.
                }
                ControlPlaneProtocolStaticRoutesIpv6RouteEntryChange::NextHopOutgoingInterface(ifname) => {
                    route.nexthop_single.ifname = ifname;
                    event_queue.insert(Event::StaticRouteInstall(prefix));
                }
                ControlPlaneProtocolStaticRoutesIpv6RouteEntryChange::NextHopNextHopAddress(addr) => {
                    route.nexthop_single.addr = addr.map(IpAddr::from);
                    event_queue.insert(Event::StaticRouteInstall(prefix));
                }
                ControlPlaneProtocolStaticRoutesIpv6RouteEntryChange::NextHopSpecialNextHop(special) => {
                    route.nexthop_special = special;
                    event_queue.insert(Event::StaticRouteInstall(prefix));
                }
                ControlPlaneProtocolStaticRoutesIpv6RouteEntryChange::NextHopNextHopListNextHop(keys, change) => {
                    apply_ipv6_route_next_hop(route, prefix, keys.index, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_ipv6_route_next_hop(route: &mut StaticRoute, prefix: IpNetwork, index: String, change: ControlPlaneProtocolStaticRoutesIpv6RouteNextHopNextHopListNextHopChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ControlPlaneProtocolStaticRoutesIpv6RouteNextHopNextHopListNextHopChange::Create => {
            route.nexthop_list.insert(index, StaticRouteNexthop::default());
        }
        ControlPlaneProtocolStaticRoutesIpv6RouteNextHopNextHopListNextHopChange::Delete => {
            route.nexthop_list.remove(&index);
        }
        ControlPlaneProtocolStaticRoutesIpv6RouteNextHopNextHopListNextHopChange::Entry(change) => {
            let nexthop = route.nexthop_list.get_mut(&index).ok_or(ApplyError::EntryNotFound)?;
            match change {
                ControlPlaneProtocolStaticRoutesIpv6RouteNextHopNextHopListNextHopEntryChange::OutgoingInterface(ifname) => {
                    nexthop.ifname = ifname;
                }
                ControlPlaneProtocolStaticRoutesIpv6RouteNextHopNextHopListNextHopEntryChange::NextHopAddress(addr) => {
                    nexthop.addr = addr.map(IpAddr::from);
                }
            }
        }
    }
    event_queue.insert(Event::StaticRouteInstall(prefix));

    Ok(())
}

fn apply_bier_sub_domain(master: &mut Master, sd_id: SubDomainId, af: AddressFamily, change: BierSubDomainChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        BierSubDomainChange::Create => {
            // The mandatory BFR prefix, underlay protocol, BFR-ID and BSL
            // leaves are applied as separate changes within the same commit.
            let bfr_prefix = match af {
                AddressFamily::Ipv4 => IpNetwork::from(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                AddressFamily::Ipv6 => IpNetwork::from(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
            };
            let sd_cfg = BierSubDomainCfg {
                sd_id,
                af,
                bfr_prefix,
                underlay_protocol: UnderlayProtocolType::IsIs,
                mt_id: bier::sub_domain::mt_id::DFLT,
                bfr_id: 0,
                bsl: Bsl::_64,
                ipa: bier::sub_domain::igp_algorithm::DFLT,
                bar: bier::sub_domain::bier_algorithm::DFLT,
                load_balance_num: bier::sub_domain::load_balance_num::DFLT,
                encap: Default::default(),
            };
            master.bier_config.sd_cfg.insert((sd_id, af), sd_cfg);
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        }
        BierSubDomainChange::Delete => {
            master.bier_config.sd_cfg.remove(&(sd_id, af));
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgSubDomainUpdate(af));
        }
        BierSubDomainChange::Entry(change) => {
            let sd_cfg = master.bier_config.sd_cfg.get_mut(&(sd_id, af)).ok_or(ApplyError::EntryNotFound)?;
            match change {
                BierSubDomainEntryChange::BfrPrefix(bfr_prefix) => {
                    sd_cfg.bfr_prefix = bfr_prefix;
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgSubDomainUpdate(af));
                }
                BierSubDomainEntryChange::UnderlayProtocolType(underlay_protocol) => {
                    sd_cfg.underlay_protocol = underlay_protocol;
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgSubDomainUpdate(af));
                }
                BierSubDomainEntryChange::MtId(mt_id) => {
                    sd_cfg.mt_id = mt_id;
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgSubDomainUpdate(af));
                }
                BierSubDomainEntryChange::BfrId(bfr_id) => {
                    sd_cfg.bfr_id = bfr_id;
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgSubDomainUpdate(af));
                }
                BierSubDomainEntryChange::Bsl(bsl) => {
                    sd_cfg.bsl = bsl;
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgSubDomainUpdate(af));
                }
                BierSubDomainEntryChange::IgpAlgorithm(ipa) => {
                    sd_cfg.ipa = ipa;
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgSubDomainUpdate(af));
                }
                BierSubDomainEntryChange::BierAlgorithm(bar) => {
                    sd_cfg.bar = bar;
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgSubDomainUpdate(af));
                }
                BierSubDomainEntryChange::LoadBalanceNum(load_balance_num) => {
                    sd_cfg.load_balance_num = load_balance_num;
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgSubDomainUpdate(af));
                }
                BierSubDomainEntryChange::Encapsulation(keys, change) => {
                    apply_bier_encapsulation(sd_cfg, sd_id, af, keys.bsl, keys.encapsulation_type, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_bier_encapsulation(
    sd_cfg: &mut BierSubDomainCfg,
    sd_id: SubDomainId,
    af: AddressFamily,
    bsl: Bsl,
    encap_type: BierEncapsulationType,
    change: BierSubDomainEncapsulationChange,
    event_queue: &mut BTreeSet<Event>,
) -> Result<(), ApplyError> {
    match change {
        BierSubDomainEncapsulationChange::Create => {
            // The mandatory max-si leaf is applied as a separate change
            // within the same commit.
            let in_bift_id = BierInBiftId::Encoding(bier::sub_domain::encapsulation::in_bift_id::in_bift_id_encoding::DFLT);
            let encap_cfg = BierEncapsulation::new(bsl, encap_type, 0, in_bift_id);
            sd_cfg.encap.insert((bsl, encap_type), encap_cfg);
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgEncapUpdate(sd_id, af, bsl, encap_type));
        }
        BierSubDomainEncapsulationChange::Delete => {
            sd_cfg.encap.remove(&(bsl, encap_type));
            event_queue.insert(Event::BierCfgUpdate);
        }
        BierSubDomainEncapsulationChange::Entry(change) => {
            let encap = sd_cfg.encap.get_mut(&(bsl, encap_type)).ok_or(ApplyError::EntryNotFound)?;
            match change {
                BierSubDomainEncapsulationEntryChange::MaxSi(max_si) => {
                    encap.max_si = max_si;
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgEncapUpdate(sd_id, af, bsl, encap_type));
                }
                BierSubDomainEncapsulationEntryChange::InBiftIdInBiftIdBase(in_bift_id_base) => {
                    let Some(in_bift_id_base) = in_bift_id_base else {
                        return Ok(());
                    };
                    encap.in_bift_id = BierInBiftId::Base(in_bift_id_base);
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgEncapUpdate(sd_id, af, bsl, encap_type));
                }
                BierSubDomainEncapsulationEntryChange::InBiftIdInBiftIdEncoding(in_bift_id_encoding) => {
                    let Some(in_bift_id_encoding) = in_bift_id_encoding else {
                        return Ok(());
                    };
                    encap.in_bift_id = BierInBiftId::Encoding(in_bift_id_encoding);
                    event_queue.insert(Event::BierCfgUpdate);
                    event_queue.insert(Event::BierCfgEncapUpdate(sd_id, af, bsl, encap_type));
                }
            }
        }
    }

    Ok(())
}

fn apply_bier_bift(master: &mut Master, bfr_id: BfrId, change: BierBiftChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        BierBiftChange::Create => {
            let bift_cfg = BierBiftCfg {
                bfr_id,
                birt: Default::default(),
            };
            master.bier_config.bift_cfg.insert(bfr_id, bift_cfg);
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgBiftUpdate(bfr_id));
        }
        BierBiftChange::Delete => {
            master.bier_config.bift_cfg.remove(&bfr_id);
            event_queue.insert(Event::BierCfgUpdate);
            event_queue.insert(Event::BierCfgBiftUpdate(bfr_id));
        }
        BierBiftChange::Entry(BierBiftEntryChange::BirtBitstringlength(keys, change)) => {
            let bift_cfg = master.bier_config.bift_cfg.get_mut(&bfr_id).ok_or(ApplyError::EntryNotFound)?;
            apply_bier_birt(bift_cfg, keys.bsl, change, event_queue)?;
        }
    }

    Ok(())
}

fn apply_bier_birt(bift_cfg: &mut BierBiftCfg, bsl: Bsl, change: BierBiftBirtBitstringlengthChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        BierBiftBirtBitstringlengthChange::Create => {
            let bift = BierBift {
                bsl,
                nbr: Default::default(),
            };
            bift_cfg.birt.insert(bsl, bift);
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Create custom event?
        }
        BierBiftBirtBitstringlengthChange::Delete => {
            bift_cfg.birt.remove(&bsl);
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Create custom event?
        }
        BierBiftBirtBitstringlengthChange::Entry(BierBiftBirtBitstringlengthEntryChange::BfrNbr(keys, change)) => {
            let birt = bift_cfg.birt.get_mut(&bsl).ok_or(ApplyError::EntryNotFound)?;
            apply_bier_bfr_nbr(birt, keys.bfr_nbr.ip(), change, event_queue)?;
        }
    }

    Ok(())
}

fn apply_bier_bfr_nbr(birt: &mut BierBift, bfr_nbr: IpAddr, change: BierBiftBirtBitstringlengthBfrNbrChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        BierBiftBirtBitstringlengthBfrNbrChange::Create => {
            // The encapsulation type and out-bift-id leaves are applied as
            // separate changes within the same commit.
            let nbr = BiftNbr {
                bfr_nbr,
                encap_type: BierEncapsulationType::Mpls,
                out_bift_id: BierOutBiftId::Encoding(bier::bift::birt_bitstringlength::bfr_nbr::out_bift_id::out_bift_id_encoding::DFLT),
            };
            birt.nbr.insert(bfr_nbr, nbr);
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Custom event?
        }
        BierBiftBirtBitstringlengthBfrNbrChange::Delete => {
            birt.nbr.remove(&bfr_nbr);
            event_queue.insert(Event::BierCfgUpdate);
            // FIXME: Custom event?
        }
        BierBiftBirtBitstringlengthBfrNbrChange::Entry(change) => {
            let nbr = birt.nbr.get_mut(&bfr_nbr).ok_or(ApplyError::EntryNotFound)?;
            match change {
                BierBiftBirtBitstringlengthBfrNbrEntryChange::EncapsulationType(encap_type) => {
                    let Some(encap_type) = encap_type else {
                        return Ok(());
                    };
                    nbr.encap_type = encap_type;
                    event_queue.insert(Event::BierCfgUpdate);
                    // FIXME: Custom event?
                }
                BierBiftBirtBitstringlengthBfrNbrEntryChange::OutBiftIdOutBiftId(out_bift_id) => {
                    let Some(out_bift_id) = out_bift_id else {
                        return Ok(());
                    };
                    nbr.out_bift_id = BierOutBiftId::Defined(out_bift_id);
                    event_queue.insert(Event::BierCfgUpdate);
                    // FIXME: Custom event?
                }
                BierBiftBirtBitstringlengthBfrNbrEntryChange::OutBiftIdOutBiftIdEncoding(out_bift_id_encoding) => {
                    let Some(out_bift_id_encoding) = out_bift_id_encoding else {
                        return Ok(());
                    };
                    nbr.out_bift_id = BierOutBiftId::Encoding(out_bift_id_encoding);
                    event_queue.insert(Event::BierCfgUpdate);
                    // FIXME: Custom event?
                }
            }
        }
    }

    Ok(())
}

fn apply_connected_prefix_sid(master: &mut Master, prefix: IpNetwork, algo: PrefixSidAlgo, change: SegmentRoutingSrMplsBindingsConnectedPrefixSidMapConnectedPrefixSidChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        SegmentRoutingSrMplsBindingsConnectedPrefixSidMapConnectedPrefixSidChange::Create => {
            // The mandatory start-sid leaf is applied as a separate change
            // within the same commit. The last-hop-behavior leaf defaults
            // to PHP.
            let psid = SrCfgPrefixSid::new(0, SidLastHopBehavior::Php);
            master.sr_config.prefix_sids.insert((prefix, algo), psid);
        }
        SegmentRoutingSrMplsBindingsConnectedPrefixSidMapConnectedPrefixSidChange::Delete => {
            master.sr_config.prefix_sids.remove(&(prefix, algo));
        }
        SegmentRoutingSrMplsBindingsConnectedPrefixSidMapConnectedPrefixSidChange::Entry(change) => {
            let psid = master.sr_config.prefix_sids.get_mut(&(prefix, algo)).ok_or(ApplyError::EntryNotFound)?;
            match change {
                SegmentRoutingSrMplsBindingsConnectedPrefixSidMapConnectedPrefixSidEntryChange::StartSid(index) => {
                    psid.index = index;
                }
                SegmentRoutingSrMplsBindingsConnectedPrefixSidMapConnectedPrefixSidEntryChange::LastHopBehavior(last_hop) => {
                    psid.last_hop = last_hop;
                }
            }
        }
    }

    event_queue.insert(Event::SrCfgUpdate);
    event_queue.insert(Event::SrCfgPrefixSidUpdate(prefix.address_family()));

    Ok(())
}

fn apply_srgb(master: &mut Master, range: LabelRange, change: SegmentRoutingSrMplsSrgbChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        // The label range was reserved during the Prepare phase.
        SegmentRoutingSrMplsSrgbChange::Create => {
            master.sr_config.srgb.insert(range);
        }
        SegmentRoutingSrMplsSrgbChange::Delete => {
            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
            master.sr_config.srgb.remove(&range);
        }
    }

    event_queue.insert(Event::SrCfgUpdate);
    event_queue.insert(Event::SrCfgLabelRangeUpdate);

    Ok(())
}

fn apply_srlb(master: &mut Master, range: LabelRange, change: SegmentRoutingSrMplsSrlbChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        // The label range was reserved during the Prepare phase.
        SegmentRoutingSrMplsSrlbChange::Create => {
            master.sr_config.srlb.insert(range);
        }
        SegmentRoutingSrMplsSrlbChange::Delete => {
            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
            master.sr_config.srlb.remove(&range);
        }
    }

    event_queue.insert(Event::SrCfgUpdate);
    event_queue.insert(Event::SrCfgLabelRangeUpdate);

    Ok(())
}

fn process_event(master: &mut Master, event: Event) {
    match event {
        Event::InstanceStart {
            protocol,
            name,
        } => {
            instance_start(master, protocol, name);
        }
        Event::StaticRouteInstall(prefix) => {
            let route = master.static_routes.get(&prefix).unwrap();

            // Get nexthops.
            let mut kind = RouteKind::Unicast;
            let mut nexthops = Vec::new();
            if let Some(nexthop) = static_nexthop_get(&master.interfaces, &route.nexthop_single) {
                nexthops.push(nexthop);
            }
            if let Some(special) = &route.nexthop_special {
                kind = match special {
                    NexthopSpecial::Blackhole => RouteKind::Blackhole,
                    NexthopSpecial::Unreachable => RouteKind::Unreachable,
                    NexthopSpecial::Prohibit => RouteKind::Prohibit,
                };
            }
            for nexthop in route.nexthop_list.values().filter_map(|nexthop| static_nexthop_get(&master.interfaces, nexthop)) {
                nexthops.push(nexthop);
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
            master.ibus_tx.route_ip_add(msg);
        }
        Event::StaticRouteUninstall(prefix) => {
            // Prepare message.
            let msg = RouteKeyMsg {
                protocol: Protocol::STATIC,
                prefix,
            };

            // Send message.
            master.ibus_tx.route_ip_del(msg);
        }
        Event::SrCfgUpdate => {
            // Update the shared SR configuration by creating a new reference-counted copy.
            master.shared.sr_config = Arc::new(master.sr_config.clone());

            // Notify protocol instances about the updated SR configuration.
            for instance in master.instances.values() {
                let _ = instance.ibus_tx.send(IbusMsg::SrCfgUpd(master.shared.sr_config.clone()));
            }
        }
        Event::SrCfgLabelRangeUpdate => {
            // Notify protocol instances about the updated SRGB/SRLB configuration.
            for instance in master.instances.values() {
                let _ = instance.ibus_tx.send(IbusMsg::SrCfgEvent(SrCfgEvent::LabelRangeUpdate));
            }
        }
        Event::SrCfgPrefixSidUpdate(af) => {
            // Notify protocol instances about the updated Prefix-SID configuration.
            for instance in master.instances.values() {
                let _ = instance.ibus_tx.send(IbusMsg::SrCfgEvent(SrCfgEvent::PrefixSidUpdate(af)));
            }
        }
        Event::BierCfgUpdate => {
            // Update the shared BIER configuration by creating a new reference-counted copy.
            master.shared.bier_config = Arc::new(master.bier_config.clone());

            // Notify protocol instances about the updated BIER configuration.
            for instance in master.instances.values() {
                let _ = instance.ibus_tx.send(IbusMsg::BierCfgUpd(master.shared.bier_config.clone()));
            }
        }
        Event::BierCfgEncapUpdate(_sd_id, af, _bsl, _encap_type) => {
            for instance in master.instances.values() {
                let _ = instance.ibus_tx.send(IbusMsg::BierCfgEvent(BierCfgEvent::EncapUpdate(af)));
            }
        }
        Event::BierCfgSubDomainUpdate(af) => {
            for instance in master.instances.values() {
                let _ = instance.ibus_tx.send(IbusMsg::BierCfgEvent(BierCfgEvent::SubDomainUpdate(af)));
            }
        }
        Event::BierCfgBiftUpdate(_bfr_id) => {
            // TODO
        }
    }
}

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

            spawn_protocol_task::<Instance>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), master.shared.clone())
        }
        Protocol::DIRECT => {
            // This protocol type can not be configured.
            unreachable!()
        }
        #[cfg(feature = "igmp")]
        Protocol::IGMP => {
            use holo_igmp::instance::Instance;

            spawn_protocol_task::<Instance>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), master.shared.clone())
        }
        #[cfg(feature = "isis")]
        Protocol::ISIS => {
            use holo_isis::instance::Instance;

            spawn_protocol_task::<Instance>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), master.shared.clone())
        }
        #[cfg(feature = "ldp")]
        Protocol::LDP => {
            use holo_ldp::instance::Instance;

            spawn_protocol_task::<Instance>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), master.shared.clone())
        }
        #[cfg(feature = "ospf")]
        Protocol::OSPFV2 => {
            use holo_ospf::instance::Instance;
            use holo_ospf::version::Ospfv2;

            spawn_protocol_task::<Instance<Ospfv2>>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), master.shared.clone())
        }
        #[cfg(feature = "ospf")]
        Protocol::OSPFV3 => {
            use holo_ospf::instance::Instance;
            use holo_ospf::version::Ospfv3;

            spawn_protocol_task::<Instance<Ospfv3>>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), master.shared.clone())
        }
        #[cfg(feature = "rip")]
        Protocol::RIPV2 => {
            use holo_rip::instance::Instance;
            use holo_rip::version::Ripv2;

            spawn_protocol_task::<Instance<Ripv2>>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), master.shared.clone())
        }
        #[cfg(feature = "rip")]
        Protocol::RIPNG => {
            use holo_rip::instance::Instance;
            use holo_rip::version::Ripng;

            spawn_protocol_task::<Instance<Ripng>>(name, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), master.shared.clone())
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

// ===== impl Master =====

impl Provider for Master {
    type Event = Event;
    type Resource = Resource;
    type Change = ConfigChange;

    const YANG_OPS_CONFIG: YangConfigOps<ConfigChange> = config::YANG_OPS_CONFIG;

    fn validation_fns() -> Vec<ValidateFn> {
        vec![
            validate,
            #[cfg(feature = "ospf")]
            holo_ospf::northbound::configuration::validate,
            #[cfg(feature = "rip")]
            holo_rip::northbound::configuration::validate,
        ]
    }

    fn prepare(&mut self, change: &ConfigChange, resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), PrepareError> {
        prepare_master(self, change, resource, event_queue)
    }

    fn abort(&mut self, change: ConfigChange, resource: &mut Option<Resource>) {
        abort_master(self, change, resource)
    }

    fn apply(&mut self, change: ConfigChange, _resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
        apply_master(self, change, event_queue)
    }

    fn process_event(&mut self, event: Event) {
        process_event(self, event);
    }

    fn relay_changes(&self, changes: ConfigChanges) -> Vec<(ConfigChanges, NbDaemonSender)> {
        // Create hash table that maps changes to the appropriate child
        // instances.
        let mut changes_map: HashMap<InstanceId, ConfigChanges> = HashMap::new();
        for change in changes {
            // HACK: parse protocol type and instance name.
            let Some(caps) = REGEX_PROTOCOLS.captures(&change.1) else {
                continue;
            };
            let ptype = caps.get(1).unwrap().as_str();
            let name = caps.get(2).unwrap().as_str();

            // Move configuration change to the appropriate instance bucket.
            let protocol = Protocol::try_from_yang(ptype).unwrap();
            let instance_id = InstanceId::new(protocol, name.to_owned());
            changes_map.entry(instance_id).or_default().push(change);
        }
        changes_map
            .into_iter()
            .filter_map(|(instance_id, changes)| self.instances.get(&instance_id).map(|instance| (changes, instance.nb_tx.clone())))
            .collect::<Vec<_>>()
    }
}

// ===== global functions =====

pub fn validate(config: &DataTree<'static>) -> Result<(), ValidationError> {
    // Ensure the BFR prefix matches the configured address family.
    for dnode in config.iter_path(bier::sub_domain::PATH) {
        let Some(af) = dnode.get_typed_path::<AddressFamily>(bier::sub_domain::address_family::PATH) else {
            let message = "failed to retrieve data node";
            return Err(ValidationError::new(&dnode, message));
        };
        if let Some(bfr_prefix) = dnode.get_typed_path::<IpNetwork>(bier::sub_domain::bfr_prefix::PATH)
            && bfr_prefix.address_family() != af
        {
            let message = "Configured address family differs from BFR prefix address family.";
            return Err(ValidationError::new(&dnode, message));
        }
    }

    Ok(())
}
