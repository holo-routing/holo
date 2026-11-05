//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use holo_northbound::configuration::{ConfigOp, InheritableConfig, Provider, YangConfigOps};
use holo_northbound::error::{ApplyError, ValidationError};
use holo_utils::bfd;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::protocol::Protocol;
use holo_utils::yang::{DataNodeRefExt, DataTreeExt};
use holo_yang::TryFromYang;
use yang5::data::DataTree;

use crate::area::{self, Area, AreaType};
use crate::collections::{AreaIndex, InterfaceIndex};
use crate::debug::InterfaceInactiveReason;
use crate::instance::Instance;
use crate::interface::{Interface, InterfaceType, VirtualLinkKey, ism};
use crate::lsdb::LsaOriginateEvent;
use crate::neighbor::nsm;
use crate::northbound::yang_gen::config::{
    self, AreaChange, AreaEntryChange, AreaInterfaceChange, AreaInterfaceEntryChange, AreaInterfaceStaticNeighborsNeighborChange, AreaInterfaceStaticNeighborsNeighborEntryChange, AreaInterfaceTraceOptionsFlagChange,
    AreaInterfaceTraceOptionsFlagEntryChange, AreaRangeChange, AreaRangeEntryChange, AreaVirtualLinkChange, AreaVirtualLinkEntryChange, ConfigChange, TraceOptionsFlagChange, TraceOptionsFlagEntryChange,
};
use crate::northbound::yang_gen::ospf;
use crate::packet::iana::PacketType;
use crate::route::RouteNetFlags;
use crate::version::Version;
use crate::{gr, ibus, spf, sr, tasks};

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
    AreaInterfaceTraceOptionsFlagChange(AreaIndex),
    InterfaceSyncHelloTx(AreaIndex, InterfaceIndex),
    InterfaceUpdateAuth(AreaIndex, InterfaceIndex),
    InterfaceBfdChange(InterfaceIndex),
    InterfaceUpdateTraceOptions(InterfaceIndex),
    InterfaceIbusSub(String),
    StubRouterChange,
    GrHelperChange,
    SrEnableChange(bool),
    RerunSpf,
    UpdateVirtualLinks,
    UpdateSummaries,
    ReinstallRoutes,
    BierEnableChange(bool),
    NodeTagsChange,
    UpdateTraceOptions,
}

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {
    pub af: Option<AddressFamily>,
    pub enabled: bool,
    pub router_id: Option<Ipv4Addr>,
    pub preference: Preference,
    pub gr: InstanceGrCfg,
    pub max_paths: u16,
    pub spf_initial_delay: u32,
    pub spf_short_delay: u32,
    pub spf_long_delay: u32,
    pub spf_hold_down: u32,
    pub spf_time_to_learn: u32,
    pub stub_router: bool,
    pub node_tags: BTreeSet<u32>,
    pub extended_lsa: bool,
    pub sr_enabled: bool,
    pub instance_id: u8,
    pub bier: BierOspfCfg,
    pub trace_opts: InstanceTraceOptions,
}

#[derive(Debug)]
pub struct BierOspfCfg {
    pub mt_id: u8,
    pub enabled: bool,
    pub advertise: bool,
    pub receive: bool,
}

#[derive(Debug)]
pub struct Preference {
    pub intra_area: u8,
    pub inter_area: u8,
    pub external: u8,
}

#[derive(Debug)]
pub struct InstanceGrCfg {
    pub helper_enabled: bool,
    pub helper_strict_lsa_checking: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum InstanceTraceOption {
    Flooding,
    GracefulRestart,
    InternalBus,
    Lsdb,
    Neighbor,
    PacketsAll,
    PacketsHello,
    PacketsDbDesc,
    PacketsLsUpdate,
    PacketsLsRequest,
    PacketsLsAck,
    Spf,
}

#[derive(Debug, Default)]
pub struct InstanceTraceOptions {
    pub flooding: bool,
    pub gr: bool,
    pub ibus: bool,
    pub lsdb: bool,
    pub neighbor: bool,
    pub packets: TraceOptionPacket,
    pub spf: bool,
}

#[derive(Debug)]
pub struct AreaCfg {
    pub area_type: AreaType,
    pub summary: bool,
    pub default_cost: u32,
}

#[derive(Debug)]
pub struct RangeCfg {
    pub advertise: bool,
    pub cost: Option<u32>,
}

#[derive(Debug)]
pub struct ReverseMetricCfg {
    pub receive: bool,
    pub metric: Option<u16>,
    pub higher: bool,
    pub offset: bool,
}

#[derive(Debug)]
pub struct InterfaceCfg<V: Version> {
    pub instance_id: InheritableConfig<u8>,
    pub if_type: InterfaceType,
    pub passive: bool,
    pub priority: u8,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub retransmit_interval: u16,
    pub transmit_delay: u16,
    pub enabled: bool,
    pub cost: u16,
    pub mtu_ignore: bool,
    pub node_flag: bool,
    pub anycast_flag: bool,
    pub static_nbrs: BTreeMap<V::NetIpAddr, StaticNbr>,
    pub auth_keychain: Option<String>,
    pub auth_keyid: Option<u32>,
    pub auth_key: Option<String>,
    pub auth_algo: Option<CryptoAlgo>,
    pub bfd_enabled: bool,
    pub bfd_params: bfd::ClientCfg,
    pub trace_opts: InterfaceTraceOptions,
    pub lls_enabled: bool,
    pub reverse_metric: ReverseMetricCfg,
}

#[derive(Debug)]
pub struct StaticNbr {
    pub cost: Option<u16>,
    pub poll_interval: u16,
    pub priority: u8,
}

#[derive(Clone, Copy, Debug)]
pub enum InterfaceTraceOption {
    PacketsAll,
    PacketsHello,
    PacketsDbDesc,
    PacketsLsUpdate,
    PacketsLsRequest,
    PacketsLsAck,
}

#[derive(Debug, Default)]
pub struct InterfaceTraceOptions {
    pub packets: TraceOptionPacket,
    pub packets_resolved: Arc<ArcSwap<TraceOptionPacketResolved>>,
}

#[derive(Debug, Default)]
pub struct TraceOptionPacket {
    pub all: Option<TraceOptionPacketType>,
    pub hello: Option<TraceOptionPacketType>,
    pub dbdesc: Option<TraceOptionPacketType>,
    pub lsreq: Option<TraceOptionPacketType>,
    pub lsupd: Option<TraceOptionPacketType>,
    pub lsack: Option<TraceOptionPacketType>,
}

#[derive(Clone, Copy, Debug)]
pub struct TraceOptionPacketResolved {
    pub hello: TraceOptionPacketType,
    pub dbdesc: TraceOptionPacketType,
    pub lsreq: TraceOptionPacketType,
    pub lsupd: TraceOptionPacketType,
    pub lsack: TraceOptionPacketType,
}

#[derive(Clone, Copy, Debug)]
pub struct TraceOptionPacketType {
    pub tx: bool,
    pub rx: bool,
}

// ===== helper functions =====

fn apply_instance<V>(instance: &mut Instance<V>, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    match change {
        ConfigChange::AddressFamily(af) => {
            instance.config.af = af;
            event_queue.insert(Event::InstanceReset);
        }
        ConfigChange::Enabled(enabled) => {
            instance.config.enabled = enabled;
            event_queue.insert(Event::InstanceUpdate);
        }
        ConfigChange::ExplicitRouterId(router_id) => {
            let old_router_id = instance.get_router_id();
            instance.config.router_id = router_id;

            // NOTE: apply the new Router-ID immediately.
            if instance.get_router_id() != old_router_id {
                event_queue.insert(Event::InstanceReset);
                event_queue.insert(Event::InstanceUpdate);
            }
        }
        ConfigChange::PreferenceAll(preference) => {
            let preference = preference.unwrap_or(ospf::preference::all::DFLT);
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;
            instance.config.preference.external = preference;
            event_queue.insert(Event::ReinstallRoutes);
        }
        ConfigChange::PreferenceIntraArea(preference) => {
            let preference = preference.unwrap_or(ospf::preference::all::DFLT);
            instance.config.preference.intra_area = preference;
            event_queue.insert(Event::ReinstallRoutes);
        }
        ConfigChange::PreferenceInterArea(preference) => {
            let preference = preference.unwrap_or(ospf::preference::all::DFLT);
            instance.config.preference.inter_area = preference;
            event_queue.insert(Event::ReinstallRoutes);
        }
        ConfigChange::PreferenceInternal(preference) => {
            let preference = preference.unwrap_or(ospf::preference::all::DFLT);
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;
            event_queue.insert(Event::ReinstallRoutes);
        }
        ConfigChange::PreferenceExternal(preference) => {
            let preference = preference.unwrap_or(ospf::preference::all::DFLT);
            instance.config.preference.external = preference;
            event_queue.insert(Event::ReinstallRoutes);
        }
        ConfigChange::GracefulRestartHelperEnabled(enabled) => {
            instance.config.gr.helper_enabled = enabled;
            event_queue.insert(Event::GrHelperChange);
        }
        ConfigChange::GracefulRestartHelperStrictLsaChecking(strict_lsa_checking) => {
            instance.config.gr.helper_strict_lsa_checking = strict_lsa_checking;
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
        ConfigChange::StubRouterAlways(op) => {
            instance.config.stub_router = op == ConfigOp::Create;
            event_queue.insert(Event::StubRouterChange);
        }
        ConfigChange::NodeTag(keys, change) => {
            apply_node_tag(instance, keys.tag, change, event_queue)?;
        }
        ConfigChange::ExtendedLsaSupport(extended_lsa) => {
            if let Some(extended_lsa) = extended_lsa {
                instance.config.extended_lsa = extended_lsa;
                event_queue.insert(Event::InstanceReset);
            }
        }
        ConfigChange::SegmentRoutingEnabled(sr_enabled) => {
            instance.config.sr_enabled = sr_enabled;
            event_queue.insert(Event::SrEnableChange(sr_enabled));
        }
        ConfigChange::InstanceId(instance_id) => {
            if let Some(instance_id) = instance_id {
                instance.config.instance_id = instance_id;
                event_queue.insert(Event::InstanceIdUpdate);
            }
        }
        ConfigChange::Area(keys, change) => {
            apply_area(instance, keys.area_id, change, event_queue)?;
        }
        ConfigChange::BierMtId(mt_id) => {
            instance.config.bier.mt_id = mt_id.unwrap_or(0);
            // TODO: should reoriginate LSA
        }
        ConfigChange::BierBierEnable(enable) => {
            instance.config.bier.enabled = enable;
            event_queue.insert(Event::BierEnableChange(enable));
        }
        ConfigChange::BierBierAdvertise(advertise) => {
            instance.config.bier.advertise = advertise;
        }
        ConfigChange::BierBierReceive(receive) => {
            instance.config.bier.receive = receive;
        }
        ConfigChange::TraceOptionsFlag(keys, change) => {
            apply_trace_options(instance, keys.name, change, event_queue)?;
        }
        ConfigChange::ReverseMetricEnableReceive(receive) => {
            instance.arenas.interfaces.iter_mut().for_each(|(_, iface)| {
                iface.config.reverse_metric.receive = receive;
            });
        }
    }

    Ok(())
}

fn apply_node_tag<V>(instance: &mut Instance<V>, tag: u32, change: config::NodeTagChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    match change {
        config::NodeTagChange::Create => {
            instance.config.node_tags.insert(tag);
        }
        config::NodeTagChange::Delete => {
            instance.config.node_tags.remove(&tag);
        }
    }
    event_queue.insert(Event::NodeTagsChange);

    Ok(())
}

fn apply_trace_options<V>(instance: &mut Instance<V>, trace_opt: InstanceTraceOption, change: TraceOptionsFlagChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    let trace_opts = &mut instance.config.trace_opts;
    match change {
        TraceOptionsFlagChange::Create => match trace_opt {
            InstanceTraceOption::Flooding => trace_opts.flooding = true,
            InstanceTraceOption::GracefulRestart => trace_opts.gr = true,
            InstanceTraceOption::InternalBus => trace_opts.ibus = true,
            InstanceTraceOption::Lsdb => trace_opts.lsdb = true,
            InstanceTraceOption::Neighbor => trace_opts.neighbor = true,
            InstanceTraceOption::Spf => trace_opts.spf = true,
            InstanceTraceOption::PacketsAll => {
                trace_opts.packets.all.get_or_insert_default();
            }
            InstanceTraceOption::PacketsHello => {
                trace_opts.packets.hello.get_or_insert_default();
            }
            InstanceTraceOption::PacketsDbDesc => {
                trace_opts.packets.dbdesc.get_or_insert_default();
            }
            InstanceTraceOption::PacketsLsRequest => {
                trace_opts.packets.lsreq.get_or_insert_default();
            }
            InstanceTraceOption::PacketsLsUpdate => {
                trace_opts.packets.lsupd.get_or_insert_default();
            }
            InstanceTraceOption::PacketsLsAck => {
                trace_opts.packets.lsack.get_or_insert_default();
            }
        },
        TraceOptionsFlagChange::Delete => match trace_opt {
            InstanceTraceOption::Flooding => trace_opts.flooding = false,
            InstanceTraceOption::GracefulRestart => trace_opts.gr = false,
            InstanceTraceOption::InternalBus => trace_opts.ibus = false,
            InstanceTraceOption::Lsdb => trace_opts.lsdb = false,
            InstanceTraceOption::Neighbor => trace_opts.neighbor = false,
            InstanceTraceOption::Spf => trace_opts.spf = false,
            InstanceTraceOption::PacketsAll => trace_opts.packets.all = None,
            InstanceTraceOption::PacketsHello => trace_opts.packets.hello = None,
            InstanceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc = None,
            InstanceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq = None,
            InstanceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd = None,
            InstanceTraceOption::PacketsLsAck => trace_opts.packets.lsack = None,
        },
        TraceOptionsFlagChange::Entry(change) => {
            let trace_opt_packet = match trace_opt {
                InstanceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InstanceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InstanceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc.as_mut(),
                InstanceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq.as_mut(),
                InstanceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd.as_mut(),
                InstanceTraceOption::PacketsLsAck => trace_opts.packets.lsack.as_mut(),
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

fn apply_area<V>(instance: &mut Instance<V>, area_id: Ipv4Addr, change: AreaChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    match change {
        AreaChange::Create => {
            let (area_idx, _) = instance.arenas.areas.insert(area_id);
            event_queue.insert(Event::AreaCreate(area_idx));
        }
        AreaChange::Delete => {
            let (area_idx, _) = instance.arenas.areas.get_mut_by_area_id(area_id).ok_or(ApplyError::EntryNotFound)?;
            event_queue.insert(Event::AreaDelete(area_idx));
            event_queue.insert(Event::RerunSpf);
        }
        AreaChange::Entry(change) => {
            let (area_idx, area) = instance.arenas.areas.get_mut_by_area_id(area_id).ok_or(ApplyError::EntryNotFound)?;
            match change {
                AreaEntryChange::VirtualLink(vlink_keys, change) => {
                    apply_virtual_link(instance, area_idx, vlink_keys.transit_area_id, vlink_keys.router_id, change, event_queue)?;
                }
                AreaEntryChange::Interface(iface_keys, change) => {
                    apply_interface(instance, area_idx, iface_keys.name, change, event_queue)?;
                }
                AreaEntryChange::AreaType(area_type) => {
                    area.config.area_type = area_type;
                    area.config.summary = ospf::areas::area::summary::DFLT;
                    area.config.default_cost = ospf::areas::area::default_cost::DFLT;

                    event_queue.insert(Event::AreaTypeChange(area_idx));
                    event_queue.insert(Event::AreaSyncHelloTx(area_idx));
                }
                AreaEntryChange::Summary(summary) => {
                    if let Some(summary) = summary {
                        area.config.summary = summary;
                        event_queue.insert(Event::UpdateSummaries);
                    }
                }
                AreaEntryChange::DefaultCost(default_cost) => {
                    if let Some(default_cost) = default_cost {
                        area.config.default_cost = default_cost;
                        event_queue.insert(Event::UpdateSummaries);
                    }
                }
                AreaEntryChange::Range(keys, change) => {
                    let Some(prefix) = V::IpNetwork::get(keys.prefix) else {
                        return Ok(());
                    };
                    apply_area_range(area, prefix, change, event_queue)?;
                }
                AreaEntryChange::ReverseMetricEnableReceive(receive) => {
                    instance.arenas.interfaces.iter_mut().filter(|(area, _)| area == &area_idx).for_each(|(_, iface)| {
                        iface.config.reverse_metric.receive = receive;
                    });
                }
            }
        }
    }

    Ok(())
}

fn apply_area_range<V>(area: &mut Area<V>, prefix: V::IpNetwork, change: AreaRangeChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    match change {
        AreaRangeChange::Create => {
            area.ranges.insert(prefix, Default::default());
        }
        AreaRangeChange::Delete => {
            area.ranges.remove(&prefix);
        }
        AreaRangeChange::Entry(change) => {
            let range = area.ranges.get_mut(&prefix).ok_or(ApplyError::EntryNotFound)?;
            match change {
                AreaRangeEntryChange::Advertise(advertise) => {
                    range.config.advertise = advertise;
                }
                AreaRangeEntryChange::Cost(cost) => {
                    range.config.cost = cost;
                }
            }
        }
    }
    event_queue.insert(Event::UpdateSummaries);

    Ok(())
}

fn apply_virtual_link<V>(instance: &mut Instance<V>, area_idx: AreaIndex, transit_area_id: Ipv4Addr, router_id: Ipv4Addr, change: AreaVirtualLinkChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    let ifname = format!("vlink-{transit_area_id}-{router_id}");
    let area = &mut instance.arenas.areas[area_idx];

    match change {
        AreaVirtualLinkChange::Create => {
            let vlink_key = VirtualLinkKey {
                transit_area_id,
                router_id,
            };
            let (iface_idx, iface) = area.interfaces.insert(&mut instance.arenas.interfaces, ifname, Some(vlink_key));
            iface.config.if_type = InterfaceType::VirtualLink;

            event_queue.insert(Event::UpdateVirtualLinks);
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        }
        AreaVirtualLinkChange::Delete => {
            let (iface_idx, _) = area.interfaces.get_mut_by_name(&mut instance.arenas.interfaces, &ifname).ok_or(ApplyError::EntryNotFound)?;
            event_queue.insert(Event::InterfaceDelete(area_idx, iface_idx));
        }
        AreaVirtualLinkChange::Entry(change) => {
            let (iface_idx, iface) = area.interfaces.get_mut_by_name(&mut instance.arenas.interfaces, &ifname).ok_or(ApplyError::EntryNotFound)?;
            match change {
                AreaVirtualLinkEntryChange::HelloInterval(hello_interval) => {
                    iface.config.hello_interval = hello_interval;
                    event_queue.insert(Event::InterfaceResetHelloInterval(area_idx, iface_idx));
                    event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
                }
                AreaVirtualLinkEntryChange::DeadInterval(dead_interval) => {
                    iface.config.dead_interval = dead_interval;
                    event_queue.insert(Event::InterfaceResetDeadInterval(area_idx, iface_idx));
                    event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
                }
                AreaVirtualLinkEntryChange::RetransmitInterval(retransmit_interval) => {
                    iface.config.retransmit_interval = retransmit_interval;
                }
                AreaVirtualLinkEntryChange::TransmitDelay(transmit_delay) => {
                    iface.config.transmit_delay = transmit_delay;
                }
                AreaVirtualLinkEntryChange::Lls(enabled) => {
                    iface.config.lls_enabled = enabled;
                }
                AreaVirtualLinkEntryChange::Enabled(enabled) => {
                    iface.config.enabled = enabled;
                    event_queue.insert(Event::InterfaceUpdate(area_idx, iface_idx));
                }
                AreaVirtualLinkEntryChange::AuthenticationOspfv2KeyChain(keychain) | AreaVirtualLinkEntryChange::AuthenticationOspfv3KeyChain(keychain) => {
                    iface.config.auth_keychain = keychain;
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
                AreaVirtualLinkEntryChange::AuthenticationOspfv2KeyId(key_id) => {
                    iface.config.auth_keyid = key_id;
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
                AreaVirtualLinkEntryChange::AuthenticationOspfv3SaId(sa_id) => {
                    iface.config.auth_keyid = sa_id.map(u32::from);
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
                AreaVirtualLinkEntryChange::AuthenticationOspfv2Key(key) | AreaVirtualLinkEntryChange::AuthenticationOspfv3Key(key) => {
                    iface.config.auth_key = key;
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
                AreaVirtualLinkEntryChange::AuthenticationOspfv2CryptoAlgorithm(algo) | AreaVirtualLinkEntryChange::AuthenticationOspfv3CryptoAlgorithm(algo) => {
                    iface.config.auth_algo = algo;
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
            }
        }
    }

    Ok(())
}

fn apply_interface<V>(instance: &mut Instance<V>, area_idx: AreaIndex, ifname: String, change: AreaInterfaceChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    let area = &mut instance.arenas.areas[area_idx];

    match change {
        AreaInterfaceChange::Create => {
            let (iface_idx, _) = area.interfaces.insert(&mut instance.arenas.interfaces, ifname.clone(), None);

            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::InterfaceUpdate(area_idx, iface_idx));
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
            event_queue.insert(Event::InterfaceIbusSub(ifname));
        }
        AreaInterfaceChange::Delete => {
            let (iface_idx, _) = area.interfaces.get_mut_by_name(&mut instance.arenas.interfaces, &ifname).ok_or(ApplyError::EntryNotFound)?;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::InterfaceDelete(area_idx, iface_idx));
        }
        AreaInterfaceChange::Entry(change) => {
            let (iface_idx, iface) = area.interfaces.get_mut_by_name(&mut instance.arenas.interfaces, &ifname).ok_or(ApplyError::EntryNotFound)?;
            match change {
                AreaInterfaceEntryChange::InterfaceType(if_type) => {
                    iface.config.if_type = if_type;
                    event_queue.insert(Event::InterfaceReset(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::Passive(passive) => {
                    iface.config.passive = passive;
                    event_queue.insert(Event::InterfaceReset(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::Priority(priority) => {
                    iface.config.priority = priority;
                    event_queue.insert(Event::InterfacePriorityChange(area_idx, iface_idx));
                    event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::StaticNeighborsNeighbor(keys, change) => {
                    let Some(identifier) = V::NetIpAddr::get(keys.identifier) else {
                        return Ok(());
                    };
                    apply_interface_static_neighbor(iface, identifier, change)?;
                }
                AreaInterfaceEntryChange::NodeFlag(node_flag) => {
                    iface.config.node_flag = node_flag;
                    event_queue.insert(Event::AreaInterfaceTraceOptionsFlagChange(area_idx));
                }
                AreaInterfaceEntryChange::AnycastFlag(anycast_flag) => {
                    if let Some(anycast_flag) = anycast_flag {
                        iface.config.anycast_flag = anycast_flag;
                        event_queue.insert(Event::AreaInterfaceTraceOptionsFlagChange(area_idx));
                    }
                }
                AreaInterfaceEntryChange::BfdEnabled(enabled) => {
                    iface.config.bfd_enabled = enabled;
                    event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                }
                AreaInterfaceEntryChange::BfdLocalMultiplier(local_multiplier) => {
                    iface.config.bfd_params.local_multiplier = local_multiplier;
                    event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                }
                AreaInterfaceEntryChange::BfdDesiredMinTxInterval(min_tx) => {
                    if let Some(min_tx) = min_tx {
                        iface.config.bfd_params.min_tx = min_tx;
                        event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                    }
                }
                AreaInterfaceEntryChange::BfdRequiredMinRxInterval(min_rx) => {
                    if let Some(min_rx) = min_rx {
                        iface.config.bfd_params.min_rx = min_rx;
                        event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                    }
                }
                AreaInterfaceEntryChange::BfdMinInterval(min_interval) => {
                    if let Some(min_interval) = min_interval {
                        iface.config.bfd_params.min_tx = min_interval;
                        iface.config.bfd_params.min_rx = min_interval;
                        event_queue.insert(Event::InterfaceBfdChange(iface_idx));
                    }
                }
                AreaInterfaceEntryChange::HelloInterval(hello_interval) => {
                    iface.config.hello_interval = hello_interval;
                    event_queue.insert(Event::InterfaceResetHelloInterval(area_idx, iface_idx));
                    event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::DeadInterval(dead_interval) => {
                    iface.config.dead_interval = dead_interval;
                    event_queue.insert(Event::InterfaceResetDeadInterval(area_idx, iface_idx));
                    event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::RetransmitInterval(retransmit_interval) => {
                    iface.config.retransmit_interval = retransmit_interval;
                }
                AreaInterfaceEntryChange::TransmitDelay(transmit_delay) => {
                    iface.config.transmit_delay = transmit_delay;
                }
                AreaInterfaceEntryChange::Lls(enabled) => {
                    iface.config.lls_enabled = enabled;
                }
                AreaInterfaceEntryChange::Enabled(enabled) => {
                    iface.config.enabled = enabled;
                    event_queue.insert(Event::InterfaceUpdate(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::Cost(cost) => {
                    iface.config.cost = cost;
                    iface.state.cost = cost;
                    event_queue.insert(Event::InterfaceCostChange(area_idx));
                }
                AreaInterfaceEntryChange::MtuIgnore(mtu_ignore) => {
                    iface.config.mtu_ignore = mtu_ignore;
                }
                AreaInterfaceEntryChange::InstanceId(instance_id) => {
                    match instance_id {
                        Some(instance_id) => {
                            iface.config.instance_id.explicit = Some(instance_id);
                            iface.config.instance_id.resolved = instance_id;
                        }
                        None => {
                            iface.config.instance_id.explicit = None;
                            iface.config.instance_id.resolved = instance.config.instance_id;
                        }
                    }
                    event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::AuthenticationOspfv2KeyChain(keychain) | AreaInterfaceEntryChange::AuthenticationOspfv3KeyChain(keychain) => {
                    iface.config.auth_keychain = keychain;
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::AuthenticationOspfv2KeyId(key_id) => {
                    iface.config.auth_keyid = key_id;
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::AuthenticationOspfv3SaId(sa_id) => {
                    iface.config.auth_keyid = sa_id.map(u32::from);
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::AuthenticationOspfv2Key(key) | AreaInterfaceEntryChange::AuthenticationOspfv3Key(key) => {
                    iface.config.auth_key = key;
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::AuthenticationOspfv2CryptoAlgorithm(algo) | AreaInterfaceEntryChange::AuthenticationOspfv3CryptoAlgorithm(algo) => {
                    iface.config.auth_algo = algo;
                    event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::TraceOptionsFlag(keys, change) => {
                    apply_interface_trace_options(iface, iface_idx, keys.name, change, event_queue)?;
                }
                AreaInterfaceEntryChange::ReverseMetricEnableReceive(receive) => {
                    iface.config.reverse_metric.receive = receive;
                }
                AreaInterfaceEntryChange::ReverseMetricMetric(metric) => {
                    iface.config.reverse_metric.metric = metric;
                    event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::ReverseMetricFlagsHigher(higher) => {
                    iface.config.reverse_metric.higher = higher;
                    event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
                }
                AreaInterfaceEntryChange::ReverseMetricFlagsOffset(offset) => {
                    iface.config.reverse_metric.offset = offset;
                    event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
                }
            }
        }
    }

    Ok(())
}

fn apply_interface_static_neighbor<V>(iface: &mut Interface<V>, identifier: V::NetIpAddr, change: AreaInterfaceStaticNeighborsNeighborChange) -> Result<(), ApplyError>
where
    V: Version,
{
    match change {
        AreaInterfaceStaticNeighborsNeighborChange::Create => {
            iface.config.static_nbrs.insert(identifier, Default::default());
        }
        AreaInterfaceStaticNeighborsNeighborChange::Delete => {
            iface.config.static_nbrs.remove(&identifier);
        }
        AreaInterfaceStaticNeighborsNeighborChange::Entry(change) => {
            let snbr = iface.config.static_nbrs.get_mut(&identifier).ok_or(ApplyError::EntryNotFound)?;
            match change {
                AreaInterfaceStaticNeighborsNeighborEntryChange::Cost(cost) => {
                    snbr.cost = cost;
                }
                AreaInterfaceStaticNeighborsNeighborEntryChange::PollInterval(poll_interval) => {
                    snbr.poll_interval = poll_interval;
                }
                AreaInterfaceStaticNeighborsNeighborEntryChange::Priority(priority) => {
                    snbr.priority = priority;
                }
            }
        }
    }

    Ok(())
}

fn apply_interface_trace_options<V>(iface: &mut Interface<V>, iface_idx: InterfaceIndex, trace_opt: InterfaceTraceOption, change: AreaInterfaceTraceOptionsFlagChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    let trace_opts = &mut iface.config.trace_opts;
    match change {
        AreaInterfaceTraceOptionsFlagChange::Create => match trace_opt {
            InterfaceTraceOption::PacketsAll => {
                trace_opts.packets.all.get_or_insert_default();
            }
            InterfaceTraceOption::PacketsHello => {
                trace_opts.packets.hello.get_or_insert_default();
            }
            InterfaceTraceOption::PacketsDbDesc => {
                trace_opts.packets.dbdesc.get_or_insert_default();
            }
            InterfaceTraceOption::PacketsLsRequest => {
                trace_opts.packets.lsreq.get_or_insert_default();
            }
            InterfaceTraceOption::PacketsLsUpdate => {
                trace_opts.packets.lsupd.get_or_insert_default();
            }
            InterfaceTraceOption::PacketsLsAck => {
                trace_opts.packets.lsack.get_or_insert_default();
            }
        },
        AreaInterfaceTraceOptionsFlagChange::Delete => match trace_opt {
            InterfaceTraceOption::PacketsAll => trace_opts.packets.all = None,
            InterfaceTraceOption::PacketsHello => trace_opts.packets.hello = None,
            InterfaceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc = None,
            InterfaceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq = None,
            InterfaceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd = None,
            InterfaceTraceOption::PacketsLsAck => trace_opts.packets.lsack = None,
        },
        AreaInterfaceTraceOptionsFlagChange::Entry(change) => {
            let trace_opt_packet = match trace_opt {
                InterfaceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InterfaceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InterfaceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc.as_mut(),
                InterfaceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq.as_mut(),
                InterfaceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd.as_mut(),
                InterfaceTraceOption::PacketsLsAck => trace_opts.packets.lsack.as_mut(),
            };
            let Some(trace_opt_packet) = trace_opt_packet else {
                return Ok(());
            };
            match change {
                AreaInterfaceTraceOptionsFlagEntryChange::Send(enable) => {
                    trace_opt_packet.tx = enable;
                }
                AreaInterfaceTraceOptionsFlagEntryChange::Receive(enable) => {
                    trace_opt_packet.rx = enable;
                }
            }
        }
    }
    event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));

    Ok(())
}

fn process_event<V>(instance: &mut Instance<V>, event: Event)
where
    V: Version,
{
    match event {
        Event::InstanceReset => instance.reset(),
        Event::InstanceUpdate => instance.update(),
        Event::InstanceIdUpdate => {
            for area_idx in instance.arenas.areas.indexes().collect::<Vec<_>>() {
                let area = &mut instance.arenas.areas[area_idx];
                for iface_idx in area.interfaces.indexes().collect::<Vec<_>>() {
                    let iface = &mut instance.arenas.interfaces[iface_idx];
                    iface.config.instance_id.resolved = iface.config.instance_id.explicit.unwrap_or(instance.config.instance_id);
                }

                process_event(instance, Event::AreaSyncHelloTx(area_idx));
            }
        }
        Event::AreaCreate(area_idx) => {
            let area = &mut instance.arenas.areas[area_idx];

            // Originate Router Information LSA(s).
            instance.tx.protocol_input.lsa_orig_event(LsaOriginateEvent::AreaStart {
                area_id: area.id,
            });
        }
        Event::AreaDelete(area_idx) => {
            let area = &mut instance.arenas.areas[area_idx];

            // Delete area's interfaces.
            for iface_idx in area.interfaces.indexes().collect::<Vec<_>>() {
                process_event(instance, Event::InterfaceDelete(area_idx, iface_idx));
            }

            // Delete area.
            instance.arenas.areas.delete(area_idx);
        }
        Event::AreaTypeChange(area_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];

                // Kill all neighbors in the area to speed-up reconvergence.
                for iface_idx in area.interfaces.indexes() {
                    let iface = &mut arenas.interfaces[iface_idx];

                    for nbr in iface.state.neighbors.iter(&arenas.neighbors) {
                        instance.tx.protocol_input.nsm_event(area.id, iface.id, nbr.id, nsm::Event::Kill);
                    }
                }

                // Purge all AS-scoped LSAs in the absence of at least one
                // active normal area.
                if !arenas.areas.iter().any(|area| area.config.area_type == AreaType::Normal && area.is_active(&arenas.interfaces)) {
                    instance.state.lsdb = Default::default();
                }
            }
        }
        Event::AreaSyncHelloTx(area_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];

                for iface_idx in area.interfaces.indexes() {
                    let iface = &mut arenas.interfaces[iface_idx];

                    iface.sync_hello_tx(area, &instance);
                }
            }
        }
        Event::InterfaceUpdate(area_idx, iface_idx) => {
            if let Some((mut instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];
                let iface = &mut arenas.interfaces[iface_idx];

                iface.update(area, &mut instance, &mut arenas.neighbors, &arenas.lsa_entries);
            }
        }
        Event::InterfaceDelete(area_idx, iface_idx) => {
            if let Some((mut instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];
                let iface = &mut arenas.interfaces[iface_idx];

                // Cancel ibus subscription.
                if !iface.is_virtual_link() {
                    instance.tx.ibus.interface_unsub(Some(iface.name.clone()));
                }

                // Stop interface if it's active.
                let reason = InterfaceInactiveReason::AdminDown;
                iface.fsm(area, &mut instance, &mut arenas.neighbors, &arenas.lsa_entries, ism::Event::InterfaceDown(reason));

                // Update the routing table to remove nexthops that are no
                // longer reachable.
                for route in instance.state.rib.values_mut() {
                    route.nexthops.retain(|_, nexthop| nexthop.iface_idx != iface_idx);
                }
            }

            let area = &mut instance.arenas.areas[area_idx];
            area.interfaces.delete(&mut instance.arenas.interfaces, iface_idx);
        }
        Event::InterfaceReset(area_idx, iface_idx) => {
            if let Some((mut instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];
                let iface = &mut arenas.interfaces[iface_idx];

                if !iface.is_down() {
                    iface.reset(area, &mut instance, &mut arenas.neighbors, &arenas.lsa_entries);
                }
            }
        }
        Event::InterfaceResetHelloInterval(area_idx, iface_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];
                let iface = &mut arenas.interfaces[iface_idx];

                if iface.state.tasks.hello_interval.is_some() {
                    iface.hello_interval_start(area, &instance);
                }
            }
        }
        Event::InterfaceResetDeadInterval(area_idx, iface_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];
                let iface = &mut arenas.interfaces[iface_idx];

                // Reset neighbor inactivity timers
                for nbr_idx in iface.state.neighbors.indexes() {
                    let nbr = &mut arenas.neighbors[nbr_idx];

                    if nbr.tasks.inactivity_timer.is_some() {
                        nbr.inactivity_timer_start(iface, area, &instance);
                    }
                }

                // Also reset the interface wait timer if it exists
                if iface.state.tasks.wait_timer.is_some() {
                    let task = tasks::ism_wait_timer(iface, area, &instance);
                    iface.state.tasks.wait_timer = Some(task);
                }
            }
        }
        Event::InterfacePriorityChange(area_idx, iface_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];
                let iface = &arenas.interfaces[iface_idx];

                // Rerun the DR election algorithm if necessary.
                if !iface.is_down() && iface.is_broadcast_or_nbma() {
                    instance.tx.protocol_input.ism_event(area.id, iface.id, ism::Event::NbrChange);
                }
            }
        }
        Event::InterfaceCostChange(area_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];

                instance.tx.protocol_input.lsa_orig_event(LsaOriginateEvent::InterfaceCostChange {
                    area_id: area.id,
                });
            }
        }
        Event::AreaInterfaceTraceOptionsFlagChange(area_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];

                instance.tx.protocol_input.lsa_orig_event(LsaOriginateEvent::InterfaceFlagChange {
                    area_id: area.id,
                });
            }
        }
        Event::InterfaceSyncHelloTx(area_idx, iface_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let area = &arenas.areas[area_idx];
                let iface = &mut arenas.interfaces[iface_idx];

                iface.sync_hello_tx(area, &instance);
            }
        }
        Event::InterfaceUpdateAuth(_area_idx, iface_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let iface = &mut arenas.interfaces[iface_idx];

                // Update interface authentication keys.
                iface.auth_update(&instance);
            }
        }
        Event::InterfaceBfdChange(iface_idx) => {
            if let Some((instance, arenas)) = instance.as_up() {
                let iface = &mut arenas.interfaces[iface_idx];

                for nbr in iface.state.neighbors.iter(&arenas.neighbors).filter(|nbr| nbr.state >= nsm::State::TwoWay) {
                    if iface.config.bfd_enabled {
                        nbr.bfd_register(iface, &instance);
                    } else {
                        nbr.bfd_unregister(iface, &instance);
                    }
                }
            }
        }
        Event::InterfaceUpdateTraceOptions(iface_idx) => {
            let iface = &mut instance.arenas.interfaces[iface_idx];
            iface.config.update_trace_options(&instance.config);
        }
        Event::InterfaceIbusSub(ifname) => {
            if instance.is_active() {
                let af = match (V::PROTOCOL, V::address_family(instance)) {
                    (Protocol::OSPFV3, AddressFamily::Ipv4) => {
                        // OSPFv3 supports both IPv4 and IPv6 but runs over
                        // IPv6 transport. When routing IPv4, both IPv4 and
                        // IPv6 interface addresses are required.
                        None
                    }
                    (_, af) => Some(af),
                };
                instance.tx.ibus.interface_sub(Some(ifname), af);
            }
        }
        Event::StubRouterChange => {
            if let Some((instance, _)) = instance.as_up() {
                // (Re)originate Router-LSAs.
                instance.tx.protocol_input.lsa_orig_event(LsaOriginateEvent::StubRouterChange);
            }
        }
        Event::GrHelperChange => {
            if let Some((mut instance, arenas)) = instance.as_up() {
                // Exit from the helper mode for all neighbors.
                if !instance.config.gr.helper_enabled {
                    gr::helper_process_topology_change(None, &mut instance, arenas);
                }

                // (Re)originate Router Information LSAs.
                instance.tx.protocol_input.lsa_orig_event(LsaOriginateEvent::GrHelperChange);
            }
        }
        Event::SrEnableChange(sr_enabled) => {
            if let Some((instance, arenas)) = instance.as_up() {
                // (Re)originate LSAs that might have been affected.
                instance.tx.protocol_input.lsa_orig_event(LsaOriginateEvent::SrEnableChange);

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
                                sr::adj_sid_del_all(nbr, iface, &instance);
                            }
                        }
                    }
                }
            }
        }
        Event::BierEnableChange(bier_enabled) => {
            if let Some((instance_up, _arenas)) = instance.as_up() {
                // (Re)originate LSAs that might have been affected.
                instance_up.tx.protocol_input.lsa_orig_event(LsaOriginateEvent::BierEnableChange);

                // Purge BIRT if bier disabled or re-install routes if enabled
                if bier_enabled {
                    process_event(instance, Event::ReinstallRoutes);
                } else {
                    instance_up.tx.ibus.bier_purge();
                }
            }
        }
        Event::RerunSpf => {
            if let Some((instance, _)) = instance.as_up() {
                instance.tx.protocol_input.spf_delay_event(spf::fsm::Event::ConfigChange);
            }
        }
        Event::UpdateVirtualLinks => {
            if let Some((instance, arenas)) = instance.as_up() {
                area::update_virtual_links(&instance, &mut arenas.areas, &mut arenas.interfaces, &arenas.lsa_entries);
            }
        }
        Event::UpdateSummaries => {
            if let Some((mut instance, arenas)) = instance.as_up() {
                area::update_summary_lsas(&mut instance, &mut arenas.areas, &arenas.interfaces, &arenas.lsa_entries);
            }
        }
        Event::ReinstallRoutes => {
            if let Some((instance, arenas)) = instance.as_up() {
                for (dest, route) in instance.state.rib.iter().filter(|(_, route)| route.flags.contains(RouteNetFlags::INSTALLED)) {
                    let distance = route.distance(instance.config);
                    ibus::tx::route_install(&instance.tx.ibus, dest, route, None, distance, &arenas.interfaces);
                }
            }
        }
        Event::NodeTagsChange => {
            if let Some((instance, arenas)) = instance.as_up() {
                let _ = V::lsa_orig_event(&instance, arenas, LsaOriginateEvent::NodeTagsChange);
            }
        }
        Event::UpdateTraceOptions => {
            for area_idx in instance.arenas.areas.indexes().collect::<Vec<_>>() {
                let area = &mut instance.arenas.areas[area_idx];
                for iface_idx in area.interfaces.indexes().collect::<Vec<_>>() {
                    let iface = &mut instance.arenas.interfaces[iface_idx];
                    iface.config.update_trace_options(&instance.config);
                }
            }
        }
    }
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
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

impl<V> InterfaceCfg<V>
where
    V: Version,
{
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
        let dbdesc = iface_trace_opts.dbdesc.or(iface_trace_opts.all).or(instance_trace_opts.dbdesc).or(instance_trace_opts.all).unwrap_or(disabled);
        let lsreq = iface_trace_opts.lsreq.or(iface_trace_opts.all).or(instance_trace_opts.lsreq).or(instance_trace_opts.all).unwrap_or(disabled);
        let lsupd = iface_trace_opts.lsupd.or(iface_trace_opts.all).or(instance_trace_opts.lsupd).or(instance_trace_opts.all).unwrap_or(disabled);
        let lsack = iface_trace_opts.lsack.or(iface_trace_opts.all).or(instance_trace_opts.lsack).or(instance_trace_opts.all).unwrap_or(disabled);

        let resolved = Arc::new(TraceOptionPacketResolved {
            hello,
            dbdesc,
            lsreq,
            lsupd,
            lsack,
        });
        self.trace_opts.packets_resolved.store(resolved);
    }
}

impl TraceOptionPacketResolved {
    pub(crate) fn tx(&self, pkt_type: PacketType) -> bool {
        match pkt_type {
            PacketType::Hello => self.hello.tx,
            PacketType::DbDesc => self.dbdesc.tx,
            PacketType::LsRequest => self.lsreq.tx,
            PacketType::LsUpdate => self.lsupd.tx,
            PacketType::LsAck => self.lsack.tx,
        }
    }

    pub(crate) fn rx(&self, pkt_type: PacketType) -> bool {
        match pkt_type {
            PacketType::Hello => self.hello.rx,
            PacketType::DbDesc => self.dbdesc.rx,
            PacketType::LsRequest => self.lsreq.rx,
            PacketType::LsUpdate => self.lsupd.rx,
            PacketType::LsAck => self.lsack.rx,
        }
    }
}

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let enabled = ospf::enabled::DFLT;
        let max_paths = ospf::spf_control::paths::DFLT;
        let spf_initial_delay = ospf::spf_control::ietf_spf_delay::initial_delay::DFLT;
        let spf_short_delay = ospf::spf_control::ietf_spf_delay::short_delay::DFLT;
        let spf_long_delay = ospf::spf_control::ietf_spf_delay::long_delay::DFLT;
        let spf_hold_down = ospf::spf_control::ietf_spf_delay::hold_down::DFLT;
        let spf_time_to_learn = ospf::spf_control::ietf_spf_delay::time_to_learn::DFLT;
        let extended_lsa = ospf::extended_lsa_support::DFLT;
        let sr_enabled = ospf::segment_routing::enabled::DFLT;
        let instance_id = ospf::instance_id::DFLT;

        InstanceCfg {
            af: None,
            enabled,
            router_id: None,
            preference: Default::default(),
            gr: Default::default(),
            max_paths,
            spf_initial_delay,
            spf_short_delay,
            spf_long_delay,
            spf_hold_down,
            spf_time_to_learn,
            stub_router: false,
            node_tags: Default::default(),
            extended_lsa,
            sr_enabled,
            instance_id,
            bier: Default::default(),
            trace_opts: Default::default(),
        }
    }
}

impl Default for BierOspfCfg {
    fn default() -> Self {
        let enabled = ospf::bier::bier::enable::DFLT;
        let advertise = ospf::bier::bier::advertise::DFLT;
        let receive = ospf::bier::bier::receive::DFLT;
        Self {
            mt_id: 0,
            enabled,
            advertise,
            receive,
        }
    }
}

impl Default for Preference {
    fn default() -> Preference {
        let intra_area = ospf::preference::all::DFLT;
        let inter_area = ospf::preference::all::DFLT;
        let external = ospf::preference::all::DFLT;

        Preference {
            intra_area,
            inter_area,
            external,
        }
    }
}

impl Default for InstanceGrCfg {
    fn default() -> InstanceGrCfg {
        let helper_enabled = ospf::graceful_restart::helper_enabled::DFLT;
        let helper_strict_lsa_checking = ospf::graceful_restart::helper_strict_lsa_checking::DFLT;

        InstanceGrCfg {
            helper_enabled,
            helper_strict_lsa_checking,
        }
    }
}

impl Default for AreaCfg {
    fn default() -> AreaCfg {
        let area_type = ospf::areas::area::area_type::DFLT;
        let area_type = AreaType::try_from_yang(area_type).unwrap();
        let summary = ospf::areas::area::summary::DFLT;
        let default_cost = ospf::areas::area::default_cost::DFLT;

        AreaCfg {
            area_type,
            summary,
            default_cost,
        }
    }
}

impl Default for RangeCfg {
    fn default() -> RangeCfg {
        let advertise = ospf::areas::area::ranges::range::advertise::DFLT;

        RangeCfg {
            advertise,
            cost: None,
        }
    }
}

impl Default for ReverseMetricCfg {
    fn default() -> Self {
        let receive = ospf::areas::area::interfaces::interface::reverse_metric::enable_receive::DFLT;
        let metric = None;
        let higher = ospf::areas::area::interfaces::interface::reverse_metric::flags::higher::DFLT;
        let offset = ospf::areas::area::interfaces::interface::reverse_metric::flags::offset::DFLT;
        Self {
            receive,
            metric,
            higher,
            offset,
        }
    }
}

impl<V> Default for InterfaceCfg<V>
where
    V: Version,
{
    fn default() -> InterfaceCfg<V> {
        let instance_id = ospf::instance_id::DFLT;
        let if_type = ospf::areas::area::interfaces::interface::interface_type::DFLT;
        let if_type = InterfaceType::try_from_yang(if_type).unwrap();
        let passive = ospf::areas::area::interfaces::interface::passive::DFLT;
        let priority = ospf::areas::area::interfaces::interface::priority::DFLT;
        let hello_interval = ospf::areas::area::interfaces::interface::hello_interval::DFLT;
        let dead_interval = ospf::areas::area::interfaces::interface::dead_interval::DFLT;
        let retransmit_interval = ospf::areas::area::interfaces::interface::retransmit_interval::DFLT;
        let transmit_delay = ospf::areas::area::interfaces::interface::transmit_delay::DFLT;
        let enabled = ospf::areas::area::interfaces::interface::enabled::DFLT;
        let cost = ospf::areas::area::interfaces::interface::cost::DFLT;
        let mtu_ignore = ospf::areas::area::interfaces::interface::mtu_ignore::DFLT;
        let node_flag = ospf::areas::area::interfaces::interface::node_flag::DFLT;
        let anycast_flag = ospf::areas::area::interfaces::interface::anycast_flag::DFLT;
        let bfd_enabled = ospf::areas::area::interfaces::interface::bfd::enabled::DFLT;
        let lls_enabled = ospf::areas::area::interfaces::interface::lls::DFLT;

        InterfaceCfg {
            instance_id: InheritableConfig::new(instance_id),
            if_type,
            passive,
            priority,
            hello_interval,
            dead_interval,
            retransmit_interval,
            transmit_delay,
            enabled,
            cost,
            mtu_ignore,
            node_flag,
            anycast_flag,
            static_nbrs: Default::default(),
            auth_keychain: None,
            auth_keyid: None,
            auth_key: None,
            auth_algo: None,
            bfd_enabled,
            bfd_params: Default::default(),
            trace_opts: Default::default(),
            lls_enabled,
            reverse_metric: Default::default(),
        }
    }
}

impl Default for StaticNbr {
    fn default() -> StaticNbr {
        let poll_interval = ospf::areas::area::interfaces::interface::static_neighbors::neighbor::poll_interval::DFLT;
        let priority = ospf::areas::area::interfaces::interface::static_neighbors::neighbor::priority::DFLT;

        StaticNbr {
            cost: None,
            poll_interval,
            priority,
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
            dbdesc: disabled,
            lsreq: disabled,
            lsupd: disabled,
            lsack: disabled,
        }
    }
}

impl Default for TraceOptionPacketType {
    fn default() -> TraceOptionPacketType {
        let tx = ospf::trace_options::flag::send::DFLT;
        let rx = ospf::trace_options::flag::receive::DFLT;

        TraceOptionPacketType {
            tx,
            rx,
        }
    }
}

// ===== global functions =====

pub fn validate(config: &DataTree<'static>) -> Result<(), ValidationError> {
    // Ensure no interface is configured in more than one area.
    for dnode in config.iter_path(ospf::areas::PATH) {
        let mut ifnames = HashSet::new();
        for dnode in dnode.iter_path(ospf::areas::area::interfaces::interface::name::PATH) {
            if !ifnames.insert(dnode.get_string()) {
                let message = format!("interface '{}' configured in more than one area", dnode.get_string());
                return Err(ValidationError::new(&dnode, message));
            }
        }
    }

    Ok(())
}
