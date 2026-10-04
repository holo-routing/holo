//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![allow(clippy::derivable_impls)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use holo_northbound::configuration::{ConfigOp, Provider, YangConfigOps};
use holo_northbound::error::ApplyError;
use holo_utils::bgp::AfiSafi;
use holo_utils::ip::{AddressFamily, IpAddrKind};
use holo_utils::policy::ApplyPolicyCfg;
use holo_utils::protocol::Protocol;

use crate::af::{Ipv4Unicast, Ipv6Unicast};
use crate::instance::{Instance, InstanceUpView};
use crate::neighbor::{Neighbor, PeerType, fsm};
use crate::network;
use crate::northbound::yang_gen::bgp;
use crate::northbound::yang_gen::config::{
    self, ConfigChange, GlobalAfiSafiChange, GlobalAfiSafiEntryChange, GlobalAfiSafiIpv4UnicastRedistributionChange, GlobalAfiSafiIpv6UnicastRedistributionChange, GlobalTraceOptionsFlagChange, GlobalTraceOptionsFlagEntryChange,
    NeighborAfiSafiChange, NeighborAfiSafiEntryChange, NeighborChange, NeighborEntryChange, NeighborTraceOptionsFlagChange, NeighborTraceOptionsFlagEntryChange,
};
use crate::packet::iana::{CeaseSubcode, ErrorCode};
use crate::packet::message::{Message, NotificationMsg};
use crate::rib::RouteOrigin;

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
    pub route_reflector: RouteReflectorCfg,
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
pub struct RouteReflectorCfg {
    pub client: bool,
    pub cluster_id: Option<Ipv4Addr>,
}

// Route reflection CLUSTER_ID, configured either as a 4-octet number or in
// dotted-quad notation.
#[derive(Clone, Copy, Debug)]
pub struct ClusterId(pub Ipv4Addr);

#[derive(Debug)]
pub struct AsPathOptions {
    pub allow_own_as: u8,
    pub replace_peer_as: bool,
    pub disable_peer_as_filter: bool,
}

#[derive(Clone, Copy, Debug)]
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

// ===== helper functions =====

fn apply_instance(instance: &mut Instance, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ConfigChange::Global(_op) => {
            // Nothing to do.
        }
        ConfigChange::GlobalAs(asn) => {
            instance.config.asn = asn;
            event_queue.insert(Event::InstanceUpdate);
        }
        ConfigChange::GlobalIdentifier(identifier) => {
            instance.config.identifier = identifier;
            event_queue.insert(Event::InstanceUpdate);
        }
        ConfigChange::GlobalDistanceExternal(distance) => {
            instance.config.distance.external = distance;
        }
        ConfigChange::GlobalDistanceInternal(distance) => {
            instance.config.distance.internal = distance;
        }
        ConfigChange::GlobalUseMultiplePathsEnabled(enabled) => {
            instance.config.multipath.enabled = enabled;
        }
        ConfigChange::GlobalUseMultiplePathsEbgpAllowMultipleAs(allow) => {
            instance.config.multipath.ebgp_allow_multiple_as = allow;
        }
        ConfigChange::GlobalUseMultiplePathsEbgpMaximumPaths(max) => {
            instance.config.multipath.ebgp_max_paths = max;
        }
        ConfigChange::GlobalUseMultiplePathsIbgpMaximumPaths(max) => {
            instance.config.multipath.ibgp_max_paths = max;
        }
        ConfigChange::GlobalRouteSelectionOptionsAlwaysCompareMed(compare) => {
            instance.config.route_selection.always_compare_med = compare;
        }
        ConfigChange::GlobalRouteSelectionOptionsIgnoreAsPathLength(ignore) => {
            instance.config.route_selection.ignore_as_path_length = ignore;
        }
        ConfigChange::GlobalRouteSelectionOptionsExternalCompareRouterId(compare) => {
            instance.config.route_selection.external_compare_router_id = compare;
        }
        ConfigChange::GlobalRouteSelectionOptionsIgnoreNextHopIgpMetric(ignore) => {
            instance.config.route_selection.ignore_next_hop_igp_metric = ignore;
        }
        ConfigChange::GlobalRouteSelectionOptionsEnableMed(enable) => {
            instance.config.route_selection.enable_med = enable;
        }
        ConfigChange::GlobalAfiSafi(keys, change) => {
            apply_afi_safi(instance, keys.name, change, event_queue)?;
        }
        ConfigChange::GlobalApplyPolicyImportPolicy(op, policy) => match op {
            ConfigOp::Create => {
                instance.config.apply_policy.import_policy.insert(policy);
            }
            ConfigOp::Delete => {
                instance.config.apply_policy.import_policy.remove(&policy);
            }
        },
        ConfigChange::GlobalApplyPolicyDefaultImportPolicy(default) => {
            instance.config.apply_policy.default_import_policy = default;
        }
        ConfigChange::GlobalApplyPolicyExportPolicy(op, policy) => match op {
            ConfigOp::Create => {
                instance.config.apply_policy.export_policy.insert(policy);
            }
            ConfigOp::Delete => {
                instance.config.apply_policy.export_policy.remove(&policy);
            }
        },
        ConfigChange::GlobalApplyPolicyDefaultExportPolicy(default) => {
            instance.config.apply_policy.default_export_policy = default;
        }
        ConfigChange::GlobalRejectAsSets(reject) => {
            instance.config.reject_as_sets = reject;
        }
        ConfigChange::GlobalTraceOptionsFlag(keys, change) => {
            apply_trace_options(instance, keys.name, change, event_queue)?;
        }
        ConfigChange::Neighbor(keys, change) => {
            apply_neighbor(instance, keys.remote_address, change, event_queue)?;
        }
    }

    Ok(())
}

fn apply_trace_options(instance: &mut Instance, trace_opt: InstanceTraceOption, change: GlobalTraceOptionsFlagChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let trace_opts = &mut instance.config.trace_opts;
    match change {
        GlobalTraceOptionsFlagChange::Create => match trace_opt {
            InstanceTraceOption::Events => trace_opts.events = true,
            InstanceTraceOption::InternalBus => trace_opts.ibus = true,
            InstanceTraceOption::Nht => trace_opts.nht = true,
            InstanceTraceOption::Route => trace_opts.route = true,
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
        },
        GlobalTraceOptionsFlagChange::Delete => match trace_opt {
            InstanceTraceOption::Events => trace_opts.events = false,
            InstanceTraceOption::InternalBus => trace_opts.ibus = false,
            InstanceTraceOption::Nht => trace_opts.nht = false,
            InstanceTraceOption::Route => trace_opts.route = false,
            InstanceTraceOption::PacketsAll => trace_opts.packets.all = None,
            InstanceTraceOption::PacketsOpen => trace_opts.packets.open = None,
            InstanceTraceOption::PacketsUpdate => trace_opts.packets.update = None,
            InstanceTraceOption::PacketsNotification => trace_opts.packets.notification = None,
            InstanceTraceOption::PacketsKeepalive => trace_opts.packets.keepalive = None,
            InstanceTraceOption::PacketsRefresh => trace_opts.packets.refresh = None,
        },
        GlobalTraceOptionsFlagChange::Entry(change) => {
            let trace_opt_packet = match trace_opt {
                InstanceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InstanceTraceOption::PacketsOpen => trace_opts.packets.open.as_mut(),
                InstanceTraceOption::PacketsUpdate => trace_opts.packets.update.as_mut(),
                InstanceTraceOption::PacketsNotification => trace_opts.packets.notification.as_mut(),
                InstanceTraceOption::PacketsKeepalive => trace_opts.packets.keepalive.as_mut(),
                InstanceTraceOption::PacketsRefresh => trace_opts.packets.refresh.as_mut(),
                _ => None,
            };
            let Some(trace_opt_packet) = trace_opt_packet else {
                return Ok(());
            };
            match change {
                GlobalTraceOptionsFlagEntryChange::Send(enable) => {
                    trace_opt_packet.tx = enable;
                }
                GlobalTraceOptionsFlagEntryChange::Receive(enable) => {
                    trace_opt_packet.rx = enable;
                }
            }
        }
    }
    event_queue.insert(Event::UpdateTraceOptions);

    Ok(())
}

fn apply_afi_safi(instance: &mut Instance, afi_safi: AfiSafi, change: GlobalAfiSafiChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        GlobalAfiSafiChange::Create => {
            instance.config.afi_safi.insert(afi_safi, Default::default());
        }
        GlobalAfiSafiChange::Delete => {
            instance.config.afi_safi.remove(&afi_safi);
        }
        GlobalAfiSafiChange::Entry(change) => {
            let afi_safi_cfg = instance.config.afi_safi.get_mut(&afi_safi).ok_or(ApplyError::EntryNotFound)?;
            match change {
                GlobalAfiSafiEntryChange::Enabled(enabled) => {
                    afi_safi_cfg.enabled = enabled;
                }
                GlobalAfiSafiEntryChange::RouteSelectionOptionsAlwaysCompareMed(compare) => {
                    afi_safi_cfg.route_selection.always_compare_med = compare;
                }
                GlobalAfiSafiEntryChange::RouteSelectionOptionsIgnoreAsPathLength(ignore) => {
                    afi_safi_cfg.route_selection.ignore_as_path_length = ignore;
                }
                GlobalAfiSafiEntryChange::RouteSelectionOptionsExternalCompareRouterId(compare) => {
                    afi_safi_cfg.route_selection.external_compare_router_id = compare;
                }
                GlobalAfiSafiEntryChange::RouteSelectionOptionsIgnoreNextHopIgpMetric(ignore) => {
                    afi_safi_cfg.route_selection.ignore_next_hop_igp_metric = ignore;
                }
                GlobalAfiSafiEntryChange::RouteSelectionOptionsEnableMed(enable) => {
                    afi_safi_cfg.route_selection.enable_med = enable;
                }
                GlobalAfiSafiEntryChange::UseMultiplePathsEnabled(enabled) => {
                    afi_safi_cfg.multipath.enabled = enabled;
                }
                GlobalAfiSafiEntryChange::UseMultiplePathsEbgpAllowMultipleAs(allow) => {
                    afi_safi_cfg.multipath.ebgp_allow_multiple_as = allow;
                }
                GlobalAfiSafiEntryChange::UseMultiplePathsEbgpMaximumPaths(max) => {
                    afi_safi_cfg.multipath.ebgp_max_paths = max;
                }
                GlobalAfiSafiEntryChange::UseMultiplePathsIbgpMaximumPaths(max) => {
                    afi_safi_cfg.multipath.ibgp_max_paths = max;
                }
                GlobalAfiSafiEntryChange::ApplyPolicyImportPolicy(op, policy) => match op {
                    ConfigOp::Create => {
                        afi_safi_cfg.apply_policy.import_policy.insert(policy);
                    }
                    ConfigOp::Delete => {
                        afi_safi_cfg.apply_policy.import_policy.remove(&policy);
                    }
                },
                GlobalAfiSafiEntryChange::ApplyPolicyDefaultImportPolicy(default) => {
                    afi_safi_cfg.apply_policy.default_import_policy = default;
                }
                GlobalAfiSafiEntryChange::ApplyPolicyExportPolicy(op, policy) => match op {
                    ConfigOp::Create => {
                        afi_safi_cfg.apply_policy.export_policy.insert(policy);
                    }
                    ConfigOp::Delete => {
                        afi_safi_cfg.apply_policy.export_policy.remove(&policy);
                    }
                },
                GlobalAfiSafiEntryChange::ApplyPolicyDefaultExportPolicy(default) => {
                    afi_safi_cfg.apply_policy.default_export_policy = default;
                }
                GlobalAfiSafiEntryChange::Ipv4UnicastPrefixLimitMaxPrefixes(max) | GlobalAfiSafiEntryChange::Ipv6UnicastPrefixLimitMaxPrefixes(max) => {
                    afi_safi_cfg.prefix_limit.max_prefixes = max;
                }
                GlobalAfiSafiEntryChange::Ipv4UnicastPrefixLimitWarningThresholdPct(threshold) | GlobalAfiSafiEntryChange::Ipv6UnicastPrefixLimitWarningThresholdPct(threshold) => {
                    afi_safi_cfg.prefix_limit.warning_threshold_pct = threshold;
                }
                GlobalAfiSafiEntryChange::Ipv4UnicastPrefixLimitTeardown(teardown) | GlobalAfiSafiEntryChange::Ipv6UnicastPrefixLimitTeardown(teardown) => {
                    afi_safi_cfg.prefix_limit.teardown = teardown;
                }
                GlobalAfiSafiEntryChange::Ipv4UnicastPrefixLimitIdleTime(idle_time) | GlobalAfiSafiEntryChange::Ipv6UnicastPrefixLimitIdleTime(idle_time) => {
                    afi_safi_cfg.prefix_limit.idle_time = idle_time;
                }
                GlobalAfiSafiEntryChange::Ipv4UnicastSendDefaultRoute(send) | GlobalAfiSafiEntryChange::Ipv6UnicastSendDefaultRoute(send) => {
                    afi_safi_cfg.send_default_route = send;
                }
                GlobalAfiSafiEntryChange::Ipv4UnicastRedistribution(keys, change) => {
                    apply_afi_safi_ipv4_redistribution(afi_safi_cfg, keys.r#type, change, event_queue)?;
                }
                GlobalAfiSafiEntryChange::Ipv6UnicastRedistribution(keys, change) => {
                    apply_afi_safi_ipv6_redistribution(afi_safi_cfg, keys.r#type, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_afi_safi_ipv4_redistribution(afi_safi_cfg: &mut InstanceAfiSafiCfg, protocol: Protocol, change: GlobalAfiSafiIpv4UnicastRedistributionChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        GlobalAfiSafiIpv4UnicastRedistributionChange::Create => {
            afi_safi_cfg.redistribution.insert(protocol, Default::default());
            event_queue.insert(Event::RedistributeIbusSub(protocol, AddressFamily::Ipv4));
        }
        GlobalAfiSafiIpv4UnicastRedistributionChange::Delete => {
            afi_safi_cfg.redistribution.remove(&protocol);
            event_queue.insert(Event::RedistributeDelete(protocol, AddressFamily::Ipv4, AfiSafi::Ipv4Unicast));
        }
    }

    Ok(())
}

fn apply_afi_safi_ipv6_redistribution(afi_safi_cfg: &mut InstanceAfiSafiCfg, protocol: Protocol, change: GlobalAfiSafiIpv6UnicastRedistributionChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        GlobalAfiSafiIpv6UnicastRedistributionChange::Create => {
            afi_safi_cfg.redistribution.insert(protocol, Default::default());
            event_queue.insert(Event::RedistributeIbusSub(protocol, AddressFamily::Ipv6));
        }
        GlobalAfiSafiIpv6UnicastRedistributionChange::Delete => {
            afi_safi_cfg.redistribution.remove(&protocol);
            event_queue.insert(Event::RedistributeDelete(protocol, AddressFamily::Ipv6, AfiSafi::Ipv6Unicast));
        }
    }

    Ok(())
}

fn apply_neighbor(instance: &mut Instance, nbr_addr: IpAddr, change: NeighborChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        NeighborChange::Create => {
            // The mandatory peer-as leaf is applied as a separate change
            // within the same commit, updating the peer type before any
            // event fires.
            let peer_type = PeerType::Internal;
            instance.neighbors.insert(nbr_addr, peer_type);

            event_queue.insert(Event::NeighborUpdate(nbr_addr));
        }
        NeighborChange::Delete => {
            event_queue.insert(Event::NeighborDelete(nbr_addr));
        }
        NeighborChange::Entry(change) => {
            let nbr = instance.neighbors.get_mut(&nbr_addr).ok_or(ApplyError::EntryNotFound)?;
            match change {
                NeighborEntryChange::Enabled(enabled) => {
                    nbr.config.enabled = enabled;
                    event_queue.insert(Event::NeighborUpdate(nbr.remote_addr));
                }
                NeighborEntryChange::PeerAs(peer_as) => {
                    nbr.config.peer_as = peer_as;
                    nbr.peer_type = if instance.config.asn == nbr.config.peer_as { PeerType::Internal } else { PeerType::External };

                    let msg = NotificationMsg::new(ErrorCode::Cease, CeaseSubcode::OtherConfigurationChange);
                    event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
                }
                NeighborEntryChange::LocalAs(local_as) => {
                    nbr.config.local_as = local_as;
                }
                NeighborEntryChange::RemovePrivateAs(private_as_remove) => {
                    nbr.config.private_as_remove = private_as_remove;
                }
                NeighborEntryChange::Description(_description) => {
                    // Nothing to do.
                }
                NeighborEntryChange::TimersConnectRetryInterval(interval) => {
                    nbr.config.timers.connect_retry_interval = interval;
                }
                NeighborEntryChange::TimersHoldTime(holdtime) => {
                    nbr.config.timers.holdtime = holdtime;
                }
                NeighborEntryChange::TimersKeepalive(keepalive) => {
                    nbr.config.timers.keepalive = keepalive;
                }
                NeighborEntryChange::TimersMinAsOriginationInterval(interval) => {
                    nbr.config.timers.min_as_orig_interval = interval;
                }
                NeighborEntryChange::TimersMinRouteAdvertisementInterval(interval) => {
                    nbr.config.timers.min_route_adv_interval = interval;
                }
                NeighborEntryChange::TransportLocalAddress(addr) => {
                    nbr.config.transport.local_addr = addr;

                    let msg = NotificationMsg::new(ErrorCode::Cease, CeaseSubcode::OtherConfigurationChange);
                    event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
                }
                NeighborEntryChange::TransportTcpMss(tcp_mss) => {
                    nbr.config.transport.tcp_mss = tcp_mss;
                }
                NeighborEntryChange::TransportEbgpMultihopEnabled(enabled) => {
                    nbr.config.transport.ebgp_multihop_enabled = enabled;

                    let msg = NotificationMsg::new(ErrorCode::Cease, CeaseSubcode::OtherConfigurationChange);
                    event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
                }
                NeighborEntryChange::TransportEbgpMultihopMultihopTtl(ttl) => {
                    nbr.config.transport.ebgp_multihop_ttl = ttl;

                    let msg = NotificationMsg::new(ErrorCode::Cease, CeaseSubcode::OtherConfigurationChange);
                    event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
                }
                NeighborEntryChange::TransportPassiveMode(passive_mode) => {
                    nbr.config.transport.passive_mode = passive_mode;
                }
                NeighborEntryChange::TransportTtlSecurity(ttl_security) => {
                    nbr.config.transport.ttl_security = Some(ttl_security);

                    let msg = NotificationMsg::new(ErrorCode::Cease, CeaseSubcode::OtherConfigurationChange);
                    event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
                }
                NeighborEntryChange::TransportSecureSessionEnabled(enabled) => {
                    nbr.config.transport.secure_session_enabled = enabled;

                    let msg = NotificationMsg::new(ErrorCode::Cease, CeaseSubcode::OtherConfigurationChange);
                    event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
                    event_queue.insert(Event::NeighborUpdateAuth(nbr.remote_addr));
                }
                NeighborEntryChange::TransportSecureSessionOptionsMd5KeyString(key) => {
                    nbr.config.transport.md5_key = key;

                    let msg = NotificationMsg::new(ErrorCode::Cease, CeaseSubcode::OtherConfigurationChange);
                    event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
                    event_queue.insert(Event::NeighborUpdateAuth(nbr.remote_addr));
                }
                NeighborEntryChange::LoggingOptionsLogNeighborStateChanges(log) => {
                    nbr.config.log_neighbor_state_changes = log;
                }
                NeighborEntryChange::RouteReflectorClusterId(cluster_id) => {
                    nbr.config.route_reflector.cluster_id = cluster_id.map(|cluster_id| cluster_id.0);

                    let msg = NotificationMsg::new(ErrorCode::Cease, CeaseSubcode::OtherConfigurationChange);
                    event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
                }
                NeighborEntryChange::RouteReflectorClient(client) => {
                    nbr.config.route_reflector.client = client;

                    let msg = NotificationMsg::new(ErrorCode::Cease, CeaseSubcode::OtherConfigurationChange);
                    event_queue.insert(Event::NeighborReset(nbr.remote_addr, msg));
                }
                NeighborEntryChange::AsPathOptionsAllowOwnAs(allow) => {
                    nbr.config.as_path_options.allow_own_as = allow;
                }
                NeighborEntryChange::AsPathOptionsReplacePeerAs(replace) => {
                    nbr.config.as_path_options.replace_peer_as = replace;
                }
                NeighborEntryChange::AsPathOptionsDisablePeerAsFilter(disable) => {
                    nbr.config.as_path_options.disable_peer_as_filter = disable;
                }
                NeighborEntryChange::ApplyPolicyImportPolicy(op, policy) => match op {
                    ConfigOp::Create => {
                        nbr.config.apply_policy.import_policy.insert(policy);
                    }
                    ConfigOp::Delete => {
                        nbr.config.apply_policy.import_policy.remove(&policy);
                    }
                },
                NeighborEntryChange::ApplyPolicyDefaultImportPolicy(default) => {
                    nbr.config.apply_policy.default_import_policy = default;
                }
                NeighborEntryChange::ApplyPolicyExportPolicy(op, policy) => match op {
                    ConfigOp::Create => {
                        nbr.config.apply_policy.export_policy.insert(policy);
                    }
                    ConfigOp::Delete => {
                        nbr.config.apply_policy.export_policy.remove(&policy);
                    }
                },
                NeighborEntryChange::ApplyPolicyDefaultExportPolicy(default) => {
                    nbr.config.apply_policy.default_export_policy = default;
                }
                NeighborEntryChange::PrefixLimitMaxPrefixes(max) => {
                    nbr.config.prefix_limit.max_prefixes = max;
                }
                NeighborEntryChange::PrefixLimitWarningThresholdPct(threshold) => {
                    nbr.config.prefix_limit.warning_threshold_pct = threshold;
                }
                NeighborEntryChange::PrefixLimitTeardown(teardown) => {
                    nbr.config.prefix_limit.teardown = teardown;
                }
                NeighborEntryChange::PrefixLimitIdleTime(idle_time) => {
                    nbr.config.prefix_limit.idle_time = idle_time;
                }
                NeighborEntryChange::AfiSafi(keys, change) => {
                    apply_neighbor_afi_safi(nbr, keys.name, change)?;
                }
                NeighborEntryChange::TraceOptionsFlag(keys, change) => {
                    apply_neighbor_trace_options(nbr, keys.name, change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_neighbor_afi_safi(nbr: &mut Neighbor, afi_safi: AfiSafi, change: NeighborAfiSafiChange) -> Result<(), ApplyError> {
    match change {
        NeighborAfiSafiChange::Create => {
            nbr.config.afi_safi.insert(afi_safi, Default::default());
        }
        NeighborAfiSafiChange::Delete => {
            nbr.config.afi_safi.remove(&afi_safi);
        }
        NeighborAfiSafiChange::Entry(change) => {
            let afi_safi_cfg = nbr.config.afi_safi.get_mut(&afi_safi).ok_or(ApplyError::EntryNotFound)?;
            match change {
                NeighborAfiSafiEntryChange::Enabled(enabled) => {
                    afi_safi_cfg.enabled = enabled;
                }
                NeighborAfiSafiEntryChange::ApplyPolicyImportPolicy(op, policy) => match op {
                    ConfigOp::Create => {
                        afi_safi_cfg.apply_policy.import_policy.insert(policy);
                    }
                    ConfigOp::Delete => {
                        afi_safi_cfg.apply_policy.import_policy.remove(&policy);
                    }
                },
                NeighborAfiSafiEntryChange::ApplyPolicyDefaultImportPolicy(default) => {
                    afi_safi_cfg.apply_policy.default_import_policy = default;
                }
                NeighborAfiSafiEntryChange::ApplyPolicyExportPolicy(op, policy) => match op {
                    ConfigOp::Create => {
                        afi_safi_cfg.apply_policy.export_policy.insert(policy);
                    }
                    ConfigOp::Delete => {
                        afi_safi_cfg.apply_policy.export_policy.remove(&policy);
                    }
                },
                NeighborAfiSafiEntryChange::ApplyPolicyDefaultExportPolicy(default) => {
                    afi_safi_cfg.apply_policy.default_export_policy = default;
                }
                NeighborAfiSafiEntryChange::Ipv4UnicastPrefixLimitMaxPrefixes(max) | NeighborAfiSafiEntryChange::Ipv6UnicastPrefixLimitMaxPrefixes(max) => {
                    afi_safi_cfg.prefix_limit.max_prefixes = max;
                }
                NeighborAfiSafiEntryChange::Ipv4UnicastPrefixLimitWarningThresholdPct(threshold) | NeighborAfiSafiEntryChange::Ipv6UnicastPrefixLimitWarningThresholdPct(threshold) => {
                    afi_safi_cfg.prefix_limit.warning_threshold_pct = threshold;
                }
                NeighborAfiSafiEntryChange::Ipv4UnicastPrefixLimitTeardown(teardown) | NeighborAfiSafiEntryChange::Ipv6UnicastPrefixLimitTeardown(teardown) => {
                    afi_safi_cfg.prefix_limit.teardown = teardown;
                }
                NeighborAfiSafiEntryChange::Ipv4UnicastPrefixLimitIdleTime(idle_time) | NeighborAfiSafiEntryChange::Ipv6UnicastPrefixLimitIdleTime(idle_time) => {
                    afi_safi_cfg.prefix_limit.idle_time = idle_time;
                }
                NeighborAfiSafiEntryChange::Ipv4UnicastSendDefaultRoute(send) | NeighborAfiSafiEntryChange::Ipv6UnicastSendDefaultRoute(send) => {
                    afi_safi_cfg.send_default_route = send;
                }
            }
        }
    }

    Ok(())
}

fn apply_neighbor_trace_options(nbr: &mut Neighbor, trace_opt: NeighborTraceOption, change: NeighborTraceOptionsFlagChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let trace_opts = &mut nbr.config.trace_opts;
    match change {
        NeighborTraceOptionsFlagChange::Create => match trace_opt {
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
        },
        NeighborTraceOptionsFlagChange::Delete => match trace_opt {
            NeighborTraceOption::Events => trace_opts.events = None,
            NeighborTraceOption::PacketsAll => trace_opts.packets.all = None,
            NeighborTraceOption::PacketsOpen => trace_opts.packets.open = None,
            NeighborTraceOption::PacketsUpdate => trace_opts.packets.update = None,
            NeighborTraceOption::PacketsNotification => trace_opts.packets.notification = None,
            NeighborTraceOption::PacketsKeepalive => trace_opts.packets.keepalive = None,
            NeighborTraceOption::PacketsRefresh => trace_opts.packets.refresh = None,
        },
        NeighborTraceOptionsFlagChange::Entry(change) => {
            let trace_opt_packet = match trace_opt {
                NeighborTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                NeighborTraceOption::PacketsOpen => trace_opts.packets.open.as_mut(),
                NeighborTraceOption::PacketsUpdate => trace_opts.packets.update.as_mut(),
                NeighborTraceOption::PacketsNotification => trace_opts.packets.notification.as_mut(),
                NeighborTraceOption::PacketsKeepalive => trace_opts.packets.keepalive.as_mut(),
                NeighborTraceOption::PacketsRefresh => trace_opts.packets.refresh.as_mut(),
                _ => None,
            };
            let Some(trace_opt_packet) = trace_opt_packet else {
                return Ok(());
            };
            match change {
                NeighborTraceOptionsFlagEntryChange::Send(enable) => {
                    trace_opt_packet.tx = enable;
                }
                NeighborTraceOptionsFlagEntryChange::Receive(enable) => {
                    trace_opt_packet.rx = enable;
                }
            }
        }
    }
    event_queue.insert(Event::UpdateTraceOptions);

    Ok(())
}

fn process_event(instance: &mut Instance, event: Event) {
    match event {
        Event::InstanceUpdate => instance.update(),
        Event::NeighborUpdate(nbr_addr) => {
            let Some((mut instance, neighbors)) = instance.as_up() else {
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
            let Some((mut instance, neighbors)) = instance.as_up() else {
                return;
            };
            let nbr = neighbors.get_mut(&nbr_addr).unwrap();

            // Unset neighbor's password in the listening sockets.
            for listener in instance.state.listening_sockets.iter().filter(|listener| listener.af == nbr_addr.address_family()) {
                network::listen_socket_md5sig_update(&listener.socket, &nbr_addr, None);
            }

            // Delete neighbor.
            let error_code = ErrorCode::Cease;
            let error_subcode = CeaseSubcode::PeerDeConfigured;
            let msg = NotificationMsg::new(error_code, error_subcode);
            nbr.fsm_event(&mut instance, fsm::Event::Stop(Some(msg)));
            neighbors.remove(&nbr_addr);
        }
        Event::NeighborReset(nbr_addr, msg) => {
            let Some((mut instance, neighbors)) = instance.as_up() else {
                return;
            };
            let nbr = neighbors.get_mut(&nbr_addr).unwrap();

            nbr.fsm_event(&mut instance, fsm::Event::Stop(Some(msg)));
        }
        Event::NeighborUpdateAuth(nbr_addr) => {
            let Some((instance, neighbors)) = instance.as_up() else {
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
            for listener in instance.state.listening_sockets.iter().filter(|listener| listener.af == nbr_addr.address_family()) {
                network::listen_socket_md5sig_update(&listener.socket, &nbr_addr, key.as_deref());
            }
        }
        Event::RedistributeIbusSub(protocol, af) => {
            instance.tx.ibus.route_redistribute_sub(protocol, Some(af));
        }
        Event::RedistributeDelete(protocol, af, afi_safi) => {
            instance.tx.ibus.route_redistribute_unsub(protocol, Some(af));

            if let Some((mut instance, _)) = instance.as_up() {
                match afi_safi {
                    AfiSafi::Ipv4Unicast => {
                        redistribute_delete::<Ipv4Unicast>(&mut instance, protocol);
                    }
                    AfiSafi::Ipv6Unicast => {
                        redistribute_delete::<Ipv6Unicast>(&mut instance, protocol);
                    }
                }
            }
        }
        Event::UpdateTraceOptions => {
            for nbr in instance.neighbors.values_mut() {
                let nbr_trace_opts = &nbr.config.trace_opts;
                let instance_trace_opts = &instance.config.trace_opts;

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

                nbr.config.trace_opts.events_resolved = nbr_trace_opts.events.unwrap_or(instance_trace_opts.events);
                nbr.config.trace_opts.packets_resolved.store(Arc::new(TraceOptionPacketResolved {
                    open,
                    update,
                    notification,
                    keepalive,
                    refresh,
                }));
            }
        }
    }
}

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
        table.queued_prefixes.insert(prefix);
    }

    // Schedule the BGP Decision Process.
    instance.state.schedule_decision_process(instance.tx);
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

        DistanceCfg {
            external,
            internal,
        }
    }
}

impl Default for MultipathCfg {
    fn default() -> MultipathCfg {
        let enabled = bgp::global::use_multiple_paths::enabled::DFLT;
        let ebgp_allow_multiple_as = bgp::global::use_multiple_paths::ebgp::allow_multiple_as::DFLT;
        let ebgp_max_paths = bgp::global::use_multiple_paths::ebgp::maximum_paths::DFLT;
        let ibgp_max_paths = bgp::global::use_multiple_paths::ibgp::maximum_paths::DFLT;

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
        let log_neighbor_state_changes = bgp::neighbors::neighbor::logging_options::log_neighbor_state_changes::DFLT;

        NeighborCfg {
            enabled,
            peer_as: 0,
            local_as: None,
            private_as_remove: None,
            timers: Default::default(),
            transport: Default::default(),
            log_neighbor_state_changes,
            route_reflector: Default::default(),
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
        let connect_retry_interval = bgp::neighbors::neighbor::timers::connect_retry_interval::DFLT;
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
        let ebgp_multihop_enabled = bgp::neighbors::neighbor::transport::ebgp_multihop::enabled::DFLT;
        let passive_mode = bgp::neighbors::neighbor::transport::passive_mode::DFLT;
        let secure_session_enabled = bgp::neighbors::neighbor::transport::secure_session::enabled::DFLT;

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
        let enabled = bgp::neighbors::neighbor::afi_safis::afi_safi::enabled::DFLT;

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

impl Default for RouteReflectorCfg {
    fn default() -> RouteReflectorCfg {
        let client = bgp::neighbors::neighbor::route_reflector::client::DFLT;

        RouteReflectorCfg {
            client,
            cluster_id: None,
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

        TraceOptionPacketType {
            tx,
            rx,
        }
    }
}
