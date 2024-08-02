//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use ipnetwork::{Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};
use tracing::{debug, debug_span};

use crate::gr::GrExitReason;
use crate::interface::{ism, Interface};
use crate::neighbor::{nsm, NeighborNetId};
use crate::packet::error::LsaValidationError;
use crate::packet::tlv::GrReason;
use crate::packet::Packet;
use crate::spf;
use crate::version::Version;

// OSPF debug messages.
#[derive(Debug)]
pub enum Debug<'a, V: Version> {
    // Instances
    InstanceCreate,
    InstanceDelete,
    InstanceStart,
    InstanceStop(InstanceInactiveReason),
    // Interfaces
    InterfaceCreate(&'a str),
    InterfaceDelete(&'a str),
    InterfaceStart(&'a str),
    InterfaceStop(&'a str, InterfaceInactiveReason),
    InterfacePrimaryAddrSelect(&'a str, &'a Ipv4Network),
    InterfacePrimaryAddrDelete(&'a str),
    InterfaceLinkLocalSelect(&'a str, &'a Ipv6Network),
    InterfaceLinkLocalDelete(&'a str),
    IsmEvent(&'a ism::State, &'a ism::Event),
    IsmTransition(&'a ism::State, &'a ism::State),
    IsmDrElection(
        Option<NeighborNetId>,
        Option<NeighborNetId>,
        Option<NeighborNetId>,
        Option<NeighborNetId>,
    ),
    // Neighbors
    NeighborCreate(Ipv4Addr),
    NeighborDelete(Ipv4Addr),
    NeighborBfdReg(Ipv4Addr),
    NeighborBfdUnreg(Ipv4Addr),
    NsmEvent(Ipv4Addr, &'a nsm::State, &'a nsm::Event),
    NsmTransition(Ipv4Addr, &'a nsm::State, &'a nsm::State),
    // Network
    PacketRx(
        &'a Interface<V>,
        &'a V::NetIpAddr,
        &'a V::NetIpAddr,
        &'a Packet<V>,
    ),
    PacketTx(u32, &'a V::NetIpAddr, &'a Packet<V>),
    PacketRxIgnore(Ipv4Addr, &'a nsm::State),
    // Flooding
    QuestionableAck(Ipv4Addr, &'a V::LsaHdr),
    LsaDiscard(Ipv4Addr, &'a V::LsaHdr, &'a LsaValidationError),
    LsaMinArrivalDiscard(Ipv4Addr, &'a V::LsaHdr),
    LsaSelfOriginated(Ipv4Addr, &'a V::LsaHdr),
    // LSDB maintenance
    LsaInstall(&'a V::LsaHdr),
    LsaOriginate(&'a V::LsaHdr),
    LsaOriginateMinInterval(&'a V::LsaHdr),
    LsaFlush(&'a V::LsaHdr, LsaFlushReason),
    LsaRefresh(&'a V::LsaHdr),
    // SPF
    SpfDelayFsmEvent(&'a spf::fsm::State, &'a spf::fsm::Event),
    SpfDelayFsmTransition(&'a spf::fsm::State, &'a spf::fsm::State),
    SpfNetworkUnreachableAbr(&'a V::IpNetwork, Ipv4Addr),
    SpfRouterUnreachableAbr(&'a Ipv4Addr, Ipv4Addr),
    SpfUnreachableAsbr(&'a V::IpNetwork, Ipv4Addr),
    // Graceful Restart
    GrHelperReject(Ipv4Addr, GrRejectReason),
    GrHelperEnter(Ipv4Addr, GrReason, u32),
    GrHelperExit(Ipv4Addr, GrExitReason),
}

// Reason why an OSPF instance is inactive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceInactiveReason {
    AdminDown,
    MissingRouterId,
    Resetting,
}

// Reason why OSPF is inactive on an interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum InterfaceInactiveReason {
    InstanceDown,
    AdminDown,
    OperationalDown,
    MissingIfindex,
    MissingMtu,
    MissingIpv4Address,
    MissingLinkLocalAddress,
    LoopedBack,
    Resetting,
}

// Reason why a SeqNoMismatch event was generated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum SeqNoMismatchReason {
    InconsistentFlags,
    InconsistentOptions,
    InconsistentSeqNo,
    UnexpectedDbDesc,
    InvalidLsaType,
}

// Reason why an LSA is being flushed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LsaFlushReason {
    Expiry,
    PrematureAging,
}

// Reason why the router failed to enter the helper mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum GrRejectReason {
    NeighborNotFull,
    TopologyChange,
    GracePeriodExpired,
    HelperDisabled,
}

// ===== impl Debug =====

impl<'a, V> Debug<'a, V>
where
    V: Version,
{
    // Log debug message using the tracing API.
    pub(crate) fn log(&self) {
        match self {
            Debug::InstanceCreate
            | Debug::InstanceDelete
            | Debug::InstanceStart => {
                // Parent span(s): ospf-instance
                debug!("{}", self);
            }
            Debug::InstanceStop(reason) => {
                // Parent span(s): ospf-instance
                debug!(%reason, "{}", self);
            }
            Debug::InterfaceCreate(name)
            | Debug::InterfaceDelete(name)
            | Debug::InterfaceStart(name) => {
                // Parent span(s): ospf-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!("{}", self);
                })
            }
            Debug::InterfaceStop(name, reason) => {
                // Parent span(s): ospf-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!(%reason, "{}", self);
                })
            }
            Debug::InterfacePrimaryAddrSelect(name, addr) => {
                // Parent span(s): ospf-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!(%addr, "{}", self);
                })
            }
            Debug::InterfacePrimaryAddrDelete(name) => {
                // Parent span(s): ospf-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!("{}", self);
                })
            }
            Debug::InterfaceLinkLocalSelect(name, addr) => {
                // Parent span(s): ospf-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!(%addr, "{}", self);
                })
            }
            Debug::InterfaceLinkLocalDelete(name) => {
                // Parent span(s): ospf-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!("{}", self);
                })
            }
            Debug::IsmEvent(state, event) => {
                // Parent span(s): ospf-instance
                debug_span!("fsm").in_scope(|| {
                    debug!(?state, ?event, "{}", self);
                })
            }
            Debug::IsmTransition(old_state, new_state) => {
                // Parent span(s): ospf-instance
                debug_span!("fsm").in_scope(|| {
                    debug!(?old_state, ?new_state, "{}", self);
                })
            }
            Debug::IsmDrElection(old_dr, new_dr, old_bdr, new_bdr) => {
                // Parent span(s): ospf-instance
                debug_span!("fsm").in_scope(|| {
                    debug!(?old_dr, ?new_dr, ?old_bdr, ?new_bdr, "{}", self);
                })
            }
            Debug::NeighborCreate(router_id)
            | Debug::NeighborDelete(router_id)
            | Debug::NeighborBfdReg(router_id)
            | Debug::NeighborBfdUnreg(router_id) => {
                // Parent span(s): ospf-instance
                debug_span!("neighbor", %router_id).in_scope(|| {
                    debug!("{}", self);
                })
            }
            Debug::NsmEvent(router_id, state, event) => {
                // Parent span(s): ospf-instance
                debug_span!("neighbor", %router_id).in_scope(|| {
                    debug_span!("fsm").in_scope(|| {
                        debug!(?state, ?event, "{}", self);
                    })
                })
            }
            Debug::NsmTransition(router_id, old_state, new_state) => {
                // Parent span(s): ospf-instance
                debug_span!("neighbor", %router_id).in_scope(|| {
                    debug_span!("fsm").in_scope(|| {
                        debug!(?old_state, ?new_state, "{}", self);
                    })
                })
            }
            Debug::PacketRx(iface, src, dst, packet) => {
                // Parent span(s): ospf-instance
                debug_span!("network").in_scope(|| {
                    debug_span!("input")
                        .in_scope(|| {
                            let data = serde_json::to_string(&packet).unwrap();
                            debug!(interface = %iface.name, %src, %dst, %data, "{}", self);
                        })
                })
            }
            Debug::PacketTx(ifindex, addr, packet) => {
                // Parent span(s): ospf-instance:network:output
                let data = serde_json::to_string(&packet).unwrap();
                debug!(%ifindex, %addr, %data, "{}", self);
            }
            Debug::PacketRxIgnore(router_id, state) => {
                // Parent span(s): ospf-instance
                debug_span!("neighbor", %router_id).in_scope(|| {
                    debug!(?state, "{}", self);
                })
            }
            Debug::QuestionableAck(router_id, lsa_hdr)
            | Debug::LsaMinArrivalDiscard(router_id, lsa_hdr)
            | Debug::LsaSelfOriginated(router_id, lsa_hdr) => {
                // Parent span(s): ospf-instance
                debug_span!("neighbor", %router_id).in_scope(|| {
                    debug!(?lsa_hdr, "{}", self);
                })
            }
            Debug::LsaDiscard(router_id, lsa_hdr, error) => {
                // Parent span(s): ospf-instance
                debug_span!("neighbor", %router_id, %error).in_scope(|| {
                    debug!(?lsa_hdr, "{}", self);
                })
            }
            Debug::LsaInstall(lsa_hdr)
            | Debug::LsaOriginate(lsa_hdr)
            | Debug::LsaOriginateMinInterval(lsa_hdr)
            | Debug::LsaRefresh(lsa_hdr) => {
                // Parent span(s): ospf-instance
                debug!(?lsa_hdr, "{}", self);
            }
            Debug::LsaFlush(lsa_hdr, reason) => {
                // Parent span(s): ospf-instance
                debug!(?lsa_hdr, %reason, "{}", self);
            }

            Debug::SpfDelayFsmEvent(state, event) => {
                // Parent span(s): ospf-instance
                debug!(?state, ?event, "{}", self);
            }
            Debug::SpfDelayFsmTransition(old_state, new_state) => {
                // Parent span(s): ospf-instance
                debug!(?old_state, ?new_state, "{}", self);
            }
            Debug::SpfNetworkUnreachableAbr(destination, abr) => {
                // Parent span(s): ospf-instance
                debug!(%destination, %abr, "{}", self);
            }
            Debug::SpfRouterUnreachableAbr(router_id, abr) => {
                // Parent span(s): ospf-instance
                debug!(%router_id, %abr, "{}", self);
            }
            Debug::SpfUnreachableAsbr(destination, asbr) => {
                // Parent span(s): ospf-instance
                debug!(%destination, %asbr, "{}", self);
            }
            Debug::GrHelperReject(router_id, reason) => {
                // Parent span(s): ospf-instance
                debug_span!("neighbor", %router_id).in_scope(|| {
                    debug!(%reason, "{}", self);
                })
            }
            Debug::GrHelperEnter(router_id, reason, grace_period) => {
                // Parent span(s): ospf-instance
                debug_span!("neighbor", %router_id).in_scope(|| {
                    debug!(%reason, %grace_period, "{}", self);
                })
            }
            Debug::GrHelperExit(router_id, reason) => {
                // Parent span(s): ospf-instance
                debug_span!("neighbor", %router_id).in_scope(|| {
                    debug!(%reason, "{}", self);
                })
            }
        }
    }
}

impl<'a, V> std::fmt::Display for Debug<'a, V>
where
    V: Version,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::InstanceCreate => {
                write!(f, "instance created")
            }
            Debug::InstanceDelete => {
                write!(f, "instance deleted")
            }
            Debug::InstanceStart => {
                write!(f, "starting instance")
            }
            Debug::InstanceStop(..) => {
                write!(f, "stopping instance")
            }
            Debug::InterfaceCreate(..) => {
                write!(f, "interface created")
            }
            Debug::InterfaceDelete(..) => {
                write!(f, "interface deleted")
            }
            Debug::InterfaceStart(..) => {
                write!(f, "starting interface")
            }
            Debug::InterfaceStop(..) => {
                write!(f, "stopping interface")
            }
            Debug::InterfacePrimaryAddrSelect(..) => {
                write!(f, "primary address selected")
            }
            Debug::InterfacePrimaryAddrDelete(..) => {
                write!(f, "primary address deleted")
            }
            Debug::InterfaceLinkLocalSelect(..) => {
                write!(f, "link-local address selected")
            }
            Debug::InterfaceLinkLocalDelete(..) => {
                write!(f, "link-local address deleted")
            }
            Debug::IsmEvent(..) => {
                write!(f, "event")
            }
            Debug::IsmTransition(..) => {
                write!(f, "state transition")
            }
            Debug::IsmDrElection(..) => {
                write!(f, "DR election")
            }
            Debug::NeighborCreate(..) => {
                write!(f, "neighbor created")
            }
            Debug::NeighborDelete(..) => {
                write!(f, "neighbor deleted")
            }
            Debug::NeighborBfdReg(..) => {
                write!(f, "BFD peer registered")
            }
            Debug::NeighborBfdUnreg(..) => {
                write!(f, "BFD peer unregistered")
            }
            Debug::NsmEvent(..) => {
                write!(f, "event")
            }
            Debug::NsmTransition(..) => {
                write!(f, "state transition")
            }
            Debug::PacketRx(..) | Debug::PacketTx(..) => {
                write!(f, "packet")
            }
            Debug::PacketRxIgnore(..) => {
                write!(
                    f,
                    "ignoring packet received from a non-adjacent neighbor"
                )
            }
            Debug::QuestionableAck(..) => {
                write!(f, "received questionable ack")
            }
            Debug::LsaDiscard(..) => {
                write!(f, "discarding LSA")
            }
            Debug::LsaMinArrivalDiscard(..) => {
                write!(f, "discarding LSA due to the MinLSArrival check")
            }
            Debug::LsaSelfOriginated(..) => {
                write!(f, "received self-originated LSA")
            }
            Debug::LsaInstall(..) => {
                write!(f, "installing LSA")
            }
            Debug::LsaOriginate(..) => {
                write!(f, "originating LSA")
            }
            Debug::LsaOriginateMinInterval(..) => {
                write!(
                    f,
                    "postponing LSA origination due to the MinLSInterval check"
                )
            }
            Debug::LsaFlush(..) => {
                write!(f, "flushing LSA")
            }
            Debug::LsaRefresh(..) => {
                write!(f, "refreshing LSA")
            }
            Debug::SpfDelayFsmEvent(..) => {
                write!(f, "SPF Delay FSM event")
            }
            Debug::SpfDelayFsmTransition(..) => {
                write!(f, "SPF Delay FSM state transition")
            }
            Debug::SpfNetworkUnreachableAbr(..)
            | Debug::SpfRouterUnreachableAbr(..) => {
                write!(f, "no route found for originating ABR")
            }
            Debug::SpfUnreachableAsbr(..) => {
                write!(f, "no route found for originating ASBR")
            }
            Debug::GrHelperReject(..) => {
                write!(f, "failed to enter helper mode")
            }
            Debug::GrHelperEnter(..) => {
                write!(f, "entering helper mode")
            }
            Debug::GrHelperExit(..) => {
                write!(f, "exiting from helper mode")
            }
        }
    }
}

// ===== impl InstanceInactiveReason =====

impl std::fmt::Display for InstanceInactiveReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstanceInactiveReason::AdminDown => {
                write!(f, "administrative status down")
            }
            InstanceInactiveReason::MissingRouterId => {
                write!(f, "missing router-id")
            }
            InstanceInactiveReason::Resetting => {
                write!(f, "resetting")
            }
        }
    }
}

// ===== impl InterfaceInactiveReason =====

impl std::fmt::Display for InterfaceInactiveReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceInactiveReason::InstanceDown => {
                write!(f, "OSPF instance down")
            }
            InterfaceInactiveReason::AdminDown => {
                write!(f, "administrative status down")
            }
            InterfaceInactiveReason::OperationalDown => {
                write!(f, "operational status down")
            }
            InterfaceInactiveReason::MissingIfindex => {
                write!(f, "missing ifindex")
            }
            InterfaceInactiveReason::MissingMtu => {
                write!(f, "missing MTU")
            }
            InterfaceInactiveReason::MissingIpv4Address => {
                write!(f, "missing IPv4 address")
            }
            InterfaceInactiveReason::MissingLinkLocalAddress => {
                write!(f, "missing link local IPv6 address")
            }
            InterfaceInactiveReason::LoopedBack => {
                write!(f, "missing IP address")
            }
            InterfaceInactiveReason::Resetting => {
                write!(f, "resetting")
            }
        }
    }
}

// ===== impl SeqNoMismatchReason =====

impl std::fmt::Display for SeqNoMismatchReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeqNoMismatchReason::InconsistentFlags => {
                write!(f, "inconsistent flags")
            }
            SeqNoMismatchReason::InconsistentOptions => {
                write!(f, "inconsistent options")
            }
            SeqNoMismatchReason::InconsistentSeqNo => {
                write!(f, "inconsistent sequence number")
            }
            SeqNoMismatchReason::UnexpectedDbDesc => {
                write!(f, "unexpected database description packet")
            }
            SeqNoMismatchReason::InvalidLsaType => {
                write!(f, "invalid LSA type")
            }
        }
    }
}

// ===== impl LsaFlushReason =====

impl std::fmt::Display for LsaFlushReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsaFlushReason::Expiry => {
                write!(f, "LSA reached MaxAge")
            }
            LsaFlushReason::PrematureAging => {
                write!(f, "premature aging")
            }
        }
    }
}

// ===== impl GrRejectReason =====

impl std::fmt::Display for GrRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrRejectReason::NeighborNotFull => {
                write!(f, "neighbor is not fully adjacent")
            }
            GrRejectReason::TopologyChange => {
                write!(
                    f,
                    "Network topology has changed since the router restarted"
                )
            }
            GrRejectReason::GracePeriodExpired => {
                write!(f, "grace period has already expired")
            }
            GrRejectReason::HelperDisabled => {
                write!(f, "graceful restart helper mode is disabled")
            }
        }
    }
}
