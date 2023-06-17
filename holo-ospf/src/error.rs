//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv4Addr;

use tracing::{error, warn, warn_span};

use crate::collections::{AreaId, InterfaceId, LsaEntryId, NeighborId};
use crate::interface::ism;
use crate::neighbor::nsm;
use crate::network::MulticastAddr;
use crate::packet::error::DecodeError;
use crate::packet::PacketType;
use crate::spf;
use crate::version::Version;

// OSPF errors.
#[derive(Debug)]
pub enum Error<V: Version> {
    // I/O errors
    IoError(IoError),
    // Inter-task communication
    AreaIdNotFound(AreaId),
    InterfaceIdNotFound(InterfaceId),
    NeighborIdNotFound(NeighborId),
    LsaEntryIdNotFound(LsaEntryId),
    // Packet input
    InvalidSrcAddr(V::NetIpAddr),
    InvalidDstAddr(V::NetIpAddr),
    PacketDecodeError(DecodeError),
    UnknownNeighbor(V::NetIpAddr, Ipv4Addr),
    PacketAuthInvalidSeqno(V::NetIpAddr, u32),
    InterfaceCfgError(String, V::NetIpAddr, PacketType, InterfaceCfgError),
    DbDescReject(Ipv4Addr, nsm::State),
    Ospfv2LsaUnknownType(V::LsaType),
    Ospfv3LsaReservedScope(V::LsaType),
    // SPF
    SpfRootNotFound(Ipv4Addr),
    SpfNexthopCalcError(V::VertexId),
    // Segment Routing
    SrgbNotFound(Ipv4Addr, Ipv4Addr),
    InvalidSidIndex(u32),
    // Other
    IsmUnexpectedEvent(ism::State, ism::Event),
    NsmUnexpectedEvent(Ipv4Addr, nsm::State, nsm::Event),
    SpfDelayUnexpectedEvent(spf::fsm::State, spf::fsm::Event),
    InterfaceStartError(String, IoError),
}

// OSPF I/O errors.
#[derive(Debug)]
pub enum IoError {
    SocketError(std::io::Error),
    MulticastJoinError(MulticastAddr, std::io::Error),
    MulticastLeaveError(MulticastAddr, std::io::Error),
    RecvError(std::io::Error),
    RecvMissingSourceAddr,
    RecvMissingAncillaryData,
    SendError(std::io::Error),
}

// OSPF interface configuration errors.
#[derive(Debug)]
pub enum InterfaceCfgError {
    AfBitClear,
    AreaIdMismatch(Ipv4Addr, Ipv4Addr),
    HelloMaskMismatch(Ipv4Addr, Ipv4Addr),
    HelloIntervalMismatch(u16, u16),
    DeadIntervalMismatch(u32, u32),
    ExternalRoutingCapabilityMismatch(bool),
    MtuMismatch(u16),
    DuplicateRouterId(Ipv4Addr),
}

// ===== impl Error =====

impl<V> Error<V>
where
    V: Version,
{
    pub(crate) fn log(&self) {
        match self {
            Error::IoError(error) => {
                error.log();
            }
            Error::AreaIdNotFound(area_id) => {
                warn!(?area_id, "{}", self);
            }
            Error::InterfaceIdNotFound(iface_id) => {
                warn!(?iface_id, "{}", self);
            }
            Error::NeighborIdNotFound(nbr_id) => {
                warn!(?nbr_id, "{}", self);
            }
            Error::LsaEntryIdNotFound(lse_id) => {
                warn!(?lse_id, "{}", self);
            }
            Error::InvalidSrcAddr(addr) => {
                warn!(address = %addr, "{}", self);
            }
            Error::InvalidDstAddr(addr) => {
                warn!(address = %addr, "{}", self);
            }
            Error::PacketDecodeError(error) => {
                warn!(%error, "{}", self);
            }
            Error::UnknownNeighbor(source, router_id) => {
                warn!(%source, %router_id, "{}", self);
            }
            Error::PacketAuthInvalidSeqno(source, seqno) => {
                warn!(%source, %seqno, "{}", self);
            }
            Error::InterfaceCfgError(iface, source, _, error) => {
                warn_span!("interface", name = %iface, %source).in_scope(|| {
                    error.log();
                })
            }
            Error::DbDescReject(router_id, state) => {
                warn_span!("neighbor", %router_id).in_scope(|| {
                    warn!(?state, "{}", self);
                })
            }
            Error::Ospfv2LsaUnknownType(lsa_type)
            | Error::Ospfv3LsaReservedScope(lsa_type) => {
                warn!(%lsa_type, "{}", self);
            }
            Error::SpfRootNotFound(area_id) => {
                warn!(%area_id, "{}", self);
            }
            Error::SpfNexthopCalcError(vertex_id) => {
                warn!(?vertex_id, "{}", self);
            }
            Error::SrgbNotFound(area_id, router_id) => {
                warn!(%area_id, %router_id, "{}", self);
            }
            Error::InvalidSidIndex(sid_index) => {
                warn!(%sid_index, "{}", self);
            }
            Error::IsmUnexpectedEvent(state, event) => warn_span!("fsm")
                .in_scope(|| {
                    warn!(?state, ?event, "{}", self);
                }),
            Error::NsmUnexpectedEvent(router_id, state, event) => {
                warn_span!("neighbor", %router_id).in_scope(|| {
                    warn_span!("fsm").in_scope(|| {
                        warn!(?state, ?event, "{}", self);
                    })
                })
            }
            Error::SpfDelayUnexpectedEvent(state, event) => {
                warn!(?state, ?event, "{}", self);
            }
            Error::InterfaceStartError(name, error) => {
                error!(%name, error = %with_source(error), "{}", self);
            }
        }
    }
}

impl<V> std::fmt::Display for Error<V>
where
    V: Version,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(error) => error.fmt(f),
            Error::AreaIdNotFound(..) => {
                write!(f, "area ID not found")
            }
            Error::InterfaceIdNotFound(..) => {
                write!(f, "interface ID not found")
            }
            Error::NeighborIdNotFound(..) => {
                write!(f, "neighbor ID not found")
            }
            Error::LsaEntryIdNotFound(..) => {
                write!(f, "LSA entry ID not found")
            }
            Error::InvalidSrcAddr(..) => {
                write!(f, "invalid source address")
            }
            Error::InvalidDstAddr(..) => {
                write!(f, "invalid destination address")
            }
            Error::PacketDecodeError(..) => {
                write!(f, "failed to decode packet")
            }
            Error::UnknownNeighbor(..) => {
                write!(f, "unknown neighbor")
            }
            Error::PacketAuthInvalidSeqno(..) => {
                write!(f, "authentication failed: decreasing sequence number")
            }
            Error::InterfaceCfgError(_, _, _, error) => error.fmt(f),
            Error::DbDescReject(..) => {
                write!(f, "database description packet rejected")
            }
            Error::Ospfv2LsaUnknownType(..) => {
                write!(f, "discarding LSA due to unknown type")
            }
            Error::Ospfv3LsaReservedScope(..) => {
                write!(f, "discarding LSA due to reserved scope")
            }
            Error::SpfRootNotFound(..) => {
                write!(f, "SPF root not found")
            }
            Error::SpfNexthopCalcError(..) => {
                write!(f, "failed to calculate nexthop address")
            }
            Error::SrgbNotFound(..) => {
                write!(f, "failed to find nexthop's neighbor SRGB")
            }
            Error::InvalidSidIndex(..) => {
                write!(f, "failed to map SID index to MPLS label")
            }
            Error::IsmUnexpectedEvent(..) => {
                write!(f, "unexpected event")
            }
            Error::NsmUnexpectedEvent(..) => {
                write!(f, "unexpected event")
            }
            Error::SpfDelayUnexpectedEvent(..) => {
                write!(f, "unexpected SPF Delay FSM event")
            }
            Error::InterfaceStartError(..) => {
                write!(f, "failed to start interface")
            }
        }
    }
}

impl<V> std::error::Error for Error<V>
where
    V: Version,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(error) => Some(error),
            Error::InterfaceStartError(_, error) => Some(error),
            _ => None,
        }
    }
}

impl<V> From<IoError> for Error<V>
where
    V: Version,
{
    fn from(error: IoError) -> Error<V> {
        Error::IoError(error)
    }
}

// ===== impl IoError =====

impl IoError {
    pub(crate) fn log(&self) {
        match self {
            IoError::SocketError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
            IoError::MulticastJoinError(addr, error)
            | IoError::MulticastLeaveError(addr, error) => {
                warn!(?addr, error = %with_source(error), "{}", self);
            }
            IoError::RecvError(error) | IoError::SendError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
            IoError::RecvMissingSourceAddr
            | IoError::RecvMissingAncillaryData => {
                warn!("{}", self);
            }
        }
    }
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoError::SocketError(..) => {
                write!(f, "failed to create raw IP socket")
            }
            IoError::MulticastJoinError(..) => {
                write!(f, "failed to join multicast group")
            }
            IoError::MulticastLeaveError(..) => {
                write!(f, "failed to leave multicast group")
            }
            IoError::RecvError(..) => {
                write!(f, "failed to receive IP packet")
            }
            IoError::RecvMissingSourceAddr => {
                write!(
                    f,
                    "failed to retrieve source address from received packet"
                )
            }
            IoError::RecvMissingAncillaryData => {
                write!(
                    f,
                    "failed to retrieve ancillary data from received packet"
                )
            }
            IoError::SendError(..) => {
                write!(f, "failed to send IP packet")
            }
        }
    }
}

impl std::error::Error for IoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IoError::SocketError(error) => Some(error),
            IoError::RecvError(error) | IoError::SendError(error) => {
                Some(error)
            }
            _ => None,
        }
    }
}

// ===== impl InterfaceCfgError =====

impl InterfaceCfgError {
    pub(crate) fn log(&self) {
        match self {
            InterfaceCfgError::AfBitClear => {
                warn!("{}", self);
            }
            InterfaceCfgError::AreaIdMismatch(received, expected) => {
                warn!(%received, %expected, "{}", self);
            }
            InterfaceCfgError::HelloMaskMismatch(received, expected) => {
                warn!(%received, %expected, "{}", self);
            }
            InterfaceCfgError::HelloIntervalMismatch(received, expected) => {
                warn!(%received, %expected, "{}", self);
            }
            InterfaceCfgError::DeadIntervalMismatch(received, expected) => {
                warn!(%received, %expected, "{}", self);
            }
            InterfaceCfgError::ExternalRoutingCapabilityMismatch(e_bit) => {
                warn!(%e_bit, "{}", self);
            }
            InterfaceCfgError::MtuMismatch(mtu) => {
                warn!(%mtu, "{}", self);
            }
            InterfaceCfgError::DuplicateRouterId(router_id) => {
                warn!(%router_id, "{}", self);
            }
        }
    }
}

impl std::fmt::Display for InterfaceCfgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceCfgError::AfBitClear => {
                write!(f, "AF-bit is clear for non-default address family")
            }
            InterfaceCfgError::AreaIdMismatch(..) => {
                write!(f, "area ID mismatch")
            }
            InterfaceCfgError::HelloMaskMismatch(..) => {
                write!(f, "network mask mismatch")
            }
            InterfaceCfgError::HelloIntervalMismatch(..) => {
                write!(f, "hello interval mismatch")
            }
            InterfaceCfgError::DeadIntervalMismatch(..) => {
                write!(f, "dead interval mismatch")
            }
            InterfaceCfgError::ExternalRoutingCapabilityMismatch(..) => {
                write!(f, "external routing capability mismatch")
            }
            InterfaceCfgError::MtuMismatch(..) => {
                write!(f, "MTU mismatch")
            }
            InterfaceCfgError::DuplicateRouterId(..) => {
                write!(f, "duplicate Router ID")
            }
        }
    }
}

impl std::error::Error for InterfaceCfgError {}

// ===== global functions =====

fn with_source<E: std::error::Error>(error: E) -> String {
    if let Some(source) = error.source() {
        format!("{} ({})", error, with_source(source))
    } else {
        error.to_string()
    }
}
