//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use ipnetwork::Ipv4Network;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::{
    Command, DecodeErrorVersion, PduVersion, RteRouteVersion, RteVersion,
};
use crate::route::Metric;

//
// The RIP packet format is:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  command (1)  |  version (1)  |       must be zero (2)        |
// +---------------+---------------+-------------------------------+
// |                                                               |
// ~                         RIP Entry (20)                        ~
// |                                                               |
// +---------------+---------------+---------------+---------------+
//
#[derive(Debug, Deserialize, Eq, new, PartialEq, Serialize)]
pub struct Pdu {
    pub command: Command,
    #[new(value = "2")]
    pub version: u8,
    pub rtes: Vec<Rte>,
    #[new(default)]
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rte_errors: Vec<DecodeError>,
}

//
// The format for the 20-octet route rte (RTE) for RIP-2 is:
//
//  0                   1                   2                   3 3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Address Family Identifier (2) |        Route Tag (2)          |
// +-------------------------------+-------------------------------+
// |                         IP Address (4)                        |
// +---------------------------------------------------------------+
// |                         Subnet Mask (4)                       |
// +---------------------------------------------------------------+
// |                         Next Hop (4)                          |
// +---------------------------------------------------------------+
// |                         Metric (4)                            |
// +---------------------------------------------------------------+
//
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Rte {
    Zero(RteZero),
    Ipv4(RteIpv4),
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RteZero {
    pub metric: Metric,
}

#[derive(Debug, Deserialize, Eq, new, PartialEq, Serialize)]
pub struct RteIpv4 {
    pub tag: u16,
    pub prefix: Ipv4Network,
    pub nexthop: Option<Ipv4Addr>,
    pub metric: Metric,
}

// RIP decode errors.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DecodeError {
    InvalidLength(usize),
    InvalidCommand(u8),
    InvalidVersion(u8),
    InvalidRteAddressFamily(u16),
    InvalidRtePrefix(Ipv4Addr, Ipv4Addr),
    InvalidRteNexthop(Ipv4Addr),
    InvalidRteMetric(u32),
}

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

// ===== impl Pdu =====

impl Pdu {
    pub const VERSION: u8 = 2;
    pub const HDR_LENGTH: usize = 4;
    pub const MAX_ENTRIES: usize = 25;
    pub const MIN_SIZE: usize = (Self::HDR_LENGTH + Rte::LENGTH);
    pub const MAX_SIZE: usize =
        (Self::HDR_LENGTH + Self::MAX_ENTRIES * Rte::LENGTH);
}

impl PduVersion<Ipv4Addr, Ipv4Network, DecodeError> for Pdu {
    type Rte = Rte;

    fn new(command: Command, rtes: Vec<Self::Rte>) -> Self {
        Pdu::new(command, rtes)
    }

    fn encode(&self) -> BytesMut {
        // Calculate PDU length.
        let size = Self::HDR_LENGTH + self.rtes.len() * Rte::LENGTH;

        // Pre-allocate buffer to hold the entire PDU.
        let mut buf = BytesMut::with_capacity(size);

        // Encode PDU header.
        buf.put_u8(self.command as u8);
        buf.put_u8(self.version);
        buf.put_u16(0);

        // Encode RTEs.
        for rte in &self.rtes {
            rte.encode(&mut buf);
        }

        buf
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut buf = Bytes::copy_from_slice(data);

        // Validate the packet length.
        let buf_size = data.len();
        if !(Self::MIN_SIZE..=Self::MAX_SIZE).contains(&buf_size) {
            return Err(DecodeError::InvalidLength(buf_size));
        }

        // Parse and validate RIP command.
        let command = buf.get_u8();
        let command = Command::from_u8(command)
            .ok_or(DecodeError::InvalidCommand(command))?;

        // Parse and validate RIP version.
        //
        // RFC 2453 specifies that new versions of RIPv2 should be backward
        // compatible.
        let version = buf.get_u8();
        if version < Self::VERSION {
            return Err(DecodeError::InvalidVersion(version));
        }

        // Ignore MBZ.
        let _ = buf.get_u16();

        // Decode RIP RTEs.
        let mut rtes = vec![];
        let mut rte_errors = vec![];
        while buf.remaining() >= Rte::LENGTH {
            match Rte::decode(&mut buf) {
                Ok(rte) => rtes.push(rte),
                Err(error) => rte_errors.push(error),
            }
        }

        let pdu = Pdu {
            command,
            version,
            rtes,
            rte_errors,
        };

        Ok(pdu)
    }

    fn command(&self) -> Command {
        self.command
    }

    fn set_command(&mut self, command: Command) {
        self.command = command;
    }

    fn max_entries(_mtu: u32) -> usize {
        Self::MAX_ENTRIES
    }

    fn rtes(&self) -> &Vec<Self::Rte> {
        &self.rtes
    }

    fn rtes_mut(&mut self) -> &mut Vec<Self::Rte> {
        &mut self.rtes
    }

    fn rte_errors(&mut self) -> Vec<DecodeError> {
        std::mem::take(&mut self.rte_errors)
    }

    fn new_dump_request() -> Self {
        let rtes = vec![Rte::Zero(RteZero {
            metric: Metric::from(Metric::INFINITE),
        })];
        Pdu::new(Command::Request, rtes)
    }

    // If there is exactly one entry in the request, and it has an address
    // family identifier of zero and a metric of infinity (i.e., 16), then this
    // is a request to send the entire routing table.
    fn is_dump_request(&self) -> bool {
        self.command == Command::Request
            && self.rtes.len() == 1
            && self.rtes[0]
                == Rte::Zero(RteZero {
                    metric: Metric::from(Metric::INFINITE),
                })
    }
}

// ===== impl Rte =====

impl Rte {
    const LENGTH: usize = 20;

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        match self {
            Rte::Zero(rte) => rte.encode(buf),
            Rte::Ipv4(rte) => rte.encode(buf),
        }
    }

    pub(crate) fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let afi = buf.get_u16();
        let rte = match afi as i32 {
            libc::AF_UNSPEC => Rte::Zero(RteZero::decode(buf)?),
            libc::AF_INET => Rte::Ipv4(RteIpv4::decode(buf)?),
            _ => {
                buf.advance(Rte::LENGTH - 2);
                return Err(DecodeError::InvalidRteAddressFamily(afi));
            }
        };

        Ok(rte)
    }
}

impl RteVersion<Ipv4Addr, Ipv4Network> for Rte {
    type Route = RteIpv4;

    fn new_route(
        prefix: Ipv4Network,
        nexthop: Option<Ipv4Addr>,
        metric: Metric,
        tag: u16,
    ) -> Self {
        Rte::Ipv4(RteIpv4::new(tag, prefix, nexthop, metric))
    }

    fn as_route(&self) -> Option<&Self::Route> {
        if let Rte::Ipv4(rte) = self {
            Some(rte)
        } else {
            None
        }
    }

    fn as_route_mut(&mut self) -> Option<&mut Self::Route> {
        if let Rte::Ipv4(rte) = self {
            Some(rte)
        } else {
            None
        }
    }

    fn as_nexthop(&self) -> Option<Option<&Ipv4Addr>> {
        None
    }
}

// ===== impl RteZero =====

impl RteZero {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(libc::AF_UNSPEC as u16);
        buf.put_u16(0);
        buf.put_u32(0);
        buf.put_u32(0);
        buf.put_u32(0);
        buf.put_u32(self.metric.get().into());
    }

    pub(crate) fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let _tag = buf.get_u16();
        let _prefix_addr = buf.get_ipv4();
        let _prefix_mask = buf.get_ipv4();
        let _nexthop = buf.get_ipv4();
        let metric = buf.get_u32();

        // Sanity checks.
        let metric = Metric::new(metric)
            .map_err(|_| DecodeError::InvalidRteMetric(metric))?;

        Ok(RteZero { metric })
    }
}

// ===== impl RteIpv4 =====

impl RteIpv4 {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(libc::AF_INET as u16);
        buf.put_u16(self.tag);
        buf.put_ipv4(&self.prefix.ip());
        buf.put_ipv4(&self.prefix.mask());
        if let Some(nexthop) = &self.nexthop {
            buf.put_ipv4(nexthop);
        } else {
            buf.put_u32(0);
        }
        buf.put_u32(self.metric.get().into());
    }

    pub(crate) fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let tag = buf.get_u16();
        let addr = buf.get_ipv4();
        let mask = buf.get_ipv4();
        let nexthop = buf.get_ipv4();
        let metric = buf.get_u32();

        // Validate addr/mask.
        if addr.is_loopback() || addr.is_broadcast() || addr.is_multicast() {
            return Err(DecodeError::InvalidRtePrefix(addr, mask));
        }
        let prefix = Ipv4Network::with_netmask(addr, mask)
            .map_err(|_| DecodeError::InvalidRtePrefix(addr, mask))?;

        // Validate nexthop.
        let nexthop = if nexthop.is_unspecified() {
            None
        } else {
            if nexthop.is_loopback() || nexthop.is_multicast() {
                return Err(DecodeError::InvalidRteNexthop(nexthop));
            }
            Some(nexthop)
        };

        // Validate metric.
        let metric = Metric::new(metric)
            .map_err(|_| DecodeError::InvalidRteMetric(metric))?;

        Ok(RteIpv4 {
            tag,
            prefix,
            nexthop,
            metric,
        })
    }
}

impl RteRouteVersion<Ipv4Addr, Ipv4Network> for RteIpv4 {
    fn prefix(&self) -> &Ipv4Network {
        &self.prefix
    }

    fn nexthop(&self) -> Option<&Ipv4Addr> {
        self.nexthop.as_ref()
    }

    fn metric(&self) -> Metric {
        self.metric
    }

    fn set_metric(&mut self, metric: Metric) {
        self.metric = metric;
    }

    fn tag(&self) -> u16 {
        self.tag
    }
}

// ===== impl DecodeError =====

impl DecodeErrorVersion for DecodeError {}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::InvalidLength(length) => {
                write!(f, "Invalid Length: {}", length)
            }
            DecodeError::InvalidCommand(command) => {
                write!(f, "Invalid RIP command: {}", command)
            }
            DecodeError::InvalidVersion(version) => {
                write!(f, "Invalid RIP version: {}", version)
            }
            DecodeError::InvalidRteAddressFamily(afi) => {
                write!(f, "Invalid RIP address-family: {}", afi)
            }
            DecodeError::InvalidRtePrefix(addr, mask) => {
                write!(f, "Invalid RTE prefix: {} mask {}", addr, mask)
            }
            DecodeError::InvalidRteNexthop(nexthop) => {
                write!(f, "Invalid RTE nexthop: {}", nexthop)
            }
            DecodeError::InvalidRteMetric(metric) => {
                write!(f, "Invalid RIP metric: {}", metric)
            }
        }
    }
}

impl std::error::Error for DecodeError {}
