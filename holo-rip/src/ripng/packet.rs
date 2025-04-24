//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv6Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::{BytesExt, BytesMutExt, TLS_BUF};
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::Ipv6NetworkExt;
use ipnetwork::Ipv6Network;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::{
    AuthCtx, Command, DecodeErrorVersion, PduVersion, RteRouteVersion,
    RteVersion,
};
use crate::route::Metric;

//
// The RIPng packet format is:
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
    #[new(value = "1")]
    pub version: u8,
    pub rtes: Vec<Rte>,
    #[new(default)]
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rte_errors: Vec<DecodeError>,
}

//
// The format for the 20-octet route rte (RTE) for RIPng is:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                        IPv6 prefix (16)                       ~
// |                                                               |
// +---------------------------------------------------------------+
// |         route tag (2)         | prefix len (1)|  metric (1)   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Rte {
    Ipv6(RteIpv6),
    Nexthop(RteNexthop),
}

#[derive(Debug, Deserialize, Eq, new, PartialEq, Serialize)]
pub struct RteIpv6 {
    pub prefix: Ipv6Network,
    pub tag: u16,
    pub metric: Metric,
}

#[derive(Debug, Deserialize, Eq, new, PartialEq, Serialize)]
pub struct RteNexthop {
    pub addr: Option<Ipv6Addr>,
}

// RIP decode errors.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DecodeError {
    InvalidLength(usize),
    InvalidCommand(u8),
    InvalidVersion(u8),
    InvalidRtePrefix(Ipv6Addr),
    InvalidRtePrefixLength(u8),
    InvalidRteNexthop(Ipv6Addr),
    InvalidRteMetric(u8),
}

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

// ===== impl Pdu =====

impl Pdu {
    pub const VERSION: u8 = 1;
    pub const HDR_LENGTH: usize = 4;
    pub const MIN_SIZE: usize = (Self::HDR_LENGTH + Rte::LENGTH);
}

impl PduVersion<Ipv6Addr, Ipv6Network, DecodeError> for Pdu {
    type Rte = Rte;

    fn new(command: Command, rtes: Vec<Self::Rte>) -> Self {
        Pdu::new(command, rtes)
    }

    // NOTE: RIPng supports only IPSec authentication.
    fn encode(&self, _auth: Option<&AuthCtx>) -> BytesMut {
        TLS_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();

            // Encode PDU header.
            buf.put_u8(self.command as u8);
            buf.put_u8(self.version);
            buf.put_u16(0);

            // Encode RTEs.
            for rte in &self.rtes {
                rte.encode(&mut buf);
            }

            buf.clone()
        })
    }

    // NOTE: RIPng supports only IPSec authentication.
    fn decode(
        data: &[u8],
        _auth: Option<&AuthCtx>,
    ) -> Result<Self, DecodeError> {
        let mut buf = Bytes::copy_from_slice(data);

        // Validate the packet length.
        let buf_size = data.len();
        if buf_size < Self::MIN_SIZE {
            return Err(DecodeError::InvalidLength(buf_size));
        }

        // Parse and validate RIP command.
        let command = buf.get_u8();
        let command = Command::from_u8(command)
            .ok_or(DecodeError::InvalidCommand(command))?;

        // Parse and validate RIP version.
        //
        // Different from RIPv2, new versions of RIPng aren't expected to be
        // backward compatible.
        let version = buf.get_u8();
        if version != Self::VERSION {
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

    // RFC 2080 - Section 2.1 says:
    // "The determination of the number of RTEs which may be put into a given
    // message is a function of the medium's MTU, the number of octets of header
    // information preceding the RIPng message, the size of the RIPng header,
    // and the size of an RTE.  The formula is:
    //
    //             +-                                                   -+
    //             | MTU - sizeof(IPv6_hdrs) - UDP_hdrlen - RIPng_hdrlen |
    // #RTEs = INT | --------------------------------------------------- |
    //             |                      RTE_size                       |
    //             +-                                                   -+"
    fn max_entries(mtu: u32, _auth_algo: Option<CryptoAlgo>) -> usize {
        const IPV6_HDR_LENGTH: usize = 40;
        const UDP_HDR_LENGTH: usize = 8;

        (mtu as usize - IPV6_HDR_LENGTH - UDP_HDR_LENGTH - Pdu::HDR_LENGTH)
            / Rte::LENGTH
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

    fn auth_seqno(&self) -> Option<u32> {
        None
    }

    fn new_dump_request() -> Self {
        let rtes = vec![Rte::Ipv6(RteIpv6 {
            prefix: Ipv6Network::new(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
            tag: 0,
            metric: Metric::from(Metric::INFINITE),
        })];
        Pdu::new(Command::Request, rtes)
    }

    // If there is exactly one entry in the request, and it has a destination
    // prefix of zero, a prefix length of zero, and a metric of infinity (i.e.,
    // 16), then this is a request to send the entire routing table.
    fn is_dump_request(&self) -> bool {
        if self.command != Command::Request || self.rtes.len() != 1 {
            return false;
        }

        if let Rte::Ipv6(rte) = &self.rtes[0]
            && rte.prefix.prefix() == 0
            && rte.metric == Metric::from(Metric::INFINITE)
        {
            return true;
        }

        false
    }
}

// ===== impl Rte =====

impl Rte {
    const LENGTH: usize = 20;

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        match self {
            Rte::Ipv6(rte) => rte.encode(buf),
            Rte::Nexthop(rte) => rte.encode(buf),
        }
    }

    pub(crate) fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let addr = buf.get_ipv6();
        let tag = buf.get_u16();
        let plen = buf.get_u8();
        let metric = buf.get_u8();

        // A next hop RTE is identified by a value of 0xFF in the metric field
        // of an RTE. The prefix field specifies the IPv6 address of the next
        // hop. The route tag and prefix length in the next hop RTE must be set
        // to zero on sending and ignored on reception.
        if metric == 0xFF {
            // An address specified as a next hop must be a link-local address.
            if !addr.is_unicast_link_local() {
                return Err(DecodeError::InvalidRteNexthop(addr));
            }

            let addr = if addr.is_unspecified() {
                None
            } else {
                Some(addr)
            };
            return Ok(Rte::Nexthop(RteNexthop { addr }));
        }

        // Sanity checks.
        if addr.is_loopback() || addr.is_multicast() {
            return Err(DecodeError::InvalidRtePrefix(addr));
        }
        if plen > Ipv6Network::MAX_PREFIXLEN {
            return Err(DecodeError::InvalidRtePrefixLength(plen));
        }
        let prefix = Ipv6Network::new(addr, plen)
            .map_err(|_| DecodeError::InvalidRtePrefix(addr))?;
        let metric = Metric::new(metric)
            .map_err(|_| DecodeError::InvalidRteMetric(metric))?;

        Ok(Rte::Ipv6(RteIpv6 {
            prefix,
            tag,
            metric,
        }))
    }
}

impl RteVersion<Ipv6Addr, Ipv6Network> for Rte {
    type Route = RteIpv6;

    fn new_route(
        prefix: Ipv6Network,
        _nexthop: Option<Ipv6Addr>,
        metric: Metric,
        tag: u16,
    ) -> Self {
        Rte::Ipv6(RteIpv6::new(prefix, tag, metric))
    }

    fn as_route(&self) -> Option<&Self::Route> {
        if let Rte::Ipv6(rte) = self {
            Some(rte)
        } else {
            None
        }
    }

    fn as_route_mut(&mut self) -> Option<&mut Self::Route> {
        if let Rte::Ipv6(rte) = self {
            Some(rte)
        } else {
            None
        }
    }

    fn as_nexthop(&self) -> Option<Option<&Ipv6Addr>> {
        if let Rte::Nexthop(rte) = self {
            Some(rte.addr.as_ref())
        } else {
            None
        }
    }
}

// ===== impl RteIpv6 =====

impl RteIpv6 {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_ipv6(&self.prefix.ip());
        buf.put_u16(self.tag);
        buf.put_u8(self.prefix.prefix());
        buf.put_u8(self.metric.get());
    }
}

impl RteRouteVersion<Ipv6Addr, Ipv6Network> for RteIpv6 {
    fn prefix(&self) -> &Ipv6Network {
        &self.prefix
    }

    fn nexthop(&self) -> Option<&Ipv6Addr> {
        None
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

// ===== impl RteNexthop =====

impl RteNexthop {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        if let Some(addr) = &self.addr {
            buf.put_ipv6(addr);
        } else {
            buf.put_u128(0);
        }
        buf.put_u16(0);
        buf.put_u8(0);
        buf.put_u8(0xff);
    }
}

// ===== impl DecodeError =====

impl DecodeErrorVersion for DecodeError {}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::InvalidLength(length) => {
                write!(f, "Invalid Length: {length}")
            }
            DecodeError::InvalidCommand(command) => {
                write!(f, "Invalid RIP command: {command}")
            }
            DecodeError::InvalidVersion(version) => {
                write!(f, "Invalid RIP version: {version}")
            }
            DecodeError::InvalidRtePrefix(addr) => {
                write!(f, "Invalid RTE prefix address: {addr}")
            }
            DecodeError::InvalidRtePrefixLength(plen) => {
                write!(f, "Invalid RTE prefix length: {plen}")
            }
            DecodeError::InvalidRteNexthop(nexthop) => {
                write!(f, "Invalid RTE nexthop: {nexthop}")
            }
            DecodeError::InvalidRteMetric(metric) => {
                write!(f, "Invalid RIP metric: {metric}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}
