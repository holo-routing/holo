//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;
use std::sync::atomic;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_utils::bytes::{BytesExt, BytesMutExt, TLS_BUF};
use holo_utils::crypto::CryptoAlgo;
use ipnetwork::Ipv4Network;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::{
    AuthCtx, Command, DecodeErrorVersion, PduVersion, RteRouteVersion,
    RteVersion,
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
    // PDU command.
    pub command: Command,
    #[new(value = "2")]
    // PDU version.
    pub version: u8,
    // List of RTEs.
    pub rtes: Vec<Rte>,
    // List of RTEs that failed to be decoded.
    #[new(default)]
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rte_errors: Vec<DecodeError>,
    // Decoded authentication sequence number.
    #[new(default)]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_seqno: Option<u32>,
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
#[derive(Debug, Deserialize, EnumAsInner, Eq, PartialEq, Serialize)]
pub enum Rte {
    Zero(RteZero),
    Ipv4(RteIpv4),
    Auth(RteAuth),
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

//
// The RIP authentication entry format is:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +---------------+---------------+-------------------------------+
// |             0xFFFF            |  Authentication Type=0x0003   |
// +---------------+---------------+---------------+---------------+
// |     RIPv2 Packet Length       |   Key ID      | Auth Data Len |
// +---------------+---------------+---------------+---------------+
// |               Sequence Number (non-decreasing)                |
// +---------------+---------------+---------------+---------------+
// |                      reserved must be zero                    |
// +---------------+---------------+---------------+---------------+
// |                      reserved must be zero                    |
// +---------------+---------------+---------------+---------------+
//
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RteAuth {
    Crypto(RteAuthCrypto),
    Trailer(RteAuthTrailer),
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RteAuthCrypto {
    pub pkt_len: u16,
    pub key_id: u8,
    pub auth_data_len: u8,
    pub seqno: u32,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RteAuthTrailer(pub Bytes);

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
    InvalidRteAuthType(u16),
    AuthTypeMismatch,
    AuthError,
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

    fn encode_auth_header(buf: &mut BytesMut, auth: Option<&AuthCtx>) {
        if let Some(auth) = &auth {
            let auth_hdr = RteAuthCrypto {
                // The packet length field will be rewritten later.
                pkt_len: 0,
                // Use a static key for now.
                key_id: 1,
                auth_data_len: auth.algo.digest_size(),
                seqno: auth.seqno.fetch_add(1, atomic::Ordering::Relaxed),
            };
            auth_hdr.encode(buf);
        }
    }

    fn encode_auth_trailer(buf: &mut BytesMut, auth: Option<&AuthCtx>) {
        if let Some(auth) = auth {
            // Update the RIPv2 Packet Length field.
            let pkt_len = buf.len() as u16;
            buf[8..10].copy_from_slice(&pkt_len.to_be_bytes());

            // Append trailer header.
            buf.put_u16(RteAuth::AFI);
            buf.put_u16(RteAuth::AUTH_TYPE_TRAILER);

            // Append message digest.
            match auth.algo {
                CryptoAlgo::Md5 => {
                    let digest = md5_digest(buf, &auth.key);
                    buf.put_slice(&digest);
                }
                _ => {
                    // Other algorithms can't be configured yet.
                    unreachable!()
                }
            }
        }
    }

    fn decode_auth_validate(
        buf: &Bytes,
        auth: Option<&AuthCtx>,
    ) -> Result<Option<u32>, DecodeError> {
        let mut auth_seqno = None;

        // Decode the first RTE in advance for authentication purposes.
        if let Ok(rte) = Rte::decode(
            &mut buf.slice(Pdu::HDR_LENGTH..Pdu::HDR_LENGTH + Rte::LENGTH),
        ) {
            // Discard the packet if its authentication type doesn't match the
            // interface's configured authentication type.
            if auth.is_some() != matches!(rte, Rte::Auth(RteAuth::Crypto(..))) {
                return Err(DecodeError::AuthTypeMismatch);
            }

            // Handle cryptographic authentication (RFC 4822).
            if let Rte::Auth(RteAuth::Crypto(rte)) = rte {
                let auth = auth.as_ref().unwrap();

                // Validate the "RIPv2 Packet Length" field.
                //
                // Note: to ensure compatibility with legacy RIP
                // implementations, the "Auth Data Len" field is not validated
                // (that field is completely ignored anyway).
                if rte.pkt_len as usize
                    > (buf.len()
                        - RteAuthCrypto::HDR_LENGTH
                        - auth.algo.digest_size() as usize)
                {
                    return Err(DecodeError::AuthError);
                }

                // Get the authentication trailer.
                let auth_trailer =
                    match Rte::decode(&mut buf.slice(rte.pkt_len as usize..)) {
                        Ok(Rte::Auth(RteAuth::Trailer(trailer))) => trailer,
                        _ => return Err(DecodeError::AuthError),
                    };

                // Compute message digest.
                let digest = match auth.algo {
                    CryptoAlgo::Md5 => {
                        let data = buf.slice(
                            ..rte.pkt_len as usize + RteAuthCrypto::HDR_LENGTH,
                        );
                        md5_digest(&data, &auth.key)
                    }
                    _ => {
                        // Other algorithms can't be configured yet.
                        unreachable!()
                    }
                };

                // Check if the received message digest is valid.
                if *auth_trailer.0 != digest {
                    return Err(DecodeError::AuthError);
                }

                // Authentication succeeded.
                auth_seqno = Some(rte.seqno);
            }
        }

        Ok(auth_seqno)
    }
}

impl PduVersion<Ipv4Addr, Ipv4Network, DecodeError> for Pdu {
    type Rte = Rte;

    fn new(command: Command, rtes: Vec<Self::Rte>) -> Self {
        Pdu::new(command, rtes)
    }

    fn encode(&self, auth: Option<&AuthCtx>) -> BytesMut {
        TLS_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();

            // Encode PDU header.
            buf.put_u8(self.command as u8);
            buf.put_u8(self.version);
            buf.put_u16(0);

            // Encode the authentication header if necessary.
            Self::encode_auth_header(&mut buf, auth);

            // Encode RTEs.
            for rte in &self.rtes {
                rte.encode(&mut buf);
            }

            // Encode the authentication trailer if necessary.
            Self::encode_auth_trailer(&mut buf, auth);

            buf.clone()
        })
    }

    fn decode(
        data: &[u8],
        auth: Option<&AuthCtx>,
    ) -> Result<Self, DecodeError> {
        let mut buf = Bytes::copy_from_slice(data);

        // Validate the packet length.
        let buf_size = data.len();
        if !(Self::MIN_SIZE..=Self::MAX_SIZE).contains(&buf_size) {
            return Err(DecodeError::InvalidLength(buf_size));
        }

        // Validate the packet before anything.
        let auth_seqno = Self::decode_auth_validate(&buf, auth)?;

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
                Ok(rte) => {
                    // Ignore authentication RTEs (already processed).
                    if rte.is_auth() {
                        continue;
                    }
                    rtes.push(rte);
                }
                Err(error) => rte_errors.push(error),
            }
        }

        let pdu = Pdu {
            command,
            version,
            rtes,
            rte_errors,
            auth_seqno,
        };

        Ok(pdu)
    }

    fn command(&self) -> Command {
        self.command
    }

    fn set_command(&mut self, command: Command) {
        self.command = command;
    }

    fn max_entries(_mtu: u32, auth_algo: Option<CryptoAlgo>) -> usize {
        let mut max_entries = Self::MAX_ENTRIES;
        if auth_algo.is_some() {
            // Reserve space for the authentication header and trailer.
            max_entries -= 2;
        }
        max_entries
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

    fn auth_seqno(&self) -> Option<u32> {
        self.auth_seqno
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
            Rte::Auth(rte) => rte.encode(buf),
        }
    }

    pub(crate) fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let afi = buf.get_u16();
        let rte = match afi {
            RteZero::AFI => Rte::Zero(RteZero::decode(buf)?),
            RteIpv4::AFI => Rte::Ipv4(RteIpv4::decode(buf)?),
            RteAuth::AFI => Rte::Auth(RteAuth::decode(buf)?),
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
    const AFI: u16 = libc::AF_UNSPEC as u16;

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(Self::AFI);
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
    const AFI: u16 = libc::AF_INET as u16;

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(Self::AFI);
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

// ===== impl RteAuth =====

impl RteAuth {
    const AFI: u16 = 0xFFFF;
    const AUTH_TYPE_TRAILER: u16 = 1;
    const AUTH_TYPE_CRYPTO: u16 = 3;

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        match self {
            RteAuth::Crypto(rte) => rte.encode(buf),
            RteAuth::Trailer(_rte) => unreachable!(),
        }
    }

    pub(crate) fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let auth_type = buf.get_u16();
        let rte = match auth_type {
            Self::AUTH_TYPE_CRYPTO => {
                RteAuth::Crypto(RteAuthCrypto::decode(buf)?)
            }
            Self::AUTH_TYPE_TRAILER => {
                RteAuth::Trailer(RteAuthTrailer(buf.clone()))
            }
            _ => {
                buf.advance(Rte::LENGTH - 4);
                return Err(DecodeError::InvalidRteAuthType(auth_type));
            }
        };

        Ok(rte)
    }
}

// ===== impl RteAuthCrypto =====

impl RteAuthCrypto {
    const HDR_LENGTH: usize = 4;

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(RteAuth::AFI);
        buf.put_u16(RteAuth::AUTH_TYPE_CRYPTO);
        buf.put_u16(self.pkt_len);
        buf.put_u8(self.key_id);
        buf.put_u8(self.auth_data_len);
        buf.put_u32(self.seqno);
        // Reserved bytes.
        buf.put_u32(0);
        // Reserved bytes.
        buf.put_u32(0);
    }

    pub(crate) fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let pkt_len = buf.get_u16();
        let key_id = buf.get_u8();
        let auth_data_len = buf.get_u8();
        let seqno = buf.get_u32();
        // Reserved bytes.
        let _ = buf.get_u32();
        // Reserved bytes.
        let _ = buf.get_u32();

        Ok(RteAuthCrypto {
            pkt_len,
            key_id,
            auth_data_len,
            seqno,
        })
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
            DecodeError::InvalidRteAuthType(auth_type) => {
                write!(f, "Invalid authentication type: {}", auth_type)
            }
            DecodeError::AuthTypeMismatch => {
                write!(f, "Authentication type mismatch")
            }
            DecodeError::AuthError => {
                write!(f, "Authentication failed")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

// ===== helper functions =====

fn md5_digest(data: &[u8], auth_key: &str) -> [u8; 16] {
    // The RIPv2 Authentication Key is always 16 octets when
    // "Keyed-MD5" is in use.
    let mut auth_key = auth_key.as_bytes().to_vec();
    auth_key.resize(16, 0);

    let mut ctx = md5::Context::new();
    ctx.consume(data);
    ctx.consume(&auth_key);
    *ctx.compute()
}
