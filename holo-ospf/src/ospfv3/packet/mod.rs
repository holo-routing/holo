//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod lsa;

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::atomic;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt, TLS_BUF};
use holo_utils::crypto::CryptoProtocolId;
use holo_utils::ip::{AddressFamily, Ipv4AddrExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::neighbor::NeighborNetId;
use crate::ospfv3::packet::lsa::{LsaHdr, LsaType};
use crate::packet::auth::{AuthDecodeCtx, AuthEncodeCtx, AuthMethod};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::packet::{
    auth, packet_encode_end, packet_encode_start, DbDescFlags, DbDescVersion,
    HelloVersion, LsAckVersion, LsRequestVersion, LsUpdateVersion,
    OptionsVersion, Packet, PacketBase, PacketHdrVersion, PacketType,
    PacketVersion,
};
use crate::version::Ospfv3;

// OSPFv3 Options field.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#ospfv3-parameters-1
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct Options: u16 {
        const V6 = 0x0001;
        const E = 0x0002;
        const N = 0x0008;
        const R = 0x0010;
        const DC = 0x0020;
        const AF = 0x0100;
        const L = 0x0200;
        const AT = 0x0400;
    }
}

// OSPFv3 authentication type.
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum AuthType {
    HmacCryptographic = 0x01,
}

// Length of LLS Data Block header.
pub const LLS_HDR_SIZE: u16 = 4;

// Length of the authentication trailer fixed header.
pub const AUTH_TRAILER_HDR_SIZE: u16 = 16;

//
// OSPFv3 packet header.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Version #   |     Type      |         Packet length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Router ID                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Area ID                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Checksum             |  Instance ID  |      0        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct PacketHdr {
    pub pkt_type: PacketType,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub instance_id: u8,
    // Decoded authentication sequence number.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_seqno: Option<u64>,
}

// OSPFv3 doesn't contain authentication data in its packet header.
#[derive(Debug)]
pub struct PacketHdrAuth;

//
// OSPFv3 Hello packet.
//
// Encoding format (packet body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Interface ID                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Rtr Priority  |             Options                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        HelloInterval          |       RouterDeadInterval      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Designated Router ID                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                Backup Designated Router ID                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Neighbor ID                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        ...                                    |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Hello {
    pub hdr: PacketHdr,
    pub iface_id: u32,
    pub priority: u8,
    pub options: Options,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub dr: Option<NeighborNetId>,
    pub bdr: Option<NeighborNetId>,
    pub neighbors: BTreeSet<Ipv4Addr>,
}

//
// OSPFv3 Database Description packet.
//
// Encoding format (packet body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
// |       0       |               Options                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
// |        Interface MTU          |      0        |0|0|0|0|0|I|M|MS|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
// |                    DD sequence number                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
// |                                                                |
// +-                                                              -+
// |                                                                |
// +-                     An LSA Header                            -+
// |                                                                |
// +-                                                              -+
// |                                                                |
// +-                                                              -+
// |                                                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+
// |                       ...                                      |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct DbDesc {
    pub hdr: PacketHdr,
    pub options: Options,
    pub mtu: u16,
    pub dd_flags: DbDescFlags,
    pub dd_seq_no: u32,
    pub lsa_hdrs: Vec<LsaHdr>,
}

//
// OSPFv3 Link State Request packet.
//
// Encoding format (packet body):
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              0                |        LS Type                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Link State ID                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Advertising Router                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                 ...                           |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsRequest {
    pub hdr: PacketHdr,
    pub entries: Vec<LsaKey<LsaType>>,
}

//
// OSPFv3 Link State Update packet.
//
// Encoding format (packet body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            # LSAs                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                                                            +-+
// |                             LSAs                              |
// +-                                                            +-+
// |                              ...                              |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsUpdate {
    pub hdr: PacketHdr,
    pub lsas: Vec<Lsa<Ospfv3>>,
}

//
// OSPFv3 Link State Acknowledgment packet.
//
// Encoding format (packet body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-                         An LSA Header                       -+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsAck {
    pub hdr: PacketHdr,
    pub lsa_hdrs: Vec<LsaHdr>,
}

// ===== impl Options =====

impl Options {
    pub(crate) fn decode(buf: &mut Bytes) -> Self {
        // Ignore unknown options.
        let _ = buf.get_u8();
        Options::from_bits_truncate(buf.get_u16())
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(0);
        buf.put_u16(self.bits());
    }
}

impl OptionsVersion<Ospfv3> for Options {
    fn e_bit(&self) -> bool {
        self.contains(Options::E)
    }
}

// ===== impl PacketHdr =====

impl PacketHdr {
    pub const VERSION: u8 = 3;
    pub const CHECKSUM_OFFSET: i32 = 12;
}

impl PacketHdrVersion<Ospfv3> for PacketHdr {
    const LENGTH: u16 = 16;

    fn decode(buf: &mut Bytes) -> DecodeResult<(Self, u16, PacketHdrAuth)> {
        // Parse version.
        let version = buf.get_u8();
        if version != Self::VERSION {
            return Err(DecodeError::InvalidVersion(version));
        }

        // Parse packet type.
        let pkt_type = buf.get_u8();
        let pkt_type = match PacketType::from_u8(pkt_type) {
            Some(pkt_type) => pkt_type,
            None => return Err(DecodeError::UnknownPacketType(pkt_type)),
        };

        // Parse and validate message length.
        let pkt_len = buf.get_u16();
        if pkt_len < Self::LENGTH {
            return Err(DecodeError::InvalidLength(pkt_len));
        }

        // Parse Router-ID.
        let router_id = buf.get_ipv4();
        if !router_id.is_usable() {
            return Err(DecodeError::InvalidRouterId(router_id));
        }

        // Parse Area ID.
        let area_id = buf.get_ipv4();

        // Parse checksum (verified separately).
        let _cksum = buf.get_u16();

        // Parse Instance ID.
        let instance_id = buf.get_u8();

        // Parse reserved field.
        let _ = buf.get_u8();

        Ok((
            PacketHdr {
                pkt_type,
                router_id,
                area_id,
                instance_id,
                auth_seqno: None,
            },
            pkt_len,
            PacketHdrAuth {},
        ))
    }

    fn encode(&self, buf: &mut BytesMut, _auth: Option<AuthEncodeCtx<'_>>) {
        buf.put_u8(Self::VERSION);
        buf.put_u8(self.pkt_type as u8);
        // The length will be initialized later.
        buf.put_u16(0);
        buf.put_ipv4(&self.router_id);
        buf.put_ipv4(&self.area_id);
        // The checksum will be computed later.
        buf.put_u16(0);
        buf.put_u8(self.instance_id);
        buf.put_u8(0);
    }

    fn update_cksum(_buf: &mut BytesMut) {
        // Computed separately (e.g. IPV6_CHECKSUM sockoption).
    }

    fn verify_cksum(_data: &[u8]) -> DecodeResult<()> {
        // Verified separately (e.g. IPV6_CHECKSUM sockoption).
        Ok(())
    }

    fn pkt_type(&self) -> PacketType {
        self.pkt_type
    }

    fn router_id(&self) -> Ipv4Addr {
        self.router_id
    }

    fn area_id(&self) -> Ipv4Addr {
        self.area_id
    }

    fn auth_seqno(&self) -> Option<u64> {
        self.auth_seqno
    }

    fn set_auth_seqno(&mut self, seqno: u64) {
        self.auth_seqno = Some(seqno)
    }

    fn generate(
        pkt_type: PacketType,
        router_id: Ipv4Addr,
        area_id: Ipv4Addr,
        instance_id: u8,
    ) -> Self {
        PacketHdr {
            pkt_type,
            router_id,
            area_id,
            instance_id,
            auth_seqno: None,
        }
    }
}

// ===== impl Hello =====

impl Hello {
    pub const BASE_LENGTH: u16 = 20;
}

impl PacketBase<Ospfv3> for Hello {
    fn decode(
        _af: AddressFamily,
        hdr: PacketHdr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        if buf.remaining() < Self::BASE_LENGTH as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }

        let iface_id = buf.get_u32();
        let priority = buf.get_u8();
        let options = Options::decode(buf);
        let hello_interval = buf.get_u16();
        let dead_interval = buf.get_u16();
        let dr = buf.get_opt_ipv4();
        let bdr = buf.get_opt_ipv4();

        // Parse list of neighbors.
        let mut neighbors = BTreeSet::new();
        let nbrs_cnt = buf.remaining() / 4;
        for _ in 0..nbrs_cnt {
            let nbr = buf.get_ipv4();
            neighbors.insert(nbr);
        }

        Ok(Hello {
            hdr,
            iface_id,
            priority,
            options,
            hello_interval,
            dead_interval,
            dr: dr.map(NeighborNetId::from),
            bdr: bdr.map(NeighborNetId::from),
            neighbors,
        })
    }

    fn encode(&self, auth: Option<AuthEncodeCtx<'_>>) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr, auth);

            buf.put_u32(self.iface_id);
            buf.put_u8(self.priority);
            self.options.encode(&mut buf);
            buf.put_u16(self.hello_interval);
            buf.put_u16(self.dead_interval);
            buf.put_ipv4(
                &self
                    .dr
                    .map(|addr| addr.get())
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
            );
            buf.put_ipv4(
                &self
                    .bdr
                    .map(|addr| addr.get())
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
            );
            for nbr in &self.neighbors {
                buf.put_ipv4(nbr);
            }

            packet_encode_end::<Ospfv3>(buf, auth)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl HelloVersion<Ospfv3> for Hello {
    fn iface_id(&self) -> Option<u32> {
        Some(self.iface_id)
    }

    fn hello_interval(&self) -> u16 {
        self.hello_interval
    }

    fn dead_interval(&self) -> u32 {
        self.dead_interval.into()
    }

    fn options(&self) -> Options {
        self.options
    }

    fn priority(&self) -> u8 {
        self.priority
    }

    fn dr(&self) -> Option<NeighborNetId> {
        self.dr
    }

    fn bdr(&self) -> Option<NeighborNetId> {
        self.bdr
    }

    fn neighbors(&self) -> &BTreeSet<Ipv4Addr> {
        &self.neighbors
    }
}

// ===== impl DbDesc =====

impl PacketBase<Ospfv3> for DbDesc {
    fn decode(
        _af: AddressFamily,
        hdr: PacketHdr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        if buf.remaining() < Self::BASE_LENGTH as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }

        let _ = buf.get_u8();
        let options = Options::decode(buf);
        let mtu = buf.get_u16();
        let _ = buf.get_u8();
        let dd_flags = DbDescFlags::from_bits_truncate(buf.get_u8());
        let dd_seq_no = buf.get_u32();

        // Parse list of LSA headers.
        let mut lsa_hdrs = vec![];
        let lsa_hdrs_cnt = buf.remaining() / LsaHdr::LENGTH as usize;
        for _ in 0..lsa_hdrs_cnt {
            let lsa_hdr = LsaHdr::decode(buf)?;
            lsa_hdrs.push(lsa_hdr);
        }

        Ok(DbDesc {
            hdr,
            options,
            mtu,
            dd_flags,
            dd_seq_no,
            lsa_hdrs,
        })
    }

    fn encode(&self, auth: Option<AuthEncodeCtx<'_>>) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr, auth);

            buf.put_u8(0);
            self.options.encode(&mut buf);
            buf.put_u16(self.mtu);
            buf.put_u8(0);
            buf.put_u8(self.dd_flags.bits());
            buf.put_u32(self.dd_seq_no);
            for lsa_hdr in &self.lsa_hdrs {
                lsa_hdr.encode(&mut buf);
            }

            packet_encode_end::<Ospfv3>(buf, auth)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl DbDescVersion<Ospfv3> for DbDesc {
    const BASE_LENGTH: u16 = 12;

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn options(&self) -> Options {
        self.options
    }

    fn dd_flags(&self) -> DbDescFlags {
        self.dd_flags
    }

    fn dd_seq_no(&self) -> u32 {
        self.dd_seq_no
    }

    fn lsa_hdrs(&self) -> &[LsaHdr] {
        &self.lsa_hdrs
    }

    fn generate(
        hdr: PacketHdr,
        options: Options,
        mtu: u16,
        dd_flags: DbDescFlags,
        dd_seq_no: u32,
        lsa_hdrs: Vec<LsaHdr>,
    ) -> Packet<Ospfv3> {
        Packet::DbDesc(DbDesc {
            hdr,
            options,
            mtu,
            dd_flags,
            dd_seq_no,
            lsa_hdrs,
        })
    }
}

// ===== impl LsRequest =====

impl PacketBase<Ospfv3> for LsRequest {
    fn decode(
        _af: AddressFamily,
        hdr: PacketHdr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        // Parse list of LSA global IDs.
        let mut entries = vec![];
        let entries_cnt = buf.remaining() / LsRequest::ENTRY_LENGTH as usize;
        for _ in 0..entries_cnt {
            let _ = buf.get_u16();
            let lsa_type = LsaType(buf.get_u16());
            let lsa_id = buf.get_ipv4();
            let adv_rtr = buf.get_ipv4();
            let entry = LsaKey {
                lsa_type,
                adv_rtr,
                lsa_id,
            };
            entries.push(entry);
        }

        Ok(LsRequest { hdr, entries })
    }

    fn encode(&self, auth: Option<AuthEncodeCtx<'_>>) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr, auth);

            for entry in &self.entries {
                buf.put_u16(0);
                buf.put_u16(entry.lsa_type.0);
                buf.put_ipv4(&entry.lsa_id);
                buf.put_ipv4(&entry.adv_rtr);
            }

            packet_encode_end::<Ospfv3>(buf, auth)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl LsRequestVersion<Ospfv3> for LsRequest {
    const ENTRY_LENGTH: u16 = 12;

    fn entries(&self) -> &[LsaKey<LsaType>] {
        &self.entries
    }

    fn generate(
        hdr: PacketHdr,
        entries: Vec<LsaKey<LsaType>>,
    ) -> Packet<Ospfv3> {
        Packet::LsRequest(LsRequest { hdr, entries })
    }
}

// ===== impl LsUpdate =====

impl LsUpdate {
    pub const BASE_LENGTH: u16 = 4;
}

impl PacketBase<Ospfv3> for LsUpdate {
    fn decode(
        af: AddressFamily,
        hdr: PacketHdr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        if buf.remaining() < Self::BASE_LENGTH as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }

        // Parse list of LSAs.
        let mut lsas = vec![];
        let lsas_cnt = buf.get_u32();
        for _ in 0..lsas_cnt {
            let lsa = Lsa::decode(af, buf)?;
            lsas.push(lsa);
        }

        Ok(LsUpdate { hdr, lsas })
    }

    fn encode(&self, auth: Option<AuthEncodeCtx<'_>>) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr, auth);

            buf.put_u32(self.lsas.len() as u32);
            for lsa in &self.lsas {
                buf.put_slice(&lsa.raw);
            }

            packet_encode_end::<Ospfv3>(buf, auth)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl LsUpdateVersion<Ospfv3> for LsUpdate {
    const BASE_LENGTH: u16 = 4;

    fn into_lsas(self) -> std::vec::IntoIter<Lsa<Ospfv3>> {
        self.lsas.into_iter()
    }

    fn generate(hdr: PacketHdr, lsas: Vec<Lsa<Ospfv3>>) -> Packet<Ospfv3> {
        Packet::LsUpdate(LsUpdate { hdr, lsas })
    }
}

// ===== impl LsAck =====

impl PacketBase<Ospfv3> for LsAck {
    fn decode(
        _af: AddressFamily,
        hdr: PacketHdr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        // Parse list of LSA headers.
        let mut lsa_hdrs = vec![];
        let lsa_hdrs_cnt = buf.remaining() / LsaHdr::LENGTH as usize;
        for _ in 0..lsa_hdrs_cnt {
            let lsa_hdr = LsaHdr::decode(buf)?;
            lsa_hdrs.push(lsa_hdr);
        }

        Ok(LsAck { hdr, lsa_hdrs })
    }

    fn encode(&self, auth: Option<AuthEncodeCtx<'_>>) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr, auth);

            for lsa_hdr in &self.lsa_hdrs {
                lsa_hdr.encode(&mut buf);
            }

            packet_encode_end::<Ospfv3>(buf, auth)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl LsAckVersion<Ospfv3> for LsAck {
    fn lsa_hdrs(&self) -> &[LsaHdr] {
        &self.lsa_hdrs
    }

    fn generate(hdr: PacketHdr, lsa_hdrs: Vec<LsaHdr>) -> Packet<Ospfv3> {
        Packet::LsAck(LsAck { hdr, lsa_hdrs })
    }
}

// ===== impl Ospfv3 =====

impl PacketVersion<Self> for Ospfv3 {
    type PacketOptions = Options;
    type PacketHdr = PacketHdr;
    type PacketHdrAuth = PacketHdrAuth;
    type PacketHello = Hello;
    type PacketDbDesc = DbDesc;
    type PacketLsRequest = LsRequest;
    type PacketLsUpdate = LsUpdate;
    type PacketLsAck = LsAck;

    fn decode_auth_validate(
        data: &[u8],
        pkt_len: u16,
        _hdr_auth: PacketHdrAuth,
        auth: Option<AuthDecodeCtx<'_>>,
    ) -> DecodeResult<Option<u64>> {
        let options = packet_options(data);

        // Check for authentication type mismatch.
        //
        // RFC 7166 states the following:
        // "OSPFv3 packet types that don't include an OSPFv3 Options
        // field will use the setting from the neighbor data structure
        // to determine whether or not the AT is expected".
        //
        // LS Updates, LS Requests, and LS Acks are the packet types
        // that lack the OSPFv3 Options field. As these packets are only
        // transmitted after bidirectional connectivity is confirmed,
        // authentication type mismatches can be ruled out. This avoids
        // the need to give the network RX tasks access to neighbor data
        // structures, which would require the introduction of locking
        // primitives.
        if let Some(options) = options
            && auth.is_some() != options.contains(Options::AT)
        {
            return Err(DecodeError::AuthTypeMismatch);
        }
        if auth.is_none() {
            return Ok(None);
        }

        // Get data after the end of the OSPF packet.
        let mut buf = Bytes::copy_from_slice(&data[pkt_len as usize..]);

        // Ignore optional LLS block (only present in Hello and Database
        // Description packets).
        if let Some(options) = &options
            && options.contains(Options::L)
        {
            if buf.remaining() < LLS_HDR_SIZE as usize {
                return Err(DecodeError::InvalidLength(buf.len() as u16));
            }
            let _lls_cksum = buf.get_u16();
            let lls_block_len = buf.get_u16();
            if buf.remaining() < (lls_block_len * 4 - LLS_HDR_SIZE) as usize {
                return Err(DecodeError::InvalidLength(buf.len() as u16));
            }
            buf.advance(lls_block_len as usize);
        }

        // Decode authentication trailer fixed header.
        if buf.remaining() < AUTH_TRAILER_HDR_SIZE as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }
        let auth_type = buf.get_u16();
        let auth_len = buf.get_u16();
        let _reserved = buf.get_u16();
        let key_id = buf.get_u16();
        let seqno = buf.get_u64();

        // Get authentication key.
        let auth = auth.as_ref().unwrap();
        let auth_key = match auth.method {
            AuthMethod::ManualKey(key) => {
                // Check if the Key ID matches.
                if key.id != key_id as u64 {
                    return Err(DecodeError::AuthKeyIdNotFound(key_id as u32));
                }
                key
            }
            AuthMethod::Keychain(keychain) => keychain
                .key_lookup_accept(key_id as u64)
                .ok_or(DecodeError::AuthKeyIdNotFound(key_id as u32))?,
        };

        // Sanity checks.
        if buf.remaining() < auth_key.algo.digest_size() as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }
        if AuthType::from_u16(auth_type) != Some(AuthType::HmacCryptographic) {
            return Err(DecodeError::UnsupportedAuthType(auth_type));
        }
        if auth_len
            != AUTH_TRAILER_HDR_SIZE + auth_key.algo.digest_size() as u16
        {
            return Err(DecodeError::AuthLenError(auth_len));
        }

        // Compute message digest.
        let rcvd_digest = buf.slice(..auth_key.algo.digest_size() as usize);
        let digest = auth::message_digest(
            &data[..pkt_len as usize + AUTH_TRAILER_HDR_SIZE as usize],
            auth_key.algo,
            &auth_key.string,
            Some(CryptoProtocolId::Ospfv3),
            Some(&auth.src_addr),
        );

        // Check if the received message digest is valid.
        if *rcvd_digest != digest {
            return Err(DecodeError::AuthError);
        }

        // Authentication succeeded.
        Ok(Some(seqno))
    }

    fn encode_auth_trailer(buf: &mut BytesMut, auth: AuthEncodeCtx<'_>) {
        // Append authentication trailer fixed header.
        buf.put_u16(AuthType::HmacCryptographic as u16);
        buf.put_u16(AUTH_TRAILER_HDR_SIZE + auth.key.algo.digest_size() as u16);
        buf.put_u16(0);
        buf.put_u16(auth.key.id as u16);
        // TODO RFC 7166 - Section 4.1.1:
        // "If the lower-order 32-bit value wraps, the higher-order 32-bit value
        // should be incremented and saved in non-volatile storage".
        buf.put_u64(auth.seqno.fetch_add(1, atomic::Ordering::Relaxed));

        // Append message digest.
        let digest = auth::message_digest(
            buf,
            auth.key.algo,
            &auth.key.string,
            Some(CryptoProtocolId::Ospfv3),
            Some(&auth.src_addr),
        );
        buf.put_slice(&digest);
    }
}

// ===== helper functions =====

// Retrieves the Options field from Hello and Database Description packets.
//
// Assumes the packet length has been validated beforehand.
fn packet_options(data: &[u8]) -> Option<Options> {
    let pkt_type = PacketType::from_u8(data[1]).unwrap();
    match pkt_type {
        PacketType::Hello => {
            let options = &data[PacketHdr::LENGTH as usize + 6..];
            let options = (options[0] as u16) << 8 | options[1] as u16;
            Some(Options::from_bits_truncate(options))
        }
        PacketType::DbDesc => {
            let options = &data[PacketHdr::LENGTH as usize + 2..];
            let options = (options[0] as u16) << 8 | options[1] as u16;
            Some(Options::from_bits_truncate(options))
        }
        PacketType::LsRequest | PacketType::LsUpdate | PacketType::LsAck => {
            None
        }
    }
}
