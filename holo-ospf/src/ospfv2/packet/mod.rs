//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod lsa;
pub mod lsa_opaque;

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt, TLS_BUF};
use holo_utils::ip::{AddressFamily, Ipv4AddrExt};
use internet_checksum::Checksum;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::neighbor::NeighborNetId;
use crate::ospfv2::packet::lsa::{LsaHdr, LsaType};
use crate::packet::auth::AuthCtx;
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::packet::{
    auth, packet_encode_end, packet_encode_start, DbDescFlags, DbDescVersion,
    HelloVersion, LsAckVersion, LsRequestVersion, LsUpdateVersion,
    OptionsVersion, Packet, PacketBase, PacketHdrVersion, PacketType,
    PacketVersion,
};
use crate::version::Ospfv2;

// OSPFv2 Options field.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-1
bitflags! {
    #[derive(Default)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct Options: u8 {
        const E = 0x02;
        const MC = 0x04;
        const NP = 0x08;
        const DC = 0x20;
        const O = 0x40;
    }
}

// OSPFv2 authentication type.
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum AuthType {
    Null = 0x00,
    Simple = 0x01,
    Cryptographic = 0x02,
}

//
// OSPFv2 packet header.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Version #   |     Type      |         Packet length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Router ID                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Area ID                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |             AuType            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Authentication                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Authentication                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct PacketHdr {
    pub pkt_type: PacketType,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    // Decoded authentication sequence number.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_seqno: Option<u64>,
}

#[derive(Debug)]
pub enum PacketHdrAuth {
    Null,
    Cryptographic {
        key_id: u8,
        auth_len: u8,
        seqno: u32,
    },
}

//
// OSPFv2 Hello packet.
//
// Encoding format (packet body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Network Mask                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         HelloInterval         |    Options    |    Rtr Pri    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     RouterDeadInterval                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Designated Router                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Backup Designated Router                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Neighbor                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Hello {
    pub hdr: PacketHdr,
    pub network_mask: Ipv4Addr,
    pub hello_interval: u16,
    pub options: Options,
    pub priority: u8,
    pub dead_interval: u32,
    pub dr: Option<NeighborNetId>,
    pub bdr: Option<NeighborNetId>,
    pub neighbors: BTreeSet<Ipv4Addr>,
}

//
// OSPFv2 Database Description packet.
//
// Encoding format (packet body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Interface MTU         |    Options    |0|0|0|0|0|I|M|MS
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     DD sequence number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-                      An LSA Header                          -+
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
pub struct DbDesc {
    pub hdr: PacketHdr,
    pub mtu: u16,
    pub options: Options,
    pub dd_flags: DbDescFlags,
    pub dd_seq_no: u32,
    pub lsa_hdrs: Vec<LsaHdr>,
}

//
// OSPFv2 Link State Request packet.
//
// Encoding format (packet body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          LS type                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Link State ID                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Advertising Router                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsRequest {
    pub hdr: PacketHdr,
    pub entries: Vec<LsaKey<LsaType>>,
}

//
// OSPFv2 Link State Update packet.
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
    pub lsas: Vec<Lsa<Ospfv2>>,
}

//
// OSPFv2 Link State Acknowledgment packet.
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

impl OptionsVersion<Ospfv2> for Options {
    fn e_bit(&self) -> bool {
        self.contains(Options::E)
    }
}

// ===== impl PacketHdr =====

impl PacketHdr {
    pub const VERSION: u8 = 2;
    pub const CKSUM_RANGE: std::ops::Range<usize> = 12..14;
    pub const AUTH_RANGE: std::ops::Range<usize> = 16..24;
}

impl PacketHdrVersion<Ospfv2> for PacketHdr {
    const LENGTH: u16 = 24;

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

        // Parse checksum (already verified).
        let _cksum = buf.get_u16();

        // Parse authentication data.
        let au_type = buf.get_u16();
        let auth = match AuthType::from_u16(au_type) {
            Some(AuthType::Null) => {
                let _ = buf.get_u64();
                PacketHdrAuth::Null
            }
            Some(AuthType::Cryptographic) => {
                let _ = buf.get_u16();
                let key_id = buf.get_u8();
                let auth_len = buf.get_u8();
                let seqno = buf.get_u32();
                PacketHdrAuth::Cryptographic {
                    key_id,
                    auth_len,
                    seqno,
                }
            }
            _ => {
                return Err(DecodeError::UnsupportedAuthType(au_type));
            }
        };

        Ok((
            PacketHdr {
                pkt_type,
                router_id,
                area_id,
                auth_seqno: None,
            },
            pkt_len,
            auth,
        ))
    }

    fn encode(&self, buf: &mut BytesMut, auth: Option<&AuthCtx>) {
        buf.put_u8(Self::VERSION);
        buf.put_u8(self.pkt_type as u8);
        // The length will be initialized later.
        buf.put_u16(0);
        buf.put_ipv4(&self.router_id);
        buf.put_ipv4(&self.area_id);
        // The checksum will be computed later.
        buf.put_u16(0);
        // Authentication.
        match auth {
            Some(auth) => {
                buf.put_u16(AuthType::Cryptographic as u16);
                buf.put_u16(0);
                buf.put_u8(auth.key_id as u8);
                buf.put_u8(auth.algo.digest_size());
                // RFC 5709 does not include provisions for handling sequence
                // number overflows.
                buf.put_u32(
                    auth.seqno.fetch_add(1, atomic::Ordering::Relaxed) as u32
                );
            }
            None => {
                buf.put_u16(AuthType::Null as u16);
                buf.put_u64(0);
            }
        }
    }

    fn update_cksum(buf: &mut BytesMut) {
        let mut cksum = Checksum::new();
        cksum.add_bytes(buf);
        buf[Self::CKSUM_RANGE].copy_from_slice(&cksum.checksum());
    }

    fn verify_cksum(data: &[u8]) -> DecodeResult<()> {
        let mut cksum = Checksum::new();
        cksum.add_bytes(&data[0..Self::AUTH_RANGE.start]);
        cksum.add_bytes(&data[Self::AUTH_RANGE.end..]);
        if cksum.checksum() != [0; 2] {
            return Err(DecodeError::InvalidChecksum);
        }

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
        _instance_id: Option<u8>,
    ) -> Self {
        PacketHdr {
            pkt_type,
            router_id,
            area_id,
            auth_seqno: None,
        }
    }
}

// ===== impl Hello =====

impl Hello {
    pub const BASE_LENGTH: u16 = 20;
}

impl PacketBase<Ospfv2> for Hello {
    fn decode(
        _af: AddressFamily,
        hdr: PacketHdr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        if buf.remaining() < Self::BASE_LENGTH as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }

        let network_mask = buf.get_ipv4();
        let hello_interval = buf.get_u16();
        // Ignore unknown options.
        let options = Options::from_bits_truncate(buf.get_u8());
        let priority = buf.get_u8();
        let dead_interval = buf.get_u32();
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
            network_mask,
            hello_interval,
            options,
            priority,
            dead_interval,
            dr: dr.map(NeighborNetId::from),
            bdr: bdr.map(NeighborNetId::from),
            neighbors,
        })
    }

    fn encode(&self, auth: Option<&AuthCtx>, src: &IpAddr) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv2>(buf, &self.hdr, auth);

            buf.put_ipv4(&self.network_mask);
            buf.put_u16(self.hello_interval);
            buf.put_u8(self.options.bits());
            buf.put_u8(self.priority);
            buf.put_u32(self.dead_interval);
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

            packet_encode_end::<Ospfv2>(buf, auth, src)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl HelloVersion<Ospfv2> for Hello {
    fn iface_id(&self) -> Option<u32> {
        None
    }

    fn hello_interval(&self) -> u16 {
        self.hello_interval
    }

    fn dead_interval(&self) -> u32 {
        self.dead_interval
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

impl PacketBase<Ospfv2> for DbDesc {
    fn decode(
        _af: AddressFamily,
        hdr: PacketHdr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        if buf.remaining() < Self::BASE_LENGTH as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }

        let mtu = buf.get_u16();
        let options = Options::from_bits_truncate(buf.get_u8());
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
            mtu,
            options,
            dd_flags,
            dd_seq_no,
            lsa_hdrs,
        })
    }

    fn encode(&self, auth: Option<&AuthCtx>, src: &IpAddr) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv2>(buf, &self.hdr, auth);

            buf.put_u16(self.mtu);
            buf.put_u8(self.options.bits());
            buf.put_u8(self.dd_flags.bits());
            buf.put_u32(self.dd_seq_no);
            for lsa_hdr in &self.lsa_hdrs {
                lsa_hdr.encode(&mut buf);
            }

            packet_encode_end::<Ospfv2>(buf, auth, src)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl DbDescVersion<Ospfv2> for DbDesc {
    const BASE_LENGTH: u16 = 8;

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
    ) -> Packet<Ospfv2> {
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

impl PacketBase<Ospfv2> for LsRequest {
    fn decode(
        _af: AddressFamily,
        hdr: PacketHdr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        // Parse list of LSA global IDs.
        let mut entries = vec![];
        let entries_cnt = buf.remaining() / LsRequest::ENTRY_LENGTH as usize;
        for _ in 0..entries_cnt {
            let lsa_type = LsaType(buf.get_u32() as u8);
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

    fn encode(&self, auth: Option<&AuthCtx>, src: &IpAddr) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv2>(buf, &self.hdr, auth);

            for entry in &self.entries {
                buf.put_u32(entry.lsa_type.0 as u32);
                buf.put_ipv4(&entry.lsa_id);
                buf.put_ipv4(&entry.adv_rtr);
            }

            packet_encode_end::<Ospfv2>(buf, auth, src)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl LsRequestVersion<Ospfv2> for LsRequest {
    const ENTRY_LENGTH: u16 = 12;

    fn entries(&self) -> &[LsaKey<LsaType>] {
        &self.entries
    }

    fn generate(
        hdr: PacketHdr,
        entries: Vec<LsaKey<LsaType>>,
    ) -> Packet<Ospfv2> {
        Packet::LsRequest(LsRequest { hdr, entries })
    }
}

// ===== impl LsUpdate =====

impl LsUpdate {
    pub const BASE_LENGTH: u16 = 4;
}

impl PacketBase<Ospfv2> for LsUpdate {
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

    fn encode(&self, auth: Option<&AuthCtx>, src: &IpAddr) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv2>(buf, &self.hdr, auth);

            buf.put_u32(self.lsas.len() as u32);
            for lsa in &self.lsas {
                buf.put_slice(&lsa.raw);
            }

            packet_encode_end::<Ospfv2>(buf, auth, src)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl LsUpdateVersion<Ospfv2> for LsUpdate {
    const BASE_LENGTH: u16 = 4;

    fn into_lsas(self) -> std::vec::IntoIter<Lsa<Ospfv2>> {
        self.lsas.into_iter()
    }

    fn generate(hdr: PacketHdr, lsas: Vec<Lsa<Ospfv2>>) -> Packet<Ospfv2> {
        Packet::LsUpdate(LsUpdate { hdr, lsas })
    }
}

// ===== impl LsAck =====

impl PacketBase<Ospfv2> for LsAck {
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

    fn encode(&self, auth: Option<&AuthCtx>, src: &IpAddr) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv2>(buf, &self.hdr, auth);

            for lsa_hdr in &self.lsa_hdrs {
                lsa_hdr.encode(&mut buf);
            }

            packet_encode_end::<Ospfv2>(buf, auth, src)
        })
    }

    fn hdr(&self) -> &PacketHdr {
        &self.hdr
    }
}

impl LsAckVersion<Ospfv2> for LsAck {
    fn lsa_hdrs(&self) -> &[LsaHdr] {
        &self.lsa_hdrs
    }

    fn generate(hdr: PacketHdr, lsa_hdrs: Vec<LsaHdr>) -> Packet<Ospfv2> {
        Packet::LsAck(LsAck { hdr, lsa_hdrs })
    }
}

// ===== impl Ospfv2 =====

impl PacketVersion<Self> for Ospfv2 {
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
        hdr_auth: PacketHdrAuth,
        auth: Option<&AuthCtx>,
        _src: &IpAddr,
    ) -> DecodeResult<Option<u64>> {
        // Discard the packet if its authentication type doesn't match the
        // interface's configured authentication type.
        if auth.is_some()
            != matches!(hdr_auth, PacketHdrAuth::Cryptographic { .. })
        {
            return Err(DecodeError::AuthTypeMismatch);
        }

        match hdr_auth {
            // No authentication.
            PacketHdrAuth::Null => Ok(None),
            // Handle cryptographic authentication.
            PacketHdrAuth::Cryptographic {
                key_id,
                auth_len,
                seqno,
            } => {
                let auth = auth.as_ref().unwrap();

                // Sanity checks.
                if auth.algo.digest_size() != auth_len {
                    return Err(DecodeError::AuthError);
                }

                // Check if the Key ID matches.
                if auth.key_id != key_id as u32 {
                    return Err(DecodeError::AuthKeyIdNotFound(key_id as u32));
                }

                // Get the authentication trailer.
                let auth_trailer = &data
                    [pkt_len as usize..pkt_len as usize + auth_len as usize];

                // Compute message digest.
                let data = &data[..pkt_len as usize];
                let digest = auth::message_digest(
                    data, auth.algo, &auth.key, None, None,
                );

                // Check if the received message digest is valid.
                if *auth_trailer != digest {
                    return Err(DecodeError::AuthError);
                }

                // Authentication succeeded.
                Ok(Some(seqno.into()))
            }
        }
    }

    fn encode_auth_trailer(buf: &mut BytesMut, auth: &AuthCtx, _src: &IpAddr) {
        let digest =
            auth::message_digest(buf, auth.algo, &auth.key, None, None);
        buf.put_slice(&digest);
    }
}
