//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod lsa;

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt, TLS_BUF};
use holo_utils::ip::{AddressFamily, Ipv4AddrExt};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::neighbor::NeighborNetId;
use crate::ospfv3::packet::lsa::{LsaHdr, LsaType};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::packet::{
    packet_encode_end, packet_encode_start, DbDescFlags, DbDescVersion,
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
    #[derive(Default)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct Options: u16 {
        const V6 = 0x0001;
        const E = 0x0002;
        const N = 0x0008;
        const R = 0x0010;
        const DC = 0x0020;
        const AF = 0x0100;
    }
}

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
}

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

    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
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

        // Ensure the length field matches the number of received bytes.
        if pkt_len != Self::LENGTH + buf.remaining() as u16 {
            return Err(DecodeError::InvalidLength(pkt_len));
        }

        Ok(PacketHdr {
            pkt_type,
            router_id,
            area_id,
            instance_id,
        })
    }

    fn encode(&self, buf: &mut BytesMut) {
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

    fn generate(
        pkt_type: PacketType,
        router_id: Ipv4Addr,
        area_id: Ipv4Addr,
        instance_id: Option<u8>,
    ) -> Self {
        PacketHdr {
            pkt_type,
            router_id,
            area_id,
            instance_id: instance_id.unwrap_or(0),
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

    fn encode(&self) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr);

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

            packet_encode_end::<Ospfv3>(buf)
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

    fn encode(&self) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr);

            buf.put_u8(0);
            self.options.encode(&mut buf);
            buf.put_u16(self.mtu);
            buf.put_u8(0);
            buf.put_u8(self.dd_flags.bits());
            buf.put_u32(self.dd_seq_no);
            for lsa_hdr in &self.lsa_hdrs {
                lsa_hdr.encode(&mut buf);
            }

            packet_encode_end::<Ospfv3>(buf)
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

    fn encode(&self) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr);

            for entry in &self.entries {
                buf.put_u16(0);
                buf.put_u16(entry.lsa_type.0);
                buf.put_ipv4(&entry.lsa_id);
                buf.put_ipv4(&entry.adv_rtr);
            }

            packet_encode_end::<Ospfv3>(buf)
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

    fn encode(&self) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr);

            buf.put_u32(self.lsas.len() as u32);
            for lsa in &self.lsas {
                buf.put_slice(&lsa.raw);
            }

            packet_encode_end::<Ospfv3>(buf)
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

    fn encode(&self) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = packet_encode_start::<Ospfv3>(buf, &self.hdr);

            for lsa_hdr in &self.lsa_hdrs {
                lsa_hdr.encode(&mut buf);
            }

            packet_encode_end::<Ospfv3>(buf)
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
    type PacketHello = Hello;
    type PacketDbDesc = DbDesc;
    type PacketLsRequest = LsRequest;
    type PacketLsUpdate = LsUpdate;
    type PacketLsAck = LsAck;
}
