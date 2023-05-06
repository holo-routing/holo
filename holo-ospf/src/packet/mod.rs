//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod error;
pub mod lsa;
pub mod tlv;

use std::cell::{RefCell, RefMut};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use bitflags::bitflags;
use bytes::{Bytes, BytesMut};
use holo_utils::ip::AddressFamily;
use num_derive::FromPrimitive;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::neighbor::NeighborNetId;
use crate::packet::error::DecodeResult;
use crate::packet::lsa::{Lsa, LsaKey};
use crate::version::Version;

// Database Description flags.
bitflags! {
    #[derive(Default)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct DbDescFlags: u8 {
        const MS = 0x01;
        const M = 0x02;
        const I = 0x04;
    }
}

// OSPF Packet Type.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-3
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum PacketType {
    Hello = 0x01,
    DbDesc = 0x02,
    LsRequest = 0x03,
    LsUpdate = 0x04,
    LsAck = 0x05,
}

// OSPF packet.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum Packet<V: Version> {
    Hello(V::PacketHello),
    DbDesc(V::PacketDbDesc),
    LsRequest(V::PacketLsRequest),
    LsUpdate(V::PacketLsUpdate),
    LsAck(V::PacketLsAck),
}

// OSPF version-specific code.
pub trait PacketVersion<V: Version> {
    type PacketOptions: OptionsVersion<V>;
    type PacketHdr: PacketHdrVersion<V>;
    type PacketHello: HelloVersion<V>;
    type PacketDbDesc: DbDescVersion<V>;
    type PacketLsRequest: LsRequestVersion<V>;
    type PacketLsUpdate: LsUpdateVersion<V>;
    type PacketLsAck: LsAckVersion<V>;
}

// OSPF version-specific code.
pub trait PacketHdrVersion<V: Version>
where
    Self: Sized,
{
    const LENGTH: u16;

    // Decode OSPF packet header from a bytes buffer.
    fn decode(buf: &mut Bytes) -> DecodeResult<Self>;

    // Encode OSPF packet header into a bytes buffer.
    fn encode(&self, buf: &mut BytesMut);

    // Update the header checksum.
    fn update_cksum(buf: &mut BytesMut);

    // Verify if the header checksum is correct.
    fn verify_cksum(data: &[u8]) -> DecodeResult<()>;

    // Return the packet type.
    fn pkt_type(&self) -> PacketType;

    // Return the packet Router ID.
    fn router_id(&self) -> Ipv4Addr;

    // Return the packet Area ID.
    fn area_id(&self) -> Ipv4Addr;

    // Create new packet header.
    fn generate(
        pkt_type: PacketType,
        router_id: Ipv4Addr,
        area_id: Ipv4Addr,
        instance_id: Option<u8>,
    ) -> Self;
}

// OSPF version-specific code.
pub trait PacketBase<V: Version>
where
    Self: Send + Sync + Clone + std::fmt::Debug + Serialize + DeserializeOwned,
{
    // Decode OSPF packet body from a bytes buffer.
    fn decode(
        af: AddressFamily,
        hdr: V::PacketHdr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self>;

    // Encode OSPF packet into a bytes buffer.
    fn encode(&self) -> Bytes;

    // Return a reference to the packet header.
    fn hdr(&self) -> &V::PacketHdr;

    // Return the packet's Router ID.
    fn router_id(&self) -> Ipv4Addr {
        self.hdr().router_id()
    }
}

// OSPF version-specific code.
pub trait OptionsVersion<V: Version>
where
    Self: Send
        + Sync
        + Clone
        + Copy
        + std::fmt::Debug
        + Eq
        + PartialEq
        + Serialize
        + DeserializeOwned,
{
    // Return whether the E-bit is set.
    fn e_bit(&self) -> bool;
}

// OSPF version-specific code.
pub trait HelloVersion<V: Version>
where
    Self: PacketBase<V>,
{
    // Return the Hello Interface ID (OSPFv3 only).
    fn iface_id(&self) -> Option<u32>;

    // Return the Hello Interval.
    fn hello_interval(&self) -> u16;

    // Return the Hello Router Dead Interval.
    fn dead_interval(&self) -> u32;

    // Return the Hello options.
    fn options(&self) -> V::PacketOptions;

    // Return the Hello priority.
    fn priority(&self) -> u8;

    // Return the Hello Designated Router.
    fn dr(&self) -> Option<NeighborNetId>;

    // Return the Hello Backup Designated Router.
    fn bdr(&self) -> Option<NeighborNetId>;

    // Return the list of neighbors contained in the Hello packet.
    fn neighbors(&self) -> &BTreeSet<Ipv4Addr>;
}

// OSPF version-specific code.
pub trait DbDescVersion<V: Version>
where
    Self: PacketBase<V>,
{
    const BASE_LENGTH: u16;

    // Return the Database Description MTU.
    fn mtu(&self) -> u16;

    // Return the Database Description options.
    fn options(&self) -> V::PacketOptions;

    // Return the Database Description flags.
    fn dd_flags(&self) -> DbDescFlags;

    // Return the Database Description sequence number.
    fn dd_seq_no(&self) -> u32;

    // Return the list of LSA headers contained in the Database Description
    // packet.
    fn lsa_hdrs(&self) -> &[V::LsaHdr];

    // Create new Database Description packet.
    fn generate(
        hdr: V::PacketHdr,
        options: V::PacketOptions,
        mtu: u16,
        dd_flags: DbDescFlags,
        dd_seq_no: u32,
        lsa_hdrs: Vec<V::LsaHdr>,
    ) -> Packet<V>;
}

// OSPF version-specific code.
pub trait LsRequestVersion<V: Version>
where
    Self: PacketBase<V>,
{
    const ENTRY_LENGTH: u16;

    // Return the list of LSA keys contained in the packet.
    fn entries(&self) -> &[LsaKey<V::LsaType>];

    // Create new Link State Request packet.
    fn generate(
        hdr: V::PacketHdr,
        entries: Vec<LsaKey<V::LsaType>>,
    ) -> Packet<V>;
}

// OSPF version-specific code.
pub trait LsUpdateVersion<V: Version>
where
    Self: PacketBase<V>,
{
    const BASE_LENGTH: u16;

    // Return an iterator over the list of LSAs contained in the packet.
    fn into_lsas(self) -> std::vec::IntoIter<Lsa<V>>;

    // Create new Link State Update packet.
    fn generate(hdr: V::PacketHdr, lsas: Vec<Lsa<V>>) -> Packet<V>;
}

// OSPF version-specific code.
pub trait LsAckVersion<V: Version>
where
    Self: PacketBase<V>,
{
    // Return the list of LSA headers contained in the packet.
    fn lsa_hdrs(&self) -> &[V::LsaHdr];

    // Create new Link State Acknowledgment packet.
    fn generate(hdr: V::PacketHdr, lsa_hdrs: Vec<V::LsaHdr>) -> Packet<V>;
}

// ===== impl Packet =====

impl<V: Version> Packet<V> {
    // Decodes OSPF packet from a bytes buffer.
    pub fn decode(af: AddressFamily, data: &[u8]) -> DecodeResult<Self> {
        V::PacketHdr::verify_cksum(data)?;
        let mut buf = Bytes::copy_from_slice(data);
        let hdr = V::PacketHdr::decode(&mut buf)?;

        let packet = match hdr.pkt_type() {
            PacketType::Hello => {
                Packet::Hello(V::PacketHello::decode(af, hdr, &mut buf)?)
            }
            PacketType::DbDesc => {
                Packet::DbDesc(V::PacketDbDesc::decode(af, hdr, &mut buf)?)
            }
            PacketType::LsRequest => Packet::LsRequest(
                V::PacketLsRequest::decode(af, hdr, &mut buf)?,
            ),
            PacketType::LsUpdate => {
                Packet::LsUpdate(V::PacketLsUpdate::decode(af, hdr, &mut buf)?)
            }
            PacketType::LsAck => {
                Packet::LsAck(V::PacketLsAck::decode(af, hdr, &mut buf)?)
            }
        };

        Ok(packet)
    }

    // Encodes OSPF packet into a bytes buffer.
    pub fn encode(&self) -> Bytes {
        match self {
            Packet::Hello(pkt) => pkt.encode(),
            Packet::DbDesc(pkt) => pkt.encode(),
            Packet::LsRequest(pkt) => pkt.encode(),
            Packet::LsUpdate(pkt) => pkt.encode(),
            Packet::LsAck(pkt) => pkt.encode(),
        }
    }

    // Returns a reference to the packet header.
    pub(crate) fn hdr(&self) -> &V::PacketHdr {
        match self {
            Packet::Hello(pkt) => pkt.hdr(),
            Packet::DbDesc(pkt) => pkt.hdr(),
            Packet::LsRequest(pkt) => pkt.hdr(),
            Packet::LsUpdate(pkt) => pkt.hdr(),
            Packet::LsAck(pkt) => pkt.hdr(),
        }
    }
}

// ===== helper functions =====

pub(crate) fn packet_encode_start<'a, V>(
    buf: &'a RefCell<BytesMut>,
    hdr: &V::PacketHdr,
) -> RefMut<'a, BytesMut>
where
    V: Version,
{
    let mut buf = buf.borrow_mut();
    buf.clear();
    hdr.encode(&mut buf);
    buf
}

pub(crate) fn packet_encode_end<V>(mut buf: RefMut<'_, BytesMut>) -> Bytes
where
    V: Version,
{
    // Initialize packet length.
    let pkt_len = buf.len() as u16;
    buf[2..4].copy_from_slice(&pkt_len.to_be_bytes());

    // Compute packet checksum.
    V::PacketHdr::update_cksum(&mut buf);

    buf.clone().freeze()
}
