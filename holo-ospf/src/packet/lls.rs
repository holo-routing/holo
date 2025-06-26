use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use serde::{self, Deserialize, Serialize};

use super::error::DecodeResult;
use super::tlv::{UnknownTlv, tlv_encode_end, tlv_encode_start, tlv_wire_len};

// LLS header size.
pub const LLS_HDR_SIZE: u16 = 4;

// LLS TLV types.
//
// IANA Registry:
// https://www.iana.org/assignments/ospf-lls-tlvs/ospf-lls-tlvs.xhtml
#[derive(ToPrimitive, FromPrimitive)]
pub enum LlsTlvType {
    ExtendedOptionsFlags = 1,
}

#[derive(Clone, Debug, Eq, PartialEq, new)]
pub struct LlsDataBlock {
    #[new(default)]
    pub cksum: u16,
    #[new(default)]
    pub length: u16,
    #[new(default)]
    pub eof: Option<EofTlv>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

impl LlsDataBlock {
    pub(crate) fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let mut lls_block = LlsDataBlock::new();

        lls_block.cksum = buf.try_get_u16()?;
        lls_block.length = buf.try_get_u16()?;

        while buf.remaining() >= LLS_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.try_get_u16()?;
            let tlv_etype = LlsTlvType::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.try_get_u16()?;
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(super::error::DecodeError::InvalidTlvLength(
                    tlv_len,
                ));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(LlsTlvType::ExtendedOptionsFlags) => {
                    let opts = EofTlv::decode(tlv_len, &mut buf_tlv)?;
                    lls_block.eof = Some(opts);
                }
                _ => {
                    // Save unknown TLV.
                    lls_block
                        .unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, buf_tlv));
                }
            }
        }
        Ok(lls_block)
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = lls_encode_start(buf);
        buf.put_u16(0);
        buf.put_u16(self.length);
        if let Some(eof) = &self.eof {
            eof.encode(buf);
        }
        lls_encode_end(buf, start_pos);
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[derive(Serialize, Deserialize)]
pub enum LlsData {
    Hello(LlsHelloData),
    DbDesc(LlsDbDescData),
}

impl LlsData {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let lls: LlsDataBlock = match self {
            Self::Hello(hello) => (*hello).into(),
            Self::DbDesc(dbdesc) => (*dbdesc).into(),
        };
        lls.encode(buf);
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[derive(Serialize, Deserialize)]
pub struct LlsHelloData {
    eof: Option<ExtendedOptionsFlags>,
}

impl From<LlsHelloData> for LlsDataBlock {
    fn from(value: LlsHelloData) -> Self {
        let mut lls = LlsDataBlock::new();
        lls.eof = value.eof.map(EofTlv);
        lls
    }
}

impl From<LlsDataBlock> for LlsHelloData {
    fn from(value: LlsDataBlock) -> Self {
        LlsHelloData {
            eof: value.eof.map(|tlv| tlv.0),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[derive(Serialize, Deserialize)]
pub struct LlsDbDescData {}

impl From<LlsDbDescData> for LlsDataBlock {
    fn from(_value: LlsDbDescData) -> Self {
        let lls = LlsDataBlock::new();
        lls
    }
}

impl From<LlsDataBlock> for LlsDbDescData {
    fn from(_value: LlsDataBlock) -> Self {
        LlsDbDescData {}
    }
}

// Extended Options and Flags
//
// IANA Registry:
// https://www.iana.org/assignments/ospf-lls-tlvs/ospf-lls-tlvs.xhtml#ospf-lls-tlvs-2
bitflags! {
    #[derive(Clone, Debug, Eq, PartialEq, Copy)]
    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct ExtendedOptionsFlags: u32 {
        const LR = 0x00000001;
        const RS = 0x00000002;
    }
}

// RFC 5613 : LLS Extended Options and Flags TLV.
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             1                 |            4                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Extended Options and Flags                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct EofTlv(ExtendedOptionsFlags);

impl EofTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len != 4 {
            return Err(super::error::DecodeError::InvalidTlvLength(tlv_len));
        }
        let opts = ExtendedOptionsFlags::from_bits_truncate(buf.try_get_u32()?);
        Ok(EofTlv(opts))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, LlsTlvType::ExtendedOptionsFlags);
        buf.put_u32(self.0.bits());
        tlv_encode_end(buf, start_pos);
    }
}

// ===== global functions =====

pub(crate) fn lls_encode_start(buf: &mut BytesMut) -> usize {
    let start_pos = buf.len();
    // Checksum will be rewritten later.
    buf.put_u16(0);
    // The LLS data block length will be rewritten later.
    buf.put_u16(0);
    start_pos
}

pub(crate) fn lls_encode_end(buf: &mut BytesMut, start_pos: usize) {
    // RFC 5613 : "The 16-bit LLS Data Length field contains the length (in
    // 32-bit words) of the LLS block including the header and payload."
    let lls_len = (buf.len() - start_pos) as u16;

    // Rewrite LLS length.
    buf[start_pos + 2..start_pos + 4].copy_from_slice(&lls_len.to_be_bytes());

    // TODO: Rewrite LLS checksum.
}
