use std::sync::atomic::Ordering;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::auth::{self, AuthEncodeCtx};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::lls::{
    ExtendedOptionsFlagsTlv, LLS_HDR_SIZE, LlsDbDescData, LlsHelloData,
    LlsTlvType, LlsVersion, lls_encode_end, lls_encode_start,
};
use crate::packet::tlv::{
    UnknownTlv, tlv_encode_end, tlv_encode_start, tlv_wire_len,
};
use crate::version::Ospfv2;

impl LlsVersion<Self> for Ospfv2 {
    type LlsDataBlock = LlsDataBlock;

    fn encode_lls_block(
        buf: &mut BytesMut,
        lls: LlsDataBlock,
        auth: Option<&AuthEncodeCtx<'_>>,
    ) {
        let start_pos = lls_encode_start(buf);

        if let Some(eof) = lls.eof {
            eof.encode(buf);
        }

        // RFC 5613 : "The CA-TLV MUST NOT appear more than once in the LLS
        // block.  Also, when present, this TLV MUST be the last TLV in the LLS
        // block."
        if let Some(auth) = auth {
            let ca =
                CryptoAuthTlv::new(auth.seqno.load(Ordering::Relaxed) as u32);
            ca.encode(buf, start_pos, auth);
        }
        lls_encode_end::<Ospfv2>(buf, start_pos, auth.is_some());
    }

    fn decode_lls_block(buf: &mut Bytes) -> DecodeResult<Option<LlsDataBlock>> {
        // Sanity check on buffer length.

        let len = buf.remaining();
        if len < LLS_HDR_SIZE as usize {
            return Ok(None);
        }

        let mut lls_block = LlsDataBlock::new();

        // Validate LLS block checksum
        // Self::verify_cksum(buf)?;

        let _cksum = buf.try_get_u16()?;
        let lls_len = buf.try_get_u16()?;

        // RFC 5613 Section 2.2: " The 16-bit LLS Data Length field contains
        // the length (in 32-bit words) of the LLS block including the header
        // and payload."
        let block_len = lls_len * 4;

        // Validate LLS block length
        if block_len as usize > buf.remaining() {
            return Err(DecodeError::InvalidLength(block_len));
        }

        while buf.remaining() >= LLS_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.try_get_u16()?;
            let tlv_etype = LlsTlvType::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.try_get_u16()?;
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(LlsTlvType::ExtendedOptionsFlags) => {
                    let opts =
                        ExtendedOptionsFlagsTlv::decode(tlv_len, &mut buf_tlv)?;
                    lls_block.eof = Some(opts);
                }
                Some(LlsTlvType::CryptoAuth) => {
                    let ca = CryptoAuthTlv::decode(tlv_len, &mut buf_tlv)?;
                    lls_block.ca = Some(ca);
                }
                _ => {
                    // Save unknown TLV.
                    lls_block
                        .unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, buf_tlv));
                }
            }
        }
        Ok(Some(lls_block))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, new)]
pub struct LlsDataBlock {
    #[new(default)]
    pub eof: Option<ExtendedOptionsFlagsTlv>,
    #[new(default)]
    pub ca: Option<CryptoAuthTlv>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

impl From<LlsHelloData> for LlsDataBlock {
    fn from(value: LlsHelloData) -> Self {
        let mut lls = LlsDataBlock::new();
        lls.eof = value.eof.map(ExtendedOptionsFlagsTlv);
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

impl From<LlsDbDescData> for LlsDataBlock {
    fn from(_value: LlsDbDescData) -> Self {
        LlsDataBlock::new()
    }
}

impl From<LlsDataBlock> for LlsDbDescData {
    fn from(_value: LlsDataBlock) -> Self {
        LlsDbDescData {}
    }
}

// RFC 5613 : LLS Cryptographic Authentication TLV
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |              2                |         AuthLen               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Sequence Number                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   .                                                               .
//   .                           AuthData                            .
//   .                                                               .
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, PartialEq, new)]
#[derive(Serialize, Deserialize)]
pub struct CryptoAuthTlv {
    pub seqno: u32,
    #[new(default)]
    pub auth_data: Vec<u32>,
}

impl CryptoAuthTlv {
    pub(crate) fn encode(
        &self,
        buf: &mut BytesMut,
        lls_start_pos: usize,
        auth: &AuthEncodeCtx<'_>,
    ) {
        let start_pos = tlv_encode_start(buf, LlsTlvType::CryptoAuth);
        buf.put_u32(self.seqno);
        let digest = auth::message_digest(
            &buf[lls_start_pos..],
            auth.key.algo,
            &auth.key.string,
            None,
            None,
        );
        buf.put_slice(&digest);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len < 4 || buf.remaining() < tlv_len as usize {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }
        let seqno = buf.try_get_u32()?;
        let mut auth_data_len = tlv_len - 4;
        let mut auth_data = Vec::new();
        while auth_data_len > 0 {
            auth_data.push(buf.try_get_u32()?);
            auth_data_len -= 4;
        }
        Ok(CryptoAuthTlv { seqno, auth_data })
    }
}
