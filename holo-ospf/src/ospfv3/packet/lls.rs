use bytes::{Buf, Bytes, BytesMut};
use derive_new::new;
use num_traits::FromPrimitive;

// use serde::{Deserialize, Serialize};
use crate::packet::auth::AuthEncodeCtx;
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::lls::{
    ExtendedOptionsFlagsTlv, LLS_HDR_SIZE, LlsDbDescData, LlsHelloData,
    LlsTlvType, LlsVersion, lls_encode_end, lls_encode_start,
};
use crate::packet::tlv::{UnknownTlv, tlv_wire_len};
use crate::version::Ospfv3;

#[derive(Clone, Debug, Eq, PartialEq, new)]
pub struct LlsDataBlock {
    #[new(default)]
    pub eof: Option<ExtendedOptionsFlagsTlv>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

// impl LlsDataBlockVersion<Ospfv3> for LlsDataBlock {}

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

impl LlsVersion<Self> for Ospfv3 {
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

        lls_encode_end::<Ospfv3>(buf, start_pos, auth.is_some());
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
