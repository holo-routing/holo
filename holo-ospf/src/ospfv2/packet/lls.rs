//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::atomic::Ordering;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use super::{PacketHdrAuth, validate_digest};
use crate::packet::auth::{self, AuthDecodeCtx, AuthEncodeCtx};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::lls::{
    ExtendedOptionsFlagsTlv, LLS_HDR_SIZE, LlsDbDescData, LlsHelloData,
    LlsTlvType, LlsVersion, lls_encode_end, lls_encode_start,
};
use crate::packet::tlv::{
    UnknownTlv, tlv_encode_end, tlv_encode_start, tlv_wire_len,
};
use crate::packet::{OptionsVersion, PacketVersion};
use crate::version::Ospfv2;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct LlsDataBlock {
    pub eof: Option<ExtendedOptionsFlagsTlv>,
    pub unknown_tlvs: Vec<UnknownTlv>,
}

impl From<LlsHelloData> for LlsDataBlock {
    fn from(value: LlsHelloData) -> Self {
        let mut lls = LlsDataBlock::default();
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
    fn from(value: LlsDbDescData) -> Self {
        let mut lls = LlsDataBlock::default();
        lls.eof = value.eof.map(ExtendedOptionsFlagsTlv);
        lls
    }
}

impl From<LlsDataBlock> for LlsDbDescData {
    fn from(value: LlsDataBlock) -> Self {
        LlsDbDescData {
            eof: value.eof.map(|tlv| tlv.0),
        }
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
    pub auth_data: Bytes,
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

        // Add place holder for auth digest.
        let auth_digest_start = buf.len();
        buf.put_slice(&vec![0; auth.key.algo.digest_size() as usize]);

        // Encode TLV length. It will be rewritten later with the same value.
        tlv_encode_end(buf, start_pos);

        // Write LLS data block length as CA TLV MUST be the last chunk of the
        // block per RFC 5613. It will be rewritten later with the same value.
        lls_encode_end::<Ospfv2>(buf, lls_start_pos, true);

        // Compute auth digest on full LLS block until auth digest.
        let digest = auth::message_digest(
            &buf[lls_start_pos..auth_digest_start],
            auth.key.algo,
            &auth.key.string,
            None,
            None,
        );

        // Replace auth digest place holder with actual digest.
        buf[auth_digest_start..].copy_from_slice(&digest);
    }

    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len < 4 || buf.remaining() < tlv_len as usize {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }
        let seqno = buf.try_get_u32()?;
        let auth_data_len = tlv_len - 4;
        let auth_data = buf.slice(..auth_data_len as usize);

        Ok(CryptoAuthTlv { seqno, auth_data })
    }
}

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
            let ca = CryptoAuthTlv::new(
                (auth.seqno.load(Ordering::Relaxed) as u32) - 1,
            );
            ca.encode(buf, start_pos, auth);
        }
        lls_encode_end::<Ospfv2>(buf, start_pos, auth.is_some());
    }

    fn decode_lls_block(
        data: &[u8],
        pkt_len: u16,
        hdr_auth: PacketHdrAuth,
        auth: Option<&AuthDecodeCtx<'_>>,
    ) -> DecodeResult<Option<LlsDataBlock>> {
        // Test the presence of the L-bit indicating a LLS data block.
        if Self::packet_options(data).is_none_or(|options| !options.l_bit()) {
            return Ok(None);
        }

        let mut buf = Bytes::copy_from_slice(&data[pkt_len as usize..]);

        // Sanity check on buffer length.
        if buf.remaining() < LLS_HDR_SIZE as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }

        // If authentication trailer is embedded, skip it.
        // The authentication digest has already been verified earlier, so no
        // need for a double check here.
        if let PacketHdrAuth::Cryptographic { auth_len, .. } = hdr_auth {
            buf.advance(auth_len as usize);
        } else {
            // Validate LLS block checksum when authentication is disabled.
            Self::verify_cksum(&buf)?;
        };

        let mut data = buf.clone();

        let mut lls_block = LlsDataBlock::default();

        let _cksum = buf.try_get_u16()?;
        let lls_len = buf.try_get_u16()?;

        // RFC 5613 Section 2.2: " The 16-bit LLS Data Length field contains
        // the length (in 32-bit words) of the LLS block including the header
        // and payload."
        let lls_len = lls_len as usize * 4;
        if lls_len < LLS_HDR_SIZE as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }
        let block_len = lls_len - LLS_HDR_SIZE as usize;

        // Validate LLS block length
        if block_len > buf.remaining() {
            return Err(DecodeError::InvalidLength(block_len as u16));
        }
        buf = buf.slice(0..block_len);
        data = data.slice(0..block_len + LLS_HDR_SIZE as usize);

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

                    if let PacketHdrAuth::Cryptographic {
                        key_id,
                        auth_len,
                        seqno,
                    } = hdr_auth
                    {
                        // RFC 5613 Section 2.5 : "The Sequence Number field
                        // contains the cryptographic sequence number
                        // that is used to prevent simple replay attacks.  For the
                        // LLS block to be considered authentic, the Sequence Number
                        // in the CA-TLV MUST match the Sequence Number in the
                        // OSPFv2 packet header Authentication field (which MUST be
                        // present)."
                        if seqno != ca.seqno {
                            return Err(DecodeError::AuthError);
                        }

                        validate_digest(
                            key_id,
                            auth_len,
                            auth,
                            &ca.auth_data,
                            // Skip the CA TLV digest
                            &data[..data.len() - ca.auth_data.len()],
                        )?;
                    }
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
