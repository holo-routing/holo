//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;

use bytes::{Buf, Bytes, BytesMut};
use num_traits::FromPrimitive;

use super::PacketHdrAuth;
use crate::ospfv3::packet::Options;
use crate::packet::auth::{AuthDecodeCtx, AuthEncodeCtx};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::lls::{
    ExtendedOptionsFlagsTlv, LLS_HDR_SIZE, LlsDbDescData, LlsHelloData,
    LlsTlvType, LlsVersion, ReverseMetricTlv, ReverseTeMetricTlv,
    lls_encode_end, lls_encode_start,
};
use crate::packet::tlv::{UnknownTlv, tlv_wire_len};
use crate::packet::{OptionsVersion, PacketVersion};
use crate::version::Ospfv3;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct LlsDataBlock {
    pub eof: Option<ExtendedOptionsFlagsTlv>,
    pub reverse_metric: Vec<ReverseMetricTlv>,
    pub reverse_te_metric: Option<ReverseTeMetricTlv>,
    pub unknown_tlvs: Vec<UnknownTlv>,
}

impl From<LlsHelloData> for LlsDataBlock {
    fn from(value: LlsHelloData) -> Self {
        let mut lls = LlsDataBlock::default();
        lls.eof = value.eof.map(ExtendedOptionsFlagsTlv);

        lls.reverse_metric =
            value.reverse_metric.iter().map(|rm| rm.into()).collect();

        lls.reverse_te_metric =
            value.reverse_te_metric.as_ref().map(|rtem| rtem.into());

        lls
    }
}

impl From<&LlsDataBlock> for LlsHelloData {
    fn from(value: &LlsDataBlock) -> Self {
        let mut reverse_metrics = BTreeMap::new();
        value.reverse_metric.iter().for_each(|tlv| {
            // RFC 9339 Section 6 : "A router MUST NOT include more than one
            // instance of this TLV per MTID. If more than a single instance of
            // this TLV per MTID is present, the receiving router MUST only use
            // the value from the first instance and ignore the others."
            reverse_metrics
                .entry(tlv.mtid)
                .or_insert((tlv.flags, tlv.metric));
        });
        LlsHelloData {
            eof: value.eof.as_ref().map(|tlv| tlv.0),
            reverse_metric: reverse_metrics,
            reverse_te_metric: value
                .reverse_te_metric
                .map(|tlv| (tlv.flags, tlv.metric)),
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

        lls.reverse_metric.iter().for_each(|tlv| tlv.encode(buf));

        if let Some(rtem) = lls.reverse_te_metric {
            rtem.encode(buf);
        }

        lls_encode_end::<Ospfv3>(buf, start_pos, auth.is_some());
    }

    fn decode_lls_block(
        buf: &[u8],
        pkt_len: u16,
        _hdr_auth: PacketHdrAuth,
        _auth: Option<&AuthDecodeCtx<'_>>,
    ) -> DecodeResult<Option<LlsDataBlock>> {
        // Test the presence of the L-bit indicating a LLS data block.
        let options = Self::packet_options(buf);
        if options.is_none_or(|options| !options.l_bit()) {
            return Ok(None);
        }

        let mut buf = Bytes::copy_from_slice(&buf[pkt_len as usize..]);

        // Sanity check on buffer length.
        if buf.remaining() < LLS_HDR_SIZE as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }

        // Validate LLS block checksum when authentication is disabled.
        if let Some(options) = options
            && !options.contains(Options::AT)
        {
            Self::verify_cksum(&buf)?;
        }

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

        while buf.remaining() > 0 {
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
                Some(LlsTlvType::ReverseMetric) => {
                    let rm = ReverseMetricTlv::decode(tlv_len, &mut buf_tlv)?;
                    lls_block.reverse_metric.push(rm);
                }
                Some(LlsTlvType::ReverseTeMetric) => {
                    let rtem =
                        ReverseTeMetricTlv::decode(tlv_len, &mut buf_tlv)?;
                    lls_block.reverse_te_metric = Some(rtem);
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
