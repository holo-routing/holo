//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

pub mod capability;
pub mod neighbor;
pub mod prefix;

use std::collections::BTreeMap;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::sr::MsdType;
use serde::{Deserialize, Serialize};

use crate::packet::error::{TlvDecodeError, TlvDecodeResult};
use crate::packet::tlv::{TLV_HDR_SIZE, tlv_encode_end, tlv_encode_start};

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct MsdStlv(BTreeMap<u8, u8>);

// ===== impl MsdStlv =====

impl MsdStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len % 2 != 0 {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let mut msds = BTreeMap::new();
        while buf.remaining() >= 2 {
            let msd_type = buf.try_get_u8()?;
            let msd_value = buf.try_get_u8()?;
            msds.insert(msd_type, msd_value);
        }

        Ok(MsdStlv(msds))
    }

    pub(crate) fn encode(&self, stlv_type: u8, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, stlv_type);
        for (msd_type, msd_value) in &self.0 {
            buf.put_u8(*msd_type);
            buf.put_u8(*msd_value);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + self.0.len() * 2
    }

    pub(crate) fn get(&self) -> &BTreeMap<u8, u8> {
        &self.0
    }
}

impl From<&BTreeMap<MsdType, u8>> for MsdStlv {
    fn from(map: &BTreeMap<MsdType, u8>) -> Self {
        let msd = map.iter().map(|(k, v)| (*k as u8, *v)).collect();
        MsdStlv(msd)
    }
}
