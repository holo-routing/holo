//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
//! SPB (Shortest Path Bridging) Sub-TLVs for IS-IS.
//!
//! This module implements Sub-TLVs carried within the MT-Capability TLV (144)
//! as defined in RFC 6329.

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use serde::{Deserialize, Serialize};

use crate::packet::consts::MtCapStlvType;
use crate::packet::error::{TlvDecodeError, TlvDecodeResult};
use crate::packet::tlv::{TLV_HDR_SIZE, tlv_encode_end, tlv_encode_start};

/// SPBM Service Identifier and Unicast Address (SPBM-SI) Sub-TLV.
///
/// This Sub-TLV is defined in RFC 6329 Section 16.1 and carries:
/// - B-MAC Address: Unicast MAC address of the node
/// - Base VID: Links this B-MAC to corresponding ECT-ALGORITHM
/// - I-SID entries: Service identifiers with T/R membership bits
///
/// Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |         B-MAC Address        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    B-MAC Address (continued)                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Resv | Base VID              |T|R|  Resv   |     I-SID      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          I-SID (continued)    | ... more I-SID entries ...   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SpbmSiStlv {
    /// B-MAC Address (6 bytes) - Unicast MAC address.
    pub bmac: [u8; 6],
    /// Base VID (12 bits) - Links to ECT-ALGORITHM in SPB-Inst Sub-TLV.
    pub base_vid: u16,
    /// List of I-SID entries with T/R flags.
    pub isid_entries: Vec<IsidEntry>,
}

/// I-SID (Service Identifier) entry within SPBM-SI Sub-TLV.
///
/// Format (4 bytes):
/// ```text
/// |T|R|  Reserved (6 bits) |     I-SID (24 bits)           |
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct IsidEntry {
    /// T bit: Transmit - indicates transmit membership.
    /// R bit: Receive - indicates receive membership.
    pub flags: IsidFlags,
    /// 24-bit Service Identifier.
    pub isid: u32,
}

bitflags! {
    /// Flags for I-SID entries.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct IsidFlags: u8 {
        /// Transmit bit - indicates transmit membership.
        const T = 0x80;
        /// Receive bit - indicates receive membership.
        const R = 0x40;
    }
}

// ===== impl SpbmSiStlv =====

impl SpbmSiStlv {
    /// B-MAC (6) + Reserved/BaseVID (2) = 8 bytes minimum.
    const MIN_SIZE: usize = 8;
    /// Each I-SID entry is 4 bytes.
    const ISID_ENTRY_SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate minimum length.
        if (stlv_len as usize) < Self::MIN_SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        // Validate I-SID entries alignment.
        let isid_bytes = (stlv_len as usize) - Self::MIN_SIZE;
        if !isid_bytes.is_multiple_of(Self::ISID_ENTRY_SIZE) {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        // Parse B-MAC Address (6 bytes).
        let mut bmac = [0u8; 6];
        buf.copy_to_slice(&mut bmac);

        // Parse Reserved (4 bits) + Base VID (12 bits).
        let base_vid_raw = buf.try_get_u16()?;
        let base_vid = base_vid_raw & 0x0FFF;

        // Parse I-SID entries.
        let num_entries = isid_bytes / Self::ISID_ENTRY_SIZE;
        let mut isid_entries = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            let entry = IsidEntry::decode(buf)?;
            isid_entries.push(entry);
        }

        Ok(SpbmSiStlv {
            bmac,
            base_vid,
            isid_entries,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, MtCapStlvType::SpbmSi);

        // B-MAC Address (6 bytes).
        buf.put_slice(&self.bmac);

        // Reserved (4 bits) + Base VID (12 bits).
        buf.put_u16(self.base_vid & 0x0FFF);

        // I-SID entries.
        for entry in &self.isid_entries {
            entry.encode(buf);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE
            + Self::MIN_SIZE
            + self.isid_entries.len() * Self::ISID_ENTRY_SIZE
    }
}

// ===== impl IsidEntry =====

impl IsidEntry {
    pub(crate) fn decode(buf: &mut Bytes) -> TlvDecodeResult<Self> {
        // First byte: T|R|Reserved(6 bits).
        let flags_byte = buf.try_get_u8()?;
        let flags = IsidFlags::from_bits_truncate(flags_byte);

        // Next 3 bytes: I-SID (24 bits).
        let isid = buf.try_get_u24()?;

        Ok(IsidEntry { flags, isid })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        // T|R|Reserved(6 bits).
        buf.put_u8(self.flags.bits());

        // I-SID (24 bits).
        buf.put_u24(self.isid);
    }
}
