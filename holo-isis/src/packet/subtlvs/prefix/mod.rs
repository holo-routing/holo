use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use serde::{Deserialize, Serialize};

use crate::packet::consts::PrefixSubTlvType;
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::tlv::{tlv_encode_end, tlv_encode_start};

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct BierInfoSubTlv {
    pub bar: u8,
    pub ipa: u8,
    pub sub_domain_id: u8,
    pub bfr_id: u16,
    // pub subtlvs: Vec<BierSubSubTlv>
}

// ===== impl BierInfoSubTlv =====

impl BierInfoSubTlv {
    const ENTRY_MIN_SIZE: usize = 5;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len < Self::ENTRY_MIN_SIZE as u8 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }
        let bar = buf.get_u8();
        let ipa = buf.get_u8();
        let sub_domain_id = buf.get_u8();
        let bfr_id = buf.get_u16();
        // TODO: decode sub-sub-tlvs
        Ok(BierInfoSubTlv {
            bar,
            ipa,
            sub_domain_id,
            bfr_id,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, PrefixSubTlvType::BierInfo);
        buf.put_u8(self.bar);
        buf.put_u8(self.ipa);
        buf.put_u8(self.sub_domain_id);
        buf.put_u16(self.bfr_id);
        // TODO: encode sub-sub-tlvs
        tlv_encode_end(buf, start_pos);
    }
}
