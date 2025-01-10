//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::ip::{
    AddressFamily, IpAddrExt, IpNetworkExt, Ipv4AddrExt, Ipv4NetworkExt,
    Ipv6AddrExt, Ipv6NetworkExt,
};
use holo_utils::mpls::Label;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::packet::DecodeCxt;
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::message::{
    LabelMessageType, Message, MessageDecodeInfo, MessageKind, MessageType,
};
use crate::packet::tlv::{self, TlvDecodeInfo, TlvKind, TlvType};

//
// Label messages.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Label Mapping (0x0400)    |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     FEC TLV                                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Label TLV                                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Label Request (0x0401)    |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     FEC TLV                                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Label Withdraw (0x0402)   |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     FEC TLV                                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Label TLV (optional)                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Label Release (0x0403)   |      Message Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     FEC TLV                                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Label TLV (optional)                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Label Abort Req (0x0404)  |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     FEC TLV                                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Label Request Message ID TLV              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct LabelMsg {
    pub msg_id: u32,
    pub msg_type: LabelMessageType,
    pub fec: TlvFec,
    pub label: Option<TlvLabel>,
    pub request_id: Option<TlvLabelRequestId>,
}

//
// FEC TLV.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|0| FEC (0x0100)              |      Length                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        FEC Element 1                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                                                               ~
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        FEC Element n                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvFec(pub Vec<FecElem>);

//
// Prefix FEC Element value encoding:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Prefix (2)   |     Address Family            |     PreLen    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Prefix                                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FecElem {
    Wildcard(FecElemWildcard),
    Prefix(IpNetwork),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FecElemWildcard {
    All,
    Typed(TypedWildcardFecElem),
}

// Forwarding Equivalence Class (FEC) Type Name Space.
//
// IANA registry:
// https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml#fec-type
pub const TLV_FEC_ELEMENT_WILDCARD: u8 = 1;
pub const TLV_FEC_ELEMENT_PREFIX: u8 = 2;
pub const TLV_FEC_ELEMENT_TYPED_WILDCARD: u8 = 5;

//
// Typed Wildcard FEC Element value encoding:
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Typed (0x05)  | FEC Element   | Len FEC Type  |               |
// | Wildcard      | Type          | Info          |               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
// |                                                               |
// ~          Additional FEC Type-specific Information             ~
// |                  (Optional)                                   |
// |                                               +-+-+-+-+-+-+-+-+
// |                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Prefix FEC Typed Wildcard FEC Element:
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Typed Wcard   | Type = Prefix |   Len = 2     |  Address...   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | ...Family     |
// +-+-+-+-+-+-+-+-+
//
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TypedWildcardFecElem {
    Prefix(AddressFamily),
}

// Generic Label TLV.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvLabel(pub Label);

// Label Request Message ID TLV.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvLabelRequestId(pub u32);

// ===== impl LabelMsg =====

impl MessageKind for LabelMsg {
    const U_BIT: bool = false;

    fn msg_id(&self) -> u32 {
        self.msg_id
    }

    fn msg_type(&self) -> MessageType {
        self.msg_type.into()
    }

    fn encode_body(&self, buf: &mut BytesMut) {
        // Encode mandatory TLV(s).
        self.fec.encode(self.msg_type(), buf);

        // Encode optional TLV(s).
        if let Some(tlv) = &self.label {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.request_id {
            tlv.encode(self.msg_type(), buf);
        }
    }

    fn decode_body(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        msgi: &mut MessageDecodeInfo,
    ) -> DecodeResult<Message> {
        // Decode mandatory FEC TLV (all label messages).
        let tlvi = tlv::decode_tlv_hdr(buf, msgi)?;
        if tlvi.tlv_type != TlvType::Fec as u16 {
            return Err(DecodeError::MissingMsgParams(
                msgi.clone(),
                TlvType::Fec,
            ));
        }
        let fec = TlvFec::decode_value(buf, cxt, &tlvi)?;

        // Create new message.
        let mut msg = LabelMsg {
            msg_type: LabelMessageType::from_u16(msgi.msg_type).unwrap(),
            msg_id: msgi.msg_id,
            fec,
            label: None,
            request_id: None,
        };

        // Decode optional TLV(s).
        msg.decode_opt_tlvs(buf, cxt, msgi)?;

        // Additional sanity checks.
        let fec_type = msg.fec.0[0].get_type();
        match msgi.msg_etype.unwrap() {
            // Check for missing message-specific mandatory parameters.
            MessageType::LabelMapping if msg.label.is_none() => {
                return Err(DecodeError::MissingMsgParams(
                    msgi.clone(),
                    TlvType::GenericLabel,
                ));
            }
            MessageType::LabelAbortReq if msg.request_id.is_none() => {
                return Err(DecodeError::MissingMsgParams(
                    msgi.clone(),
                    TlvType::LabelRequestId,
                ));
            }
            // RFC 5036 - Section 3.4.1:
            // "Note that this version of LDP supports the use of multiple FEC
            // Elements per FEC for the Label Mapping message only".
            MessageType::LabelRequest
            | MessageType::LabelWithdraw
            | MessageType::LabelRelease
            | MessageType::LabelAbortReq
                if msg.fec.0.len() > 1 =>
            {
                return Err(DecodeError::InvalidTlvValue(tlvi));
            }
            // RFC 5918 - Section 1:
            // "Use of the Wildcard FEC Element is limited to Label Withdraw and
            // Label Release messages only".
            MessageType::LabelMapping
            | MessageType::LabelRequest
            | MessageType::LabelAbortReq
                if fec_type == TLV_FEC_ELEMENT_WILDCARD =>
            {
                return Err(DecodeError::UnknownFec(tlvi, fec_type));
            }
            // RFC 5918 - Section 4:
            // "An LDP implementation that supports the Typed Wildcard FEC
            // Element MUST support its use in Label Request, Label Withdraw,
            // and Label Release messages".
            MessageType::LabelMapping | MessageType::LabelAbortReq
                if fec_type == TLV_FEC_ELEMENT_TYPED_WILDCARD =>
            {
                return Err(DecodeError::UnknownFec(tlvi, fec_type));
            }
            _ => (),
        }

        // Check for invalid explicit null labels.
        if let Some(label) = &msg.label {
            for fec_elem in &msg.fec.0 {
                if let FecElem::Prefix(prefix) = fec_elem {
                    if (prefix.is_ipv4()
                        && label.0.get() == Label::IPV6_EXPLICIT_NULL)
                        || (prefix.is_ipv6()
                            && label.0.get() == Label::IPV4_EXPLICIT_NULL)
                    {
                        return Err(DecodeError::InvalidTlvValue(tlvi));
                    }
                }
            }
        }

        Ok(Message::Label(msg))
    }

    fn decode_opt_tlv(
        &mut self,
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<bool> {
        match tlvi.tlv_etype.unwrap() {
            TlvType::AtmLabel | TlvType::FrLabel => {
                return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
            }
            TlvType::HopCount | TlvType::PathVector => {
                // Ignore - loop detection is unnecessary for frame-mode MPLS
                // networks.
                return Ok(false);
            }
            TlvType::GenericLabel => {
                self.label = Some(TlvLabel::decode_value(buf, cxt, tlvi)?);
            }
            TlvType::LabelRequestId => {
                self.request_id =
                    Some(TlvLabelRequestId::decode_value(buf, cxt, tlvi)?);
            }
            _ => {
                return Ok(true);
            }
        };

        Ok(false)
    }
}

impl LabelMsg {
    pub(crate) fn get_label(&self) -> Option<Label> {
        self.label.as_ref().map(|label| label.0)
    }
}

// ===== impl TlvFec =====

impl TlvKind for TlvFec {
    const TLV_TYPE: TlvType = TlvType::Fec;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        for fec_elem in &self.0 {
            fec_elem.encode(buf);
        }
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        // FEC list can't be empty.
        if tlvi.tlv_len < 1 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let mut fec_elems: Vec<FecElem> = vec![];
        let mut tlv_rlen = tlvi.tlv_len;
        while tlv_rlen >= 1 {
            let fec_elem = FecElem::decode(buf, tlvi, &mut tlv_rlen)?;

            fec_elems.push(fec_elem);
        }

        Ok(Self(fec_elems))
    }
}

// ===== impl FecElem =====

impl FecElem {
    fn get_type(&self) -> u8 {
        match self {
            FecElem::Wildcard(FecElemWildcard::All) => TLV_FEC_ELEMENT_WILDCARD,
            FecElem::Wildcard(FecElemWildcard::Typed(..)) => {
                TLV_FEC_ELEMENT_TYPED_WILDCARD
            }
            FecElem::Prefix(_) => TLV_FEC_ELEMENT_PREFIX,
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            FecElem::Wildcard(FecElemWildcard::All) => {
                buf.put_u8(TLV_FEC_ELEMENT_WILDCARD);
            }
            FecElem::Wildcard(FecElemWildcard::Typed(typed_wcard)) => {
                typed_wcard.encode(buf);
            }
            FecElem::Prefix(prefix) => {
                // FEC element type.
                buf.put_u8(TLV_FEC_ELEMENT_PREFIX);

                // FEC address family.
                let af = match prefix {
                    IpNetwork::V4(_) => AddressFamily::Ipv4,
                    IpNetwork::V6(_) => AddressFamily::Ipv6,
                };
                buf.put_u16(af as u16);

                // FEC prefix length.
                let plen = prefix.prefix();
                buf.put_u8(plen);

                // FEC prefix (variable length).
                let prefix_bytes = prefix.ip().bytes();
                let plen_wire = prefix_wire_len(plen);
                buf.put(&prefix_bytes[0..plen_wire]);
            }
        }
    }

    fn decode(
        buf: &mut Bytes,
        tlvi: &TlvDecodeInfo,
        tlv_rlen: &mut u16,
    ) -> DecodeResult<Self> {
        // Parse FEC element type.
        let fec_elem_type = buf.get_u8();
        *tlv_rlen -= 1;

        match fec_elem_type {
            TLV_FEC_ELEMENT_WILDCARD => {
                Ok(FecElem::Wildcard(FecElemWildcard::All))
            }
            TLV_FEC_ELEMENT_PREFIX => {
                if *tlv_rlen < 3 {
                    return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
                }

                // Parse prefix address family.
                let af = buf.get_u16();
                *tlv_rlen -= 2;
                let af = match FromPrimitive::from_u16(af) {
                    Some(AddressFamily::Ipv4) => AddressFamily::Ipv4,
                    Some(AddressFamily::Ipv6) => AddressFamily::Ipv6,
                    _ => {
                        return Err(DecodeError::UnsupportedAf(
                            tlvi.clone(),
                            af,
                        ));
                    }
                };

                // Parse prefix length.
                let plen = buf.get_u8();
                *tlv_rlen -= 1;
                let plen_wire = prefix_wire_len(plen);
                if (*tlv_rlen < plen_wire as u16)
                    || (af == AddressFamily::Ipv4
                        && plen > Ipv4Network::MAX_PREFIXLEN)
                    || (af == AddressFamily::Ipv6
                        && plen > Ipv6Network::MAX_PREFIXLEN)
                {
                    return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
                }

                // Parse prefix.
                let prefix = match af {
                    AddressFamily::Ipv4 => {
                        let mut prefix_bytes = [0; Ipv4Addr::LENGTH];
                        buf.copy_to_slice(&mut prefix_bytes[..plen_wire]);
                        Ipv4Addr::from(prefix_bytes).into()
                    }
                    AddressFamily::Ipv6 => {
                        let mut prefix_bytes = [0; Ipv6Addr::LENGTH];
                        buf.copy_to_slice(&mut prefix_bytes[..plen_wire]);
                        Ipv6Addr::from(prefix_bytes).into()
                    }
                };
                *tlv_rlen -= plen_wire as u16;
                IpNetwork::new(prefix, plen)
                    .map(|prefix| FecElem::Prefix(prefix.apply_mask()))
                    .map_err(|_| DecodeError::InvalidTlvValue(tlvi.clone()))
            }
            TLV_FEC_ELEMENT_TYPED_WILDCARD => {
                let elem = TypedWildcardFecElem::decode(buf, tlvi, tlv_rlen)?;
                Ok(FecElem::Wildcard(FecElemWildcard::Typed(elem)))
            }
            _ => Err(DecodeError::UnknownFec(tlvi.clone(), fec_elem_type)),
        }
    }
}

impl From<IpNetwork> for FecElem {
    fn from(prefix: IpNetwork) -> FecElem {
        FecElem::Prefix(prefix)
    }
}

// ===== impl TypedWildcardFecElem =====

impl TypedWildcardFecElem {
    fn encode(&self, buf: &mut BytesMut) {
        // FEC element type.
        buf.put_u8(TLV_FEC_ELEMENT_TYPED_WILDCARD);

        match self {
            TypedWildcardFecElem::Prefix(af) => {
                // Typed Wildcard FEC element type.
                buf.put_u8(TLV_FEC_ELEMENT_PREFIX);

                // Len FEC Type Info.
                buf.put_u8(2);

                // Address Family.
                buf.put_u16(*af as u16);
            }
        };
    }

    fn decode(
        buf: &mut Bytes,
        tlvi: &TlvDecodeInfo,
        tlv_rlen: &mut u16,
    ) -> DecodeResult<Self> {
        if *tlv_rlen < 2 {
            return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
        }

        // Typed Wildcard FEC element type.
        let typed_wcard = buf.get_u8();
        *tlv_rlen -= 1;

        match typed_wcard {
            TLV_FEC_ELEMENT_PREFIX => {
                if *tlv_rlen < 3 {
                    return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
                }

                // Len FEC Type Info.
                let len = buf.get_u8();
                *tlv_rlen -= 1;
                if len != 2 {
                    return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
                }

                // Address Family.
                let af = buf.get_u16();
                *tlv_rlen -= 2;
                let af = match FromPrimitive::from_u16(af) {
                    Some(AddressFamily::Ipv4) => AddressFamily::Ipv4,
                    Some(AddressFamily::Ipv6) => AddressFamily::Ipv6,
                    _ => {
                        return Err(DecodeError::UnsupportedAf(
                            tlvi.clone(),
                            af,
                        ));
                    }
                };

                Ok(TypedWildcardFecElem::Prefix(af))
            }
            _ => Err(DecodeError::UnknownFec(tlvi.clone(), typed_wcard)),
        }
    }
}

// ===== impl TlvLabel =====

impl TlvKind for TlvLabel {
    const TLV_TYPE: TlvType = TlvType::GenericLabel;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0.get());
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let label = buf.get_u32();
        if label > *Label::UNRESERVED_RANGE.end()
            || (label < *Label::RESERVED_RANGE.end()
                && label != Label::IPV4_EXPLICIT_NULL
                && label != Label::IPV6_EXPLICIT_NULL
                && label != Label::IMPLICIT_NULL)
        {
            return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
        }

        Ok(Self(Label::new(label)))
    }
}

// ===== impl TlvLabelRequestId =====

impl TlvKind for TlvLabelRequestId {
    const TLV_TYPE: TlvType = TlvType::LabelRequestId;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let request_id = buf.get_u32();

        Ok(Self(request_id))
    }
}

// ===== global functions =====

// Calculate the number of bytes required to encode a prefix.
fn prefix_wire_len(len: u8) -> usize {
    (len as usize + 7) / 8
}
