//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::ip::AddressFamily;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::message::{
    AddressMessageType, Message, MessageDecodeInfo, MessageKind, MessageType,
};
use crate::packet::tlv::{self, TlvDecodeInfo, TlvKind, TlvType};
use crate::packet::DecodeCxt;

//
// Address messages.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Address (0x0300)          |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                     Address List TLV                          |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Address Withdraw (0x0301) |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                     Address List TLV                          |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddressMsg {
    pub msg_id: u32,
    pub msg_type: AddressMessageType,
    pub addr_list: TlvAddressList,
}

//
// Address List TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|0| Address List (0x0101)     |      Length                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Address Family            |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
// |                                                               |
// |                        Addresses                              |
// ~                                                               ~
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TlvAddressList {
    Ipv4(BTreeSet<Ipv4Addr>),
    Ipv6(BTreeSet<Ipv6Addr>),
}

// ===== impl AddressMsg =====

impl MessageKind for AddressMsg {
    const U_BIT: bool = false;

    fn msg_id(&self) -> u32 {
        self.msg_id
    }

    fn msg_type(&self) -> MessageType {
        self.msg_type.into()
    }

    fn encode_body(&self, buf: &mut BytesMut) {
        // Encode mandatory TLV(s).
        self.addr_list.encode(self.msg_type(), buf);
    }

    fn decode_body(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        msgi: &mut MessageDecodeInfo,
    ) -> DecodeResult<Message> {
        // Decode mandatory TLV(s).
        let tlvi = tlv::decode_tlv_hdr(buf, msgi)?;
        if tlvi.tlv_type != TlvType::AddrList as u16 {
            return Err(DecodeError::MissingMsgParams(
                msgi.clone(),
                TlvType::AddrList,
            ));
        }
        let addr_list = TlvAddressList::decode_value(buf, cxt, &tlvi)?;

        // Create new message.
        let mut msg = AddressMsg {
            msg_type: AddressMessageType::from_u16(msgi.msg_type).unwrap(),
            msg_id: msgi.msg_id,
            addr_list,
        };

        // Decode optional TLV(s).
        msg.decode_opt_tlvs(buf, cxt, msgi)?;

        Ok(Message::Address(msg))
    }
}

// ===== impl TlvAddressList =====

impl TlvKind for TlvAddressList {
    const TLV_TYPE: TlvType = TlvType::AddrList;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        match self {
            TlvAddressList::Ipv4(addr_list) => {
                buf.put_u16(AddressFamily::Ipv4 as u16);
                for addr in addr_list {
                    buf.put_ipv4(addr);
                }
            }
            TlvAddressList::Ipv6(addr_list) => {
                buf.put_u16(AddressFamily::Ipv6 as u16);
                for addr in addr_list {
                    buf.put_ipv6(addr);
                }
            }
        }
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len < 4 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        // Parse address family identifier.
        let af = buf.get_u16();
        let af = match FromPrimitive::from_u16(af) {
            Some(AddressFamily::Ipv4) => AddressFamily::Ipv4,
            Some(AddressFamily::Ipv6) => AddressFamily::Ipv6,
            _ => return Err(DecodeError::UnsupportedAf(tlvi.clone(), af)),
        };

        // Parse list of addresses.
        let mut tlv_rlen = tlvi.tlv_len - 2;
        match af {
            AddressFamily::Ipv4 => {
                let mut addr_list = BTreeSet::new();
                while tlv_rlen > 0 {
                    if tlv_rlen < 4 {
                        return Err(DecodeError::InvalidTlvLength(
                            tlvi.tlv_len,
                        ));
                    }
                    let addr = buf.get_ipv4();
                    addr_list.insert(addr);
                    tlv_rlen -= 4;
                }
                Ok(TlvAddressList::Ipv4(addr_list))
            }
            AddressFamily::Ipv6 => {
                let mut addr_list = BTreeSet::new();
                while tlv_rlen > 0 {
                    if tlv_rlen < 16 {
                        return Err(DecodeError::InvalidTlvLength(
                            tlvi.tlv_len,
                        ));
                    }
                    let addr = buf.get_ipv6();
                    addr_list.insert(addr);
                    tlv_rlen -= 16;
                }
                Ok(TlvAddressList::Ipv6(addr_list))
            }
        }
    }
}
