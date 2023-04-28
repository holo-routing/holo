//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

mod address;
mod capability;
mod hello;
mod keepalive;
mod label;
mod notification;
mod pdu;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use bytes::{Bytes, BytesMut};
use holo_ldp::packet::*;
use ipnetwork::IpNetwork;

thread_local! {
    static IPV4_CXT: DecodeCxt = DecodeCxt {
        pkt_info: PacketInfo {
            src_addr: IpAddr::from_str("1.1.1.1").unwrap(),
            multicast: None,
        },
        pdu_max_len: Pdu::DFLT_MAX_LEN,
        validate_pdu_hdr: None,
        validate_msg_hdr: None,
    };
    static IPV6_CXT: DecodeCxt = DecodeCxt {
        pkt_info: PacketInfo {
            src_addr: IpAddr::from_str("2001:db8:1000::1").unwrap(),
            multicast: None,
        },
        pdu_max_len: Pdu::DFLT_MAX_LEN,
        validate_pdu_hdr: None,
        validate_msg_hdr: None,
    };
}

//
// Helper functions.
//

fn test_encode_msg(bytes_expected: &[u8], msg: &Message) {
    let mut bytes_actual = BytesMut::with_capacity(1500);
    msg.encode(&mut bytes_actual);
    assert_eq!(bytes_expected, bytes_actual.as_ref());
}

fn test_decode_msg(cxt: &DecodeCxt, bytes: &[u8], msg_expected: &Message) {
    let mut buf = Bytes::copy_from_slice(&bytes);

    // Create fake PDU decode information, required to decode LDP messages.
    let len = buf.len() as u16;
    let mut pdui = PduDecodeInfo {
        version: Pdu::VERSION,
        lsr_id: Ipv4Addr::new(1, 1, 1, 1),
        lspace_id: 0,
        pdu_raw: Bytes::new(),
        pdu_len: len,
        pdu_rlen: len,
    };

    let msg_actual =
        Message::decode(&mut buf, &cxt, &mut pdui).unwrap().unwrap();
    assert_eq!(pdui.pdu_rlen, 0);
    assert_eq!(*msg_expected, msg_actual);
}

fn test_encode_pdu(bytes_expected: &[u8], pdu: &Pdu) {
    let bytes_actual = pdu.encode(Pdu::DFLT_MAX_LEN);
    assert_eq!(bytes_expected, bytes_actual.as_ref());
}

fn test_decode_pdu(cxt: &DecodeCxt, bytes: &[u8], pdu_expected: &Pdu) {
    let _pdu_size = Pdu::get_pdu_size(&bytes, cxt).unwrap();
    let pdu_actual = Pdu::decode(&bytes, &cxt).unwrap();
    assert_eq!(*pdu_expected, pdu_actual);
}
