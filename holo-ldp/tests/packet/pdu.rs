use std::collections::VecDeque;

use super::*;

static PDU1: Lazy<(Vec<u8>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0x00, 0x26, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x04,
            0x00, 0x0f, 0x20, 0x00, 0x04, 0x01, 0x00, 0x04, 0x01, 0x01, 0x01,
            0x01, 0x04, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02,
        ],
        Pdu {
            version: 1,
            lsr_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
            lspace_id: 0,
            messages: VecDeque::from(vec![Message::Hello(HelloMsg {
                msg_id: 1,
                params: TlvCommonHelloParams {
                    holdtime: 15,
                    flags: HelloFlags::GTSM,
                },
                ipv4_addr: Some(TlvIpv4TransAddr(
                    Ipv4Addr::from_str("1.1.1.1").unwrap(),
                )),
                ipv6_addr: None,
                cfg_seqno: Some(TlvConfigSeqNo(2)),
                dual_stack: None,
            })]),
        },
    )
});

#[test]
fn test_encode_pdu1() {
    let (ref bytes, ref pdu) = *PDU1;
    test_encode_pdu(bytes, pdu);
}

#[test]
fn test_decode_pdu1() {
    let (ref bytes, ref pdu) = *PDU1;
    IPV4_CXT.with(|cxt| test_decode_pdu(cxt, bytes, pdu));
}
