use super::*;

static HELLO_MSG1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x01, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00,
            0x04, 0x00, 0x0f, 0x20, 0x00, 0x04, 0x01, 0x00, 0x04, 0x01, 0x01,
            0x01, 0x01, 0x04, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02,
        ],
        HelloMsg {
            msg_id: 1,
            params: TlvCommonHelloParams {
                holdtime: 15,
                flags: HelloFlags::GTSM,
            },
            ipv4_addr: Some(TlvIpv4TransAddr(ip4!("1.1.1.1"))),
            ipv6_addr: None,
            cfg_seqno: Some(TlvConfigSeqNo(2)),
            dual_stack: None,
        }
        .into(),
    )
});
static HELLO_MSG2: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x01, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x02, 0x04, 0x00, 0x00,
            0x04, 0x00, 0x0f, 0x00, 0x00, 0x04, 0x03, 0x00, 0x10, 0x20, 0x01,
            0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x04, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02,
            0x87, 0x01, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00,
        ],
        HelloMsg {
            msg_id: 2,
            params: TlvCommonHelloParams {
                holdtime: 15,
                flags: HelloFlags::empty(),
            },
            ipv4_addr: None,
            ipv6_addr: Some(TlvIpv6TransAddr(ip6!("2001:db8:1000::1"))),
            cfg_seqno: Some(TlvConfigSeqNo(2)),
            dual_stack: Some(TlvDualStack(TransportPref::LDPOIPV6)),
        }
        .into(),
    )
});

#[test]
fn test_encode_hello1() {
    let (ref bytes, ref msg) = *HELLO_MSG1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_hello1() {
    let (ref bytes, ref msg) = *HELLO_MSG1;
    IPV4_CXT.with(|cxt| test_decode_msg(cxt, bytes, msg));
}

#[test]
fn test_encode_hello2() {
    let (ref bytes, ref msg) = *HELLO_MSG2;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_hello2() {
    let (ref bytes, ref msg) = *HELLO_MSG2;
    IPV6_CXT.with(|cxt| test_decode_msg(cxt, bytes, msg));
}
