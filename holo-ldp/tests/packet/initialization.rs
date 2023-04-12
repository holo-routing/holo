use super::*;

static INIT_MSG1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x35, 0x05, 0x00, 0x00,
            0x0e, 0x00, 0x01, 0x00, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x01, 0x01, 0x00, 0x00, 0x85, 0x06, 0x00, 0x01, 0x80, 0x85, 0x0b,
            0x00, 0x01, 0x80, 0x86, 0x03, 0x00, 0x01, 0x80,
        ],
        InitMsg {
            msg_id: 53,
            params: TlvCommonSessParams {
                version: 1,
                keepalive_time: 180,
                flags: InitFlags::empty(),
                pvlim: 0,
                max_pdu_len: 0,
                lsr_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                lspace_id: 0,
            },
            cap_dynamic: Some(TlvCapDynamic()),
            cap_twcard_fec: Some(TlvCapTwcardFec(true)),
            cap_unrec_notif: Some(TlvCapUnrecNotif(true)),
        }
        .into(),
    )
});

#[test]
fn test_encode_init1() {
    let (ref bytes, ref msg) = *INIT_MSG1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_init1() {
    let (ref bytes, ref msg) = *INIT_MSG1;
    IPV4_CXT.with(|cxt| test_decode_msg(cxt, bytes, msg));
}
