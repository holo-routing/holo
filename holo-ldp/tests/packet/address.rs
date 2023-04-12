use maplit::btreeset;

use super::*;

static ADDRESS_MSG1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x01, 0x00,
            0x0a, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x0a, 0x00, 0x01, 0x01,
        ],
        AddressMsg {
            msg_id: 10,
            msg_type: AddressMessageType::Address,
            addr_list: TlvAddressList::Ipv4(btreeset![
                Ipv4Addr::from_str("10.0.1.1").unwrap(),
                Ipv4Addr::from_str("1.1.1.1").unwrap(),
            ]),
        }
        .into(),
    )
});

static ADDRESS_MSG2: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x01, 0x00,
            0x42, 0x00, 0x02, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d,
            0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c,
            0xb5, 0xdb, 0xff, 0xfe, 0xd0, 0x3e, 0x5e, 0xfe, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x38, 0x04, 0xcf, 0xff, 0xfe, 0x6f, 0xce,
            0x5c,
        ],
        AddressMsg {
            msg_id: 11,
            msg_type: AddressMessageType::Address,
            addr_list: TlvAddressList::Ipv6(btreeset![
                Ipv6Addr::from_str("2001:db8:1000::1").unwrap(),
                Ipv6Addr::from_str("fe80::3804:cfff:fe6f:ce5c").unwrap(),
                Ipv6Addr::from_str("2001:db8:1::1").unwrap(),
                Ipv6Addr::from_str("fe80::2cb5:dbff:fed0:3e5e").unwrap(),
            ]),
        }
        .into(),
    )
});

#[test]
fn test_encode_address1() {
    let (ref bytes, ref msg) = *ADDRESS_MSG1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_address1() {
    let (ref bytes, ref msg) = *ADDRESS_MSG1;
    IPV4_CXT.with(|cxt| test_decode_msg(cxt, bytes, msg));
}

#[test]
fn test_encode_address2() {
    let (ref bytes, ref msg) = *ADDRESS_MSG2;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_address2() {
    let (ref bytes, ref msg) = *ADDRESS_MSG2;
    IPV4_CXT.with(|cxt| test_decode_msg(cxt, bytes, msg));
}
