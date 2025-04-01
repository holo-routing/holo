use super::*;

static NOTIFICATION_MSG1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x27, 0x03, 0x00, 0x00,
            0x0a, 0x80, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x1f, 0x04, 0x00,
        ],
        NotifMsg {
            msg_id: 39,
            status: TlvStatus {
                status_code: StatusCode::BadTlvLen.encode(false),
                msg_id: 31,
                msg_type: MessageType::LabelMapping as u16,
            },
            ext_status: None,
            returned_pdu: None,
            returned_msg: None,
            returned_tlvs: None,
            fec: None,
        }
        .into(),
    )
});

#[test]
fn test_encode_notification1() {
    let (ref bytes, ref msg) = *NOTIFICATION_MSG1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_notification1() {
    let (ref bytes, ref msg) = *NOTIFICATION_MSG1;
    test_decode_msg(&IPV4_CXT, bytes, msg);
}
