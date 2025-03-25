use holo_utils::ip::AddressFamily;
use holo_utils::mpls::Label;

use super::*;

static LABEL_MAPPING_MSG1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x04, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x39, 0x01, 0x00, 0x00,
            0x08, 0x02, 0x00, 0x01, 0x20, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x10,
        ],
        LabelMsg {
            msg_id: 57,
            msg_type: LabelMessageType::LabelMapping,
            fec: TlvFec(vec![FecElem::Prefix(net!("1.1.1.1/32"))]),
            label: Some(TlvLabel(Label::new(16))),
            request_id: None,
        }
        .into(),
    )
});
static LABEL_MAPPING_MSG2: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x04, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x41, 0x01, 0x00, 0x00,
            0x14, 0x02, 0x00, 0x02, 0x80, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x12,
        ],
        LabelMsg {
            msg_id: 65,
            msg_type: LabelMessageType::LabelMapping,
            fec: TlvFec(vec![FecElem::Prefix(net!("2001:db8:1000::1/128"))]),
            label: Some(TlvLabel(Label::new(18))),
            request_id: None,
        }
        .into(),
    )
});
static LABEL_REQUEST_MSG1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x04, 0x01, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x41, 0x01, 0x00, 0x00,
            0x05, 0x05, 0x02, 0x02, 0x00, 0x01,
        ],
        LabelMsg {
            msg_id: 65,
            msg_type: LabelMessageType::LabelRequest,
            fec: TlvFec(vec![FecElem::Wildcard(FecElemWildcard::Typed(
                TypedWildcardFecElem::Prefix(AddressFamily::Ipv4),
            ))]),
            label: None,
            request_id: None,
        }
        .into(),
    )
});

#[test]
fn test_encode_label_mapping1() {
    let (ref bytes, ref msg) = *LABEL_MAPPING_MSG1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_label_mapping1() {
    let (ref bytes, ref msg) = *LABEL_MAPPING_MSG1;
    test_decode_msg(&IPV4_CXT, bytes, msg);
}

#[test]
fn test_encode_label_mapping2() {
    let (ref bytes, ref msg) = *LABEL_MAPPING_MSG2;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_label_mapping2() {
    let (ref bytes, ref msg) = *LABEL_MAPPING_MSG2;
    test_decode_msg(&IPV4_CXT, bytes, msg);
}

#[test]
fn test_encode_label_request1() {
    let (ref bytes, ref msg) = *LABEL_REQUEST_MSG1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_label_request1() {
    let (ref bytes, ref msg) = *LABEL_REQUEST_MSG1;
    test_decode_msg(&IPV4_CXT, bytes, msg);
}
