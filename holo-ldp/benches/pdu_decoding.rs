use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock as Lazy;

use criterion::{criterion_group, criterion_main, Criterion};
use holo_ldp::packet::*;

static DECODE_CTX: Lazy<DecodeCxt> = Lazy::new(|| DecodeCxt {
    pkt_info: PacketInfo {
        src_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        multicast: None,
    },
    pdu_max_len: Pdu::DFLT_MAX_LEN,
    validate_pdu_hdr: None,
    validate_msg_hdr: None,
});

fn pdu_decode(n: u64) {
    let bytes = vec![
        0x00, 0x01, 0x00, 0x26, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x04, 0x00, 0x0f,
        0x20, 0x00, 0x04, 0x01, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, 0x04, 0x02,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x02,
    ];

    for _ in 0..n {
        let _pdu_size = Pdu::get_pdu_size(&bytes, &DECODE_CTX).unwrap();
        Pdu::decode(&bytes, &DECODE_CTX).unwrap();
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("PDU decode", |b| b.iter(|| pdu_decode(black_box(10000))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
