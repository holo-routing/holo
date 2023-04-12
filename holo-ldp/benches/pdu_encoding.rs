#![feature(lazy_cell)]

use std::collections::VecDeque;
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use criterion::{criterion_group, criterion_main, Criterion};
use holo_ldp::packet::*;

static PDU: Lazy<Pdu> = Lazy::new(|| Pdu {
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
        cfg_seqno: Some(TlvConfigSeqNo(2)),
        ..Default::default()
    })]),
});

fn pdu_encode(n: u64) {
    for _ in 0..n {
        PDU.encode();
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("PDU encode", |b| b.iter(|| pdu_encode(black_box(10000))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
