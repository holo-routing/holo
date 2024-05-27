use std::hint::black_box;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use criterion::{criterion_group, criterion_main, Criterion};
use holo_bgp::packet::consts::{Afi, Safi, BGP_VERSION};
use holo_bgp::packet::message::{
    Capability, EncodeCxt, Message, NegotiatedCapability, OpenMsg,
};

static MESSAGE: Lazy<Message> = Lazy::new(|| {
    Message::Open(OpenMsg {
        version: BGP_VERSION,
        my_as: 1,
        holdtime: 180,
        identifier: Ipv4Addr::from_str("1.1.1.1").unwrap(),
        capabilities: [
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::MultiProtocol {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAsNumber { asn: 65550 },
            Capability::RouteRefresh,
            Capability::EnhancedRouteRefresh,
        ]
        .into(),
    })
});

fn msg_encode(n: u64) {
    let cxt = EncodeCxt {
        capabilities: [NegotiatedCapability::FourOctetAsNumber].into(),
    };

    for _ in 0..n {
        MESSAGE.encode(&cxt);
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Message encode", |b| {
        b.iter(|| msg_encode(black_box(10000)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
