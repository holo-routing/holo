#![feature(lazy_cell)]

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use criterion::{criterion_group, criterion_main, Criterion};
use holo_ospf::ospfv2::packet::lsa::*;
use holo_ospf::ospfv2::packet::*;
use holo_ospf::packet::lsa::*;
use holo_ospf::packet::*;
use holo_ospf::version::Ospfv2;

static PACKET: Lazy<Packet<Ospfv2>> = Lazy::new(|| {
    Packet::LsUpdate(LsUpdate {
        hdr: PacketHdr {
            pkt_type: PacketType::LsUpdate,
            router_id: Ipv4Addr::from_str("2.2.2.2").unwrap(),
            area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
        },
        lsas: vec![
            Lsa::new(
                49,
                Some(Options::E),
                Ipv4Addr::from_str("2.2.2.2").unwrap(),
                Ipv4Addr::from_str("2.2.2.2").unwrap(),
                0x80000002,
                LsaBody::Router(LsaRouter {
                    flags: LsaRouterFlags::B,
                    links: vec![LsaRouterLink {
                        link_type: LsaRouterLinkType::StubNetwork,
                        link_id: Ipv4Addr::from_str("10.0.1.0").unwrap(),
                        link_data: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                        metric: 10,
                    }],
                }),
            ),
            Lsa::new(
                49,
                Some(Options::E),
                Ipv4Addr::from_str("2.2.2.2").unwrap(),
                Ipv4Addr::from_str("2.2.2.2").unwrap(),
                0x80000001,
                LsaBody::SummaryNetwork(LsaSummary {
                    mask: Ipv4Addr::from_str("255.255.255.255").unwrap(),
                    metric: 0,
                }),
            ),
            Lsa::new(
                49,
                Some(Options::E),
                Ipv4Addr::from_str("10.0.2.0").unwrap(),
                Ipv4Addr::from_str("2.2.2.2").unwrap(),
                0x80000001,
                LsaBody::SummaryNetwork(LsaSummary {
                    mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                    metric: 10,
                }),
            ),
        ],
    })
});

fn packet_encode(n: u64) {
    for _ in 0..n {
        PACKET.encode();
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Packet encode", |b| {
        b.iter(|| packet_encode(black_box(10000)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
