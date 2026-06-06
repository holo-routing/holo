use std::hint::black_box;
use std::sync::LazyLock as Lazy;

use const_addrs::ip4;
use criterion::{Criterion, criterion_group, criterion_main};
use holo_ospf::ospfv2::packet::iana::*;
use holo_ospf::ospfv2::packet::lsa::*;
use holo_ospf::ospfv2::packet::*;
use holo_ospf::packet::iana::*;
use holo_ospf::packet::lsa::*;
use holo_ospf::packet::*;
use holo_ospf::version::Ospfv2;

static PACKET: Lazy<Packet<Ospfv2>> = Lazy::new(|| {
    Packet::LsUpdate(LsUpdate {
        hdr: PacketHdr {
            pkt_type: PacketType::LsUpdate,
            router_id: ip4!("2.2.2.2"),
            area_id: ip4!("0.0.0.1"),
            auth_seqno: None,
        },
        lsas: vec![
            Lsa::new(
                49,
                Some(Options::E),
                ip4!("2.2.2.2"),
                ip4!("2.2.2.2"),
                0x80000002,
                LsaBody::Router(LsaRouter {
                    flags: LsaRouterFlags::B,
                    links: vec![LsaRouterLink {
                        link_type: LsaRouterLinkType::StubNetwork,
                        link_id: ip4!("10.0.1.0"),
                        link_data: ip4!("255.255.255.0"),
                        metric: 10,
                    }],
                }),
            ),
            Lsa::new(
                49,
                Some(Options::E),
                ip4!("2.2.2.2"),
                ip4!("2.2.2.2"),
                0x80000001,
                LsaBody::SummaryNetwork(LsaSummary {
                    mask: ip4!("255.255.255.255"),
                    metric: 0,
                }),
            ),
            Lsa::new(
                49,
                Some(Options::E),
                ip4!("10.0.2.0"),
                ip4!("2.2.2.2"),
                0x80000001,
                LsaBody::SummaryNetwork(LsaSummary {
                    mask: ip4!("255.255.255.0"),
                    metric: 10,
                }),
            ),
        ],
    })
});

fn packet_encode(n: u64) {
    for _ in 0..n {
        PACKET.encode(None);
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Packet encode", |b| {
        b.iter(|| packet_encode(black_box(10000)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
