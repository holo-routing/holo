//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::sync::LazyLock as Lazy;

use const_addrs::{ip4, ip6, net4, net6};
use holo_isis::packet::pdu::{Lsp, LspFlags, LspTlvs, Pdu};
use holo_isis::packet::subtlvs::MsdStlv;
use holo_isis::packet::subtlvs::capability::{
    LabelBlockEntry, NodeAdminTagStlv, SrAlgoStlv, SrCapabilitiesFlags,
    SrCapabilitiesStlv, SrLocalBlockStlv,
};
use holo_isis::packet::subtlvs::neighbor::{
    AdjSidFlags, AdjSidStlv, AdminGroupStlv, Ipv4InterfaceAddrStlv,
    Ipv4NeighborAddrStlv, MaxLinkBwStlv, MaxResvLinkBwStlv,
    TeDefaultMetricStlv, UnreservedBwStlv,
};
use holo_isis::packet::subtlvs::prefix::{
    Ipv4SourceRidStlv, Ipv6SourceRidStlv, PrefixAttrFlags, PrefixAttrFlagsStlv,
    PrefixSidFlags, PrefixSidStlv,
};
use holo_isis::packet::tlv::{
    AreaAddressesTlv, DynamicHostnameTlv, Ipv4AddressesTlv, Ipv4Reach,
    Ipv4ReachStlvs, Ipv4ReachTlv, Ipv4RouterIdTlv, Ipv6AddressesTlv, Ipv6Reach,
    Ipv6ReachStlvs, Ipv6ReachTlv, Ipv6RouterIdTlv, IsReach, IsReachStlvs,
    IsReachTlv, LegacyIpv4Reach, LegacyIpv4ReachTlv, LegacyIsReach,
    LegacyIsReachTlv, LspBufferSizeTlv, MtFlags, MultiTopologyEntry,
    MultiTopologyTlv, ProtocolsSupportedTlv, PurgeOriginatorIdTlv,
    RouterCapFlags, RouterCapStlvs, RouterCapTlv,
};
use holo_isis::packet::{AreaAddr, LanId, LevelNumber, LspId, SystemId};
use holo_utils::keychain::Key;
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use maplit::btreemap;

use super::{KEY_HMAC_MD5, KEY_HMAC_SHA256, test_decode_pdu, test_encode_pdu};

//
// Test packets.
//

static LSP1: Lazy<(Vec<u8>, Option<&Key>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x83, 0x1b, 0x01, 0x00, 0x12, 0x01, 0x00, 0x00, 0x01, 0x6a, 0x04,
            0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x4e, 0xaa, 0x01, 0x81, 0x01, 0xcc, 0xf2, 0x30, 0x01,
            0x01, 0x01, 0x01, 0x00, 0x02, 0x09, 0xc0, 0x00, 0x1f, 0x40, 0x01,
            0x03, 0x00, 0x3e, 0x80, 0x13, 0x01, 0x00, 0x16, 0x09, 0x00, 0x00,
            0x03, 0xe8, 0x01, 0x03, 0x00, 0x3a, 0x98, 0x17, 0x02, 0x01, 0x10,
            0x15, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x03, 0x01, 0x04, 0x03, 0x49, 0x00, 0x00, 0x16, 0x61,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x0a, 0x56,
            0x03, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x06, 0x04, 0x0a, 0x00, 0x01,
            0x01, 0x08, 0x04, 0x0a, 0x00, 0x01, 0x02, 0x09, 0x04, 0x4c, 0xee,
            0x6b, 0x28, 0x0a, 0x04, 0x4b, 0x3e, 0xbc, 0x20, 0x0b, 0x20, 0x4b,
            0x3e, 0xbc, 0x20, 0x4b, 0x3e, 0xbc, 0x20, 0x4b, 0x3e, 0xbc, 0x20,
            0x4b, 0x3e, 0xbc, 0x20, 0x4b, 0x3e, 0xbc, 0x20, 0x4b, 0x3e, 0xbc,
            0x20, 0x4b, 0x3e, 0xbc, 0x20, 0x4b, 0x3e, 0xbc, 0x20, 0x12, 0x03,
            0x00, 0x00, 0x64, 0x20, 0x0b, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x3a, 0x98, 0x0f, 0x02, 0x01, 0x10, 0x84, 0x04,
            0x01, 0x01, 0x01, 0x01, 0x87, 0x35, 0x00, 0x00, 0x00, 0x0a, 0x58,
            0x0a, 0x00, 0x01, 0x23, 0x04, 0x01, 0x40, 0x0b, 0x04, 0x01, 0x01,
            0x01, 0x01, 0x0c, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x06,
            0x40, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0a, 0x20,
            0x01, 0x01, 0x01, 0x01, 0x86, 0x04, 0x01, 0x01, 0x01, 0x01, 0xe8,
            0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xec, 0x48, 0x00, 0x00, 0x00,
            0x0a, 0x20, 0x80, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x04, 0x01,
            0x20, 0x0b, 0x04, 0x01, 0x01, 0x01, 0x01, 0x0c, 0x10, 0x20, 0x01,
            0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x03, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x0b,
            0x00, 0x00, 0x00, 0x0a, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x10,
            0x00, 0x00, 0x00, 0x8c, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ],
        None,
        Pdu::Lsp(Lsp::new(
            LevelNumber::L1,
            1170,
            LspId::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
            0x00000004,
            LspFlags::IS_TYPE1,
            LspTlvs {
                auth: None,
                protocols_supported: Some(ProtocolsSupportedTlv {
                    list: vec![0xcc],
                }),
                router_cap: vec![RouterCapTlv {
                    router_id: Some(ip4!("1.1.1.1")),
                    flags: RouterCapFlags::empty(),
                    sub_tlvs: RouterCapStlvs {
                        sr_cap: Some(SrCapabilitiesStlv::new(
                            SrCapabilitiesFlags::I | SrCapabilitiesFlags::V,
                            vec![LabelBlockEntry::new(
                                8000,
                                Sid::Label(Label::new(16000)),
                            )],
                        )),
                        sr_algo: Some(SrAlgoStlv::new(
                            [IgpAlgoType::Spf].into(),
                        )),
                        srlb: Some(SrLocalBlockStlv::new(vec![
                            LabelBlockEntry::new(
                                1000,
                                Sid::Label(Label::new(15000)),
                            ),
                        ])),
                        node_msd: Some(MsdStlv::new(btreemap! { 1 => 16 })),
                        node_tags: vec![NodeAdminTagStlv::new(
                            [1, 2, 3].into(),
                        )],
                        ..Default::default()
                    },
                }],
                area_addrs: vec![AreaAddressesTlv {
                    list: vec![AreaAddr::from([0x49, 0, 0].as_slice())],
                }],
                multi_topology: vec![],
                purge_originator_id: None,
                hostname: None,
                lsp_buf_size: None,
                is_reach: vec![],
                ext_is_reach: vec![IsReachTlv {
                    mt_id: None,
                    list: vec![IsReach {
                        neighbor: LanId::from([
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
                        ]),
                        metric: 10,
                        sub_tlvs: IsReachStlvs {
                            admin_group: Some(AdminGroupStlv::new(0x0f)),
                            ipv4_interface_addr: vec![
                                Ipv4InterfaceAddrStlv::new(ip4!("10.0.1.1")),
                            ],
                            ipv4_neighbor_addr: vec![
                                Ipv4NeighborAddrStlv::new(ip4!("10.0.1.2")),
                            ],
                            max_link_bw: Some(MaxLinkBwStlv::new(125000000.0)),
                            max_resv_link_bw: Some(MaxResvLinkBwStlv::new(
                                12500000.0,
                            )),
                            unreserved_bw: Some(UnreservedBwStlv::new([
                                12500000.0, 12500000.0, 12500000.0, 12500000.0,
                                12500000.0, 12500000.0, 12500000.0, 12500000.0,
                            ])),
                            te_default_metric: Some(TeDefaultMetricStlv::new(
                                100,
                            )),
                            adj_sids: vec![AdjSidStlv {
                                flags: AdjSidFlags::V | AdjSidFlags::L,
                                weight: 0,
                                nbr_system_id: Some(SystemId::from([
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                ])),
                                sid: Sid::Label(Label::new(15000)),
                            }],
                            link_msd: Some(MsdStlv::new(btreemap! { 1 => 16 })),
                            unknown: vec![],
                        },
                    }],
                }],
                mt_is_reach: vec![],
                ipv4_addrs: vec![Ipv4AddressesTlv {
                    list: vec![ip4!("1.1.1.1")],
                }],
                ipv4_internal_reach: vec![],
                ipv4_external_reach: vec![],
                ext_ipv4_reach: vec![Ipv4ReachTlv {
                    mt_id: None,
                    list: vec![
                        Ipv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("10.0.1.0/24"),
                            sub_tlvs: Ipv4ReachStlvs {
                                prefix_attr_flags: Some(
                                    PrefixAttrFlagsStlv::new(
                                        PrefixAttrFlags::R,
                                    ),
                                ),
                                ipv4_source_rid: Some(Ipv4SourceRidStlv::new(
                                    ip4!("1.1.1.1"),
                                )),
                                ipv6_source_rid: Some(Ipv6SourceRidStlv::new(
                                    ip6!("2001:db8::1"),
                                )),
                                prefix_sids: btreemap! {
                                    IgpAlgoType::Spf => {
                                        PrefixSidStlv {
                                            flags: PrefixSidFlags::N,
                                            algo: IgpAlgoType::Spf,
                                            sid: Sid::Index(10),
                                        }
                                    }
                                },
                                ..Default::default()
                            },
                        },
                        Ipv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("1.1.1.1/32"),
                            sub_tlvs: Default::default(),
                        },
                    ],
                }],
                mt_ipv4_reach: vec![],
                ipv4_router_id: Some(Ipv4RouterIdTlv::new(ip4!("1.1.1.1"))),
                ipv6_addrs: vec![Ipv6AddressesTlv {
                    list: vec![ip6!("2001:db8::1")],
                }],
                ipv6_reach: vec![Ipv6ReachTlv {
                    mt_id: None,
                    list: vec![
                        Ipv6Reach {
                            metric: 10,
                            up_down: false,
                            external: false,
                            prefix: net6!("2001:db8::1/128"),
                            sub_tlvs: Ipv6ReachStlvs {
                                prefix_attr_flags: Some(
                                    PrefixAttrFlagsStlv::new(
                                        PrefixAttrFlags::N,
                                    ),
                                ),
                                ipv4_source_rid: Some(Ipv4SourceRidStlv::new(
                                    ip4!("1.1.1.1"),
                                )),
                                ipv6_source_rid: Some(Ipv6SourceRidStlv::new(
                                    ip6!("2001:db8::1"),
                                )),
                                prefix_sids: btreemap! {
                                    IgpAlgoType::Spf => {
                                        PrefixSidStlv {
                                            flags: PrefixSidFlags::N,
                                            algo: IgpAlgoType::Spf,
                                            sid: Sid::Index(11),
                                        }
                                    }
                                },
                                ..Default::default()
                            },
                        },
                        Ipv6Reach {
                            metric: 10,
                            up_down: false,
                            external: false,
                            prefix: net6!("2001:db8:1000::0/64"),
                            sub_tlvs: Default::default(),
                        },
                    ],
                }],
                mt_ipv6_reach: vec![],
                ipv6_router_id: Some(Ipv6RouterIdTlv::new(ip6!("2001:db8::1"))),
                unknown: vec![],
            },
            None,
        )),
    )
});

static LSP2: Lazy<(Vec<u8>, Option<&Key>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x83, 0x1b, 0x01, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00, 0x8d, 0x04,
            0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x13, 0xb3, 0x9b, 0x01, 0x81, 0x01, 0xcc, 0x01, 0x04, 0x03,
            0x49, 0x00, 0x00, 0x89, 0x04, 0x68, 0x6f, 0x6c, 0x6f, 0x0e, 0x02,
            0x05, 0xd4, 0x02, 0x17, 0x00, 0x0a, 0x80, 0x80, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x80, 0x80, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x84, 0x04, 0x06, 0x06, 0x06, 0x06,
            0x80, 0x24, 0x0a, 0x80, 0x80, 0x80, 0x0a, 0x00, 0x07, 0x00, 0xff,
            0xff, 0xff, 0x00, 0x0a, 0x80, 0x80, 0x80, 0x0a, 0x00, 0x08, 0x00,
            0xff, 0xff, 0xff, 0x00, 0x0a, 0x80, 0x80, 0x80, 0x06, 0x06, 0x06,
            0x06, 0xff, 0xff, 0xff, 0xff, 0x82, 0x18, 0x0a, 0x80, 0x80, 0x80,
            0xac, 0x10, 0x01, 0x00, 0xff, 0xff, 0xff, 0x00, 0x4a, 0x80, 0x80,
            0x80, 0xac, 0x10, 0x02, 0x00, 0xff, 0xff, 0xff, 0x00,
        ],
        None,
        Pdu::Lsp(Lsp::new(
            LevelNumber::L1,
            1187,
            LspId::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00]),
            0x00000013,
            LspFlags::IS_TYPE1,
            LspTlvs {
                auth: None,
                protocols_supported: Some(ProtocolsSupportedTlv {
                    list: vec![0xcc],
                }),
                router_cap: vec![],
                area_addrs: vec![AreaAddressesTlv {
                    list: vec![AreaAddr::from([0x49, 0, 0].as_slice())],
                }],
                multi_topology: vec![],
                purge_originator_id: None,
                hostname: Some(DynamicHostnameTlv {
                    hostname: "holo".to_owned(),
                }),
                lsp_buf_size: Some(LspBufferSizeTlv { size: 1492 }),
                is_reach: vec![LegacyIsReachTlv {
                    list: vec![
                        LegacyIsReach {
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            neighbor: LanId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
                            ]),
                        },
                        LegacyIsReach {
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            neighbor: LanId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
                            ]),
                        },
                    ],
                }],
                ext_is_reach: vec![],
                mt_is_reach: vec![],
                ipv4_addrs: vec![Ipv4AddressesTlv {
                    list: vec![ip4!("6.6.6.6")],
                }],
                ipv4_internal_reach: vec![LegacyIpv4ReachTlv {
                    list: vec![
                        LegacyIpv4Reach {
                            up_down: false,
                            ie_bit: false,
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            prefix: net4!("10.0.7.0/24"),
                        },
                        LegacyIpv4Reach {
                            up_down: false,
                            ie_bit: false,
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            prefix: net4!("10.0.8.0/24"),
                        },
                        LegacyIpv4Reach {
                            up_down: false,
                            ie_bit: false,
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            prefix: net4!("6.6.6.6/32"),
                        },
                    ],
                }],
                ipv4_external_reach: vec![LegacyIpv4ReachTlv {
                    list: vec![
                        LegacyIpv4Reach {
                            up_down: false,
                            ie_bit: false,
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            prefix: net4!("172.16.1.0/24"),
                        },
                        LegacyIpv4Reach {
                            up_down: false,
                            ie_bit: true,
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            prefix: net4!("172.16.2.0/24"),
                        },
                    ],
                }],
                ext_ipv4_reach: vec![],
                mt_ipv4_reach: vec![],
                ipv4_router_id: None,
                ipv6_addrs: vec![],
                ipv6_reach: vec![],
                mt_ipv6_reach: vec![],
                ipv6_router_id: None,
                unknown: vec![],
            },
            None,
        )),
    )
});

static LSP3_HMAC_MD5: Lazy<(Vec<u8>, Option<&Key>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x83, 0x1b, 0x01, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00, 0x5d, 0x04,
            0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0xd5, 0x41, 0x01, 0x0a, 0x11, 0x36, 0xcf, 0xab, 0x8f,
            0xed, 0xdf, 0xeb, 0xb5, 0x7e, 0xf0, 0xf7, 0x84, 0x23, 0x6f, 0xf8,
            0x37, 0x17, 0x81, 0x01, 0xcc, 0x01, 0x04, 0x03, 0x49, 0x00, 0x00,
            0x16, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00,
            0x0a, 0x00, 0x84, 0x04, 0x01, 0x01, 0x01, 0x01, 0x87, 0x11, 0x00,
            0x00, 0x00, 0x0a, 0x18, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a,
            0x20, 0x01, 0x01, 0x01, 0x01,
        ],
        Some(&KEY_HMAC_MD5),
        Pdu::Lsp(Lsp::new(
            LevelNumber::L1,
            1170,
            LspId::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
            0x00000004,
            LspFlags::IS_TYPE1,
            LspTlvs {
                auth: None,
                protocols_supported: Some(ProtocolsSupportedTlv {
                    list: vec![0xcc],
                }),
                router_cap: vec![],
                area_addrs: vec![AreaAddressesTlv {
                    list: vec![AreaAddr::from([0x49, 0, 0].as_slice())],
                }],
                multi_topology: vec![],
                purge_originator_id: None,
                hostname: None,
                lsp_buf_size: None,
                is_reach: vec![],
                ext_is_reach: vec![IsReachTlv {
                    mt_id: None,
                    list: vec![IsReach {
                        neighbor: LanId::from([
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
                        ]),
                        metric: 10,
                        sub_tlvs: Default::default(),
                    }],
                }],
                mt_is_reach: vec![],
                ipv4_addrs: vec![Ipv4AddressesTlv {
                    list: vec![ip4!("1.1.1.1")],
                }],
                ipv4_internal_reach: vec![],
                ipv4_external_reach: vec![],
                ext_ipv4_reach: vec![Ipv4ReachTlv {
                    mt_id: None,
                    list: vec![
                        Ipv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("10.0.1.0/24"),
                            sub_tlvs: Default::default(),
                        },
                        Ipv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("1.1.1.1/32"),
                            sub_tlvs: Default::default(),
                        },
                    ],
                }],
                mt_ipv4_reach: vec![],
                ipv4_router_id: None,
                ipv6_addrs: vec![],
                ipv6_reach: vec![],
                mt_ipv6_reach: vec![],
                ipv6_router_id: None,
                unknown: vec![],
            },
            Some(&KEY_HMAC_MD5),
        )),
    )
});

static LSP3_HMAC_SHA256: Lazy<(Vec<u8>, Option<&Key>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x83, 0x1b, 0x01, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00, 0x6f, 0x04,
            0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x77, 0xa6, 0x01, 0x0a, 0x23, 0x03, 0x00, 0x01, 0xc2,
            0xd4, 0x57, 0xfb, 0xb0, 0x6b, 0xfe, 0x01, 0xec, 0x91, 0x30, 0x27,
            0xa2, 0x9e, 0xd1, 0xbd, 0xe3, 0x07, 0x74, 0xe5, 0x71, 0x87, 0xeb,
            0x78, 0x6c, 0x8f, 0xb0, 0x4c, 0xad, 0x46, 0x65, 0xb6, 0x81, 0x01,
            0xcc, 0x01, 0x04, 0x03, 0x49, 0x00, 0x00, 0x16, 0x0b, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x0a, 0x00, 0x84, 0x04,
            0x01, 0x01, 0x01, 0x01, 0x87, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x18,
            0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x20, 0x01, 0x01, 0x01,
            0x01,
        ],
        Some(&KEY_HMAC_SHA256),
        Pdu::Lsp(Lsp::new(
            LevelNumber::L1,
            1170,
            LspId::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
            0x00000004,
            LspFlags::IS_TYPE1,
            LspTlvs {
                auth: None,
                protocols_supported: Some(ProtocolsSupportedTlv {
                    list: vec![0xcc],
                }),
                router_cap: vec![],
                area_addrs: vec![AreaAddressesTlv {
                    list: vec![AreaAddr::from([0x49, 0, 0].as_slice())],
                }],
                multi_topology: vec![],
                purge_originator_id: None,
                hostname: None,
                lsp_buf_size: None,
                is_reach: vec![],
                ext_is_reach: vec![IsReachTlv {
                    mt_id: None,
                    list: vec![IsReach {
                        neighbor: LanId::from([
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
                        ]),
                        metric: 10,
                        sub_tlvs: Default::default(),
                    }],
                }],
                mt_is_reach: vec![],
                ipv4_addrs: vec![Ipv4AddressesTlv {
                    list: vec![ip4!("1.1.1.1")],
                }],
                ipv4_internal_reach: vec![],
                ipv4_external_reach: vec![],
                ext_ipv4_reach: vec![Ipv4ReachTlv {
                    mt_id: None,
                    list: vec![
                        Ipv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("10.0.1.0/24"),
                            sub_tlvs: Default::default(),
                        },
                        Ipv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("1.1.1.1/32"),
                            sub_tlvs: Default::default(),
                        },
                    ],
                }],
                mt_ipv4_reach: vec![],
                ipv4_router_id: None,
                ipv6_addrs: vec![],
                ipv6_reach: vec![],
                mt_ipv6_reach: vec![],
                ipv6_router_id: None,
                unknown: vec![],
            },
            Some(&KEY_HMAC_SHA256),
        )),
    )
});

static LSP4: Lazy<(Vec<u8>, Option<&Key>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x83, 0x1b, 0x01, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00, 0x9a, 0x04,
            0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x3a, 0x4b, 0x01, 0x81, 0x02, 0xcc, 0x8e, 0x01, 0x04,
            0x03, 0x49, 0x00, 0x00, 0xe5, 0x04, 0x00, 0x00, 0x00, 0x02, 0x16,
            0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x0a,
            0x00, 0xde, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x03, 0x00, 0x00, 0x0a, 0x00, 0x84, 0x04, 0x01, 0x01, 0x01, 0x01,
            0x87, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x18, 0x0a, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x0a, 0x20, 0x01, 0x01, 0x01, 0x01, 0xe8, 0x10, 0x20,
            0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0xed, 0x26, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x0a, 0x00, 0x80, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x0a, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00,
        ],
        None,
        Pdu::Lsp(Lsp::new(
            LevelNumber::L1,
            1170,
            LspId::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
            0x00000004,
            LspFlags::IS_TYPE1,
            LspTlvs {
                auth: None,
                protocols_supported: Some(ProtocolsSupportedTlv {
                    list: vec![0xcc, 0x8e],
                }),
                router_cap: vec![],
                area_addrs: vec![AreaAddressesTlv {
                    list: vec![AreaAddr::from([0x49, 0, 0].as_slice())],
                }],
                multi_topology: vec![MultiTopologyTlv {
                    list: vec![
                        MultiTopologyEntry {
                            flags: MtFlags::empty(),
                            mt_id: 0,
                        },
                        MultiTopologyEntry {
                            flags: MtFlags::empty(),
                            mt_id: 2,
                        },
                    ],
                }],
                purge_originator_id: None,
                hostname: None,
                lsp_buf_size: None,
                is_reach: vec![],
                ext_is_reach: vec![IsReachTlv {
                    mt_id: None,
                    list: vec![IsReach {
                        neighbor: LanId::from([
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
                        ]),
                        metric: 10,
                        sub_tlvs: Default::default(),
                    }],
                }],
                mt_is_reach: vec![IsReachTlv {
                    mt_id: Some(2),
                    list: vec![IsReach {
                        neighbor: LanId::from([
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
                        ]),
                        metric: 10,
                        sub_tlvs: Default::default(),
                    }],
                }],
                ipv4_addrs: vec![Ipv4AddressesTlv {
                    list: vec![ip4!("1.1.1.1")],
                }],
                ipv4_internal_reach: vec![],
                ipv4_external_reach: vec![],
                ext_ipv4_reach: vec![Ipv4ReachTlv {
                    mt_id: None,
                    list: vec![
                        Ipv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("10.0.1.0/24"),
                            sub_tlvs: Default::default(),
                        },
                        Ipv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("1.1.1.1/32"),
                            sub_tlvs: Default::default(),
                        },
                    ],
                }],
                mt_ipv4_reach: vec![],
                ipv4_router_id: None,
                ipv6_addrs: vec![Ipv6AddressesTlv {
                    list: vec![ip6!("2001:db8::1")],
                }],
                ipv6_reach: vec![],
                mt_ipv6_reach: vec![Ipv6ReachTlv {
                    mt_id: Some(2),
                    list: vec![
                        Ipv6Reach {
                            metric: 10,
                            up_down: false,
                            external: false,
                            prefix: net6!("2001:db8::1/128"),
                            sub_tlvs: Default::default(),
                        },
                        Ipv6Reach {
                            metric: 10,
                            up_down: false,
                            external: false,
                            prefix: net6!("2001:db8:1000::0/64"),
                            sub_tlvs: Default::default(),
                        },
                    ],
                }],
                ipv6_router_id: None,
                unknown: vec![],
            },
            None,
        )),
    )
});

static LSP5: Lazy<(Vec<u8>, Option<&Key>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x83, 0x1b, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x30, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05, 0xd4, 0xc0, 0x02, 0x0d, 0x0d, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x89, 0x04,
            0x68, 0x6f, 0x6c, 0x6f,
        ],
        None,
        Pdu::Lsp(Lsp::new(
            LevelNumber::L2,
            0,
            LspId::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
            0x00000005,
            LspFlags::IS_TYPE2,
            LspTlvs {
                auth: None,
                protocols_supported: None,
                router_cap: vec![],
                area_addrs: vec![],
                multi_topology: vec![],
                purge_originator_id: Some(PurgeOriginatorIdTlv {
                    system_id: SystemId::from([
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                    ]),
                    system_id_rcvd: Some(SystemId::from([
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                    ])),
                }),
                hostname: Some(DynamicHostnameTlv {
                    hostname: "holo".to_owned(),
                }),
                lsp_buf_size: None,
                is_reach: vec![],
                ext_is_reach: vec![],
                mt_is_reach: vec![],
                ipv4_addrs: vec![],
                ipv4_internal_reach: vec![],
                ipv4_external_reach: vec![],
                ext_ipv4_reach: vec![],
                mt_ipv4_reach: vec![],
                ipv4_router_id: None,
                ipv6_addrs: vec![],
                ipv6_reach: vec![],
                mt_ipv6_reach: vec![],
                ipv6_router_id: None,
                unknown: vec![],
            },
            None,
        )),
    )
});

//
// Tests.
//

#[test]
fn test_encode_lsp1() {
    let (ref bytes, ref auth, ref lsp) = *LSP1;
    test_encode_pdu(bytes, lsp, auth);
}

#[test]
fn test_decode_lsp1() {
    let (ref bytes, ref auth, ref lsp) = *LSP1;
    test_decode_pdu(bytes, lsp, auth);
}

#[test]
fn test_encode_lsp2() {
    let (ref bytes, ref auth, ref lsp) = *LSP2;
    test_encode_pdu(bytes, lsp, auth);
}

#[test]
fn test_decode_lsp2() {
    let (ref bytes, ref auth, ref lsp) = *LSP2;
    test_decode_pdu(bytes, lsp, auth);
}

#[test]
fn test_encode_lsp3_hmac_md5() {
    let (ref bytes, ref auth, ref lsp) = *LSP3_HMAC_MD5;
    test_encode_pdu(bytes, lsp, auth);
}

#[test]
fn test_decode_lsp3_hmac_md5() {
    let (ref bytes, ref auth, ref lsp) = *LSP3_HMAC_MD5;
    test_decode_pdu(bytes, lsp, auth);
}

#[test]
fn test_encode_lsp3_hmac_sha256() {
    let (ref bytes, ref auth, ref lsp) = *LSP3_HMAC_SHA256;
    test_encode_pdu(bytes, lsp, auth);
}

#[test]
fn test_decode_lsp3_hmac_sha256() {
    let (ref bytes, ref auth, ref lsp) = *LSP3_HMAC_SHA256;
    test_decode_pdu(bytes, lsp, auth);
}

#[test]
fn test_encode_lsp4() {
    let (ref bytes, ref auth, ref lsp) = *LSP4;
    test_encode_pdu(bytes, lsp, auth);
}

#[test]
fn test_decode_lsp4() {
    let (ref bytes, ref auth, ref lsp) = *LSP4;
    test_decode_pdu(bytes, lsp, auth);
}

#[test]
fn test_encode_lsp5() {
    let (ref bytes, ref auth, ref lsp) = *LSP5;
    test_encode_pdu(bytes, lsp, auth);
}

#[test]
fn test_decode_lsp5() {
    let (ref bytes, ref auth, ref lsp) = *LSP5;
    test_decode_pdu(bytes, lsp, auth);
}
