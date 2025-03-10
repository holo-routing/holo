use super::*;

//
// Test packets.
//

static LSP1: Lazy<(Vec<u8>, Option<&Key>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x83, 0x1b, 0x01, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00, 0xdf, 0x04,
            0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x66, 0x91, 0x01, 0x81, 0x01, 0xcc, 0x01, 0x04, 0x03,
            0x49, 0x00, 0x00, 0x16, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x03, 0x00, 0x00, 0x0a, 0x45, 0x03, 0x04, 0x00, 0x00, 0x00, 0x0f,
            0x06, 0x04, 0x0a, 0x00, 0x01, 0x01, 0x08, 0x04, 0x0a, 0x00, 0x01,
            0x02, 0x09, 0x04, 0x4c, 0xee, 0x6b, 0x28, 0x0a, 0x04, 0x4b, 0x3e,
            0xbc, 0x20, 0x0b, 0x20, 0x4b, 0x3e, 0xbc, 0x20, 0x4b, 0x3e, 0xbc,
            0x20, 0x4b, 0x3e, 0xbc, 0x20, 0x4b, 0x3e, 0xbc, 0x20, 0x4b, 0x3e,
            0xbc, 0x20, 0x4b, 0x3e, 0xbc, 0x20, 0x4b, 0x3e, 0xbc, 0x20, 0x4b,
            0x3e, 0xbc, 0x20, 0x12, 0x03, 0x00, 0x00, 0x64, 0x84, 0x04, 0x01,
            0x01, 0x01, 0x01, 0x87, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x18, 0x0a,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x20, 0x01, 0x01, 0x01, 0x01,
            0x86, 0x04, 0x01, 0x01, 0x01, 0x01, 0xe8, 0x10, 0x20, 0x01, 0x0d,
            0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0xec, 0x24, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x80, 0x20,
            0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x40, 0x20,
            0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x8c, 0x10, 0x20, 0x01,
            0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01,
        ],
        None,
        Pdu::Lsp(Box::new(Lsp::new(
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
                area_addrs: vec![AreaAddressesTlv {
                    list: vec![AreaAddr::from([0x49, 0, 0].as_slice())],
                }],
                hostname: None,
                lsp_buf_size: None,
                is_reach: vec![],
                ext_is_reach: vec![ExtIsReachTlv {
                    list: vec![ExtIsReach {
                        neighbor: LanId::from([
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
                        ]),
                        metric: 10,
                        sub_tlvs: ExtIsReachSubTlvs {
                            admin_group: Some(AdminGroupSubTlv::new(0x0f)),
                            ipv4_interface_addr: vec![
                                Ipv4InterfaceAddrSubTlv::new(ip4!("10.0.1.1")),
                            ],
                            ipv4_neighbor_addr: vec![
                                Ipv4NeighborAddrSubTlv::new(ip4!("10.0.1.2")),
                            ],
                            max_link_bw: Some(MaxLinkBwSubTlv::new(
                                125000000.0,
                            )),
                            max_resv_link_bw: Some(MaxResvLinkBwSubTlv::new(
                                12500000.0,
                            )),
                            unreserved_bw: Some(UnreservedBwSubTlv::new([
                                12500000.0, 12500000.0, 12500000.0, 12500000.0,
                                12500000.0, 12500000.0, 12500000.0, 12500000.0,
                            ])),
                            te_default_metric: Some(
                                TeDefaultMetricSubTlv::new(100),
                            ),
                            unknown: vec![],
                        },
                    }],
                }],
                ipv4_addrs: vec![Ipv4AddressesTlv {
                    list: vec![ip4!("1.1.1.1")],
                }],
                ipv4_internal_reach: vec![],
                ipv4_external_reach: vec![],
                ext_ipv4_reach: vec![ExtIpv4ReachTlv {
                    list: vec![
                        ExtIpv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("10.0.1.0/24"),
                            sub_tlvs: Default::default(),
                        },
                        ExtIpv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("1.1.1.1/32"),
                            sub_tlvs: Default::default(),
                        },
                    ],
                }],
                ipv4_router_id: Some(Ipv4RouterIdTlv::new(ip4!("1.1.1.1"))),
                ipv6_addrs: vec![Ipv6AddressesTlv {
                    list: vec![ip6!("2001:db8::1")],
                }],
                ipv6_reach: vec![Ipv6ReachTlv {
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
                ipv6_router_id: Some(Ipv6RouterIdTlv::new(ip6!("2001:db8::1"))),
                unknown: vec![],
            },
            None,
        ))),
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
        Pdu::Lsp(Box::new(Lsp::new(
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
                area_addrs: vec![AreaAddressesTlv {
                    list: vec![AreaAddr::from([0x49, 0, 0].as_slice())],
                }],
                hostname: Some(DynamicHostnameTlv {
                    hostname: "holo".to_owned(),
                }),
                lsp_buf_size: Some(LspBufferSizeTlv { size: 1492 }),
                is_reach: vec![IsReachTlv {
                    list: vec![
                        IsReach {
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            neighbor: LanId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
                            ]),
                        },
                        IsReach {
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
                ipv4_addrs: vec![Ipv4AddressesTlv {
                    list: vec![ip4!("6.6.6.6")],
                }],
                ipv4_internal_reach: vec![Ipv4ReachTlv {
                    list: vec![
                        Ipv4Reach {
                            up_down: false,
                            ie_bit: false,
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            prefix: net4!("10.0.7.0/24"),
                        },
                        Ipv4Reach {
                            up_down: false,
                            ie_bit: false,
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            prefix: net4!("10.0.8.0/24"),
                        },
                        Ipv4Reach {
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
                ipv4_external_reach: vec![Ipv4ReachTlv {
                    list: vec![
                        Ipv4Reach {
                            up_down: false,
                            ie_bit: false,
                            metric: 10,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            prefix: net4!("172.16.1.0/24"),
                        },
                        Ipv4Reach {
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
                ipv4_router_id: None,
                ipv6_addrs: vec![],
                ipv6_reach: vec![],
                ipv6_router_id: None,
                unknown: vec![],
            },
            None,
        ))),
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
        Pdu::Lsp(Box::new(Lsp::new(
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
                area_addrs: vec![AreaAddressesTlv {
                    list: vec![AreaAddr::from([0x49, 0, 0].as_slice())],
                }],
                hostname: None,
                lsp_buf_size: None,
                is_reach: vec![],
                ext_is_reach: vec![ExtIsReachTlv {
                    list: vec![ExtIsReach {
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
                ext_ipv4_reach: vec![ExtIpv4ReachTlv {
                    list: vec![
                        ExtIpv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("10.0.1.0/24"),
                            sub_tlvs: Default::default(),
                        },
                        ExtIpv4Reach {
                            metric: 10,
                            up_down: false,
                            prefix: net4!("1.1.1.1/32"),
                            sub_tlvs: Default::default(),
                        },
                    ],
                }],
                ipv4_router_id: None,
                ipv6_addrs: vec![],
                ipv6_reach: vec![],
                ipv6_router_id: None,
                unknown: vec![],
            },
            Some(&KEY_HMAC_MD5),
        ))),
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
