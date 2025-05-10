//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use bytes::Bytes;
use holo_bgp::neighbor::PeerType;
use holo_bgp::packet::attribute::{AsPathSegment, Attrs};
use holo_bgp::packet::consts::{Afi, AttrType, Safi};
use holo_bgp::packet::error::{AttrError, UpdateMessageError};
use holo_bgp::packet::message::{
    DecodeCxt, MpReachNlri, MpUnreachNlri, NegotiatedCapability,
};

#[test]
fn test_attr_decode1() {
    let data: &[u8] = &[0x6e, 0x02, 0x02, 0x02, 0x01, 0x73, 0x73, 0x00];
    let mut buf = Bytes::copy_from_slice(data);
    let cxt = DecodeCxt {
        peer_type: PeerType::Internal,
        peer_as: 7566081,
        capabilities: BTreeSet::new(),
    };
    let mut nexthop: Option<Ipv4Addr> = None;
    let nlri_present = false;
    let mut mp_unreach: Option<MpUnreachNlri> = None;
    let mut mp_reach: Option<MpReachNlri> = None;
    let result = Attrs::decode(
        &mut buf,
        &cxt,
        &mut nexthop,
        nlri_present,
        &mut mp_unreach,
        &mut mp_reach,
    );
    assert_eq!(Ok(None), result);
}

#[test]
fn test_attr_decode2() {
    let data: &[u8] = &[
        0xe2, 0x11, 0x01, 0x02, 0x02, 0x4b, 0x02, 0xbe, 0x63, 0x27, 0xff, 0xfd,
        0x03, 0x21,
    ];
    let mut buf = Bytes::copy_from_slice(data);
    let cxt = DecodeCxt {
        peer_type: PeerType::Internal,
        peer_as: 3187821314,
        capabilities: BTreeSet::from([NegotiatedCapability::MultiProtocol {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        }]),
    };
    let mut nexthop: Option<Ipv4Addr> = None;
    let nlri_present = false;
    let mut mp_unreach: Option<MpUnreachNlri> = None;
    let mut mp_reach: Option<MpReachNlri> = None;
    let result = Attrs::decode(
        &mut buf,
        &cxt,
        &mut nexthop,
        nlri_present,
        &mut mp_unreach,
        &mut mp_reach,
    );
    let expected = Err(UpdateMessageError::UnrecognizedWellKnownAttribute);
    assert_eq!(expected, result);
}

#[test]
fn test_as_path_segment_decode1() {
    let data: &[u8] = &[];
    let mut buf = Bytes::copy_from_slice(data);
    let attr_type = AttrType::Origin;
    let four_byte_asn_cap = false;
    let result = AsPathSegment::decode(&mut buf, attr_type, four_byte_asn_cap);
    let expected = Err(AttrError::Discard);

    assert_eq!(expected, result);
}

#[test]
fn test_mp_reach_nlri_decode1() {
    // checks whether while decoding and checking the afi, the nexthop_len and
    // reserve exist when getting them from the buffer.
    let data: &[u8] = &[
        0x0, 0x02, 0x1, 0x10, 0x00, 0xdf, 0x3f, 0x1a, 0x1a, 0x1a, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut buf = Bytes::copy_from_slice(data);
    let mut mp_reach: Option<MpReachNlri> = None;

    let _ = MpReachNlri::decode(&mut buf, &mut mp_reach);
}
