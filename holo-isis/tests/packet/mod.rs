//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

mod hello;
mod lsp;
mod snp;

use std::sync::LazyLock as Lazy;

use bytes::Bytes;
use const_addrs::{ip4, ip6, net4, net6};
use holo_isis::packet::auth::AuthMethod;
use holo_isis::packet::consts::LspFlags;
use holo_isis::packet::pdu::{
    Hello, HelloTlvs, HelloVariant, Lsp, LspTlvs, Pdu, Snp, SnpTlvs,
};
use holo_isis::packet::subtlvs::neighbor::{
    AdminGroupSubTlv, Ipv4InterfaceAddrSubTlv, Ipv4NeighborAddrSubTlv,
    MaxLinkBwSubTlv, MaxResvLinkBwSubTlv, TeDefaultMetricSubTlv,
    UnreservedBwSubTlv,
};
use holo_isis::packet::tlv::{
    AreaAddressesTlv, DynamicHostnameTlv, ExtIpv4Reach, ExtIpv4ReachTlv,
    ExtIsReach, ExtIsReachSubTlvs, ExtIsReachTlv, Ipv4AddressesTlv, Ipv4Reach,
    Ipv4ReachTlv, Ipv4RouterIdTlv, Ipv6AddressesTlv, Ipv6Reach, Ipv6ReachTlv,
    Ipv6RouterIdTlv, IsReach, IsReachTlv, LspBufferSizeTlv, LspEntriesTlv,
    LspEntry, NeighborsTlv, PaddingTlv, ProtocolsSupportedTlv,
};
use holo_isis::packet::{
    AreaAddr, LanId, LevelNumber, LevelType, LspId, SystemId,
};
use holo_protocol::assert_eq_hex;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::keychain::Key;

//
// Helper functions.
//

fn test_encode_pdu(bytes_expected: &[u8], pdu: &Pdu, auth: &Option<&Key>) {
    let bytes_actual = pdu.clone().encode(*auth);
    assert_eq_hex!(bytes_expected, bytes_actual);
}

fn test_decode_pdu(bytes: &[u8], pdu_expected: &Pdu, auth: &Option<&Key>) {
    let bytes = Bytes::copy_from_slice(bytes);
    let auth = auth.cloned().map(AuthMethod::ManualKey);
    let mut pdu_actual =
        Pdu::decode(bytes.clone(), auth.as_ref(), auth.as_ref()).unwrap();
    if let Pdu::Lsp(pdu) = &mut pdu_actual {
        pdu.raw = bytes;
    }
    assert_eq!(*pdu_expected, pdu_actual);
}

//
// Authentication keys.
//

static KEY_CLEAR_TEXT: Lazy<Key> = Lazy::new(|| {
    Key::new(1, CryptoAlgo::ClearText, "HOLO".as_bytes().to_vec())
});
static KEY_HMAC_MD5: Lazy<Key> =
    Lazy::new(|| Key::new(1, CryptoAlgo::HmacMd5, "HOLO".as_bytes().to_vec()));
