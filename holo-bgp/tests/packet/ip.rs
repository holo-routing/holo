//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT

// Meant for the ipv4/6 encoders and decoders inside the
// holo_bgp::packet::message file.

use bytes::Bytes;
use holo_bgp::packet::error::{DecodeError, UpdateMessageError};
use holo_bgp::packet::message::{decode_ipv4_prefix, decode_ipv6_prefix};

// Try decode_ipv6_prefix with empty bytes, which should not be decodable.
#[test]
fn test_decode_ipv6_prefix1() {
    let mut b = Bytes::new();
    let result = decode_ipv6_prefix(&mut b);
    let expected_err = Err(DecodeError::UpdateMessage(
        UpdateMessageError::InvalidNetworkField,
    ));
    assert_eq!(result, expected_err);
}

// Try decode_ipv4_prefix with empty bytes, which should not be decodable.
#[test]
fn test_decode_ipv4_prefix1() {
    let mut b = Bytes::new();
    let result = decode_ipv4_prefix(&mut b);
    let expected_err = Err(DecodeError::UpdateMessage(
        UpdateMessageError::InvalidNetworkField,
    ));
    assert_eq!(result, expected_err);
}
