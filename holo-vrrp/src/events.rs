//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use crate::error::Error;
use crate::interface::Interface;
use crate::packet::{DecodeResult, VrrpPacket};

// ===== Network packet receipt =====

pub(crate) fn process_packet(
    _interface: &mut Interface,
    _src: IpAddr,
    _packet: DecodeResult<VrrpPacket>,
) -> Result<(), Error> {
    // TODO

    Ok(())
}
