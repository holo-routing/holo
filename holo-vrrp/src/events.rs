//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use crate::error::Error;
use crate::interface::Interface;
use crate::packet::{DecodeResult, Packet};

// ===== Network packet receipt =====

pub(crate) fn process_packet(
    _interface: &mut Interface,
    _src: IpAddr,
    _packet: DecodeResult<Packet>,
) -> Result<(), Error> {
    // TODO

    Ok(())
}
