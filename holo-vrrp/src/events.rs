//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use crate::error::Error;
use crate::instance::Instance;
use crate::packet::{DecodeResult, VRRPPacket};

// ===== Network packet receipt =====

pub(crate) fn process_packet(
    _instance: &mut Instance,
    _src: IpAddr,
    _packet: DecodeResult<VRRPPacket>,

) -> Result<(), Error> {
    // TODO

    Ok(())
}
