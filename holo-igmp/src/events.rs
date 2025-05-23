//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use crate::error::Error;
use crate::instance::Instance;
use crate::packet::{DecodeResult, Packet};

// ===== Network packet receipt =====

pub(crate) fn process_packet(
    instance: &mut Instance,
    ifname: String,
    src: Ipv4Addr,
    packet: DecodeResult<Packet>,
) -> Result<(), Error> {
    // Lookup interface.
    let Some((_instance, _iface)) = instance.get_interface(&ifname) else {
        return Ok(());
    };

    // TODO
    tracing::debug!(%ifname, %src, "received packet: {:?}", packet);

    Ok(())
}
