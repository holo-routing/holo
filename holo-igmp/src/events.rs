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
    ifindex: u32,
    src: Ipv4Addr,
    packet: DecodeResult<Packet>,
) -> Result<(), Error> {
    // Lookup interface.
    let Some((_instance, interfaces)) = instance.as_up() else {
        return Ok(());
    };
    let Some(iface) = interfaces
        .values_mut()
        .find(|iface| iface.system.ifindex == Some(ifindex))
    else {
        return Ok(());
    };

    // TODO
    tracing::debug!(ifname = %iface.name, %src, data = ?packet, "received packet");

    Ok(())
}
