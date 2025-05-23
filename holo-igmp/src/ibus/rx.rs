//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::southbound::InterfaceUpdateMsg;

use crate::error::Error;
use crate::instance::Instance;

// ===== global functions =====

pub(crate) fn process_iface_update(
    instance: &mut Instance,
    msg: InterfaceUpdateMsg,
) -> Result<(), Error> {
    // Lookup interface.
    let Some((mut instance, iface)) = instance.get_interface(&msg.ifname)
    else {
        return Ok(());
    };

    // Update interface data.
    iface.system.flags = msg.flags;
    iface.system.ifindex = Some(msg.ifindex);

    // Check if IGMP needs to be activated or deactivated on this interface.
    iface.update(&mut instance);

    Ok(())
}
