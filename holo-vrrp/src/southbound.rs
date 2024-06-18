//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::southbound::{AddressMsg, InterfaceUpdateMsg};

use crate::instance::Instance;

// ===== global functions =====

pub(crate) fn router_id_query(ibus_tx: &IbusSender) {
    let _ = ibus_tx.send(IbusMsg::RouterIdQuery);
}

pub(crate) async fn process_router_id_update(
    _instance: &mut Instance,
    _router_id: Option<Ipv4Addr>,
) {
    // TODO
}

pub(crate) fn process_iface_update(
    _instance: &mut Instance,
    _msg: InterfaceUpdateMsg,
) {
    // TODO
}

pub(crate) fn process_addr_add(_instance: &mut Instance, _msg: AddressMsg) {
    // TODO
}

pub(crate) fn process_addr_del(_instance: &mut Instance, _msg: AddressMsg) {
    // TODO
}
