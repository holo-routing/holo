//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::{HostnameMsg, IbusMsg, IbusSender};

use crate::Master;

// ===== global functions =====

pub(crate) fn process_msg(master: &mut Master, msg: IbusMsg) {
    if let IbusMsg::Hostname(HostnameMsg::Query) = msg {
        notify_hostname_update(&master.ibus_tx, master.config.hostname.clone());
    }
}

pub(crate) fn notify_hostname_update(
    ibus_tx: &IbusSender,
    hostname: Option<String>,
) {
    let msg = HostnameMsg::Update(hostname);
    notify(ibus_tx, msg.into());
}

// ===== helper functions =====

fn notify(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
