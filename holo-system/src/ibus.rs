//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::{IbusClient, IbusClientId, IbusMsg, IbusSender};

use crate::Master;

// ===== global functions =====

pub(crate) fn process_msg(
    master: &mut Master,
    client: IbusClient,
    msg: IbusMsg,
) {
    match msg {
        IbusMsg::HostnameSub {} => {
            notify_hostname_update(&client.tx, master.config.hostname.clone());
            master.hostname_subscriptions.insert(client.id, client.tx);
        }
        // Ignore other events.
        _ => {}
    }
}

// Cleans up all state associated with a disconnected client.
pub(crate) fn disconnect(master: &mut Master, id: IbusClientId) {
    master.hostname_subscriptions.remove(&id);
}

pub(crate) fn notify_hostname_update(
    ibus_tx: &IbusSender,
    hostname: Option<String>,
) {
    let msg = IbusMsg::HostnameUpdate(hostname);
    notify(ibus_tx, msg);
}

// ===== helper functions =====

fn notify(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
