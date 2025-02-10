//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::{IbusMsg, IbusSender};

use crate::Master;

// ===== global functions =====

pub(crate) fn process_msg(master: &mut Master, msg: IbusMsg) {
    match msg {
        IbusMsg::HostnameSub { subscriber } => {
            let subscriber = subscriber.unwrap();
            notify_hostname_update(
                &subscriber.tx,
                master.config.hostname.clone(),
            );
            master
                .hostname_subscriptions
                .insert(subscriber.id, subscriber.tx);
        }
        // Ignore other events.
        _ => {}
    }
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
