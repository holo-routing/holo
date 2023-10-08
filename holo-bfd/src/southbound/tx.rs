//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use derive_new::new;
use holo_southbound::tx::SouthboundTx;
use holo_southbound::zclient::messages::{ZapiTxHelloInfo, ZapiTxMsg};

#[derive(Debug, new)]
pub struct InstanceSouthboundTx(pub SouthboundTx);

// ===== impl InstanceSouthboundTx =====

impl InstanceSouthboundTx {
    pub(crate) fn initial_requests(&self) {
        for msg in [
            // Hello message.
            ZapiTxMsg::Hello(ZapiTxHelloInfo {
                redist_default: self.0.zclient.redist_default,
                instance: self.0.zclient.instance,
                session_id: 0,
                receive_notify: self.0.zclient.receive_notify as u8,
            }),
            // Request interface information.
            ZapiTxMsg::InterfaceAdd,
        ] {
            self.0.send(msg);
        }
    }
}
