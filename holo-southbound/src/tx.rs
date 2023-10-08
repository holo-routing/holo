//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use derive_new::new;
use holo_utils::task::Task;
use holo_utils::{UnboundedReceiver, UnboundedSender};
use tokio::net::unix;
use tracing::Instrument;

use crate::debug::Debug;
use crate::zclient::messages::ZapiTxMsg;
use crate::zclient::Zclient;

#[derive(Debug, new)]
pub struct SouthboundTx {
    // Southbound zclient.
    pub zclient: Arc<Zclient>,

    // Southbound Tx channel (transmission end).
    pub channel_tx: UnboundedSender<ZapiTxMsg>,

    // Southbound Tx channel (receiving end).
    //
    // This channel can be used in a testing environment to collect the sent
    // ZAPI messages.
    #[cfg(feature = "testing")]
    pub channel_rx: Option<UnboundedReceiver<ZapiTxMsg>>,

    // Southbound Tx task.
    #[cfg(not(feature = "testing"))]
    pub task: Task<()>,
}

// ===== impl SouthboundTx =====

impl SouthboundTx {
    pub fn send(&self, msg: ZapiTxMsg) {
        Debug::MsgTx(&msg).log();
        self.channel_tx.send(msg).unwrap();
    }
}

// ===== global functions =====

// Starts task used to send messages to zebra.
pub(crate) fn tx_task(
    zclient: &Arc<Zclient>,
    write_half: unix::OwnedWriteHalf,
    sb_txc: UnboundedReceiver<ZapiTxMsg>,
) -> Task<()> {
    let zclient = zclient.clone();
    Task::spawn(
        async move {
            zclient.write_loop(write_half, sb_txc).await;
        }
        .in_current_span(),
    )
}
