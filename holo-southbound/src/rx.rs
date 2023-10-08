//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use async_trait::async_trait;
use derive_new::new;
use holo_utils::task::Task;
use holo_utils::{Receiver, Sender};
use tokio::net::unix;
use tracing::Instrument;

use crate::zclient::messages::{
    ZapiRtrIdInfo, ZapiRxAddressInfo, ZapiRxIfaceInfo, ZapiRxMsg,
    ZapiRxRouteInfo,
};
use crate::zclient::Zclient;

#[derive(Debug, new)]
pub struct SouthboundRx {
    // Southbound zclient.
    pub zclient: Arc<Zclient>,

    // Southbound Rx channel (transmission end).
    //
    // This channel can be used in a testing environment to inject ZAPI
    // messages.
    #[cfg(feature = "testing")]
    pub channel_tx: Option<Sender<ZapiRxMsg>>,

    // Southbound Rx channel (receiving end).
    pub channel_rx: Receiver<ZapiRxMsg>,

    // Southbound Rx task.
    #[cfg(not(feature = "testing"))]
    pub task: Task<()>,
}

#[async_trait]
pub trait SouthboundRxCallbacks: Send {
    // Process a Router-ID update message.
    async fn process_rtr_id_upd(&mut self, _msg: ZapiRtrIdInfo) {}

    // Process an interface update message.
    async fn process_iface_upd(&mut self, _msg: ZapiRxIfaceInfo) {}

    // Process an address addition message.
    async fn process_addr_add(&mut self, _msg: ZapiRxAddressInfo) {}

    // Process an address removal message.
    async fn process_addr_del(&mut self, _msg: ZapiRxAddressInfo) {}

    // Process a route addition message.
    async fn process_route_add(&mut self, _msg: ZapiRxRouteInfo) {}

    // Process a route deletion message.
    async fn process_route_del(&mut self, _msg: ZapiRxRouteInfo) {}
}

// ===== impl SouthboundRx =====

impl SouthboundRx {
    pub async fn recv(&mut self) -> Option<ZapiRxMsg> {
        self.channel_rx.recv().await
    }
}

// ===== global functions =====

// Starts task used to read messages received from zebra.
pub(crate) fn rx_task(
    zclient: &Arc<Zclient>,
    read_half: unix::OwnedReadHalf,
    sb_rxp: Sender<ZapiRxMsg>,
) -> Task<()> {
    let zclient = zclient.clone();
    Task::spawn(
        async move {
            zclient.read_loop(read_half, sb_rxp).await;
        }
        .in_current_span(),
    )
}
