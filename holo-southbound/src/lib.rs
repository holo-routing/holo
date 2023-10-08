//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![warn(rust_2018_idioms)]
#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]

pub mod debug;
pub mod rx;
pub mod tx;
pub mod zclient;

use std::sync::Arc;
use std::time::Duration;

use holo_utils::protocol::Protocol;
use tokio::sync::mpsc;

use crate::debug::Debug;
use crate::rx::{SouthboundRx, SouthboundRxCallbacks};
use crate::tx::SouthboundTx;
use crate::zclient::messages::ZapiRxMsg;
use crate::zclient::Zclient;

// ===== global functions =====

// Starts the southbound layer for the given protocol.
pub async fn start(protocol: Protocol) -> (SouthboundTx, SouthboundRx) {
    // Initialize reference-counted zclient.
    let zclient = Zclient::new(0, 0, protocol.into(), false);
    let zclient = Arc::new(zclient);

    // Create southbound channels.
    let (sb_txp, sb_txc) = mpsc::unbounded_channel();
    let (sb_rxp, sb_rxc) = mpsc::channel(4);

    #[cfg(not(feature = "testing"))]
    {
        // Connect to zebra (try until it succeeds).
        let mut fail = 0usize;
        let stream = loop {
            match zclient.connect().await {
                Ok(stream) => break stream,
                Err(error) => {
                    error.log();
                    fail = fail.saturating_add(1);
                    tokio::time::sleep(Duration::from_secs(if fail < 10 {
                        1
                    } else {
                        10
                    }))
                    .await;
                }
            }
        };
        let (read_half, write_half) = stream.into_split();

        // Start zclient Tx task.
        let tx_task = tx::tx_task(&zclient, write_half, sb_txc);
        let tx = SouthboundTx::new(zclient.clone(), sb_txp, tx_task);

        // Start zclient Rx task.
        let rx_task = rx::rx_task(&zclient, read_half, sb_rxp);
        let rx = SouthboundRx::new(zclient, sb_rxc, rx_task);

        (tx, rx)
    }
    #[cfg(feature = "testing")]
    {
        let tx = SouthboundTx::new(zclient.clone(), sb_txp, Some(sb_txc));
        let rx = SouthboundRx::new(zclient, Some(sb_rxp), sb_rxc);
        (tx, rx)
    }
}

// Processes message coming from zebra.
pub async fn process_southbound_msg<ProtocolInstance>(
    instance: &mut ProtocolInstance,
    msg: ZapiRxMsg,
) where
    ProtocolInstance: SouthboundRxCallbacks,
{
    Debug::MsgRx(&msg).log();

    match msg {
        ZapiRxMsg::RouterIdUpd(msg) => {
            instance.process_rtr_id_upd(msg).await;
        }
        ZapiRxMsg::InterfaceUpd(msg) => {
            instance.process_iface_upd(msg).await;
        }
        ZapiRxMsg::AddressAdd(msg) => {
            instance.process_addr_add(msg).await;
        }
        ZapiRxMsg::AddressDel(msg) => {
            instance.process_addr_del(msg).await;
        }
        ZapiRxMsg::RouteAdd(msg) => {
            instance.process_route_add(msg).await;
        }
        ZapiRxMsg::RouteDel(msg) => {
            instance.process_route_del(msg).await;
        }
    }
}
