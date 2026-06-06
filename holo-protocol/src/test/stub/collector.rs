//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::{Arc, Mutex};

use futures::stream::{self, BoxStream, SelectAll, StreamExt};
use holo_northbound::NbProviderReceiver;
use holo_utils::ibus::{IbusChannelsRx, IbusConn, IbusMsg};
use tokio::sync::mpsc::Receiver;
use yang5::data::{Data, DataFormat, DataPrinterFlags};

use crate::ProtocolInstance;

pub struct MessageCollector {
    nb_notifications: Arc<Mutex<Vec<String>>>,
    ibus_output: Arc<Mutex<Vec<String>>>,
    protocol_output: Arc<Mutex<Vec<String>>>,
    pub rx_task: tokio::task::JoinHandle<()>,
}

// ===== impl MessageCollector =====

impl MessageCollector {
    pub(crate) fn new<P: ProtocolInstance>(
        nb_notifications_rx: NbProviderReceiver,
        ibus_output_rx: IbusChannelsRx,
        protocol_output_rx: Receiver<P::ProtocolOutputMsg>,
    ) -> Self {
        let nb_notifications = Arc::new(Mutex::new(Vec::new()));
        let ibus_output = Arc::new(Mutex::new(Vec::new()));
        let protocol_output = Arc::new(Mutex::new(Vec::new()));

        let rx_task = MessageCollector::rx_task::<P>(
            nb_notifications_rx,
            ibus_output_rx,
            protocol_output_rx,
            nb_notifications.clone(),
            ibus_output.clone(),
            protocol_output.clone(),
        );

        MessageCollector {
            nb_notifications,
            ibus_output,
            protocol_output,
            rx_task,
        }
    }

    pub(crate) fn nb_notifications(&self) -> Vec<String> {
        let mut messages = Vec::new();
        std::mem::swap(
            &mut *self.nb_notifications.lock().unwrap(),
            &mut messages,
        );
        messages
    }

    pub(crate) fn ibus_output(&self) -> Vec<String> {
        let mut messages = Vec::new();
        std::mem::swap(&mut *self.ibus_output.lock().unwrap(), &mut messages);
        messages
    }

    pub(crate) fn protocol_output(&self) -> Vec<String> {
        let mut messages = Vec::new();
        std::mem::swap(
            &mut *self.protocol_output.lock().unwrap(),
            &mut messages,
        );
        messages
    }

    pub(crate) fn reset_output(&self) {
        let _ = self.nb_notifications();
        let _ = self.ibus_output();
        let _ = self.protocol_output();
    }

    fn rx_task<P: ProtocolInstance>(
        mut nb_notifications_rx: NbProviderReceiver,
        mut ibus_output_rx: IbusChannelsRx,
        mut protocol_output_rx: Receiver<P::ProtocolOutputMsg>,
        nb_notifications: Arc<Mutex<Vec<String>>>,
        ibus_output: Arc<Mutex<Vec<String>>>,
        protocol_output: Arc<Mutex<Vec<String>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut routing: SelectAll<BoxStream<'static, IbusMsg>> =
                SelectAll::new();
            let mut interface: SelectAll<BoxStream<'static, IbusMsg>> =
                SelectAll::new();
            let mut system: SelectAll<BoxStream<'static, IbusMsg>> =
                SelectAll::new();
            let mut keychain: SelectAll<BoxStream<'static, IbusMsg>> =
                SelectAll::new();
            let mut policy: SelectAll<BoxStream<'static, IbusMsg>> =
                SelectAll::new();

            loop {
                tokio::select! {
                    biased;
                    Some(msg) = nb_notifications_rx.recv() => {
                        let data = msg
                            .data
                            .print_string(
                                DataFormat::JSON,
                                DataPrinterFlags::WITH_SIBLINGS
                                    | DataPrinterFlags::SHRINK
                                    | DataPrinterFlags::WD_TRIM,
                            )
                            .unwrap();
                        nb_notifications.lock().unwrap().push(data);
                    }
                    Some(conn) = ibus_output_rx.routing.recv() => {
                        routing.push(connection_stream(conn));
                    }
                    Some(conn) = ibus_output_rx.interface.recv() => {
                        interface.push(connection_stream(conn));
                    }
                    Some(conn) = ibus_output_rx.system.recv() => {
                        system.push(connection_stream(conn));
                    }
                    Some(conn) = ibus_output_rx.keychain.recv() => {
                        keychain.push(connection_stream(conn));
                    }
                    Some(conn) = ibus_output_rx.policy.recv() => {
                        policy.push(connection_stream(conn));
                    }
                    Some(msg) = routing.next(), if !routing.is_empty() => {
                        let data = serde_json::to_string(&msg).unwrap();
                        ibus_output.lock().unwrap().push(data);
                    }
                    Some(msg) = interface.next(), if !interface.is_empty() => {
                        let data = serde_json::to_string(&msg).unwrap();
                        ibus_output.lock().unwrap().push(data);
                    }
                    Some(msg) = system.next(), if !system.is_empty() => {
                        let data = serde_json::to_string(&msg).unwrap();
                        ibus_output.lock().unwrap().push(data);
                    }
                    Some(msg) = keychain.next(), if !keychain.is_empty() => {
                        let data = serde_json::to_string(&msg).unwrap();
                        ibus_output.lock().unwrap().push(data);
                    }
                    Some(msg) = policy.next(), if !policy.is_empty() => {
                        let data = serde_json::to_string(&msg).unwrap();
                        ibus_output.lock().unwrap().push(data);
                    }
                    Some(msg) = protocol_output_rx.recv() => {
                        let data = serde_json::to_string(&msg).unwrap();
                        protocol_output.lock().unwrap().push(data);
                    }
                    else => break,
                }
            }
        })
    }
}

// Wraps a connection's receive channel into a stream of its messages, which
// ends once the channel is closed.
fn connection_stream(conn: IbusConn) -> BoxStream<'static, IbusMsg> {
    stream::unfold(conn.rx, |mut rx| async move {
        rx.recv().await.map(|msg| (msg, rx))
    })
    .boxed()
}
