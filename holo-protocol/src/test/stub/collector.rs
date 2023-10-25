//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::{Arc, Mutex};

use holo_northbound::NbProviderReceiver;
use holo_utils::ibus::IbusReceiver;
use holo_utils::Receiver;
use yang2::data::{Data, DataFormat, DataPrinterFlags};

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
        ibus_output_rx: IbusReceiver,
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
        mut ibus_output_rx: IbusReceiver,
        mut protocol_output_rx: Receiver<P::ProtocolOutputMsg>,
        nb_notifications: Arc<Mutex<Vec<String>>>,
        ibus_output: Arc<Mutex<Vec<String>>>,
        protocol_output: Arc<Mutex<Vec<String>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(msg) = nb_notifications_rx.recv() => {
                        let data = msg
                            .data
                            .print_string(
                                DataFormat::JSON,
                                DataPrinterFlags::WITH_SIBLINGS
                                    | DataPrinterFlags::SHRINK
                                    | DataPrinterFlags::WD_TRIM,
                            )
                            .unwrap()
                            .unwrap_or_default();
                        nb_notifications.lock().unwrap().push(data);
                    }
                    Ok(msg) = ibus_output_rx.recv() => {
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
