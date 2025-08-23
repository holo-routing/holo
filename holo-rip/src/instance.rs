//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::task::{IntervalTask, TimeoutTask};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};

use crate::debug::{Debug, InstanceInactiveReason, InterfaceInactiveReason};
use crate::error::Error;
use crate::interface::Interfaces;
use crate::neighbor::Neighbor;
use crate::northbound::configuration::InstanceCfg;
use crate::packet::Command;
use crate::route::Route;
use crate::tasks::messages::input::{
    InitialUpdateMsg, NbrTimeoutMsg, RouteGcTimeoutMsg, RouteTimeoutMsg,
    TriggeredUpdMsg, TriggeredUpdTimeoutMsg, UdpRxPduMsg, UpdateIntervalMsg,
};
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::version::Version;
use crate::{events, ibus, tasks};

#[derive(Debug)]
pub struct Instance<V: Version> {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: Option<InstanceState<V>>,
    // Instance interfaces.
    pub interfaces: Interfaces<V>,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance<V>>,
}

#[derive(Debug, Default)]
pub struct InstanceSys {
    pub router_id: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub struct InstanceState<V: Version> {
    // Outbound update tasks.
    pub initial_update_task: Option<TimeoutTask>,
    pub update_interval_task: IntervalTask,
    // Triggered update information.
    pub triggered_upd_timeout_task: Option<TimeoutTask>,
    pub pending_trigger_upd: bool,
    // RIP neighbors.
    pub neighbors: BTreeMap<V::IpAddr, Neighbor<V>>,
    // RIP routing table.
    pub routes: BTreeMap<V::IpNetwork, Route<V>>,
    // Message statistics.
    pub statistics: MessageStatistics,
    // Authentication non-decreasing sequence number.
    pub auth_seqno: Arc<AtomicU32>,
}

// Inbound and outbound statistic counters.
#[derive(Debug, Default)]
pub struct MessageStatistics {
    pub discontinuity_time: Option<DateTime<Utc>>,
    pub requests_rcvd: u32,
    pub requests_sent: u32,
    pub responses_rcvd: u32,
    pub responses_sent: u32,
}

pub struct InstanceUpView<'a, V: Version> {
    pub name: &'a str,
    pub system: &'a InstanceSys,
    pub config: &'a InstanceCfg,
    pub state: &'a mut InstanceState<V>,
    pub tx: &'a InstanceChannelsTx<Instance<V>>,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx<V: Version> {
    // UDP Rx event.
    pub udp_pdu_rx: Sender<UdpRxPduMsg<V>>,
    // Initial update.
    pub initial_update: Sender<InitialUpdateMsg>,
    // Update interval.
    pub update_interval: Sender<UpdateIntervalMsg>,
    // Triggered update event.
    pub triggered_upd: UnboundedSender<TriggeredUpdMsg>,
    // Triggered update timeout event.
    pub triggered_upd_timeout: Sender<TriggeredUpdTimeoutMsg>,
    // Neighbor timeout event.
    pub nbr_timeout: Sender<NbrTimeoutMsg<V>>,
    // Route timeout event.
    pub route_timeout: Sender<RouteTimeoutMsg<V>>,
    // Route garbage-collection event.
    pub route_gc_timeout: Sender<RouteGcTimeoutMsg<V>>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx<V: Version> {
    // UDP Rx event.
    pub udp_pdu_rx: Receiver<UdpRxPduMsg<V>>,
    // Initial update.
    pub initial_update: Receiver<InitialUpdateMsg>,
    // Update interval.
    pub update_interval: Receiver<UpdateIntervalMsg>,
    // Triggered update event.
    pub triggered_upd: UnboundedReceiver<TriggeredUpdMsg>,
    // Triggered update timeout event.
    pub triggered_upd_timeout: Receiver<TriggeredUpdTimeoutMsg>,
    // Neighbor timeout event.
    pub nbr_timeout: Receiver<NbrTimeoutMsg<V>>,
    // Route timeout event.
    pub route_timeout: Receiver<RouteTimeoutMsg<V>>,
    // Route garbage-collection event.
    pub route_gc_timeout: Receiver<RouteGcTimeoutMsg<V>>,
}

// ===== impl Instance =====

impl<V> Instance<V>
where
    V: Version,
{
    // Checks if the instance needs to be started or stopped in response to a
    // northbound or southbound event.
    pub(crate) fn update(&mut self) {
        match self.is_ready() {
            Ok(()) if !self.is_active() => {
                self.start();
            }
            Err(reason) if self.is_active() => {
                self.stop(reason);
            }
            _ => (),
        }
    }

    fn start(&mut self) {
        Debug::<V>::InstanceStart.log();

        let update_interval = self.config.update_interval;
        let state = InstanceState::new(update_interval, &self.tx);
        self.state = Some(state);
        let (mut instance, interfaces) = self.as_up().unwrap();

        // Try to start interfaces.
        for iface in interfaces.iter_mut() {
            iface.update(&mut instance);
        }
    }

    fn stop(&mut self, reason: InstanceInactiveReason) {
        if !self.is_active() {
            return;
        }

        Debug::<V>::InstanceStop(reason).log();

        // Stop interfaces.
        let (mut instance, interfaces) = self.as_up().unwrap();
        for iface in interfaces.iter_mut() {
            iface.stop(&mut instance, InterfaceInactiveReason::InstanceDown);
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.state.is_some()
    }

    // Returns whether the instance is ready for RIP operation.
    //
    // NOTE: as of now there's nothing that can cause a RIP instance to be
    // deactivated (other than unconfiguration). In the future, one possible
    // deactivation cause is when the underlying VRF becomes inoperative.
    fn is_ready(&self) -> Result<(), InstanceInactiveReason> {
        Ok(())
    }

    // Returns a view struct for the instance if it's operational.
    pub(crate) fn as_up(
        &mut self,
    ) -> Option<(InstanceUpView<'_, V>, &mut Interfaces<V>)> {
        if let Some(state) = &mut self.state {
            let instance = InstanceUpView {
                name: &self.name,
                system: &self.system,
                config: &self.config,
                state,
                tx: &self.tx,
            };
            Some((instance, &mut self.interfaces))
        } else {
            None
        }
    }
}

impl<V> ProtocolInstance for Instance<V>
where
    V: Version,
{
    const PROTOCOL: Protocol = V::PROTOCOL;

    type ProtocolInputMsg = ProtocolInputMsg<V>;
    type ProtocolOutputMsg = ProtocolOutputMsg<V>;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx<V>;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx<V>;

    fn new(
        name: String,
        _shared: InstanceShared,
        tx: InstanceChannelsTx<Instance<V>>,
    ) -> Instance<V> {
        Debug::<V>::InstanceCreate.log();

        Instance {
            name,
            system: Default::default(),
            config: Default::default(),
            interfaces: Default::default(),
            state: None,
            tx,
        }
    }

    fn init(&mut self) {
        self.update();
    }

    fn shutdown(mut self) {
        // Ensure instance is disabled before exiting.
        self.stop(InstanceInactiveReason::AdminDown);
        Debug::<V>::InstanceDelete.log();
    }

    fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg) {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg<V>) {
        // Ignore event if the instance isn't active.
        let Some((mut instance, interfaces)) = self.as_up() else {
            return;
        };

        if let Err(error) = process_protocol_msg(&mut instance, interfaces, msg)
        {
            error.log();
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx<V>, ProtocolInputChannelsRx<V>) {
        let (udp_pdu_rxp, udp_pdu_rxc) = mpsc::channel(4);
        let (initial_updatep, initial_updatec) = mpsc::channel(4);
        let (update_intervalp, update_intervalc) = mpsc::channel(4);
        let (nbr_timeoutp, nbr_timeoutc) = mpsc::channel(4);
        let (route_timeoutp, route_timeoutc) = mpsc::channel(4);
        let (route_gc_timeoutp, route_gc_timeoutc) = mpsc::channel(4);
        let (triggered_updp, triggered_updc) = mpsc::unbounded_channel();
        let (triggered_upd_timeoutp, triggered_upd_timeoutc) = mpsc::channel(4);

        let tx = ProtocolInputChannelsTx {
            udp_pdu_rx: udp_pdu_rxp,
            initial_update: initial_updatep,
            update_interval: update_intervalp,
            nbr_timeout: nbr_timeoutp,
            route_timeout: route_timeoutp,
            route_gc_timeout: route_gc_timeoutp,
            triggered_upd: triggered_updp,
            triggered_upd_timeout: triggered_upd_timeoutp,
        };
        let rx = ProtocolInputChannelsRx {
            udp_pdu_rx: udp_pdu_rxc,
            initial_update: initial_updatec,
            update_interval: update_intervalc,
            nbr_timeout: nbr_timeoutc,
            route_timeout: route_timeoutc,
            route_gc_timeout: route_gc_timeoutc,
            triggered_upd: triggered_updc,
            triggered_upd_timeout: triggered_upd_timeoutc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!(
            "{}/tests/conformance/{}",
            env!("CARGO_MANIFEST_DIR"),
            V::PROTOCOL
        )
    }
}

// ===== impl InstanceState =====

impl<V> InstanceState<V>
where
    V: Version,
{
    fn new(
        update_interval: u16,
        tx: &InstanceChannelsTx<Instance<V>>,
    ) -> InstanceState<V> {
        // Start initial update timeout task.
        let initial_update_task =
            tasks::initial_update(&tx.protocol_input.initial_update);

        // Start update interval task.
        let interval = Duration::from_secs(update_interval.into());
        let update_interval_task = tasks::update_interval(
            interval,
            &tx.protocol_input.update_interval,
        );

        InstanceState {
            initial_update_task: Some(initial_update_task),
            update_interval_task,
            triggered_upd_timeout_task: None,
            pending_trigger_upd: false,
            neighbors: Default::default(),
            routes: Default::default(),
            statistics: Default::default(),
            // Initialize the authentication sequence number as the number of
            // seconds since the Unix epoch (1 January 1970).
            // By using this approach, the chances of successfully replaying
            // packets from a restarted RIP instance are significantly reduced.
            auth_seqno: Arc::new(
                (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs() as u32)
                    .into(),
            ),
        }
    }

    pub(crate) fn next_update(&self) -> Duration {
        self.update_interval_task.remaining()
    }

    pub(crate) fn next_triggered_update(&self) -> Option<Duration> {
        self.triggered_upd_timeout_task
            .as_ref()
            .map(TimeoutTask::remaining)
    }
}

// ===== impl MessageStatistics =====

impl MessageStatistics {
    pub(crate) fn update(&mut self, command: Command, sent: bool) {
        self.discontinuity_time = Some(Utc::now());
        match (command, sent) {
            (Command::Request, false) => self.requests_rcvd += 1,
            (Command::Request, true) => self.requests_sent += 1,
            (Command::Response, false) => self.responses_rcvd += 1,
            (Command::Response, true) => self.responses_sent += 1,
        }
    }
}

// ===== impl ProtocolInputChannelsTx =====

impl<V> ProtocolInputChannelsTx<V>
where
    V: Version,
{
    pub(crate) fn trigger_update(&self) {
        let _ = self.triggered_upd.send(TriggeredUpdMsg {});
    }
}

// ===== impl ProtocolInputChannelsRx =====

impl<V> MessageReceiver<ProtocolInputMsg<V>> for ProtocolInputChannelsRx<V>
where
    V: Version,
{
    async fn recv(&mut self) -> Option<ProtocolInputMsg<V>> {
        tokio::select! {
            msg = self.udp_pdu_rx.recv() => {
                msg.map(ProtocolInputMsg::UdpRxPdu)
            }
            msg = self.initial_update.recv() => {
                msg.map(ProtocolInputMsg::InitialUpdate)
            }
            msg = self.update_interval.recv() => {
                msg.map(ProtocolInputMsg::UpdateInterval)
            }
            msg = self.triggered_upd.recv() => {
                msg.map(ProtocolInputMsg::TriggeredUpd)
            }
            msg = self.triggered_upd_timeout.recv() => {
                msg.map(ProtocolInputMsg::TriggeredUpdTimeout)
            }
            msg = self.nbr_timeout.recv() => {
                msg.map(ProtocolInputMsg::NbrTimeout)
            }
            msg = self.route_timeout.recv() => {
                msg.map(ProtocolInputMsg::RouteTimeout)
            }
            msg = self.route_gc_timeout.recv() => {
                msg.map(ProtocolInputMsg::RouteGcTimeout)
            }
        }
    }
}

// ===== helper functions =====

fn process_ibus_msg<V>(
    instance: &mut Instance<V>,
    msg: IbusMsg,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if instance.config.trace_opts.ibus {
        Debug::<V>::IbusRx(&msg).log();
    }

    match msg {
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            ibus::rx::process_iface_update(instance, msg);
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            ibus::rx::process_addr_add(instance, msg);
        }
        // Interface address delete notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            ibus::rx::process_addr_del(instance, msg);
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Interfaces<V>,
    msg: ProtocolInputMsg<V>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    match msg {
        // Received UDP discovery PDU.
        ProtocolInputMsg::UdpRxPdu(msg) => {
            events::process_pdu(instance, interfaces, msg.src, msg.pdu);
        }
        // Route initial update.
        ProtocolInputMsg::InitialUpdate(_msg) => {
            events::process_initial_update(instance, interfaces);
        }
        // Route update interval.
        ProtocolInputMsg::UpdateInterval(_msg) => {
            events::process_update_interval(instance, interfaces);
        }
        // Signal to send triggered update.
        ProtocolInputMsg::TriggeredUpd(_msg) => {
            events::process_triggered_update(instance, interfaces);
        }
        // Triggered update timeout has expired.
        ProtocolInputMsg::TriggeredUpdTimeout(_msg) => {
            events::process_triggered_update_timeout(instance, interfaces);
        }
        // Neighbor's timeout has expired.
        ProtocolInputMsg::NbrTimeout(msg) => {
            events::process_nbr_timeout(instance, msg.addr);
        }
        // Route's timeout has expired.
        ProtocolInputMsg::RouteTimeout(msg) => {
            events::process_route_timeout(instance, interfaces, msg.prefix);
        }
        // Route's garbage-collection timeout has expired.
        ProtocolInputMsg::RouteGcTimeout(msg) => {
            events::process_route_gc_timeout(instance, msg.prefix);
        }
    }

    Ok(())
}
