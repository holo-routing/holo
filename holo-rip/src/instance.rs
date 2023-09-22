//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enum_as_inner::EnumAsInner;
use holo_northbound::paths::control_plane_protocol::rip;
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_southbound::rx::SouthboundRx;
use holo_southbound::tx::SouthboundTx;
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::task::{IntervalTask, TimeoutTask};
use holo_utils::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc;

use crate::debug::{Debug, InstanceInactiveReason, InterfaceInactiveReason};
use crate::interface::Interfaces;
use crate::neighbor::Neighbor;
use crate::packet::Command;
use crate::route::{Metric, Route};
use crate::southbound::rx::InstanceSouthboundRx;
use crate::southbound::tx::InstanceSouthboundTx;
use crate::tasks::messages::input::{
    InitialUpdateMsg, NbrTimeoutMsg, RouteGcTimeoutMsg, RouteTimeoutMsg,
    TriggeredUpdMsg, TriggeredUpdTimeoutMsg, UdpRxPduMsg, UpdateIntervalMsg,
};
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::version::Version;
use crate::{events, tasks};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, EnumAsInner)]
pub enum Instance<V: Version> {
    Up(InstanceUp<V>),
    Down(InstanceDown<V>),
    // This state is required to allow in-place mutations of Instance.
    Transitioning,
}

pub type InstanceUp<V> = InstanceCommon<V, InstanceState<V>>;
pub type InstanceDown<V> = InstanceCommon<V, InstanceStateDown>;

#[derive(Debug)]
pub struct InstanceCommon<V: Version, State> {
    // Instance state-independent data.
    pub core: InstanceCore<V>,
    // Instance state-dependent data.
    pub state: State,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance<V>>,
}

#[derive(Debug)]
pub struct InstanceCore<V: Version> {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance interfaces.
    pub interfaces: Interfaces<V>,
}

#[derive(Debug, Default)]
pub struct InstanceSys {
    pub router_id: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub struct InstanceCfg {
    pub default_metric: Metric,
    pub distance: u8,
    pub triggered_update_threshold: u8,
    pub update_interval: u16,
    pub invalid_interval: u16,
    pub flush_interval: u16,
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

#[derive(Debug)]
pub struct InstanceStateDown();

// Inbound and outbound statistic counters.
#[derive(Debug, Default)]
pub struct MessageStatistics {
    pub discontinuity_time: Option<DateTime<Utc>>,
    pub requests_rcvd: u32,
    pub requests_sent: u32,
    pub responses_rcvd: u32,
    pub responses_sent: u32,
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
    pub(crate) async fn update(&mut self) {
        match self.is_ready() {
            Ok(()) if !self.is_active() => {
                self.start().await;
            }
            Err(reason) if self.is_active() => {
                self.stop(reason);
            }
            _ => (),
        }
    }

    async fn start(&mut self) {
        let instance = &self.as_down().unwrap();
        let update_interval = instance.core.config.update_interval;
        let instance = std::mem::replace(self, Instance::Transitioning)
            .into_down()
            .unwrap();
        let state = InstanceState::new(update_interval, &instance.tx).await;
        *self = Instance::Up(instance.start(state));
    }

    fn stop(&mut self, reason: InstanceInactiveReason) {
        if !self.is_active() {
            return;
        }

        let instance = std::mem::replace(self, Instance::Transitioning)
            .into_up()
            .unwrap();
        *self = Instance::Down(instance.stop(reason));
    }

    fn is_active(&self) -> bool {
        matches!(self, Instance::Up(_))
    }

    // Returns whether the instance is ready for RIP operation.
    //
    // NOTE: as of now there's nothing that can cause a RIP instance to be
    // deactivated (other than unconfiguration). In the future, one possible
    // deactivation cause is when the underlying VRF becomes inoperative.
    fn is_ready(&self) -> Result<(), InstanceInactiveReason> {
        Ok(())
    }

    #[allow(dead_code)]
    #[inline]
    pub(crate) fn core(&self) -> &InstanceCore<V> {
        match self {
            Instance::Up(instance) => &instance.core,
            Instance::Down(instance) => &instance.core,
            Instance::Transitioning => unreachable!(),
        }
    }

    #[inline]
    pub(crate) fn core_mut(&mut self) -> &mut InstanceCore<V> {
        match self {
            Instance::Up(instance) => &mut instance.core,
            Instance::Down(instance) => &mut instance.core,
            Instance::Transitioning => unreachable!(),
        }
    }
}

#[async_trait]
impl<V> ProtocolInstance for Instance<V>
where
    V: Version,
{
    const PROTOCOL: Protocol = V::PROTOCOL;

    type ProtocolInputMsg = ProtocolInputMsg<V>;
    type ProtocolOutputMsg = ProtocolOutputMsg<V>;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx<V>;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx<V>;
    type SouthboundTx = InstanceSouthboundTx;
    type SouthboundRx = InstanceSouthboundRx;

    async fn new(
        name: String,
        _shared: InstanceShared,
        tx: InstanceChannelsTx<Instance<V>>,
    ) -> Instance<V> {
        Debug::<V>::InstanceCreate.log();

        Instance::Down(InstanceDown {
            core: InstanceCore {
                name,
                system: Default::default(),
                config: Default::default(),
                interfaces: Default::default(),
            },
            state: InstanceStateDown(),
            tx,
        })
    }

    async fn init(&mut self) {
        self.update().await;
    }

    async fn shutdown(mut self) {
        // Ensure instance is disabled before exiting.
        self.stop(InstanceInactiveReason::AdminDown);
        Debug::<V>::InstanceDelete.log();
    }

    fn process_ibus_msg(&mut self, _msg: IbusMsg) {}

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg<V>) {
        // Ignore event if the instance isn't active.
        if let Instance::Up(instance) = self {
            instance.process_protocol_msg(msg);
        }
    }

    fn southbound_start(
        sb_tx: SouthboundTx,
        sb_rx: SouthboundRx,
    ) -> (Self::SouthboundTx, Self::SouthboundRx) {
        let sb_tx = InstanceSouthboundTx::new(sb_tx);
        let sb_rx = InstanceSouthboundRx::new(sb_rx);
        sb_tx.initial_requests();
        (sb_tx, sb_rx)
    }

    fn protocol_input_channels(
    ) -> (ProtocolInputChannelsTx<V>, ProtocolInputChannelsRx<V>) {
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

// ===== impl InstanceCommon =====

// Active RIP instance.
impl<V> InstanceCommon<V, InstanceState<V>>
where
    V: Version,
{
    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg<V>) {
        match msg {
            // Received UDP discovery PDU.
            ProtocolInputMsg::UdpRxPdu(msg) => {
                events::process_pdu(self, msg.src, msg.pdu);
            }
            // Route initial update.
            ProtocolInputMsg::InitialUpdate(_msg) => {
                events::process_initial_update(self);
            }
            // Route update interval.
            ProtocolInputMsg::UpdateInterval(_msg) => {
                events::process_update_interval(self);
            }
            // Signal to send triggered update.
            ProtocolInputMsg::TriggeredUpd(_msg) => {
                events::process_triggered_update(self);
            }
            // Triggered update timeout has expired.
            ProtocolInputMsg::TriggeredUpdTimeout(_msg) => {
                events::process_triggered_update_timeout(self);
            }
            // Neighbor's timeout has expired.
            ProtocolInputMsg::NbrTimeout(msg) => {
                events::process_nbr_timeout(self, msg.addr);
            }
            // Route's timeout has expired.
            ProtocolInputMsg::RouteTimeout(msg) => {
                events::process_route_timeout(self, msg.prefix);
            }
            // Route's garbage-collection timeout has expired.
            ProtocolInputMsg::RouteGcTimeout(msg) => {
                events::process_route_gc_timeout(self, msg.prefix);
            }
        }
    }

    fn stop(
        mut self,
        reason: InstanceInactiveReason,
    ) -> InstanceCommon<V, InstanceStateDown> {
        Debug::<V>::InstanceStop(reason).log();

        // Stop interfaces.
        for iface in self.core.interfaces.iter_mut() {
            iface.stop(
                &mut self.state,
                &self.tx,
                InterfaceInactiveReason::InstanceDown,
            );
        }

        InstanceCommon::<V, InstanceStateDown> {
            core: self.core,
            state: InstanceStateDown(),
            tx: self.tx,
        }
    }
}

// Inactive RIP instance.
impl<V> InstanceCommon<V, InstanceStateDown>
where
    V: Version,
{
    fn start(
        self,
        state: InstanceState<V>,
    ) -> InstanceCommon<V, InstanceState<V>> {
        Debug::<V>::InstanceStart.log();

        let mut instance = InstanceCommon::<V, InstanceState<V>> {
            core: self.core,
            state,
            tx: self.tx,
        };

        // Try to start interfaces.
        for iface in instance.core.interfaces.iter_mut() {
            iface.update(&mut instance.state, &instance.tx);
        }

        instance
    }
}

// ===== impl InstanceCfg =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let default_metric = Metric::from(rip::default_metric::DFLT);
        let distance = rip::distance::DFLT;
        let triggered_update_threshold = rip::triggered_update_threshold::DFLT;
        let update_interval = rip::timers::update_interval::DFLT;
        let invalid_interval = rip::timers::invalid_interval::DFLT;
        let flush_interval = rip::timers::flush_interval::DFLT;

        InstanceCfg {
            default_metric,
            distance,
            triggered_update_threshold,
            update_interval,
            invalid_interval,
            flush_interval,
        }
    }
}

// ===== impl InstanceState =====

impl<V> InstanceState<V>
where
    V: Version,
{
    async fn new(
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

#[async_trait]
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
