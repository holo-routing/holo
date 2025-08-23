//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use chrono::{DateTime, Utc};
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::ip::AddressFamily;
use holo_utils::protocol::Protocol;
use holo_utils::task::TimeoutTask;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};

use crate::collections::{
    AreaId, Areas, Arena, InterfaceId, LsaEntryId, Lsdb, LsdbId, NeighborId,
};
use crate::debug::{
    Debug, InstanceInactiveReason, InterfaceInactiveReason, LsaFlushReason,
};
use crate::error::Error;
use crate::interface::{Interface, ism};
use crate::lsdb::{LsaEntry, LsaLogEntry, LsaOriginateEvent};
use crate::neighbor::{Neighbor, nsm};
use crate::northbound::configuration::InstanceCfg;
use crate::northbound::notification;
use crate::route::{RouteNet, RouteNetFlags};
use crate::spf::{SpfLogEntry, SpfTriggerLsa};
use crate::tasks::messages::input::{
    DbDescFreeMsg, DelayedAckMsg, GracePeriodMsg, IsmEventMsg, LsaFlushMsg,
    LsaOrigCheckMsg, LsaOrigDelayedMsg, LsaOrigEventMsg, LsaRefreshMsg,
    LsdbMaxAgeSweepMsg, NetRxPacketMsg, NsmEventMsg, RxmtIntervalMsg,
    SendLsUpdateMsg, SpfDelayEventMsg,
};
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::version::Version;
use crate::{events, ibus, lsdb, output, spf};

pub struct Instance<V: Version> {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: Option<InstanceState<V>>,
    // Instance arenas.
    pub arenas: InstanceArenas<V>,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance<V>>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug, Default)]
pub struct InstanceSys {
    pub router_id: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub struct InstanceState<V: Version> {
    // Instance address-family.
    pub af: AddressFamily,
    // Instance Router ID.
    pub router_id: Ipv4Addr,
    // LSDB of AS-scope LSAs.
    pub lsdb: Lsdb<V>,
    // SPF data.
    pub spf_last_event_rcvd: Option<Instant>,
    pub spf_last_time: Option<Instant>,
    pub spf_delay_state: spf::fsm::State,
    pub spf_delay_timer: Option<TimeoutTask>,
    pub spf_hold_down_timer: Option<TimeoutTask>,
    pub spf_learn_timer: Option<TimeoutTask>,
    // List of LSAs that have changed since the last SPF computation.
    pub spf_trigger_lsas: Vec<SpfTriggerLsa<V>>,
    // Time the SPF was scheduled.
    pub spf_schedule_time: Option<Instant>,
    // Routing table.
    pub rib: BTreeMap<V::IpNetwork, RouteNet<V>>,
    // Statistics.
    pub orig_lsa_count: u32,
    pub rx_lsa_count: u32,
    pub discontinuity_time: DateTime<Utc>,
    // LSA log.
    pub lsa_log: VecDeque<LsaLogEntry<V>>,
    pub lsa_log_next_id: u32,
    // SPF log.
    pub spf_log: VecDeque<SpfLogEntry<V>>,
    pub spf_log_next_id: u32,
    // Number of neighbors performing a graceful restart.
    pub gr_helper_count: usize,
    // Authentication non-decreasing sequence number.
    pub auth_seqno: Arc<AtomicU64>,
    // Hostname cache.
    pub hostnames: BTreeMap<Ipv4Addr, String>,
}

#[derive(Debug, Default)]
pub struct InstanceArenas<V: Version> {
    pub areas: Areas<V>,
    pub interfaces: Arena<Interface<V>>,
    pub neighbors: Arena<Neighbor<V>>,
    pub lsa_entries: Arena<LsaEntry<V>>,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx<V: Version> {
    // Interface FSM event.
    pub ism_event: UnboundedSender<IsmEventMsg>,
    // Neighbor FSM event.
    pub nsm_event: UnboundedSender<NsmEventMsg>,
    // Packet Rx event.
    pub net_packet_rx: Sender<NetRxPacketMsg<V>>,
    // Free last sent/received Database Description packets.
    pub dbdesc_free: Sender<DbDescFreeMsg>,
    // Request to send LS Update.
    pub send_lsupd: UnboundedSender<SendLsUpdateMsg>,
    // Packet retransmission interval.
    pub rxmt_interval: Sender<RxmtIntervalMsg>,
    // Delayed Ack timeout.
    pub delayed_ack_timeout: UnboundedSender<DelayedAckMsg>,
    // LSA originate event.
    pub lsa_orig_event: UnboundedSender<LsaOrigEventMsg>,
    // LSA originate check.
    pub lsa_orig_check: UnboundedSender<LsaOrigCheckMsg<V>>,
    // LSA delayed origination timer.
    pub lsa_orig_delayed_timer: Sender<LsaOrigDelayedMsg<V>>,
    // LSA flush event.
    pub lsa_flush: UnboundedSender<LsaFlushMsg<V>>,
    // LSA refresh event.
    pub lsa_refresh: UnboundedSender<LsaRefreshMsg<V>>,
    // LSDB MaxAge sweep timer.
    pub lsdb_maxage_sweep_interval: Sender<LsdbMaxAgeSweepMsg>,
    // SPF run event.
    pub spf_delay_event: UnboundedSender<SpfDelayEventMsg>,
    // Grace period timeout.
    pub grace_period: Sender<GracePeriodMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx<V: Version> {
    // Interface FSM event.
    pub ism_event: UnboundedReceiver<IsmEventMsg>,
    // Neighbor FSM event.
    pub nsm_event: UnboundedReceiver<NsmEventMsg>,
    // Packet Rx event.
    pub net_packet_rx: Receiver<NetRxPacketMsg<V>>,
    // Free last sent/received Database Description packets.
    pub dbdesc_free: Receiver<DbDescFreeMsg>,
    // Request to send LS Update.
    pub send_lsupd: UnboundedReceiver<SendLsUpdateMsg>,
    // Packet retransmission interval.
    pub rxmt_interval: Receiver<RxmtIntervalMsg>,
    // Delayed Ack timeout.
    pub delayed_ack_timeout: UnboundedReceiver<DelayedAckMsg>,
    // LSA originate event.
    pub lsa_orig_event: UnboundedReceiver<LsaOrigEventMsg>,
    // LSA originate check.
    pub lsa_orig_check: UnboundedReceiver<LsaOrigCheckMsg<V>>,
    // LSA delayed origination timer.
    pub lsa_orig_delayed_timer: Receiver<LsaOrigDelayedMsg<V>>,
    // LSA flush event.
    pub lsa_flush: UnboundedReceiver<LsaFlushMsg<V>>,
    // LSA refresh event.
    pub lsa_refresh: UnboundedReceiver<LsaRefreshMsg<V>>,
    // LSDB MaxAge sweep timer.
    pub lsdb_maxage_sweep_interval: Receiver<LsdbMaxAgeSweepMsg>,
    // SPF run event.
    pub spf_delay_event: UnboundedReceiver<SpfDelayEventMsg>,
    // Grace period timeout.
    pub grace_period: Receiver<GracePeriodMsg>,
}

pub struct InstanceUpView<'a, V: Version> {
    pub name: &'a str,
    pub system: &'a InstanceSys,
    pub config: &'a InstanceCfg,
    pub state: &'a mut InstanceState<V>,
    pub tx: &'a InstanceChannelsTx<Instance<V>>,
    pub shared: &'a InstanceShared,
}

// OSPF version-specific code.
pub trait InstanceVersion<V: Version> {
    const STRICT_AUTH_SEQNO_CHECK: bool;

    // Return the instance's address family (IPv4 or IPv6).
    fn address_family(instance: &Instance<V>) -> AddressFamily;

    // Return the instance's initial authentication sequence number.
    fn initial_auth_seqno(boot_count: u32) -> u64;
}

// ===== impl Instance =====

impl<V> Instance<V>
where
    V: Version,
{
    // Checks if the instance needs to be started or stopped in response to a
    // northbound or southbound event.
    pub(crate) fn update(&mut self) {
        let af = V::address_family(self);
        let router_id = self.get_router_id();

        match self.is_ready(router_id) {
            Ok(()) if !self.is_active() => {
                self.start(af, router_id.unwrap());
            }
            Err(reason) if self.is_active() => {
                self.stop(reason);
            }
            _ => (),
        }
    }

    fn start(&mut self, af: AddressFamily, router_id: Ipv4Addr) {
        Debug::<V>::InstanceStart.log();

        let state = InstanceState::new(af, router_id, self.boot_count_get());

        // Store instance initial state.
        self.state = Some(state);

        // Iterate over all configured areas.
        let (instance, arenas) = self.as_up().unwrap();
        for area in arenas.areas.iter() {
            // Try to start interfaces.
            for iface_idx in area.interfaces.indexes() {
                let iface = &mut arenas.interfaces[iface_idx];

                iface.update(
                    area,
                    &instance,
                    &mut arenas.neighbors,
                    &arenas.lsa_entries,
                );
            }

            // Originate Router Information LSA(s).
            instance.tx.protocol_input.lsa_orig_event(
                LsaOriginateEvent::AreaStart { area_id: area.id },
            );
        }

        // Update boot count in non-volatile storage.
        self.boot_count_update();
    }

    fn stop(&mut self, reason: InstanceInactiveReason) {
        if !self.is_active() {
            return;
        }

        Debug::<V>::InstanceStop(reason).log();

        // Flush all self-originated LSAs.
        let (mut instance, arenas) = self.as_up().unwrap();
        lsdb::flush_all_self_originated(&mut instance, arenas);

        // Uninstall all routes.
        for (dest, route) in
            instance.state.rib.iter().filter(|(_, route)| {
                route.flags.contains(RouteNetFlags::INSTALLED)
            })
        {
            ibus::tx::route_uninstall(&instance.tx.ibus, dest, route);
        }

        for area in arenas.areas.iter_mut() {
            // Clear area's state.
            area.state = Default::default();

            // Stop interfaces.
            for iface_idx in area.interfaces.indexes() {
                let iface = &mut arenas.interfaces[iface_idx];
                if iface.is_down() || iface.is_passive() {
                    continue;
                }

                // Send pending LS Updates.
                output::send_lsupd(
                    None,
                    iface,
                    area,
                    &instance,
                    &mut arenas.neighbors,
                );

                let reason = InterfaceInactiveReason::InstanceDown;
                iface.fsm(
                    area,
                    &instance,
                    &mut arenas.neighbors,
                    &arenas.lsa_entries,
                    ism::Event::InterfaceDown(reason),
                );
            }
        }

        // Clear instance state.
        self.state = None;
    }

    pub(crate) fn reset(&mut self) {
        if self.is_active() {
            self.stop(InstanceInactiveReason::Resetting);
            self.update();
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.state.is_some()
    }

    // Returns whether the instance is ready for OSPF operation.
    fn is_ready(
        &self,
        router_id: Option<Ipv4Addr>,
    ) -> Result<(), InstanceInactiveReason> {
        if !self.config.enabled || self.arenas.interfaces.is_empty() {
            return Err(InstanceInactiveReason::AdminDown);
        }

        if router_id.is_none() {
            return Err(InstanceInactiveReason::MissingRouterId);
        }

        Ok(())
    }

    pub(crate) fn get_router_id(&self) -> Option<Ipv4Addr> {
        self.config.router_id.or(self.system.router_id)
    }

    // Retrieves the boot count of the instance from non-volatile memory.
    fn boot_count_get(&self) -> u32 {
        let mut boot_count = 0;

        if let Some(db) = &self.shared.db {
            let db = db.lock().unwrap();

            let key = format!("{}-{}-boot-count", V::PROTOCOL, self.name);
            if let Some(value) = db.get::<u32>(&key) {
                boot_count = value;
            }
        }

        boot_count
    }

    // Stores the updated boot count of the instance in non-volatile memory.
    fn boot_count_update(&mut self) {
        if let Some(db) = &self.shared.db {
            let mut db = db.lock().unwrap();
            let mut boot_count = 0;

            let key = format!("{}-{}-boot-count", V::PROTOCOL, self.name);
            if let Some(value) = db.get::<u32>(&key) {
                boot_count = value;
            }
            boot_count += 1;
            if let Err(error) = db.set(&key, &boot_count) {
                Error::<V>::BootCountNvmUpdate(error).log();
            }
        }
    }

    pub(crate) fn as_up(
        &mut self,
    ) -> Option<(InstanceUpView<'_, V>, &mut InstanceArenas<V>)> {
        if let Some(state) = &mut self.state {
            let instance = InstanceUpView {
                name: &self.name,
                system: &self.system,
                config: &self.config,
                state,
                tx: &self.tx,
                shared: &self.shared,
            };
            Some((instance, &mut self.arenas))
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
        shared: InstanceShared,
        tx: InstanceChannelsTx<Instance<V>>,
    ) -> Instance<V> {
        Debug::<V>::InstanceCreate.log();

        Instance {
            name,
            system: Default::default(),
            config: Default::default(),
            state: None,
            arenas: Default::default(),
            tx,
            shared,
        }
    }

    fn init(&mut self) {
        // Request information about the system Router ID.
        ibus::tx::router_id_sub(&self.tx.ibus);

        // Request information about the system hostname.
        ibus::tx::hostname_sub(&self.tx.ibus);
    }

    fn shutdown(mut self) {
        // Ensure instance is disabled before exiting.
        self.stop(InstanceInactiveReason::AdminDown);
    }

    fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg) {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg<V>) {
        // Ignore event if the instance isn't active.
        if let Some((mut instance, arenas)) = self.as_up()
            && let Err(error) = process_protocol_msg(&mut instance, arenas, msg)
        {
            error.log();

            // Send notification.
            if let Error::InterfaceCfgError(ifname, src, pkt_type, error) =
                &error
            {
                notification::if_config_error(
                    &instance, ifname, src, pkt_type, error,
                );
            }
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx<V>, ProtocolInputChannelsRx<V>) {
        let (ism_eventp, ism_eventc) = mpsc::unbounded_channel();
        let (nsm_eventp, nsm_eventc) = mpsc::unbounded_channel();
        let (net_packet_rxp, net_packet_rxc) = mpsc::channel(4);
        let (dbdesc_freep, dbdesc_freec) = mpsc::channel(4);
        let (send_lsupdp, send_lsupdc) = mpsc::unbounded_channel();
        let (rxmt_intervalp, rxmt_intervalc) = mpsc::channel(4);
        let (delayed_ack_timeoutp, delayed_ack_timeoutc) =
            mpsc::unbounded_channel();
        let (lsa_orig_eventp, lsa_orig_eventc) = mpsc::unbounded_channel();
        let (lsa_orig_checkp, lsa_orig_checkc) = mpsc::unbounded_channel();
        let (lsa_orig_delayed_timerp, lsa_orig_delayed_timerc) =
            mpsc::channel(4);
        let (lsa_flushp, lsa_flushc) = mpsc::unbounded_channel();
        let (lsa_refreshp, lsa_refreshc) = mpsc::unbounded_channel();
        let (lsdb_maxage_sweep_intervalp, lsdb_maxage_sweep_intervalc) =
            mpsc::channel(4);
        let (spf_delay_eventp, spf_delay_eventc) = mpsc::unbounded_channel();
        let (grace_periodp, grace_periodc) = mpsc::channel(4);

        let tx = ProtocolInputChannelsTx {
            ism_event: ism_eventp,
            nsm_event: nsm_eventp,
            net_packet_rx: net_packet_rxp,
            dbdesc_free: dbdesc_freep,
            send_lsupd: send_lsupdp,
            rxmt_interval: rxmt_intervalp,
            delayed_ack_timeout: delayed_ack_timeoutp,
            lsa_orig_event: lsa_orig_eventp,
            lsa_orig_check: lsa_orig_checkp,
            lsa_orig_delayed_timer: lsa_orig_delayed_timerp,
            lsa_flush: lsa_flushp,
            lsa_refresh: lsa_refreshp,
            lsdb_maxage_sweep_interval: lsdb_maxage_sweep_intervalp,
            spf_delay_event: spf_delay_eventp,
            grace_period: grace_periodp,
        };
        let rx = ProtocolInputChannelsRx {
            ism_event: ism_eventc,
            nsm_event: nsm_eventc,
            net_packet_rx: net_packet_rxc,
            dbdesc_free: dbdesc_freec,
            send_lsupd: send_lsupdc,
            rxmt_interval: rxmt_intervalc,
            delayed_ack_timeout: delayed_ack_timeoutc,
            lsa_orig_event: lsa_orig_eventc,
            lsa_orig_check: lsa_orig_checkc,
            lsa_orig_delayed_timer: lsa_orig_delayed_timerc,
            lsa_flush: lsa_flushc,
            lsa_refresh: lsa_refreshc,
            lsdb_maxage_sweep_interval: lsdb_maxage_sweep_intervalc,
            spf_delay_event: spf_delay_eventc,
            grace_period: grace_periodc,
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

impl<V> std::fmt::Debug for Instance<V>
where
    V: Version,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Action").field("name", &self.name).finish()
    }
}

impl<V> Drop for Instance<V>
where
    V: Version,
{
    fn drop(&mut self) {
        Debug::<V>::InstanceDelete.log();
    }
}

// ===== impl InstanceState =====

impl<V> InstanceState<V>
where
    V: Version,
{
    fn new(
        af: AddressFamily,
        router_id: Ipv4Addr,
        boot_count: u32,
    ) -> InstanceState<V> {
        InstanceState {
            af,
            router_id,
            lsdb: Default::default(),
            spf_last_event_rcvd: None,
            spf_last_time: None,
            spf_delay_state: spf::fsm::State::Quiet,
            spf_delay_timer: None,
            spf_hold_down_timer: None,
            spf_learn_timer: None,
            spf_trigger_lsas: Default::default(),
            spf_schedule_time: None,
            rib: Default::default(),
            orig_lsa_count: 0,
            rx_lsa_count: 0,
            discontinuity_time: Utc::now(),
            lsa_log: Default::default(),
            lsa_log_next_id: 0,
            spf_log: Default::default(),
            spf_log_next_id: 0,
            gr_helper_count: 0,
            auth_seqno: Arc::new(V::initial_auth_seqno(boot_count).into()),
            hostnames: Default::default(),
        }
    }
}

// ===== impl ProtocolInputChannelsTx =====

impl<V> ProtocolInputChannelsTx<V>
where
    V: Version,
{
    pub(crate) fn ism_event(
        &self,
        area_id: AreaId,
        iface_id: InterfaceId,
        event: ism::Event,
    ) {
        let _ = self.ism_event.send(IsmEventMsg {
            area_key: area_id.into(),
            iface_key: iface_id.into(),
            event,
        });
    }

    pub(crate) fn nsm_event(
        &self,
        area_id: AreaId,
        iface_id: InterfaceId,
        nbr_id: NeighborId,
        event: nsm::Event,
    ) {
        let _ = self.nsm_event.send(NsmEventMsg {
            area_key: area_id.into(),
            iface_key: iface_id.into(),
            nbr_key: nbr_id.into(),
            event,
        });
    }

    pub(crate) fn send_lsupd(
        &self,
        area_id: AreaId,
        iface_id: InterfaceId,
        nbr_id: Option<NeighborId>,
    ) {
        let _ = self.send_lsupd.send(SendLsUpdateMsg {
            area_key: area_id.into(),
            iface_key: iface_id.into(),
            nbr_key: nbr_id.map(std::convert::Into::into),
        });
    }

    pub(crate) fn lsa_orig_event(&self, event: LsaOriginateEvent) {
        let _ = self.lsa_orig_event.send(LsaOrigEventMsg { event });
    }

    pub(crate) fn lsa_orig_check(
        &self,
        lsdb_id: LsdbId,
        options: Option<V::PacketOptions>,
        lsa_id: Ipv4Addr,
        lsa_body: V::LsaBody,
    ) {
        let _ = self.lsa_orig_check.send(LsaOrigCheckMsg {
            lsdb_key: lsdb_id.into(),
            options,
            lsa_id,
            lsa_body,
        });
    }

    pub(crate) fn lsa_flush(
        &self,
        lsdb_id: LsdbId,
        lse_id: LsaEntryId,
        reason: LsaFlushReason,
    ) {
        let _ = self.lsa_flush.send(LsaFlushMsg {
            lsdb_key: lsdb_id.into(),
            lse_key: lse_id.into(),
            reason,
        });
    }

    pub(crate) fn spf_delay_event(&self, event: spf::fsm::Event) {
        let _ = self.spf_delay_event.send(SpfDelayEventMsg { event });
    }
}

// ===== impl ProtocolInputChannelsRx =====

impl<V> MessageReceiver<ProtocolInputMsg<V>> for ProtocolInputChannelsRx<V>
where
    V: Version,
{
    async fn recv(&mut self) -> Option<ProtocolInputMsg<V>> {
        tokio::select! {
            biased;
            msg = self.ism_event.recv() => {
                msg.map(ProtocolInputMsg::IsmEvent)
            }
            msg = self.nsm_event.recv() => {
                msg.map(ProtocolInputMsg::NsmEvent)
            }
            msg = self.net_packet_rx.recv() => {
                msg.map(ProtocolInputMsg::NetRxPacket)
            }
            msg = self.dbdesc_free.recv() => {
                msg.map(ProtocolInputMsg::DbDescFree)
            }
            msg = self.send_lsupd.recv() => {
                msg.map(ProtocolInputMsg::SendLsUpdate)
            }
            msg = self.rxmt_interval.recv() => {
                msg.map(ProtocolInputMsg::RxmtInterval)
            }
            msg = self.delayed_ack_timeout.recv() => {
                msg.map(ProtocolInputMsg::DelayedAck)
            }
            msg = self.lsa_orig_event.recv() => {
                msg.map(ProtocolInputMsg::LsaOrigEvent)
            }
            msg = self.lsa_orig_check.recv() => {
                msg.map(ProtocolInputMsg::LsaOrigCheck)
            }
            msg = self.lsa_orig_delayed_timer.recv() => {
                msg.map(ProtocolInputMsg::LsaOrigDelayed)
            }
            msg = self.lsa_flush.recv() => {
                msg.map(ProtocolInputMsg::LsaFlush)
            }
            msg = self.lsa_refresh.recv() => {
                msg.map(ProtocolInputMsg::LsaRefresh)
            }
            msg = self.lsdb_maxage_sweep_interval.recv() => {
                msg.map(ProtocolInputMsg::LsdbMaxAgeSweep)
            }
            msg = self.spf_delay_event.recv() => {
                msg.map(ProtocolInputMsg::SpfDelayEvent)
            }
            msg = self.grace_period.recv() => {
                msg.map(ProtocolInputMsg::GracePeriod)
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
        // BFD peer state update event.
        IbusMsg::BfdStateUpd { sess_key, state } => {
            ibus::rx::process_bfd_state_update(instance, sess_key, state)?
        }
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
        // Keychain update event.
        IbusMsg::KeychainUpd(keychain) => {
            // Update the local copy of the keychain.
            instance
                .shared
                .keychains
                .insert(keychain.name.clone(), keychain.clone());

            // Update all interfaces using this keychain.
            ibus::rx::process_keychain_update(instance, &keychain.name)?
        }
        // Keychain delete event.
        IbusMsg::KeychainDel(keychain_name) => {
            // Remove the local copy of the keychain.
            instance.shared.keychains.remove(&keychain_name);

            // Update all interfaces using this keychain.
            ibus::rx::process_keychain_update(instance, &keychain_name)?
        }
        // Router ID update notification.
        IbusMsg::RouterIdUpdate(router_id) => {
            ibus::rx::process_router_id_update(instance, router_id);
        }
        // SR configuration update.
        IbusMsg::SrCfgUpd(sr_config) => {
            instance.shared.sr_config = sr_config;
        }
        // BIER configuration update.
        IbusMsg::BierCfgUpd(bier_config) => {
            instance.shared.bier_config = bier_config;
        }
        // SR configuration event.
        IbusMsg::SrCfgEvent(event) => {
            ibus::rx::process_sr_cfg_change(instance, event)?
        }
        IbusMsg::BierCfgEvent(event) => {
            ibus::rx::process_bier_cfg_change(instance, event)?
        }
        IbusMsg::HostnameUpdate(hostname) => {
            ibus::rx::process_hostname_update(instance, hostname)?;
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    msg: ProtocolInputMsg<V>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    match msg {
        // Interface FSM event.
        ProtocolInputMsg::IsmEvent(msg) => events::process_ism_event(
            instance,
            arenas,
            msg.area_key,
            msg.iface_key,
            msg.event,
        )?,
        // Neighbor FSM event.
        ProtocolInputMsg::NsmEvent(msg) => events::process_nsm_event(
            instance,
            arenas,
            msg.area_key,
            msg.iface_key,
            msg.nbr_key,
            msg.event,
        )?,
        // Received network packet.
        ProtocolInputMsg::NetRxPacket(msg) => {
            events::process_packet(
                instance,
                arenas,
                msg.area_key,
                msg.iface_key,
                msg.src,
                msg.dst,
                msg.packet,
            )?;
        }
        // Free last sent/received Database Description packets.
        ProtocolInputMsg::DbDescFree(msg) => events::process_dbdesc_free(
            instance,
            arenas,
            msg.area_key,
            msg.iface_key,
            msg.nbr_key,
        )?,
        // Request to send LS Update.
        ProtocolInputMsg::SendLsUpdate(msg) => events::process_send_lsupd(
            instance,
            arenas,
            msg.area_key,
            msg.iface_key,
            msg.nbr_key,
        )?,
        // Packet retransmission.
        ProtocolInputMsg::RxmtInterval(msg) => events::process_packet_rxmt(
            instance,
            arenas,
            msg.area_key,
            msg.iface_key,
            msg.nbr_key,
            msg.packet_type,
        )?,
        // Delayed Ack timeout.
        ProtocolInputMsg::DelayedAck(msg) => {
            events::process_delayed_ack_timeout(
                instance,
                arenas,
                msg.area_key,
                msg.iface_key,
            )?
        }
        // LSA origination event.
        ProtocolInputMsg::LsaOrigEvent(msg) => {
            events::process_lsa_orig_event(instance, arenas, msg.event)?
        }
        // LSA origination check.
        ProtocolInputMsg::LsaOrigCheck(msg) => events::process_lsa_orig_check(
            instance,
            arenas,
            msg.lsdb_key,
            msg.options,
            msg.lsa_id,
            msg.lsa_body,
        )?,
        // LSA delayed origination timer.
        ProtocolInputMsg::LsaOrigDelayed(msg) => {
            events::process_lsa_orig_delayed_timer(
                instance,
                arenas,
                msg.lsdb_key,
                msg.lsa_key,
            )?
        }
        // LSA flush.
        ProtocolInputMsg::LsaFlush(msg) => events::process_lsa_flush(
            instance,
            arenas,
            msg.lsdb_key,
            msg.lse_key,
            msg.reason,
        )?,
        // LSA refresh event.
        ProtocolInputMsg::LsaRefresh(msg) => events::process_lsa_refresh(
            instance,
            arenas,
            msg.lsdb_key,
            msg.lse_key,
        )?,
        // LSA MaxAge sweep interval.
        ProtocolInputMsg::LsdbMaxAgeSweep(msg) => {
            events::process_lsdb_maxage_sweep_interval(
                instance,
                arenas,
                msg.lsdb_key,
            )?
        }
        // SPF run event.
        ProtocolInputMsg::SpfDelayEvent(msg) => {
            events::process_spf_delay_event(instance, arenas, msg.event)?
        }
        // Grace period timeout.
        ProtocolInputMsg::GracePeriod(msg) => {
            events::process_grace_period_timeout(
                instance,
                arenas,
                msg.area_key,
                msg.iface_key,
                msg.nbr_key,
            )?
        }
    }

    Ok(())
}
