//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::Instant;

use chrono::{DateTime, Utc};
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::sr::MsdType;
use holo_utils::task::TimeoutTask;
use ipnetwork::IpNetwork;
use prefix_trie::joint::map::JointPrefixMap;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};

use crate::adjacency::{Adjacency, AdjacencyState};
use crate::collections::{Arena, InterfaceId, Interfaces, Lsdb, LspEntryId};
use crate::debug::{
    Debug, InstanceInactiveReason, InterfaceInactiveReason, LspPurgeReason,
};
use crate::error::Error;
use crate::interface::CircuitIdAllocator;
use crate::lsdb::{LspEntry, LspLogEntry};
use crate::northbound::configuration::InstanceCfg;
use crate::packet::{LevelNumber, LevelType, Levels, SystemId};
use crate::route::{Route, RouteFlags, RouteSys, SummaryRoute};
use crate::spf::{SpfLogEntry, SpfScheduler, Spt, Topologies};
use crate::tasks::messages::input::{
    AdjHoldTimerMsg, DisElectionMsg, LspDeleteMsg, LspOriginateMsg,
    LspPurgeMsg, LspRefreshMsg, NetRxPduMsg, SendCsnpMsg, SendPsnpMsg,
    SpfDelayEventMsg,
};
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, ibus, lsdb, spf, tasks};

#[derive(Debug)]
pub struct Instance {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: Option<InstanceState>,
    // Instance arenas.
    pub arenas: InstanceArenas,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug, Default)]
pub struct InstanceSys {
    // System Router ID.
    pub router_id: Option<Ipv4Addr>,
    // Node MSD,
    pub node_msd: BTreeMap<MsdType, u8>,
    // Redistributed routes.
    pub routes: Levels<JointPrefixMap<IpNetwork, RouteSys>>,
}

#[derive(Debug)]
pub struct InstanceState {
    // Boot count.
    pub boot_count: u64,
    // Circuit ID allocator.
    pub circuit_id_allocator: CircuitIdAllocator,
    // Hostname database.
    pub hostnames: BTreeMap<SystemId, String>,
    // Link State Database.
    pub lsdb: Levels<Lsdb>,
    // LSP origination data.
    pub lsp_orig_last: Option<Instant>,
    pub lsp_orig_backoff: Option<TimeoutTask>,
    pub lsp_orig_pending: Option<LevelType>,
    // SPF scheduler state.
    pub spf_sched: Levels<SpfScheduler>,
    // Shortest-path tree.
    pub spt: Topologies<Levels<Spt>>,
    // Routing table (per-level and L1/L2).
    pub rib_single: Levels<BTreeMap<IpNetwork, Route>>,
    pub rib_multi: BTreeMap<IpNetwork, Route>,
    // Summary routes (L1 to L2).
    pub summaries: BTreeMap<IpNetwork, SummaryRoute>,
    // Event counters.
    pub counters: Levels<InstanceCounters>,
    pub discontinuity_time: DateTime<Utc>,
    // Log of LSP updates.
    pub lsp_log: VecDeque<LspLogEntry>,
    pub lsp_log_next_id: u32,
    // Log of SPF runs.
    pub spf_log: VecDeque<SpfLogEntry>,
    pub spf_log_next_id: u32,
}

#[derive(Debug, Default)]
pub struct InstanceCounters {
    pub corrupted_lsps: u32,
    pub auth_type_fails: u32,
    pub auth_fails: u32,
    pub database_overload: u32,
    pub own_lsp_purge: u32,
    pub manual_addr_drop_from_area: u32,
    pub max_sequence: u32,
    pub seqno_skipped: u32,
    pub id_len_mismatch: u32,
    pub partition_changes: u32,
    pub lsp_errors: u32,
    pub spf_runs: u32,
}

#[derive(Debug, Default)]
pub struct InstanceArenas {
    pub interfaces: Interfaces,
    pub adjacencies: Arena<Adjacency>,
    pub lsp_entries: Arena<LspEntry>,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // PDU Rx event.
    pub net_pdu_rx: Sender<NetRxPduMsg>,
    // Adjacency hold timer event.
    pub adj_holdtimer: Sender<AdjHoldTimerMsg>,
    // Request to run DIS election.
    pub dis_election: UnboundedSender<DisElectionMsg>,
    // Request to send PSNP(s).
    pub send_psnp: UnboundedSender<SendPsnpMsg>,
    // Request to send CSNP(s).
    pub send_csnp: UnboundedSender<SendCsnpMsg>,
    // LSP originate event.
    pub lsp_originate: UnboundedSender<LspOriginateMsg>,
    // LSP purge event.
    pub lsp_purge: UnboundedSender<LspPurgeMsg>,
    // LSP delete event.
    pub lsp_delete: UnboundedSender<LspDeleteMsg>,
    // LSP refresh event.
    pub lsp_refresh: UnboundedSender<LspRefreshMsg>,
    // SPF Delay FSM event.
    pub spf_delay_event: UnboundedSender<SpfDelayEventMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // PDU Rx event.
    pub net_pdu_rx: Receiver<NetRxPduMsg>,
    // Adjacency hold timer event.
    pub adj_holdtimer: Receiver<AdjHoldTimerMsg>,
    // Request to run DIS election.
    pub dis_election: UnboundedReceiver<DisElectionMsg>,
    // Request to send PSNP(s).
    pub send_psnp: UnboundedReceiver<SendPsnpMsg>,
    // Request to send CSNP(s).
    pub send_csnp: UnboundedReceiver<SendCsnpMsg>,
    // LSP originate event.
    pub lsp_originate: UnboundedReceiver<LspOriginateMsg>,
    // LSP purge event.
    pub lsp_purge: UnboundedReceiver<LspPurgeMsg>,
    // LSP delete event.
    pub lsp_delete: UnboundedReceiver<LspDeleteMsg>,
    // LSP refresh event.
    pub lsp_refresh: UnboundedReceiver<LspRefreshMsg>,
    // SPF Delay FSM event.
    pub spf_delay_event: UnboundedReceiver<SpfDelayEventMsg>,
}

pub struct InstanceUpView<'a> {
    pub name: &'a str,
    pub system: &'a InstanceSys,
    pub config: &'a InstanceCfg,
    pub state: &'a mut InstanceState,
    pub tx: &'a InstanceChannelsTx<Instance>,
    pub shared: &'a InstanceShared,
}

// ===== impl Instance =====

impl Instance {
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

    // Starts the IS-IS instance.
    fn start(&mut self) {
        Debug::InstanceStart.log();

        // Create instance initial state.
        let boot_count = self.boot_count_increment();
        let state = InstanceState::new(boot_count);
        self.state = Some(state);
        let (mut instance, arenas) = self.as_up().unwrap();

        // Start interfaces.
        for iface in arenas.interfaces.iter_mut() {
            iface
                .update(&mut instance, &mut arenas.adjacencies)
                .unwrap();
        }

        // Schedule initial LSP origination.
        instance.schedule_lsp_origination(LevelType::All);
    }

    // Stops the IS-IS instance.
    fn stop(&mut self, reason: InstanceInactiveReason) {
        let (mut instance, arenas) = self.as_up().unwrap();

        Debug::InstanceStop(reason).log();

        // Uninstall all routes.
        for (prefix, route) in instance
            .state
            .rib(instance.config.level_type)
            .iter()
            .filter(|(_, route)| route.flags.contains(RouteFlags::INSTALLED))
        {
            ibus::tx::route_uninstall(&instance.tx.ibus, prefix, route);
        }

        // Stop interfaces.
        let reason = InterfaceInactiveReason::InstanceDown;
        for iface in arenas
            .interfaces
            .iter_mut()
            .filter(|iface| iface.state.active)
        {
            iface.stop(&mut instance, &mut arenas.adjacencies, reason);
        }

        // Clear instance state.
        self.state = None;
    }

    // Resets the IS-IS instance.
    pub(crate) fn reset(&mut self) {
        if self.is_active() {
            self.stop(InstanceInactiveReason::Resetting);
            self.update();
        }
    }

    // Returns whether the IS-IS instance is operational.
    pub(crate) fn is_active(&self) -> bool {
        self.state.is_some()
    }

    // Returns whether the instance is ready for IS-IS operation.
    fn is_ready(&self) -> Result<(), InstanceInactiveReason> {
        if !self.config.enabled || self.config.system_id.is_none() {
            return Err(InstanceInactiveReason::AdminDown);
        }

        Ok(())
    }

    // Increments and stores the boot count for the instance in non-volatile
    // memory. Returns the updated count.
    fn boot_count_increment(&mut self) -> u64 {
        let mut boot_count = 0;
        if let Some(db) = &self.shared.db {
            let mut db = db.lock().unwrap();

            let key = format!("{}-{}-boot-count", Protocol::ISIS, self.name);
            boot_count = db.get::<u64>(&key).unwrap_or(0) + 1;
            if let Err(error) = db.set(&key, &boot_count) {
                Error::BootCountNvmUpdate(error).log();
            }
        }
        boot_count
    }

    // Returns a view struct for the instance if it's operational.
    pub(crate) fn as_up(
        &mut self,
    ) -> Option<(InstanceUpView<'_>, &mut InstanceArenas)> {
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

impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::ISIS;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    fn new(
        name: String,
        shared: InstanceShared,
        tx: InstanceChannelsTx<Instance>,
    ) -> Instance {
        Debug::InstanceCreate.log();

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
        Debug::InstanceDelete.log();
    }

    fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg) {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        // Ignore event if the instance isn't active.
        let Some((mut instance, arenas)) = self.as_up() else {
            return;
        };

        if let Err(error) = process_protocol_msg(&mut instance, arenas, msg) {
            error.log();
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (net_pdu_rxp, net_pdu_rxc) = mpsc::channel(4);
        let (adj_holdtimerp, adj_holdtimerc) = mpsc::channel(4);
        let (dis_electionp, dis_electionc) = mpsc::unbounded_channel();
        let (send_psnpp, send_psnpc) = mpsc::unbounded_channel();
        let (send_csnpp, send_csnpc) = mpsc::unbounded_channel();
        let (lsp_originatep, lsp_originatec) = mpsc::unbounded_channel();
        let (lsp_purgep, lsp_purgec) = mpsc::unbounded_channel();
        let (lsp_deletep, lsp_deletec) = mpsc::unbounded_channel();
        let (lsp_refreshp, lsp_refreshc) = mpsc::unbounded_channel();
        let (spf_delay_eventp, spf_delay_eventc) = mpsc::unbounded_channel();

        let tx = ProtocolInputChannelsTx {
            net_pdu_rx: net_pdu_rxp,
            adj_holdtimer: adj_holdtimerp,
            dis_election: dis_electionp,
            send_psnp: send_psnpp,
            send_csnp: send_csnpp,
            lsp_originate: lsp_originatep,
            lsp_purge: lsp_purgep,
            lsp_delete: lsp_deletep,
            lsp_refresh: lsp_refreshp,
            spf_delay_event: spf_delay_eventp,
        };
        let rx = ProtocolInputChannelsRx {
            net_pdu_rx: net_pdu_rxc,
            adj_holdtimer: adj_holdtimerc,
            dis_election: dis_electionc,
            send_psnp: send_psnpc,
            send_csnp: send_csnpc,
            lsp_originate: lsp_originatec,
            lsp_purge: lsp_purgec,
            lsp_delete: lsp_deletec,
            lsp_refresh: lsp_refreshc,
            spf_delay_event: spf_delay_eventc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests/conformance", env!("CARGO_MANIFEST_DIR"),)
    }
}

// ===== impl InstanceState =====

impl InstanceState {
    fn new(boot_count: u64) -> InstanceState {
        InstanceState {
            boot_count,
            circuit_id_allocator: Default::default(),
            hostnames: Default::default(),
            lsdb: Default::default(),
            lsp_orig_last: None,
            lsp_orig_backoff: None,
            lsp_orig_pending: None,
            spf_sched: Default::default(),
            spt: Default::default(),
            rib_single: Default::default(),
            rib_multi: Default::default(),
            summaries: Default::default(),
            counters: Default::default(),
            discontinuity_time: Utc::now(),
            lsp_log: Default::default(),
            lsp_log_next_id: 0,
            spf_log: Default::default(),
            spf_log_next_id: 0,
        }
    }

    // Returns a reference to the RIB for the specified level type.
    pub(crate) fn rib(
        &self,
        level_type: LevelType,
    ) -> &BTreeMap<IpNetwork, Route> {
        match level_type {
            LevelType::L1 | LevelType::L2 => self.rib_single.get(level_type),
            LevelType::All => &self.rib_multi,
        }
    }

    // Returns a mutable reference to the RIB for the specified level type.
    pub(crate) fn rib_mut(
        &mut self,
        level_type: LevelType,
    ) -> &mut BTreeMap<IpNetwork, Route> {
        match level_type {
            LevelType::L1 | LevelType::L2 => {
                self.rib_single.get_mut(level_type)
            }
            LevelType::All => &mut self.rib_multi,
        }
    }
}

// ===== impl ProtocolInputChannelsTx =====

impl ProtocolInputChannelsTx {
    pub(crate) fn dis_election(
        &self,
        iface_id: InterfaceId,
        level: LevelNumber,
    ) {
        let msg = DisElectionMsg {
            iface_key: iface_id.into(),
            level,
        };
        let _ = self.dis_election.send(msg);
    }

    pub(crate) fn lsp_purge(
        &self,
        level: LevelNumber,
        lse_id: LspEntryId,
        reason: LspPurgeReason,
    ) {
        let msg = LspPurgeMsg {
            level,
            lse_key: lse_id.into(),
            reason,
        };
        let _ = self.lsp_purge.send(msg);
    }

    pub(crate) fn lsp_refresh(&self, level: LevelNumber, lse_id: LspEntryId) {
        let msg = LspRefreshMsg {
            level,
            lse_key: lse_id.into(),
        };
        let _ = self.lsp_refresh.send(msg);
    }

    pub(crate) fn spf_delay_event(
        &self,
        level: LevelNumber,
        event: spf::fsm::Event,
    ) {
        let _ = self.spf_delay_event.send(SpfDelayEventMsg { level, event });
    }
}

// ===== impl ProtocolInputChannelsRx =====

impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            biased;
            msg = self.net_pdu_rx.recv() => {
                msg.map(ProtocolInputMsg::NetRxPdu)
            }
            msg = self.adj_holdtimer.recv() => {
                msg.map(ProtocolInputMsg::AdjHoldTimer)
            }
            msg = self.dis_election.recv() => {
                msg.map(ProtocolInputMsg::DisElection)
            }
            msg = self.send_psnp.recv() => {
                msg.map(ProtocolInputMsg::SendPsnp)
            }
            msg = self.send_csnp.recv() => {
                msg.map(ProtocolInputMsg::SendCsnp)
            }
            msg = self.lsp_originate.recv() => {
                msg.map(ProtocolInputMsg::LspOriginate)
            }
            msg = self.lsp_purge.recv() => {
                msg.map(ProtocolInputMsg::LspPurge)
            }
            msg = self.lsp_delete.recv() => {
                msg.map(ProtocolInputMsg::LspDelete)
            }
            msg = self.lsp_refresh.recv() => {
                msg.map(ProtocolInputMsg::LspRefresh)
            }
            msg = self.spf_delay_event.recv() => {
                msg.map(ProtocolInputMsg::SpfDelayEvent)
            }
        }
    }
}

// ===== impl InstanceUpView =====

impl InstanceUpView<'_> {
    // Checks if the instance is attached to the Level 2 backbone.
    pub(crate) fn is_l2_attached_to_backbone(
        &self,
        mt_id: impl Into<u16>,
        interfaces: &Interfaces,
        adjacencies: &Arena<Adjacency>,
    ) -> bool {
        let mt_id = mt_id.into();
        interfaces
            .iter()
            .flat_map(|iface| iface.adjacencies(adjacencies))
            .filter(|adj| adj.topologies.contains(&mt_id))
            .filter(|adj| adj.state == AdjacencyState::Up)
            .filter(|adj| adj.level_usage.intersects(LevelNumber::L2))
            .any(|adj| adj.area_addrs.is_disjoint(&self.config.area_addrs))
    }

    pub(crate) fn schedule_lsp_origination(
        &mut self,
        level_type: impl Into<LevelType>,
    ) {
        let level_type = level_type.into();

        // Update pending LSP origination with the union of the current and
        // new level.
        self.state.lsp_orig_pending = match self.state.lsp_orig_pending {
            Some(pending_level) => Some(level_type.union(pending_level)),
            None => Some(level_type),
        };

        #[cfg(not(feature = "deterministic"))]
        {
            // If LSP origination is currently in backoff, do nothing.
            if self.state.lsp_orig_backoff.is_some() {
                return;
            }

            // If the minimum interval since the last LSP origination hasn't
            // passed, initiate a backoff timer and return.
            if let Some(last) = self.state.lsp_orig_last
                && last.elapsed().as_secs() < lsdb::LSP_MIN_GEN_INTERVAL
            {
                let task = tasks::lsp_originate_timer(
                    &self.tx.protocol_input.lsp_originate,
                );
                self.state.lsp_orig_backoff = Some(task);
                return;
            }
        }

        // Trigger LSP origination.
        let _ = self
            .tx
            .protocol_input
            .lsp_originate
            .send(LspOriginateMsg {});
    }
}

// ===== helper functions =====

fn process_ibus_msg(
    instance: &mut Instance,
    msg: IbusMsg,
) -> Result<(), Error> {
    if instance.config.trace_opts.ibus {
        Debug::IbusRx(&msg).log();
    }

    match msg {
        // BFD peer state update event.
        IbusMsg::BfdStateUpd { sess_key, state } => {
            ibus::rx::process_bfd_state_update(instance, sess_key, state)?
        }
        // Router ID update notification.
        IbusMsg::RouterIdUpdate(router_id) => {
            ibus::rx::process_router_id_update(instance, router_id);
        }
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            ibus::rx::process_iface_update(instance, msg)?;
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            ibus::rx::process_addr_add(instance, msg);
        }
        // Interface address deletion notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            ibus::rx::process_addr_del(instance, msg);
        }
        // Route redistribute update notification.
        IbusMsg::RouteRedistributeAdd(msg) => {
            ibus::rx::process_route_add(instance, msg);
        }
        // Route redistribute delete notification.
        IbusMsg::RouteRedistributeDel(msg) => {
            ibus::rx::process_route_del(instance, msg);
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
        // Hostname update notification.
        IbusMsg::HostnameUpdate(hostname) => {
            ibus::rx::process_hostname_update(instance, hostname);
        }
        // SR configuration update.
        IbusMsg::SrCfgUpd(sr_config) => {
            ibus::rx::process_sr_cfg_update(instance, sr_config);
        }
        // Node MSD update.
        IbusMsg::NodeMsdUpd(node_msd) => {
            ibus::rx::process_msd_update(instance, node_msd);
        }
        // BIER configuration update.
        IbusMsg::BierCfgUpd(bier_config) => {
            instance.shared.bier_config = bier_config;
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg(
    instance: &mut InstanceUpView<'_>,
    arenas: &mut InstanceArenas,
    msg: ProtocolInputMsg,
) -> Result<(), Error> {
    match msg {
        // Received network PDU.
        ProtocolInputMsg::NetRxPdu(msg) => {
            events::process_pdu(
                instance,
                arenas,
                msg.iface_key,
                msg.src,
                msg.bytes,
                msg.pdu,
            )?;
        }
        // Adjacency hold timer event.
        ProtocolInputMsg::AdjHoldTimer(msg) => match msg {
            AdjHoldTimerMsg::Broadcast {
                iface_key,
                adj_key,
                level,
            } => {
                events::process_lan_adj_holdtimer_expiry(
                    instance, arenas, iface_key, adj_key, level,
                )?;
            }
            AdjHoldTimerMsg::PointToPoint { iface_key } => {
                events::process_p2p_adj_holdtimer_expiry(
                    instance, arenas, iface_key,
                )?;
            }
        },
        // Request to run DIS election.
        ProtocolInputMsg::DisElection(msg) => {
            events::process_dis_election(
                instance,
                arenas,
                msg.iface_key,
                msg.level,
            )?;
        }
        // Request to run send PSNP(s).
        ProtocolInputMsg::SendPsnp(msg) => {
            events::process_send_psnp(
                instance,
                arenas,
                msg.iface_key,
                msg.level,
            )?;
        }
        // Request to run send CSNP(s).
        ProtocolInputMsg::SendCsnp(msg) => {
            events::process_send_csnp(
                instance,
                arenas,
                msg.iface_key,
                msg.level,
            )?;
        }
        // LSP origination event.
        ProtocolInputMsg::LspOriginate(_msg) => {
            events::process_lsp_originate(instance, arenas)?;
        }
        // LSP purge event.
        ProtocolInputMsg::LspPurge(msg) => {
            events::process_lsp_purge(
                instance,
                arenas,
                msg.level,
                msg.lse_key,
                msg.reason,
            )?;
        }
        // LSP delete event.
        ProtocolInputMsg::LspDelete(msg) => {
            events::process_lsp_delete(
                instance,
                arenas,
                msg.level,
                msg.lse_key,
            )?;
        }
        // LSP refresh event.
        ProtocolInputMsg::LspRefresh(msg) => {
            events::process_lsp_refresh(
                instance,
                arenas,
                msg.level,
                msg.lse_key,
            )?;
        }
        // SPF Delay FSM event.
        ProtocolInputMsg::SpfDelayEvent(msg) => {
            events::process_spf_delay_event(
                instance, arenas, msg.level, msg.event,
            )?
        }
    }

    Ok(())
}
