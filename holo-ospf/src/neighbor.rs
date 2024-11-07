//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use holo_utils::bfd;
use holo_utils::ibus::BfdSessionMsg;
use holo_utils::task::{IntervalTask, TimeoutTask};
use nsm::{Event, State};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::area::Area;
use crate::collections::{Arena, NeighborId};
use crate::debug::Debug;
use crate::error::Error;
use crate::instance::InstanceUpView;
use crate::interface::{ism, Interface, InterfaceType};
use crate::lsdb::{LsaEntry, LsaOriginateEvent};
use crate::northbound::notification;
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::packet::tlv::GrReason;
use crate::packet::{DbDescFlags, DbDescVersion, PacketType};
use crate::tasks::messages::input::RxmtIntervalMsg;
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::version::Version;
use crate::{output, sr, tasks};

#[derive(Debug)]
pub struct Neighbor<V: Version> {
    pub id: NeighborId,
    pub router_id: Ipv4Addr,
    pub iface_id: Option<u32>,
    pub src: V::NetIpAddr,
    pub dr: Option<NeighborNetId>,
    pub bdr: Option<NeighborNetId>,
    pub priority: u8,
    pub state: State,

    pub options: Option<V::PacketOptions>,
    pub dd_flags: DbDescFlags,
    pub dd_seq_no: u32,
    pub last_rcvd_dbdesc: Option<LastDbDesc<V>>,
    pub last_sent_dbdesc: Option<NetTxPacketMsg<V>>,
    pub auth_seqno: HashMap<PacketType, u64>,

    pub event_count: u32,
    pub discontinuity_time: DateTime<Utc>,

    pub adj_sids: Vec<V::AdjSid>,
    pub gr: Option<NeighborGrHelper>,
    pub lists: NeighborLsaLists<V>,
    pub tasks: NeighborTasks,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct NeighborNetId(Ipv4Addr);

#[derive(Debug)]
pub struct LastDbDesc<V: Version> {
    pub options: V::PacketOptions,
    pub dd_flags: DbDescFlags,
    pub dd_seq_no: u32,
}

#[derive(Debug)]
pub struct NeighborLsaLists<V: Version> {
    // LSAs enqueued for transmission in LS Update packets.
    pub ls_update: BTreeMap<LsaKey<V::LsaType>, Arc<Lsa<V>>>,
    // LSAs waiting to be acknowledged.
    pub ls_rxmt: BTreeMap<LsaKey<V::LsaType>, Arc<Lsa<V>>>,
    // LSA headers enqueued for transmission in Database Description packets.
    pub db_summary: BTreeMap<LsaKey<V::LsaType>, Arc<Lsa<V>>>,
    // LSAs that need to be received from this neighbor.
    pub ls_request: BTreeMap<LsaKey<V::LsaType>, V::LsaHdr>,
    // LSAs that were requested but not received yet.
    pub ls_request_pending: BTreeMap<LsaKey<V::LsaType>, V::LsaHdr>,
}

#[derive(Debug)]
pub struct NeighborGrHelper {
    pub restart_reason: GrReason,
    pub grace_period: TimeoutTask,
}

#[derive(Debug, Default)]
pub struct NeighborTasks {
    pub inactivity_timer: Option<TimeoutTask>,
    pub dbdesc_free_timer: Option<TimeoutTask>,
    rxmt_dbdesc: Option<IntervalTask>,
    rxmt_lsreq: Option<IntervalTask>,
    rxmt_lsupd: Option<IntervalTask>,
}

#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub enum RxmtPacketType {
    DbDesc,
    LsRequest,
    LsUpdate,
}

// OSPF version-specific code.
pub trait NeighborVersion<V: Version> {
    // Return IPv4 address used to identify neighbor on a multi-access network.
    fn network_id(addr: &V::NetIpAddr, router_id: Ipv4Addr) -> NeighborNetId;
}

// Neighbor state machine.
pub mod nsm {
    use serde::{Deserialize, Serialize};

    use crate::debug::SeqNoMismatchReason;

    #[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
    #[derive(Deserialize, Serialize)]
    pub enum State {
        #[default]
        Down,
        Attempt,
        Init,
        TwoWay,
        ExStart,
        Exchange,
        Loading,
        Full,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    pub enum Event {
        HelloRcvd,
        Start,
        TwoWayRcvd,
        NegotiationDone,
        ExchangeDone,
        BadLsReq,
        LoadingDone,
        AdjOk,
        SeqNoMismatch(SeqNoMismatchReason),
        OneWayRcvd,
        Kill,
        InactivityTimer,
        LinkDown,
    }
}

// ===== impl Neighbor =====

impl<V> Neighbor<V>
where
    V: Version,
{
    pub(crate) fn new(
        id: NeighborId,
        router_id: Ipv4Addr,
        src: V::NetIpAddr,
    ) -> Neighbor<V> {
        Debug::<V>::NeighborCreate(router_id).log();

        // Initialize the DD Sequence Number.
        let dd_seq_no = {
            #[cfg(not(feature = "deterministic"))]
            {
                // Random value.
                rand::thread_rng().next_u32()
            }
            #[cfg(feature = "deterministic")]
            {
                // Fixed value for deterministic test results.
                router_id.into()
            }
        };

        Neighbor {
            id,
            router_id,
            iface_id: None,
            src,
            dr: None,
            bdr: None,
            priority: 0,
            state: State::Down,
            options: None,
            dd_flags: DbDescFlags::empty(),
            dd_seq_no,
            last_rcvd_dbdesc: None,
            last_sent_dbdesc: None,
            auth_seqno: Default::default(),
            event_count: 0,
            discontinuity_time: Utc::now(),
            adj_sids: Default::default(),
            gr: None,
            lists: Default::default(),
            tasks: Default::default(),
        }
    }

    pub(crate) fn fsm(
        &mut self,
        iface: &mut Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        lsa_entries: &Arena<LsaEntry<V>>,
        event: Event,
    ) {
        Debug::<V>::NsmEvent(self.router_id, &self.state, &event).log();

        let new_state = match (self.state, &event) {
            // NSM (state, event) -> (Action, new state)
            (State::Down, Event::Start) => {
                // TODO: Send an Hello Packet to the NBMA neighbor.
                self.inactivity_timer_reset(iface, area, instance);
                Some(State::Attempt)
            }
            // NSM (state, event) -> (Action, new state)
            (State::Attempt | State::Down, Event::HelloRcvd) => {
                self.inactivity_timer_reset(iface, area, instance);
                Some(State::Init)
            }
            // NSM (state, event) -> (Action, new state)
            (
                State::Init
                | State::TwoWay
                | State::ExStart
                | State::Exchange
                | State::Loading
                | State::Full,
                Event::HelloRcvd,
            ) => {
                self.inactivity_timer_reset(iface, area, instance);
                None
            }
            // NSM (state, event) -> (Action, new state)
            (State::Init, Event::TwoWayRcvd)
            | (State::TwoWay, Event::AdjOk) => {
                if iface.need_adjacency(self) {
                    self.dd_seq_no += 1;
                    self.dd_flags.insert(
                        DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS,
                    );
                    output::send_dbdesc(self, iface, area, instance);
                    Some(State::ExStart)
                } else {
                    Some(State::TwoWay)
                }
            }
            // NSM (state, event) -> (Action, new state)
            (State::ExStart, Event::NegotiationDone) => {
                // List the contents of the entire LSDB in the summary list.
                let options = self.options;
                for lse in iface
                    .state
                    .lsdb
                    .iter(lsa_entries)
                    .chain(area.state.lsdb.iter(lsa_entries))
                    .chain(instance.state.lsdb.iter(lsa_entries))
                    .map(|(_, lse)| lse)
                    // Filter out unneeded LSAs.
                    .filter(|lse| {
                        V::lsa_type_is_valid(
                            Some(area.config.area_type),
                            options,
                            lse.data.hdr.lsa_type(),
                        )
                    })
                {
                    let lsa_key = lse.data.hdr.key();
                    if lse.data.hdr.is_maxage() {
                        self.lists.ls_rxmt.insert(lsa_key, lse.data.clone());
                        self.rxmt_lsupd_start_check(iface, area, instance);
                    } else {
                        self.lists.db_summary.insert(lsa_key, lse.data.clone());
                    }
                }

                self.dd_flags.remove(DbDescFlags::I);
                Some(State::Exchange)
            }
            // NSM (state, event) -> (Action, new state)
            (State::Exchange, Event::ExchangeDone) => {
                if self.lists.ls_request_pending.is_empty()
                    && self.lists.ls_request.is_empty()
                {
                    Some(State::Full)
                } else {
                    // Wait for outstanding LS Requests to be responded.
                    Some(State::Loading)
                }
            }
            // NSM (state, event) -> (Action, new state)
            (State::Loading, Event::LoadingDone) => {
                // No action required.
                Some(State::Full)
            }
            // NSM (state, event) -> (Action, new state)
            (
                State::ExStart | State::Exchange | State::Loading | State::Full,
                Event::AdjOk,
            ) => {
                if iface.need_adjacency(self) {
                    None
                } else {
                    self.reset_adjacency();
                    Some(State::TwoWay)
                }
            }
            // NSM (state, event) -> (Action, new state)
            (
                State::Exchange | State::Loading | State::Full,
                Event::SeqNoMismatch(_) | Event::BadLsReq,
            ) => {
                self.reset_adjacency();
                self.dd_seq_no += 1;
                self.dd_flags
                    .insert(DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS);
                output::send_dbdesc(self, iface, area, instance);
                Some(State::ExStart)
            }
            // NSM (state, event) -> (Action, new state)
            (_, Event::Kill | Event::LinkDown | Event::InactivityTimer) => {
                self.reset_adjacency();
                self.tasks.inactivity_timer = None;

                // If we're acting as a graceful restart helper for the
                // neighbor, do not change its state once the Inactivity Timer
                // event is triggered.
                //
                // If the neighbor fails to restart before the grace period
                // expires, it will be removed.
                if event == Event::InactivityTimer && self.gr.is_some() {
                    None
                } else {
                    Some(State::Down)
                }
            }
            // NSM (state, event) -> (Action, new state)
            (
                State::TwoWay
                | State::ExStart
                | State::Exchange
                | State::Loading
                | State::Full,
                Event::OneWayRcvd,
            ) => {
                self.reset_adjacency();
                self.tasks.inactivity_timer = None;

                // If we're acting as a graceful restart helper for the
                // neighbor, do not change its state once the 1-Way event is
                // triggered.
                if self.gr.is_some() {
                    None
                } else {
                    Some(State::Init)
                }
            }
            // NSM (state, event) -> (Action, new state)
            (
                State::TwoWay
                | State::ExStart
                | State::Exchange
                | State::Loading
                | State::Full,
                Event::TwoWayRcvd,
            ) => {
                // No action required.
                None
            }
            // NSM (state, event) -> (Action, new state)
            (State::Init, Event::OneWayRcvd) => {
                // No action required.
                None
            }
            // Catch-all wildcard.
            _ => {
                Error::<V>::NsmUnexpectedEvent(
                    self.router_id,
                    self.state,
                    event,
                )
                .log();
                return;
            }
        };

        // Check for FSM state change.
        if let Some(new_state) = new_state {
            if new_state != self.state {
                self.fsm_state_change(iface, area, instance, event, new_state);
            }
        }
    }

    fn fsm_state_change(
        &mut self,
        iface: &mut Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        event: Event,
        new_state: State,
    ) {
        // Check for bidirectional communication change.
        if new_state >= State::TwoWay && self.state < State::TwoWay
            || new_state < State::TwoWay && self.state >= State::TwoWay
        {
            // Trigger the NeighborChange event on broadcast/NBMA networks.
            if iface.is_broadcast_or_nbma() {
                instance.tx.protocol_input.ism_event(
                    area.id,
                    iface.id,
                    ism::Event::NbrChange,
                );
            }

            // Register or unregister BFD peer.
            if iface.config.bfd_enabled {
                if new_state >= State::TwoWay {
                    self.bfd_register(iface, instance);
                } else {
                    self.bfd_unregister(iface, instance);
                }
            }
        }

        // Check if the neighbor changed to/from the FULL state.
        if (new_state == State::Full || self.state == State::Full)
            && self.gr.is_none()
        {
            // (Re)originate LSAs that might have been affected.
            instance.tx.protocol_input.lsa_orig_event(
                LsaOriginateEvent::NeighborToFromFull {
                    area_id: area.id,
                    iface_id: iface.id,
                },
            );
        }

        // Update Adj-SID(s) associated to this neighbor.
        if instance.config.sr_enabled && self.gr.is_none() {
            let mut two_way_or_higher_change = false;

            if new_state >= State::TwoWay && self.state < State::TwoWay {
                two_way_or_higher_change = true;
                sr::adj_sid_add(self, iface, instance);
            } else if new_state < State::TwoWay && self.state >= State::TwoWay {
                two_way_or_higher_change = true;
                sr::adj_sid_del_all(self, instance);
            }

            if two_way_or_higher_change {
                // (Re)originate LSAs that might have been affected.
                instance.tx.protocol_input.lsa_orig_event(
                    LsaOriginateEvent::NeighborTwoWayOrHigherChange {
                        area_id: area.id,
                        iface_id: iface.id,
                    },
                );
            }
        }

        // If a neighboring router has become inactive (Hello Packets have
        // not been seen for RouterDeadInterval seconds), it may still be
        // necessary to send Hello Packets to the dead neighbor. These Hello
        // Packets will be sent at the reduced rate PollInterval.
        if iface.config.if_type == InterfaceType::NonBroadcast {
            if new_state == State::Down && event == Event::InactivityTimer {
                if let Some(snbr) = iface.config.static_nbrs.get(&self.src) {
                    iface.nbma_poll_interval_start(
                        area,
                        instance,
                        self.src,
                        snbr.poll_interval,
                    );
                }
            } else if self.state == State::Down {
                iface.nbma_poll_interval_stop(self.src);
            }
        }

        // Effectively transition to the new FSM state.
        Debug::<V>::NsmTransition(self.router_id, &self.state, &new_state)
            .log();
        self.state = new_state;
        notification::nbr_state_change(instance, iface, self);

        // Update statistics.
        self.event_count += 1;
        self.discontinuity_time = Utc::now();
    }

    pub(crate) fn loading_done_check(
        &mut self,
        iface: &Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        // Check if all pending LSA requests were received.
        if self.lists.ls_request_pending.is_empty() {
            // Stop the LS Request rxmt task.
            self.rxmt_lsreq_stop();

            // Check if there are new LSAs to request.
            if !self.lists.ls_request.is_empty() {
                output::send_lsreq(self, iface, area, instance);
            } else if self.state == nsm::State::Loading {
                // Database loading has completed.
                instance.tx.protocol_input.nsm_event(
                    area.id,
                    iface.id,
                    self.id,
                    nsm::Event::LoadingDone,
                );
            }
        }
    }

    fn reset_adjacency(&mut self) {
        self.options = None;
        self.last_rcvd_dbdesc = None;
        self.last_sent_dbdesc = None;
        self.lists = Default::default();
        self.tasks.dbdesc_free_timer = None;
        self.tasks.rxmt_dbdesc = None;
        self.tasks.rxmt_lsreq = None;
        self.tasks.rxmt_lsupd = None;
    }

    pub(crate) fn dbdesc_is_dup(&self, dbdesc: &V::PacketDbDesc) -> bool {
        if let Some(last_rcvd_dbdesc) = &self.last_rcvd_dbdesc {
            if last_rcvd_dbdesc.options == dbdesc.options()
                && last_rcvd_dbdesc.dd_flags == dbdesc.dd_flags()
                && last_rcvd_dbdesc.dd_seq_no == dbdesc.dd_seq_no()
            {
                return true;
            }
        }

        false
    }

    pub(crate) fn bfd_register(
        &self,
        iface: &Interface<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        Debug::<V>::NeighborBfdReg(self.router_id).log();

        let msg = BfdSessionMsg::Registration {
            sess_key: self.bfd_session_key(iface),
            client_id: self.bfd_client_id(instance),
            client_config: Some(iface.config.bfd_params),
        };
        let _ = instance.tx.ibus.send(msg.into());
    }

    pub(crate) fn bfd_unregister(
        &self,
        iface: &Interface<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        Debug::<V>::NeighborBfdUnreg(self.router_id).log();

        let msg = BfdSessionMsg::Unregistration {
            sess_key: self.bfd_session_key(iface),
            client_id: self.bfd_client_id(instance),
        };
        let _ = instance.tx.ibus.send(msg.into());
    }

    fn bfd_session_key(&self, iface: &Interface<V>) -> bfd::SessionKey {
        bfd::SessionKey::new_ip_single_hop(iface.name.clone(), self.src.into())
    }

    fn bfd_client_id(&self, instance: &InstanceUpView<'_, V>) -> bfd::ClientId {
        bfd::ClientId::new(V::PROTOCOL, instance.name.to_owned())
    }

    pub(crate) fn network_id(&self) -> NeighborNetId {
        <V as NeighborVersion<V>>::network_id(&self.src, self.router_id)
    }

    pub(crate) fn inactivity_timer_start(
        &mut self,
        iface: &Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        let task = tasks::nsm_inactivity_timer(self, iface, area, instance);
        self.tasks.inactivity_timer = Some(task);
    }

    fn inactivity_timer_reset(
        &mut self,
        iface: &Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        if let Some(inactivity_timer) = self.tasks.inactivity_timer.as_mut() {
            inactivity_timer.reset(None);
        } else {
            self.inactivity_timer_start(iface, area, instance);
        }
    }

    pub(crate) fn rxmt_dbdesc_start(
        &mut self,
        iface: &Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        let msg = RxmtIntervalMsg {
            area_key: area.id.into(),
            iface_key: iface.id.into(),
            nbr_key: self.id.into(),
            packet_type: RxmtPacketType::DbDesc,
        };

        let task = tasks::packet_rxmt_interval(iface, msg, instance);
        self.tasks.rxmt_dbdesc = Some(task);
    }

    pub(crate) fn rxmt_dbdesc_stop(&mut self) {
        self.tasks.rxmt_dbdesc = None;
    }

    pub(crate) fn rxmt_lsreq_start(
        &mut self,
        iface: &Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        let msg = RxmtIntervalMsg {
            area_key: area.id.into(),
            iface_key: iface.id.into(),
            nbr_key: self.id.into(),
            packet_type: RxmtPacketType::LsRequest,
        };

        let task = tasks::packet_rxmt_interval(iface, msg, instance);
        self.tasks.rxmt_lsreq = Some(task);
    }

    fn rxmt_lsreq_stop(&mut self) {
        self.tasks.rxmt_lsreq = None;
    }

    pub(crate) fn rxmt_lsupd_start_check(
        &mut self,
        iface: &Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        if !self.lists.ls_rxmt.is_empty() && self.tasks.rxmt_lsupd.is_none() {
            let msg = RxmtIntervalMsg {
                area_key: area.id.into(),
                iface_key: iface.id.into(),
                nbr_key: self.id.into(),
                packet_type: RxmtPacketType::LsUpdate,
            };
            let task = tasks::packet_rxmt_interval(iface, msg, instance);
            self.tasks.rxmt_lsupd = Some(task);
        }
    }

    pub(crate) fn rxmt_lsupd_stop_check(&mut self) {
        if self.lists.ls_rxmt.is_empty() && self.tasks.rxmt_lsupd.is_some() {
            self.tasks.rxmt_lsupd = None;
        }
    }
}

impl<V> Drop for Neighbor<V>
where
    V: Version,
{
    fn drop(&mut self) {
        Debug::<V>::NeighborDelete(self.router_id).log();
    }
}

// ===== impl NeighborNetId =====

impl NeighborNetId {
    pub(crate) fn get(&self) -> Ipv4Addr {
        self.0
    }
}

impl std::fmt::Display for NeighborNetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Ipv4Addr> for NeighborNetId {
    fn from(addr: Ipv4Addr) -> NeighborNetId {
        NeighborNetId(addr)
    }
}

// ===== impl NeighborLsaLists =====

impl<V> Default for NeighborLsaLists<V>
where
    V: Version,
{
    fn default() -> NeighborLsaLists<V> {
        NeighborLsaLists {
            ls_update: Default::default(),
            ls_rxmt: Default::default(),
            db_summary: Default::default(),
            ls_request: Default::default(),
            ls_request_pending: Default::default(),
        }
    }
}
