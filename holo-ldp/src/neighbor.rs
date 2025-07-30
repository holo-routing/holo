//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU32, AtomicU64};
use std::time::{Duration, Instant};

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use holo_utils::ip::AddressFamily;
use holo_utils::mpls::Label;
use holo_utils::socket::{TcpConnInfo, TcpStream};
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Sender, UnboundedSender};

use crate::collections::{NeighborId, NeighborIndex};
use crate::debug::Debug;
use crate::error::Error;
use crate::fec::{Fec, LabelMapping, LabelRequest};
use crate::instance::{InstanceState, InstanceUpView};
use crate::northbound::configuration::InstanceCfg;
use crate::northbound::notification;
use crate::packet::message::MessageType;
use crate::packet::messages::address::TlvAddressList;
use crate::packet::messages::capability::{
    TlvCapDynamic, TlvCapTwcardFec, TlvCapUnrecNotif,
};
use crate::packet::messages::initialization::{InitFlags, TlvCommonSessParams};
use crate::packet::messages::label::{
    FecElem, FecElemWildcard, TlvFec, TlvLabel, TlvLabelRequestId,
    TypedWildcardFecElem,
};
use crate::packet::messages::notification::{StatusCode, TlvStatus};
use crate::packet::messages::{
    AddressMsg, InitMsg, KeepaliveMsg, LabelMsg, NotifMsg,
};
use crate::packet::pdu::Pdu;
use crate::packet::{AddressMessageType, LabelMessageType, Message};
#[cfg(feature = "testing")]
use crate::tasks::messages::ProtocolOutputMsg;
use crate::tasks::messages::input::{
    NbrBackoffTimeoutMsg, NbrKaTimeoutMsg, NbrRxPduMsg, TcpConnectMsg,
};
use crate::tasks::messages::output::NbrTxPduMsg;
use crate::{ibus, tasks};

#[derive(Debug)]
pub struct Neighbor {
    pub id: NeighborId,
    pub lsr_id: Ipv4Addr,
    pub trans_addr: IpAddr,
    pub state: fsm::State,
    pub cfg_seqno: u32,
    pub conn_info: Option<TcpConnInfo>,
    pub max_pdu_len: u16,
    pub init_attempts: usize,
    pub kalive_holdtime_rcvd: Option<u16>,
    pub kalive_holdtime_negotiated: Option<u16>,
    pub kalive_interval: u16,
    pub rcvd_label_adv_mode: Option<LabelAdvMode>,
    pub addr_list: BTreeSet<IpAddr>,
    pub rcvd_mappings: BTreeMap<IpNetwork, LabelMapping>,
    pub sent_mappings: BTreeMap<IpNetwork, LabelMapping>,
    pub rcvd_requests: BTreeMap<IpNetwork, LabelRequest>,
    pub sent_requests: BTreeMap<IpNetwork, LabelRequest>,
    pub sent_withdraws: BTreeMap<IpNetwork, Label>,
    pub statistics: Statistics,
    pub uptime: Option<Instant>,
    pub pdu_txp: Option<UnboundedSender<NbrTxPduMsg>>,
    pub tasks: NeighborTasks,
    pub flags: NeighborFlags,
}

#[derive(Debug, Default)]
pub struct NeighborTasks {
    pub connect: Option<Task<()>>,
    pub backoff_timeout: Option<TimeoutTask>,
    pub tcp_rx: Option<Task<()>>,
    pub kalive_tx: Option<IntervalTask>,
    pub kalive_timeout: Option<TimeoutTask>,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct NeighborFlags: u8 {
        const GTSM = 0x01;
        const CAP_DYNAMIC = 0x02;
        const CAP_TYPED_WCARD = 0x04;
        const CAP_UNREC_NOTIF = 0x08;
    }
}

// Neighbor statistics.
#[derive(Debug, Default)]
pub struct Statistics {
    pub discontinuity_time: Option<DateTime<Utc>>,
    pub msgs_rcvd: MessageStatistics,
    pub msgs_sent: MessageStatistics,
}

// Inbound and outbound statistic counters.
#[derive(Debug, Default)]
pub struct MessageStatistics {
    pub address: u64,
    pub address_withdraw: u64,
    pub initialization: u64,
    pub keepalive: Arc<AtomicU64>,
    pub label_abort_request: u64,
    pub label_mapping: u64,
    pub label_release: u64,
    pub label_request: u64,
    pub label_withdraw: u64,
    pub notification: u64,
    pub total: u64,
    pub total_bytes: u64,
}

#[derive(Debug)]
pub enum LabelDistMode {
    Independent,
    Ordered,
}

#[derive(Debug)]
pub enum LabelAdvMode {
    DownstreamUnsolicited,
    DownstreamOnDemand,
}

// Session Initialization FSM:
pub mod fsm {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum State {
        NonExistent,
        Initialized,
        OpenRec,
        OpenSent,
        Operational,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum Event {
        MatchedAdjacency,
        ConnectionUp,
        KeepaliveRcvd,
        InitRcvd,
        InitSent,
        ConnectionDown,
        // Fatal error notifications.
        ErrorRcvd,
        ErrorSent,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Action {
        SendInitAndKeepalive,
        SendInit,
        SendKeepalive,
        StartSession,
        CloseSession,
    }
}

// ===== impl Neighbor =====

impl Neighbor {
    pub(crate) fn new(
        id: NeighborId,
        lsr_id: Ipv4Addr,
        trans_addr: IpAddr,
        kalive_interval: u16,
    ) -> Neighbor {
        Debug::NbrCreate(&lsr_id).log();

        Neighbor {
            id,
            lsr_id,
            trans_addr,
            state: fsm::State::NonExistent,
            cfg_seqno: 0,
            conn_info: None,
            max_pdu_len: Pdu::DFLT_MAX_LEN,
            init_attempts: 0,
            kalive_holdtime_rcvd: None,
            kalive_holdtime_negotiated: None,
            kalive_interval,
            rcvd_label_adv_mode: None,
            addr_list: BTreeSet::default(),
            rcvd_mappings: Default::default(),
            sent_mappings: Default::default(),
            rcvd_requests: Default::default(),
            sent_requests: Default::default(),
            sent_withdraws: Default::default(),
            statistics: Default::default(),
            uptime: None,
            pdu_txp: None,
            tasks: Default::default(),
            flags: NeighborFlags::empty(),
        }
    }

    pub(crate) fn is_session_active_role<A: Into<IpAddr>>(
        &self,
        trans_addr: A,
    ) -> bool {
        let trans_addr = trans_addr.into();
        trans_addr > self.trans_addr
    }

    pub(crate) fn fsm(
        instance: &mut InstanceUpView<'_>,
        nbr_idx: NeighborIndex,
        event: fsm::Event,
    ) {
        let nbr = &mut instance.state.neighbors[nbr_idx];
        match nbr.fsm_event(event) {
            Ok((new_state, action)) => {
                Debug::NbrFsmTransition(
                    &nbr.lsr_id,
                    &event,
                    &nbr.state,
                    &new_state,
                )
                .log();

                let old_state = nbr.state;
                nbr.state = new_state;
                if new_state == fsm::State::Operational
                    || old_state == fsm::State::Operational
                {
                    notification::mpls_ldp_peer_event(
                        &instance.tx.nb,
                        instance.name,
                        nbr,
                    );
                }

                if let Some(action) = action {
                    Neighbor::fsm_action(instance, nbr_idx, action);
                }
            }
            Err(error) => {
                error.log();
            }
        }
    }

    fn fsm_event(
        &self,
        event: fsm::Event,
    ) -> Result<(fsm::State, Option<fsm::Action>), Error> {
        use fsm::{Action, Event, State};
        match self.state {
            // Passive role.
            State::NonExistent if event == Event::MatchedAdjacency => {
                let new_state = State::Initialized;
                let action = None;
                Ok((new_state, action))
            }
            // Active role.
            State::NonExistent if event == Event::ConnectionUp => {
                let new_state = State::Initialized;
                let action = Some(Action::SendInit);
                Ok((new_state, action))
            }
            // Passive role.
            State::Initialized if event == Event::InitRcvd => {
                let new_state = State::OpenRec;
                let action = Some(Action::SendInitAndKeepalive);
                Ok((new_state, action))
            }
            // Active role.
            State::Initialized if event == Event::InitSent => {
                let new_state = State::OpenSent;
                let action = None;
                Ok((new_state, action))
            }
            // Active/passive roles.
            State::OpenRec if event == Event::KeepaliveRcvd => {
                let new_state = State::Operational;
                let action = Some(Action::StartSession);
                Ok((new_state, action))
            }
            // Active/passive roles.
            State::OpenSent if event == Event::InitRcvd => {
                let new_state = State::OpenRec;
                let action = Some(Action::SendKeepalive);
                Ok((new_state, action))
            }
            // Session maintenance.
            State::Initialized
            | State::OpenRec
            | State::OpenSent
            | State::Operational
                if event == Event::ConnectionDown
                    || event == Event::ErrorRcvd
                    || event == Event::ErrorSent =>
            {
                let new_state = State::NonExistent;
                let action = Some(Action::CloseSession);
                Ok((new_state, action))
            }
            _ => Err(Error::NbrFsmUnexpectedEvent(
                self.lsr_id,
                self.state,
                event,
            )),
        }
    }

    fn fsm_action(
        instance: &mut InstanceUpView<'_>,
        nbr_idx: NeighborIndex,
        action: fsm::Action,
    ) {
        let nbr = &mut instance.state.neighbors[nbr_idx];
        match action {
            fsm::Action::SendInitAndKeepalive => {
                // Send initialization message.
                nbr.send_init(instance.config, &instance.state.msg_id);

                // Send keepalive message.
                nbr.send_keepalive(&instance.state.msg_id);

                // Start keepalive timeout task.
                nbr.start_kalive_timeout(
                    &instance.tx.protocol_input.nbr_ka_timeout,
                );
            }
            fsm::Action::SendInit => {
                // Send initialization message.
                nbr.send_init(instance.config, &instance.state.msg_id);
                Neighbor::fsm(instance, nbr_idx, fsm::Event::InitSent);
            }
            fsm::Action::SendKeepalive => {
                // Send keepalive message.
                nbr.send_keepalive(&instance.state.msg_id);

                // Start keepalive timeout task.
                nbr.start_kalive_timeout(
                    &instance.tx.protocol_input.nbr_ka_timeout,
                );
            }
            fsm::Action::StartSession => {
                // Reset counter of connection attempts.
                nbr.init_attempts = 0;

                // Start keepalive tx task.
                nbr.start_kalive_interval(&instance.state.msg_id);

                // Start keepalive timeout task.
                nbr.start_kalive_timeout(
                    &instance.tx.protocol_input.nbr_ka_timeout,
                );

                // Send address message;
                let addr_list = instance
                    .system
                    .ipv4_addr_list
                    .iter()
                    .map(|addr| addr.ip())
                    .collect();
                nbr.send_address(
                    &instance.state.msg_id,
                    AddressMessageType::Address,
                    addr_list,
                );

                // Send label mappings
                for fec in instance.state.fecs.values_mut() {
                    if fec.inner.local_label.is_none() {
                        continue;
                    }
                    nbr.send_label_mapping(&instance.state.msg_id, fec);
                }

                // Signal completion of label advertisements.
                if nbr.flags.contains(NeighborFlags::CAP_UNREC_NOTIF) {
                    nbr.send_end_of_lib(
                        &instance.state.msg_id,
                        TypedWildcardFecElem::Prefix(AddressFamily::Ipv4),
                    );
                }
            }
            fsm::Action::CloseSession => {
                // Iterate over all FECs.
                for fec in instance.state.fecs.values_mut() {
                    let old_fec_status = fec.is_operational();

                    // Uninstall mapping received from this neighbor (if any).
                    for nexthop in fec
                        .nexthops
                        .values_mut()
                        .filter(|nexthop| nbr.addr_list.contains(&nexthop.addr))
                    {
                        ibus::tx::label_uninstall(
                            &instance.tx.ibus,
                            &fec.inner,
                            nexthop,
                        );
                        nexthop.set_label(None);
                    }
                    if old_fec_status != fec.is_operational() {
                        notification::mpls_ldp_fec_event(
                            &instance.tx.nb,
                            instance.name,
                            fec,
                        );
                    }

                    // Remove downstream and upstream label bindings (if any).
                    fec.inner.downstream.remove(&nbr.lsr_id);
                    fec.inner.upstream.remove(&nbr.lsr_id);
                }

                // Close session.
                nbr.close_session();

                // Update the neighbor ID to prevent events from the old session
                // from leaking into a new session.
                let id = instance.state.neighbors.next_id();
                instance.state.neighbors.update_id(nbr_idx, id);
            }
        }
    }

    pub(crate) fn start_backoff_timeout(
        &mut self,
        nbr_backoff_timeoutp: &Sender<NbrBackoffTimeoutMsg>,
    ) {
        let task = tasks::nbr_backoff_timeout(self, nbr_backoff_timeoutp);
        self.tasks.backoff_timeout = Some(task);
    }

    pub(crate) fn stop_backoff_timeout(&mut self) {
        self.tasks.backoff_timeout = None;
    }

    pub(crate) fn start_kalive_interval(&mut self, msg_id: &Arc<AtomicU32>) {
        let keepalive_counter = &self.statistics.msgs_sent.keepalive;
        let task = tasks::nbr_kalive_interval(self, msg_id, keepalive_counter);
        self.tasks.kalive_tx = Some(task);
    }

    pub(crate) fn start_kalive_timeout(
        &mut self,
        nbr_ka_timeoutp: &Sender<NbrKaTimeoutMsg>,
    ) {
        let task = tasks::nbr_kalive_timeout(self, nbr_ka_timeoutp);
        self.tasks.kalive_timeout = Some(task);
    }

    pub(crate) fn connect<I: Into<IpAddr>>(
        &mut self,
        local_addr: I,
        password: Option<&str>,
        tcp_connectp: &Sender<TcpConnectMsg>,
    ) {
        let local_addr = local_addr.into();
        let task = tasks::tcp_connect(self, local_addr, password, tcp_connectp);
        self.tasks.connect = Some(task);
    }

    pub(crate) fn setup_connection(
        &mut self,
        stream: TcpStream,
        conn_info: TcpConnInfo,
        local_lsr_id: Ipv4Addr,
        nbr_pdu_rxp: &Sender<NbrRxPduMsg>,
        #[cfg(feature = "testing")] proto_output_tx: &Sender<ProtocolOutputMsg>,
    ) {
        self.conn_info = Some(conn_info);
        self.uptime = Some(Instant::now());

        // Split TCP stream into two halves.
        let (read_half, write_half) = stream.into_split();

        // Spawn neighbor TCP Tx/Rx tasks.
        let (pdu_txp, pdu_txc) = mpsc::unbounded_channel();
        let mut tx_task = tasks::nbr_tx(
            self,
            local_lsr_id,
            write_half,
            pdu_txc,
            #[cfg(feature = "testing")]
            proto_output_tx,
        );
        let tcp_rx_task = tasks::nbr_rx(self, read_half, nbr_pdu_rxp);
        self.tasks.tcp_rx = Some(tcp_rx_task);
        self.pdu_txp = Some(pdu_txp);

        // We don't need to keep track of the tx task because that task will
        // exit gracefully as soon as the tx end of its mpsc channel is
        // dropped. By doing that, we ensure that messages sent while the
        // neighbor is being shut down will be delivered.
        tx_task.detach();
    }

    pub(crate) fn close_session(&mut self) {
        self.conn_info = None;
        self.kalive_holdtime_rcvd = None;
        self.kalive_holdtime_negotiated = None;
        self.rcvd_label_adv_mode = None;
        self.addr_list.clear();
        self.rcvd_mappings.clear();
        self.sent_mappings.clear();
        self.rcvd_requests.clear();
        self.sent_requests.clear();
        self.sent_withdraws.clear();
        self.statistics = Default::default();
        self.uptime = None;
        self.tasks = Default::default();
        self.pdu_txp = None;
    }

    pub(crate) fn is_operational(&self) -> bool {
        self.state == fsm::State::Operational
    }

    pub(crate) fn kalive_timeout_remaining(&self) -> Option<Duration> {
        self.tasks
            .kalive_timeout
            .as_ref()
            .map(TimeoutTask::remaining)
    }

    pub(crate) fn next_kalive(&self) -> Option<Duration> {
        self.tasks.kalive_tx.as_ref().map(IntervalTask::remaining)
    }

    fn send_message<M: Into<Message>>(&mut self, msg: M, flush: bool) {
        let msg = msg.into();

        Debug::NbrMsgTx(&self.lsr_id, &msg).log();

        // Update statistics.
        self.statistics.msgs_sent.update(&msg);
        self.statistics.discontinuity_time = Some(Utc::now());

        // Ignore any possible error as the connection might have gone down
        // already.
        let nbr_id = self.id;
        let msg = NbrTxPduMsg { nbr_id, msg, flush };
        let _ = self.pdu_txp.as_ref().unwrap().send(msg);
    }

    pub(crate) fn send_init(
        &mut self,
        instance_cfg: &InstanceCfg,
        msg_id: &Arc<AtomicU32>,
    ) {
        let msg = InitMsg {
            msg_id: InstanceState::get_next_msg_id(msg_id),
            params: TlvCommonSessParams {
                version: 1,
                keepalive_time: instance_cfg.session_ka_holdtime,
                flags: InitFlags::empty(),
                pvlim: 0,
                max_pdu_len: 0,
                lsr_id: self.lsr_id,
                lspace_id: 0,
            },
            cap_dynamic: Some(TlvCapDynamic()),
            cap_twcard_fec: Some(TlvCapTwcardFec(true)),
            cap_unrec_notif: Some(TlvCapUnrecNotif(true)),
        };
        self.send_message(msg, true);
    }

    pub(crate) fn generate_keepalive(msg_id: &Arc<AtomicU32>) -> Message {
        KeepaliveMsg {
            msg_id: InstanceState::get_next_msg_id(msg_id),
        }
        .into()
    }

    pub(crate) fn send_keepalive(&mut self, msg_id: &Arc<AtomicU32>) {
        let msg = Neighbor::generate_keepalive(msg_id);
        self.send_message(msg, true);
    }

    pub(crate) fn send_notification<M>(
        &mut self,
        msg_id: &Arc<AtomicU32>,
        status_code: StatusCode,
        peer_msg: M,
        wcard_fec: Option<TypedWildcardFecElem>,
    ) where
        M: Into<Option<Message>>,
    {
        let peer_msg = peer_msg.into();
        let mut peer_msg_id = 0;
        let mut peer_msg_type = 0;

        if let Some(peer_msg) = peer_msg {
            peer_msg_id = peer_msg.msg_id();
            peer_msg_type = peer_msg.msg_type() as u16;
        }

        let msg = NotifMsg {
            msg_id: InstanceState::get_next_msg_id(msg_id),
            status: TlvStatus {
                status_code: status_code.encode(false),
                msg_id: peer_msg_id,
                msg_type: peer_msg_type,
            },
            ext_status: None,
            returned_pdu: None,
            returned_msg: None,
            returned_tlvs: None,
            fec: wcard_fec.map(|wcard_fec| {
                TlvFec(vec![FecElem::Wildcard(FecElemWildcard::Typed(
                    wcard_fec,
                ))])
            }),
        };
        self.send_message(msg, true);
    }

    pub(crate) fn send_shutdown<M>(
        &mut self,
        msg_id: &Arc<AtomicU32>,
        peer_msg: M,
    ) where
        M: Into<Option<Message>>,
    {
        self.send_notification(msg_id, StatusCode::Shutdown, peer_msg, None);
    }

    pub(crate) fn send_end_of_lib(
        &mut self,
        msg_id: &Arc<AtomicU32>,
        wcard_fec: TypedWildcardFecElem,
    ) {
        self.send_notification(
            msg_id,
            StatusCode::EndOfLib,
            None,
            Some(wcard_fec),
        );
    }

    pub(crate) fn send_address(
        &mut self,
        msg_id: &Arc<AtomicU32>,
        msg_type: AddressMessageType,
        addr_list: BTreeSet<Ipv4Addr>,
    ) {
        let msg = AddressMsg {
            msg_id: InstanceState::get_next_msg_id(msg_id),
            msg_type,
            addr_list: TlvAddressList::Ipv4(addr_list),
        };
        self.send_message(msg, false);
    }

    fn send_label(
        &mut self,
        msg_id: &Arc<AtomicU32>,
        msg_type: LabelMessageType,
        fec_elem: FecElem,
        label: Option<Label>,
        request_id: Option<u32>,
    ) {
        let label = label.map(TlvLabel);
        let request_id = request_id.map(TlvLabelRequestId);
        let fec = TlvFec(vec![fec_elem]);

        let msg = LabelMsg {
            msg_id: InstanceState::get_next_msg_id(msg_id),
            msg_type,
            fec,
            label,
            request_id,
        };
        self.send_message(msg, false);
    }

    pub(crate) fn send_label_mapping(
        &mut self,
        msg_id: &Arc<AtomicU32>,
        fec: &mut Fec,
    ) {
        let prefix = *fec.inner.prefix;
        let label = fec.inner.local_label.unwrap();
        let mut request_id = None;

        // This function skips SL.1 - 3 and SL.9 - 14 because the label
        // allocation is done way earlier (we're merging capable).

        // SL.6: is there a pending request for this mapping?
        if let btree_map::Entry::Occupied(o) = self.rcvd_requests.entry(prefix)
        {
            // Set label request msg id in the mapping response.
            let request = o.get();
            request_id = Some(request.id);

            // SL.7: delete record of pending request.
            o.remove_entry();
        }

        // SL.4: send label mapping.
        self.send_label(
            msg_id,
            LabelMessageType::LabelMapping,
            FecElem::Prefix(prefix),
            Some(label),
            request_id,
        );

        // SL.5: record sent label mapping.
        let mapping = LabelMapping { label };
        fec.inner.upstream.insert(self.lsr_id, mapping);
        self.sent_mappings.insert(prefix, mapping);
    }

    pub(crate) fn send_label_withdraw(
        &mut self,
        msg_id: &Arc<AtomicU32>,
        fec: &Fec,
    ) {
        let prefix = *fec.inner.prefix;
        let label = fec.inner.local_label.unwrap();

        // SWd.1: send label withdraw.
        self.send_label(
            msg_id,
            LabelMessageType::LabelWithdraw,
            FecElem::Prefix(prefix),
            Some(label),
            None,
        );

        // SWd.2: record label withdraw.
        self.sent_withdraws.insert(prefix, label);
    }

    pub(crate) fn send_label_release(
        &mut self,
        msg_id: &Arc<AtomicU32>,
        fec_elem: FecElem,
        label: Option<Label>,
    ) {
        self.send_label(
            msg_id,
            LabelMessageType::LabelRelease,
            fec_elem,
            label,
            None,
        );
    }
}

impl Drop for Neighbor {
    fn drop(&mut self) {
        Debug::NbrDelete(&self.lsr_id).log();
    }
}

// ===== impl MessageStatistics =====

impl MessageStatistics {
    pub(crate) fn update(&mut self, msg: &Message) {
        self.total += 1;
        // TODO: update total_bytes
        match msg.msg_type() {
            MessageType::Notification => {
                self.notification += 1;
            }
            MessageType::Initialization => {
                self.initialization += 1;
            }
            MessageType::Keepalive => {
                self.keepalive.fetch_add(1, atomic::Ordering::Relaxed);
            }
            MessageType::Address => {
                self.address += 1;
            }
            MessageType::AddressWithdraw => {
                self.address_withdraw += 1;
            }
            MessageType::LabelMapping => {
                self.label_mapping += 1;
            }
            MessageType::LabelRequest => {
                self.label_request += 1;
            }
            MessageType::LabelWithdraw => {
                self.label_withdraw += 1;
            }
            MessageType::LabelRelease => {
                self.label_release += 1;
            }
            MessageType::LabelAbortReq => {
                self.label_abort_request += 1;
            }
            _ => (),
        };
    }
}
