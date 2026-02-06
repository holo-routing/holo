//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, HashMap, HashSet, hash_map};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, atomic};

use chrono::{DateTime, Utc};
use derive_new::new;
use generational_arena::{Arena, Index};
use holo_protocol::InstanceChannelsTx;
use holo_utils::bfd::{ClientCfg, ClientId, SessionKey, State};
use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::ip::{IpAddrExt, IpAddrKind};
use holo_utils::socket::{TTL_MAX, UdpSocket};
use holo_utils::task::{IntervalTask, TimeoutTask};
use rand::RngCore;
use tokio::sync::mpsc::Sender;

use crate::debug::Debug;
use crate::error::{Error, IoError};
use crate::master::Master;
use crate::northbound::configuration::SessionCfg;
use crate::northbound::notification;
use crate::northbound::yang_gen::bfd;
use crate::packet::{DiagnosticCode, Packet, PacketFlags};
use crate::tasks::messages::input::DetectTimerMsg;
use crate::{network, tasks};

// The slow Tx interval is used to conserve bandwidth when the session is not
// up.
const SLOW_TX_INTERVAL: u32 = 1000000;

pub type SessionId = usize;
pub type SessionIndex = Index;

#[derive(Debug)]
pub struct Session {
    pub id: SessionId,
    pub key: SessionKey,
    pub config: SessionCfg,
    pub config_enabled: bool,
    pub state: SessionState,
    pub statistics: SessionStatistics,
    pub clients: HashMap<usize, SessionClient>,
}

#[derive(Debug)]
pub struct SessionState {
    pub socket_tx: Option<Arc<UdpSocket>>,
    pub sockaddr: Option<SocketAddr>,
    pub curr_min_tx: u32,
    pub curr_min_rx: u32,
    pub local_state: State,
    pub local_discr: u32,
    pub local_diag: DiagnosticCode,
    pub demand_mode: bool,
    pub remote: Option<SessionRemoteInfo>,
    pub poll_active: Arc<AtomicBool>,
    pub tx_interval: Option<IntervalTask>,
    pub detection_timer: Option<TimeoutTask>,
}

#[derive(Debug, new)]
pub struct SessionRemoteInfo {
    pub state: State,
    pub discr: u32,
    pub diag: u8,
    pub multiplier: u8,
    pub min_tx: u32,
    pub min_rx: u32,
    pub demand_mode: bool,
}

#[derive(Debug)]
pub struct SessionStatistics {
    pub create_time: DateTime<Utc>,
    pub last_state_change_time: Option<DateTime<Utc>>,
    pub last_down_time: Option<DateTime<Utc>>,
    pub last_up_time: Option<DateTime<Utc>>,
    pub down_count: u32,
    pub admin_down_count: u32,
    pub rx_packet_count: u64,
    pub tx_packet_count: Arc<AtomicU64>,
    pub rx_error_count: u64,
    pub tx_error_count: Arc<AtomicU64>,
}

#[derive(Debug)]
#[derive(new)]
pub struct SessionClient {
    pub id: ClientId,
    pub config: Option<ClientCfg>,
    pub tx: IbusSender,
}

#[derive(Debug, Default)]
pub struct Sessions {
    // Session arena.
    arena: Arena<Session>,
    // Session hash table keyed by ID (1:1).
    id_tree: HashMap<SessionId, SessionIndex>,
    // Session binary tree keyed by BFD key (1:1).
    key_tree: BTreeMap<SessionKey, SessionIndex>,
    // Session hash table keyed by local discriminator (1:1).
    discr_tree: HashMap<u32, SessionIndex>,
    // Session hash table keyed by interface name (1:N).
    ifname_tree: HashMap<String, HashSet<SessionIndex>>,
    // Session hash table keyed by socket address (1:1).
    sockaddr_tree: HashMap<SocketAddr, SessionIndex>,
    // Next available ID.
    next_id: SessionId,
}

// ===== impl Session =====

impl Session {
    // Creates a new BFD session.
    fn new(id: SessionId, key: SessionKey) -> Session {
        Debug::SessionCreate(&key).log();

        Session {
            id,
            key,
            config: Default::default(),
            config_enabled: false,
            state: Default::default(),
            statistics: Default::default(),
            clients: Default::default(),
        }
    }

    // Updates the FSM state of the BFD session.
    pub(crate) fn state_update(
        &mut self,
        state: State,
        diag: DiagnosticCode,
        tx: &InstanceChannelsTx<Master>,
    ) {
        let old_state = self.state.local_state;
        self.state.local_state = state;
        self.state.local_diag = diag;

        Debug::FsmTransition(&self.key, old_state, state).log();

        // Notify protocol clients about the state transition if necessary.
        if self.should_notify_clients(old_state) {
            for client in self.clients.values() {
                let msg = IbusMsg::BfdStateUpd {
                    sess_key: self.key.clone(),
                    state,
                };
                let _ = client.tx.send(msg);
            }
        }

        // Send YANG notification.
        notification::state_change(&tx.nb, self);

        // Update statistics.
        self.statistics.last_state_change_time = Some(Utc::now());
        match state {
            State::AdminDown => {
                self.statistics.admin_down_count += 1;
            }
            State::Down => {
                self.statistics.last_down_time = Some(Utc::now());
                self.statistics.down_count += 1;
            }
            State::Up => {
                self.statistics.last_up_time = Some(Utc::now());
            }
            _ => {}
        }

        if old_state == State::Up {
            // Activate slow Tx interval.
            self.state.curr_min_tx = self.desired_tx_interval();
        } else if state == State::Up {
            // Start Poll Sequence to deactivate slow Tx interval.
            self.poll_sequence_start();
        }

        // Synchronize the Tx task since the local state has changed.
        self.update_tx_interval();
    }

    // Returns whether the client protocols should be notified about the
    // session's state transition.
    fn should_notify_clients(&self, old_state: State) -> bool {
        let new_state = self.state.local_state;
        if new_state == State::Up {
            return true;
        }

        if old_state == State::Up {
            // RFC 5882 - Section 4.2:
            // "If a BFD session transitions from Up state to AdminDown, or the
            // session transitions from Up to Down because the remote system is
            // indicating that the session is in state AdminDown, clients SHOULD
            // NOT take any control protocol action".
            if new_state == State::AdminDown {
                return false;
            }
            if let Some(remote) = &self.state.remote
                && new_state == State::Down
                && remote.state == State::AdminDown
            {
                return false;
            }

            return true;
        }

        false
    }

    // Returns the locally configured Detection time multiplier.
    //
    // In case this value is configured differently by different clients (or
    // statically), the smallest value is chosen.
    fn local_multiplier(&self) -> u8 {
        self.clients
            .values()
            .filter_map(|client| client.config.as_ref())
            .min_by_key(|config| config.local_multiplier)
            .map(|config| {
                std::cmp::min(
                    config.local_multiplier,
                    self.config.local_multiplier,
                )
            })
            .unwrap_or(self.config.local_multiplier)
    }

    // Returns the locally configured Desired Min Tx Interval.
    //
    // In case this value is configured differently by different clients (or
    // statically), the smallest value is chosen.
    pub(crate) fn desired_tx_interval(&self) -> u32 {
        // When bfd.SessionState is not Up, the system MUST set
        // bfd.DesiredMinTxInterval to a value of not less than one second
        // This is intended to ensure that the bandwidth consumed by BFD
        // sessions that are not Up is negligible, particularly in the case
        // where a neighbor may not be running BFD.
        if self.state.local_state != State::Up {
            return SLOW_TX_INTERVAL;
        }

        self.clients
            .values()
            .filter_map(|client| client.config.as_ref())
            .min_by_key(|config| config.min_tx)
            .map(|config| std::cmp::min(config.min_tx, self.config.min_tx))
            .unwrap_or(self.config.min_tx)
    }

    // Returns the locally configured Required Min Rx Interval.
    //
    // In case this value is configured differently by different clients (or
    // statically), the smallest value is chosen.
    pub(crate) fn required_min_rx(&self) -> u32 {
        self.clients
            .values()
            .filter_map(|client| client.config.as_ref())
            .min_by_key(|config| config.min_rx)
            .map(|config| std::cmp::min(config.min_rx, self.config.min_rx))
            .unwrap_or(self.config.min_rx)
    }

    // Returns the last value of Required Min Rx Interval received from the
    // remote system in a BFD Control packet.
    pub(crate) fn remote_min_rx_interval(&self) -> u32 {
        // If we haven't heard from our peer yet, return the initial value (1
        // microsecond).
        self.state
            .remote
            .as_ref()
            .map(|remote| remote.min_rx)
            .unwrap_or(1)
    }

    // Returns the negotiated Tx interval for the session.
    pub(crate) fn negotiated_tx_interval(&self) -> Option<u32> {
        let remote_min_rx = self.remote_min_rx_interval();

        // A system MUST NOT periodically transmit BFD Control packets if
        // bfd.RemoteMinRxInterval is zero.
        if remote_min_rx == 0 {
            return None;
        }

        Some(std::cmp::max(self.state.curr_min_tx, remote_min_rx))
    }

    // Returns the negotiated Rx interval for the session.
    pub(crate) fn negotiated_rx_interval(&self) -> Option<u32> {
        self.state
            .remote
            .as_ref()
            .map(|remote| std::cmp::max(self.state.curr_min_rx, remote.min_tx))
    }

    // Returns the negotiated detection time for the session.
    pub(crate) fn detection_time(&self) -> Option<u32> {
        // In Asynchronous mode, the Detection Time calculated in the local
        // system is equal to the value of Detect Mult received from the remote
        // system, multiplied by the agreed transmit interval of the remote
        // system (the greater of bfd.RequiredMinRxInterval and the last
        // received Desired Min Tx Interval).
        self.state.remote.as_ref().map(|remote| {
            remote.multiplier as u32 * self.negotiated_rx_interval().unwrap()
        })
    }

    // Generates BFD Control Packet according to the session's state and
    // configuration.
    pub(crate) fn generate_packet(&self) -> Packet {
        Packet {
            version: 1,
            diag: self.state.local_diag as u8,
            state: self.state.local_state,
            flags: PacketFlags::empty(),
            detect_mult: self.local_multiplier(),
            my_discr: self.state.local_discr,
            your_discr: self
                .state
                .remote
                .as_ref()
                .map(|remote| remote.discr)
                .unwrap_or(0),
            desired_min_tx: self.desired_tx_interval(),
            req_min_rx: self.required_min_rx(),
            req_min_echo_rx: 0,
        }
    }

    // Creates or updates the UDP socket used to send BFD packets.
    pub(crate) fn update_socket_tx(&mut self) {
        let (ifname, af, src, ttl) = match &self.key {
            SessionKey::IpSingleHop { ifname, dst } => {
                let af = dst.address_family();
                let src = self.config.src.unwrap_or(IpAddr::unspecified(af));
                (Some(ifname.as_str()), af, src, TTL_MAX)
            }
            SessionKey::IpMultihop { src, dst } => {
                let af = dst.address_family();
                let ttl = self.config.tx_ttl.unwrap_or(TTL_MAX);
                (None, af, *src, ttl)
            }
        };
        match network::socket_tx(ifname, af, src, ttl) {
            Ok(socket) => self.state.socket_tx = Some(Arc::new(socket)),
            Err(error) => {
                IoError::UdpSocketError(error).log();
            }
        }
    }

    // (Re)starts or stops the periodic transmission of BFD packets.
    pub(crate) fn update_tx_interval(&mut self) {
        if let Some(socket_tx) = &self.state.socket_tx
            && let Some(interval) = self.negotiated_tx_interval()
        {
            // (Re)start Tx interval.
            let sockaddr = self.state.sockaddr.unwrap();
            let task =
                tasks::udp_tx_interval(self, interval, socket_tx, sockaddr);
            self.state.tx_interval = Some(task);
        } else {
            // Stop Tx interval.
            self.state.tx_interval = None;
        }
    }

    // Sends single BFD control packet with the F-bit set.
    pub(crate) fn send_tx_final(&mut self) {
        if let Some(socket_tx) = &self.state.socket_tx {
            let sockaddr = self.state.sockaddr.unwrap();
            tasks::udp_tx_final(self, socket_tx, sockaddr);
        }
    }

    // (Re)sets the detection time (timeout) for this session.
    pub(crate) fn update_detection_time(
        &mut self,
        detect_timerp: &Sender<DetectTimerMsg>,
    ) {
        let task = tasks::detection_timer(self, detect_timerp);
        self.state.detection_timer = Some(task);
    }

    // Initiates a Poll Sequence.
    pub(crate) fn poll_sequence_start(&self) {
        self.state
            .poll_active
            .store(true, atomic::Ordering::Relaxed);
    }

    // Terminates a Poll Sequence.
    pub(crate) fn poll_sequence_terminate(&self) {
        self.state
            .poll_active
            .store(false, atomic::Ordering::Relaxed);
    }

    // Checks whether a Poll Sequence is in progress.
    pub(crate) fn poll_sequence_is_active(&self) -> bool {
        self.state.poll_active.load(atomic::Ordering::Relaxed)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        Debug::SessionDelete(&self.key).log();
    }
}

// ===== impl SessionState =====

impl Default for SessionState {
    fn default() -> SessionState {
        SessionState {
            socket_tx: None,
            sockaddr: None,
            curr_min_tx:
                bfd::ip_sh::sessions::session::desired_min_tx_interval::DFLT,
            curr_min_rx:
                bfd::ip_sh::sessions::session::required_min_rx_interval::DFLT,
            local_state: State::Down,
            local_discr: rand::rng().next_u32(),
            local_diag: DiagnosticCode::Nothing,
            demand_mode: false,
            remote: None,
            poll_active: Arc::new(AtomicBool::new(false)),
            tx_interval: None,
            detection_timer: None,
        }
    }
}

// ===== impl SessionStatistics =====

impl Default for SessionStatistics {
    fn default() -> SessionStatistics {
        SessionStatistics {
            create_time: Utc::now(),
            last_state_change_time: None,
            last_down_time: None,
            last_up_time: None,
            down_count: 0,
            admin_down_count: 0,
            rx_packet_count: 0,
            tx_packet_count: Arc::new(AtomicU64::new(0)),
            rx_error_count: 0,
            tx_error_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

// ===== impl Sessions =====

impl Sessions {
    pub(crate) fn insert(
        &mut self,
        sess_key: SessionKey,
    ) -> (SessionIndex, &mut Session) {
        // Check for existing entry first.
        if let Some((sess_idx, _)) = self.get_mut_by_key(&sess_key) {
            let sess = &mut self.arena[sess_idx];
            return (sess_idx, sess);
        }

        // Create and insert session into the arena.
        let id = self.next_id();
        let sess = Session::new(id, sess_key);
        let sess_idx = self.arena.insert(sess);

        // Link session to different collections.
        let sess = &mut self.arena[sess_idx];
        self.id_tree.insert(sess.id, sess_idx);
        self.key_tree.insert(sess.key.clone(), sess_idx);
        self.discr_tree.insert(sess.state.local_discr, sess_idx);
        if let SessionKey::IpSingleHop { ifname, .. } = &sess.key {
            self.ifname_tree
                .entry(ifname.clone())
                .or_default()
                .insert(sess_idx);
        }

        // Return a mutable reference to the session.
        (sess_idx, sess)
    }

    pub(crate) fn delete_check(&mut self, sess_idx: SessionIndex) {
        let sess = &mut self.arena[sess_idx];

        // Delete session only if it's not statically configured and also not
        // registered by any client.
        if !sess.config_enabled && sess.clients.is_empty() {
            self.delete(sess_idx);
        }
    }

    fn delete(&mut self, sess_idx: SessionIndex) {
        let sess = &mut self.arena[sess_idx];

        // Unlink session from different collections.
        self.id_tree.remove(&sess.id);
        self.key_tree.remove(&sess.key);
        self.discr_tree.remove(&sess.state.local_discr);
        if let SessionKey::IpSingleHop { ifname, .. } = &sess.key
            && let hash_map::Entry::Occupied(mut o) =
                self.ifname_tree.entry(ifname.clone())
        {
            let tree = o.get_mut();
            tree.remove(&sess_idx);
            if tree.is_empty() {
                o.remove_entry();
            }
        }
        if let Some(sockaddr) = &sess.state.sockaddr {
            self.sockaddr_tree.remove(sockaddr);
        }

        // Remove session from the arena.
        self.arena.remove(sess_idx);
    }

    pub(crate) fn update_ifindex(
        &mut self,
        sess_idx: SessionIndex,
        ifindex: Option<u32>,
    ) {
        let sess = &mut self.arena[sess_idx];

        if let Some(sockaddr) = sess.state.sockaddr.take() {
            self.sockaddr_tree.remove(&sockaddr);

            // Stop Tx interval.
            sess.state.tx_interval = None;
        }
        if let Some(ifindex) = ifindex {
            let (_, dst) = sess.key.as_ip_single_hop().unwrap();
            let mut sockaddr =
                SocketAddr::new(*dst, network::PORT_DST_SINGLE_HOP);
            if let SocketAddr::V6(sockaddr) = &mut sockaddr {
                sockaddr.set_scope_id(ifindex);
            }
            sess.state.sockaddr = Some(sockaddr);
            self.sockaddr_tree.insert(sockaddr, sess_idx);

            // Start Tx interval.
            sess.update_tx_interval();
        }
    }

    // Returns a reference to the session corresponding to the given ID.
    #[expect(unused)]
    pub(crate) fn get_by_id(
        &self,
        id: SessionId,
    ) -> Result<(SessionIndex, &Session), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|sess_idx| (sess_idx, &self.arena[sess_idx]))
            .ok_or(Error::SessionIdNotFound(id))
    }

    // Returns a mutable reference to the session corresponding to the given
    // ID.
    pub(crate) fn get_mut_by_id(
        &mut self,
        id: SessionId,
    ) -> Result<(SessionIndex, &mut Session), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |sess_idx| (sess_idx, &mut self.arena[sess_idx]))
            .ok_or(Error::SessionIdNotFound(id))
    }

    // Returns a reference to the session corresponding to the given BFD key.
    #[expect(unused)]
    pub(crate) fn get_by_key(
        &self,
        key: &SessionKey,
    ) -> Option<(SessionIndex, &Session)> {
        self.key_tree
            .get(key)
            .copied()
            .map(|sess_idx| (sess_idx, &self.arena[sess_idx]))
    }

    // Returns a mutable reference to the session corresponding to the given
    // BFD key.
    pub(crate) fn get_mut_by_key(
        &mut self,
        key: &SessionKey,
    ) -> Option<(SessionIndex, &mut Session)> {
        self.key_tree
            .get(key)
            .copied()
            .map(move |sess_idx| (sess_idx, &mut self.arena[sess_idx]))
    }

    // Returns a reference to the session corresponding to the given local
    // discriminator.
    #[expect(unused)]
    pub(crate) fn get_by_discr(
        &self,
        discr: u32,
    ) -> Option<(SessionIndex, &Session)> {
        self.discr_tree
            .get(&discr)
            .copied()
            .map(|sess_idx| (sess_idx, &self.arena[sess_idx]))
    }

    // Returns a mutable reference to the session corresponding to the given
    // local discriminator.
    pub(crate) fn get_mut_by_discr(
        &mut self,
        discr: u32,
    ) -> Option<(SessionIndex, &mut Session)> {
        self.discr_tree
            .get(&discr)
            .copied()
            .map(move |sess_idx| (sess_idx, &mut self.arena[sess_idx]))
    }

    // Returns a reference to the session corresponding to the given socket
    // address (IP address + ifindex).
    #[expect(unused)]
    pub(crate) fn get_by_sockaddr(
        &self,
        mut sockaddr: SocketAddr,
    ) -> Option<(SessionIndex, &Session)> {
        sockaddr.set_port(network::PORT_DST_SINGLE_HOP);
        self.sockaddr_tree
            .get(&sockaddr)
            .copied()
            .map(|sess_idx| (sess_idx, &self.arena[sess_idx]))
    }

    // Returns a mutable reference to the session corresponding to the given
    // socket address (IP address + ifindex).
    pub(crate) fn get_mut_by_sockaddr(
        &mut self,
        mut sockaddr: SocketAddr,
    ) -> Option<(SessionIndex, &mut Session)> {
        sockaddr.set_port(network::PORT_DST_SINGLE_HOP);
        self.sockaddr_tree
            .get(&sockaddr)
            .copied()
            .map(move |sess_idx| (sess_idx, &mut self.arena[sess_idx]))
    }

    // Returns an iterator visiting all sessions.
    //
    // Sessions are ordered by their BFD keys.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &'_ Session> + '_ {
        self.key_tree
            .values()
            .map(|sess_idx| &self.arena[*sess_idx])
    }

    // Returns an iterator visiting all IP Single-Hop sessions attached to the
    // given interface.
    //
    // Iteration order is undefined.
    pub(crate) fn iter_by_ifname(
        &self,
        ifname: &String,
    ) -> impl Iterator<Item = SessionIndex> + '_ {
        self.ifname_tree
            .get(ifname)
            .into_iter()
            .flat_map(|sessions| sessions.iter().copied())
    }

    // Get next session ID.
    fn next_id(&mut self) -> SessionId {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }
}

impl std::ops::Index<SessionIndex> for Sessions {
    type Output = Session;

    fn index(&self, index: SessionIndex) -> &Self::Output {
        &self.arena[index]
    }
}

impl std::ops::IndexMut<SessionIndex> for Sessions {
    fn index_mut(&mut self, index: SessionIndex) -> &mut Self::Output {
        &mut self.arena[index]
    }
}
