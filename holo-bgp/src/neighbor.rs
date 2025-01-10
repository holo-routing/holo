//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU32};
use std::time::Duration;

use chrono::{DateTime, Utc};
use holo_protocol::InstanceChannelsTx;
use holo_utils::bgp::{AfiSafi, RouteType, WellKnownCommunities};
use holo_utils::ibus::IbusSender;
use holo_utils::socket::{TTL_MAX, TcpConnInfo, TcpStream};
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use holo_utils::{Sender, UnboundedSender};
use num_traits::{FromPrimitive, ToPrimitive};
use tokio::sync::mpsc;

use crate::af::{AddressFamily, Ipv4Unicast, Ipv6Unicast};
use crate::debug::Debug;
use crate::error::Error;
use crate::instance::{Instance, InstanceUpView};
use crate::northbound::configuration::{InstanceCfg, NeighborCfg};
use crate::northbound::notification;
use crate::northbound::rpc::ClearType;
use crate::packet::attribute::Attrs;
use crate::packet::consts::{
    AS_TRANS, Afi, BGP_VERSION, CeaseSubcode, ErrorCode, FsmErrorSubcode, Safi,
};
use crate::packet::message::{
    Capability, DecodeCxt, EncodeCxt, KeepaliveMsg, Message,
    NegotiatedCapability, NotificationMsg, OpenMsg, RouteRefreshMsg,
};
use crate::rib::{Rib, Route, RouteOrigin};
#[cfg(feature = "testing")]
use crate::tasks::messages::ProtocolOutputMsg;
use crate::tasks::messages::input::{NbrRxMsg, NbrTimerMsg, TcpConnectMsg};
use crate::tasks::messages::output::NbrTxMsg;
use crate::{events, rib, tasks};

// Large hold-time used during session initialization.
const LARGE_HOLDTIME: u16 = 240;

// BGP neighbor.
#[derive(Debug)]
pub struct Neighbor {
    pub remote_addr: IpAddr,
    pub config: NeighborCfg,
    pub state: fsm::State,
    pub peer_type: PeerType,
    pub conn_info: Option<TcpConnInfo>,
    pub shared_subnet: bool,
    pub identifier: Option<Ipv4Addr>,
    pub holdtime_nego: Option<u16>,
    pub capabilities_adv: BTreeSet<Capability>,
    pub capabilities_rcvd: BTreeSet<Capability>,
    pub capabilities_nego: BTreeSet<NegotiatedCapability>,
    pub notification_sent: Option<(DateTime<Utc>, NotificationMsg)>,
    pub notification_rcvd: Option<(DateTime<Utc>, NotificationMsg)>,
    pub last_established: Option<DateTime<Utc>>,
    pub statistics: NeighborStatistics,
    pub tasks: NeighborTasks,
    pub update_queues: NeighborUpdateQueues,
    pub msg_txp: Option<UnboundedSender<NbrTxMsg>>,
}

// BGP peer type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerType {
    Internal,
    External,
}

// Neighbor statistics.
#[derive(Debug, Default)]
pub struct NeighborStatistics {
    pub established_transitions: u32,
    pub msgs_rcvd: MessageStatistics,
    pub msgs_sent: MessageStatistics,
    pub erroneous_updates_withdrawn: u32,
    pub erroneous_updates_attribute_discarded: u32,
    pub in_update_elapsed_time: Duration,
}

// Inbound and outbound message counters.
#[derive(Debug, Default)]
pub struct MessageStatistics {
    pub total: Arc<AtomicU32>,
    pub updates: u32,
    pub notifications: u32,
    pub route_refreshes: u32,
}

// Neighbor tasks.
#[derive(Debug, Default)]
pub struct NeighborTasks {
    pub autostart: Option<TimeoutTask>,
    pub connect: Option<Task<()>>,
    pub connect_retry: Option<TimeoutTask>,
    pub tcp_rx: Option<Task<()>>,
    pub keepalive: Option<IntervalTask>,
    pub holdtime: Option<TimeoutTask>,
}

// Neighbor Tx update queues.
#[derive(Debug, Default)]
pub struct NeighborUpdateQueues {
    pub ipv4_unicast: NeighborUpdateQueue<Ipv4Unicast>,
    pub ipv6_unicast: NeighborUpdateQueue<Ipv6Unicast>,
}

// Neighbor Tx update queue.
#[derive(Debug)]
pub struct NeighborUpdateQueue<A: AddressFamily> {
    pub reach: BTreeMap<Attrs, BTreeSet<A::IpNetwork>>,
    pub unreach: BTreeSet<A::IpNetwork>,
}

// Type aliases.
pub type Neighbors = BTreeMap<IpAddr, Neighbor>;

// Finite State Machine.
pub mod fsm {
    use holo_utils::socket::{TcpConnInfo, TcpStream};
    use serde::{Deserialize, Serialize};

    use crate::packet::error::DecodeError;
    use crate::packet::message::{NotificationMsg, OpenMsg};

    // FSM states.
    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub enum State {
        Idle,
        Connect,
        Active,
        OpenSent,
        OpenConfirm,
        Established,
    }

    // FSM events.
    //
    // The original RFC FSM events are listed above each event for clarity.
    #[derive(Debug)]
    pub enum Event {
        // ManualStart
        // ManualStart_with_PassiveTcpEstablishment
        Start,
        // ManualStop
        Stop(Option<NotificationMsg>),
        // Tcp_CR_Acked
        // TcpConnectionConfirmed
        Connected(TcpStream, TcpConnInfo),
        // TcpConnectionFails
        ConnFail,
        // BGPHeaderErr
        // BGPOpenMsgErr
        // UpdateMsgErr
        RcvdError(DecodeError),
        // BGPOpen
        RcvdOpen(OpenMsg),
        // NotifMsg
        RcvdNotif(NotificationMsg),
        // KeepAliveMsg
        RcvdKalive,
        // UpdateMsg
        RcvdUpdate,
        // ConnectRetryTimer_Expires
        // HoldTimer_Expires
        // AutomaticStart
        // AutomaticStart_with_PassiveTcpEstablishment
        Timer(Timer),
    }

    // BGP timers.
    //
    // Note: KEEPALIVE messages are sent independently, separate from the FSM.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    pub enum Timer {
        ConnectRetry,
        Hold,
        AutoStart,
    }
}

// ===== impl Neighbor =====

impl Neighbor {
    // Creates a new neighbor in the Idle state with default configuration.
    pub(crate) fn new(remote_addr: IpAddr, peer_type: PeerType) -> Neighbor {
        Neighbor {
            remote_addr,
            config: Default::default(),
            state: fsm::State::Idle,
            peer_type,
            conn_info: None,
            shared_subnet: false,
            identifier: None,
            holdtime_nego: None,
            capabilities_adv: Default::default(),
            capabilities_rcvd: Default::default(),
            capabilities_nego: Default::default(),
            notification_sent: None,
            notification_rcvd: None,
            last_established: None,
            statistics: Default::default(),
            tasks: Default::default(),
            update_queues: Default::default(),
            msg_txp: None,
        }
    }

    // Injects an event into the neighbor's FSM.
    pub(crate) fn fsm_event(
        &mut self,
        instance: &mut InstanceUpView<'_>,
        event: fsm::Event,
    ) {
        Debug::NbrFsmEvent(&self.remote_addr, &event).log();

        // Process FSM event.
        let rib = &mut instance.state.rib;
        let next_state = match self.state {
            // Idle state
            fsm::State::Idle => match event {
                fsm::Event::Start
                | fsm::Event::Timer(fsm::Timer::AutoStart) => {
                    self.connect_retry_start(
                        &instance.tx.protocol_input.nbr_timer,
                    );
                    if self.config.transport.passive_mode {
                        Some(fsm::State::Active)
                    } else {
                        self.connect(&instance.tx.protocol_input.tcp_connect);
                        Some(fsm::State::Connect)
                    }
                }
                _ => None,
            },
            // Connect state
            fsm::State::Connect => match event {
                fsm::Event::Start => None,
                fsm::Event::Stop(_) => {
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
                fsm::Event::Connected(stream, conn_info) => {
                    self.connect_retry_stop();
                    self.connection_setup(
                        stream,
                        conn_info,
                        &instance.tx.protocol_input.nbr_msg_rx,
                        #[cfg(feature = "testing")]
                        &instance.tx.protocol_output,
                    );
                    self.open_send(instance.config, instance.state.router_id);
                    self.holdtime_start(
                        LARGE_HOLDTIME,
                        &instance.tx.protocol_input.nbr_timer,
                    );
                    Some(fsm::State::OpenSent)
                }
                fsm::Event::ConnFail => {
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdError(error) => {
                    let msg = NotificationMsg::from(error);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
                fsm::Event::Timer(fsm::Timer::ConnectRetry) => {
                    self.connect(&instance.tx.protocol_input.tcp_connect);
                    self.connect_retry_start(
                        &instance.tx.protocol_input.nbr_timer,
                    );
                    None
                }
                _ => {
                    // FSM error.
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
            },
            // Active state
            fsm::State::Active => match event {
                fsm::Event::Start => None,
                fsm::Event::Stop(_) => {
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
                fsm::Event::Connected(stream, conn_info) => {
                    self.connect_retry_stop();
                    self.connection_setup(
                        stream,
                        conn_info,
                        &instance.tx.protocol_input.nbr_msg_rx,
                        #[cfg(feature = "testing")]
                        &instance.tx.protocol_output,
                    );
                    self.open_send(instance.config, instance.state.router_id);
                    self.holdtime_start(
                        LARGE_HOLDTIME,
                        &instance.tx.protocol_input.nbr_timer,
                    );
                    Some(fsm::State::OpenSent)
                }
                fsm::Event::ConnFail => {
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdError(error) => {
                    let msg = NotificationMsg::from(error);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
                fsm::Event::Timer(fsm::Timer::ConnectRetry) => {
                    self.connect(&instance.tx.protocol_input.tcp_connect);
                    self.connect_retry_start(
                        &instance.tx.protocol_input.nbr_timer,
                    );
                    Some(fsm::State::Connect)
                }
                _ => {
                    // FSM error.
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
            },
            // OpenSent state
            fsm::State::OpenSent => match event {
                fsm::Event::Start => None,
                fsm::Event::Stop(msg) => {
                    self.session_close(rib, instance.tx, msg);
                    Some(fsm::State::Idle)
                }
                fsm::Event::ConnFail => {
                    self.session_close(rib, instance.tx, None);
                    self.connect_retry_start(
                        &instance.tx.protocol_input.nbr_timer,
                    );
                    Some(fsm::State::Active)
                }
                fsm::Event::RcvdError(error) => {
                    let msg = NotificationMsg::from(error);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdOpen(msg) => {
                    let next_state = self.open_process(instance, msg);
                    Some(next_state)
                }
                fsm::Event::Timer(fsm::Timer::Hold) => {
                    let error_code = ErrorCode::HoldTimerExpired;
                    let error_subcode = 0;
                    let msg = NotificationMsg::new(error_code, error_subcode);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
                _ => {
                    // FSM error.
                    let error_code = ErrorCode::FiniteStateMachineError;
                    let error_subcode =
                        FsmErrorSubcode::UnexpectedMessageInOpenSent;
                    let msg = NotificationMsg::new(error_code, error_subcode);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
            },
            // OpenConfirm state
            fsm::State::OpenConfirm => match event {
                fsm::Event::Start => None,
                fsm::Event::Stop(msg) => {
                    self.session_close(rib, instance.tx, msg);
                    Some(fsm::State::Idle)
                }
                fsm::Event::ConnFail => {
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdError(error) => {
                    let msg = NotificationMsg::from(error);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdOpen(_msg) => {
                    // TODO: collision detection
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdNotif(_) => {
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdKalive => {
                    self.holdtime_restart();
                    Some(fsm::State::Established)
                }
                fsm::Event::Timer(fsm::Timer::Hold) => {
                    let error_code = ErrorCode::HoldTimerExpired;
                    let error_subcode = 0;
                    let msg = NotificationMsg::new(error_code, error_subcode);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
                _ => {
                    // FSM error.
                    let error_code = ErrorCode::FiniteStateMachineError;
                    let error_subcode =
                        FsmErrorSubcode::UnexpectedMessageInOpenConfirm;
                    let msg = NotificationMsg::new(error_code, error_subcode);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
            },
            // Established state
            fsm::State::Established => match event {
                fsm::Event::Start => None,
                fsm::Event::Stop(msg) => {
                    self.session_close(rib, instance.tx, msg);
                    Some(fsm::State::Idle)
                }
                fsm::Event::ConnFail => {
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdError(error) => {
                    let msg = NotificationMsg::from(error);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdNotif(_) => {
                    self.session_close(rib, instance.tx, None);
                    Some(fsm::State::Idle)
                }
                fsm::Event::RcvdKalive | fsm::Event::RcvdUpdate => {
                    self.holdtime_restart();
                    None
                }
                fsm::Event::Timer(fsm::Timer::Hold) => {
                    let error_code = ErrorCode::HoldTimerExpired;
                    let error_subcode = 0;
                    let msg = NotificationMsg::new(error_code, error_subcode);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
                _ => {
                    // FSM error.
                    let error_code = ErrorCode::FiniteStateMachineError;
                    let error_subcode =
                        FsmErrorSubcode::UnexpectedMessageInEstablished;
                    let msg = NotificationMsg::new(error_code, error_subcode);
                    self.session_close(rib, instance.tx, Some(msg));
                    Some(fsm::State::Idle)
                }
            },
        };

        // Change to next FSM state when applicable.
        if let Some(next_state) = next_state
            && self.state != next_state
        {
            // Schedule auto-start unless the peer has been manually disabled.
            if next_state == fsm::State::Idle && self.config.enabled {
                self.autostart_start(&instance.tx.protocol_input.nbr_timer);
            } else {
                self.autostart_stop();
            }

            self.fsm_state_change(instance, next_state);
        }
    }

    // Updates the neighbor's FSM state.
    fn fsm_state_change(
        &mut self,
        instance: &mut InstanceUpView<'_>,
        next_state: fsm::State,
    ) {
        Debug::NbrFsmTransition(&self.remote_addr, &self.state, &next_state)
            .log();

        // Send YANG-modeled notification.
        if next_state == fsm::State::Established {
            notification::established(instance, self);
        } else if self.state == fsm::State::Established {
            notification::backward_transition(instance, self);
        }

        // Keep track of the time that the BGP session last transitioned in or
        // out of the Established state.
        if self.state == fsm::State::Established
            || next_state == fsm::State::Established
        {
            self.last_established = Some(Utc::now());
        }

        if next_state == fsm::State::Established {
            // Update statistics.
            self.statistics.established_transitions += 1;

            // Initialize session.
            self.session_init(instance);
        }

        self.state = next_state;
    }

    // Sets up the connection for the BGP neighbor, spawning necessary tasks for
    // TCP communication.
    fn connection_setup(
        &mut self,
        stream: TcpStream,
        conn_info: TcpConnInfo,
        nbr_msg_rxp: &Sender<NbrRxMsg>,
        #[cfg(feature = "testing")] proto_output_tx: &Sender<ProtocolOutputMsg>,
    ) {
        // Store TCP connection information.
        self.conn_info = Some(conn_info);

        // Split TCP stream into two halves.
        let (read_half, write_half) = stream.into_split();

        // Spawn neighbor TCP Tx task.
        let (msg_txp, msg_txc) = mpsc::unbounded_channel();
        let cxt = EncodeCxt {
            capabilities: Default::default(),
        };
        let mut tx_task = tasks::nbr_tx(
            self,
            cxt,
            write_half,
            msg_txc,
            #[cfg(feature = "testing")]
            proto_output_tx,
        );
        self.msg_txp = Some(msg_txp);

        // Spawn neighbor TCP Rx task.
        let cxt = DecodeCxt {
            peer_type: self.peer_type,
            peer_as: self.config.peer_as,
            capabilities: Default::default(),
        };
        let tcp_rx_task = tasks::nbr_rx(self, cxt, read_half, nbr_msg_rxp);
        self.tasks.tcp_rx = Some(tcp_rx_task);

        // No need to keep track of the Tx task since it gracefully exits as
        // soon as the tx end of its mpsc channel is dropped. This ensures that
        // messages sent during neighbor shutdown will be delivered.
        tx_task.detach();
    }

    // Initializes the BGP session.
    fn session_init(&mut self, instance: &mut InstanceUpView<'_>) {
        // Compute the negotiated capabilities.
        self.capabilities_nego = self
            .capabilities_adv
            .iter()
            .map(|cap| cap.as_negotiated())
            .collect::<BTreeSet<_>>()
            .intersection(
                &self
                    .capabilities_rcvd
                    .iter()
                    .map(|cap| cap.as_negotiated())
                    .collect::<BTreeSet<_>>(),
            )
            .cloned()
            .collect();

        // Update the Tx task with the negotiated capabilities.
        let msg = NbrTxMsg::UpdateCapabilities(self.capabilities_nego.clone());
        let _ = self.msg_txp.as_ref().unwrap().send(msg);

        // Send initial routing updates.
        self.initial_routing_update::<Ipv4Unicast>(instance);
        self.initial_routing_update::<Ipv6Unicast>(instance);
    }

    // Closes the BGP session, performing necessary cleanup and releasing resources.
    fn session_close(
        &mut self,
        rib: &mut Rib,
        instance_tx: &InstanceChannelsTx<Instance>,
        send_notif: Option<NotificationMsg>,
    ) {
        // Send a notification message.
        if self.state >= fsm::State::OpenSent
            && let Some(msg) = send_notif
        {
            self.message_send(Message::Notification(msg));
        }

        // Set the ConnectRetryTimer to zero.
        self.connect_retry_stop();

        // Release all resources.
        self.conn_info = None;
        self.identifier = None;
        self.holdtime_nego = None;
        self.capabilities_adv.clear();
        self.capabilities_rcvd.clear();
        self.capabilities_nego.clear();
        self.clear_routes::<Ipv4Unicast>(rib, &instance_tx.ibus);
        self.clear_routes::<Ipv6Unicast>(rib, &instance_tx.ibus);
        self.tasks = Default::default();
        self.msg_txp = None;

        // Trigger the BGP Decision Process.
        instance_tx.protocol_input.trigger_decision_process();
    }

    // Enqueues a single BGP message for transmission.
    pub(crate) fn message_send(&mut self, msg: Message) {
        Debug::NbrMsgTx(&self.remote_addr, &msg).log();

        // Update statistics.
        self.statistics.msgs_sent.update(&msg);

        // Keep track of the last sent notification.
        if let Message::Notification(msg) = &msg {
            self.notification_sent = Some((Utc::now(), msg.clone()));
        }

        // Ignore any possible error as the connection might have gone down
        // already.
        let nbr_addr = self.remote_addr;
        let msg = NbrTxMsg::SendMessage { nbr_addr, msg };
        let _ = self.msg_txp.as_ref().unwrap().send(msg);
    }

    // Enqueues a list of BGP messages for transmission.
    //
    // This method is more efficient for handling a large number of messages,
    // as they are sent all at once.
    pub(crate) fn message_list_send(&mut self, msg_list: Vec<Message>) {
        for msg in &msg_list {
            Debug::NbrMsgTx(&self.remote_addr, msg).log();

            // Update statistics.
            self.statistics.msgs_sent.update(msg);

            // Keep track of the last sent notification.
            if let Message::Notification(msg) = &msg {
                self.notification_sent = Some((Utc::now(), msg.clone()));
            }
        }

        // Ignore any possible error as the connection might have gone down
        // already.
        let nbr_addr = self.remote_addr;
        let msg = NbrTxMsg::SendMessageList { nbr_addr, msg_list };
        let _ = self.msg_txp.as_ref().unwrap().send(msg);
    }

    // Sends a BGP OPEN message based on the local configuration.
    fn open_send(&mut self, instance_cfg: &InstanceCfg, identifier: Ipv4Addr) {
        // Base capabilities.
        let mut capabilities: BTreeSet<_> =
            [Capability::RouteRefresh, Capability::FourOctetAsNumber {
                asn: instance_cfg.asn,
            }]
            .into();

        // Multiprotocol capabilities.
        if let Some(afi_safi) = self.config.afi_safi.get(&AfiSafi::Ipv4Unicast)
            && afi_safi.enabled
        {
            capabilities.insert(Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            });
        }
        if let Some(afi_safi) = self.config.afi_safi.get(&AfiSafi::Ipv6Unicast)
            && afi_safi.enabled
        {
            capabilities.insert(Capability::MultiProtocol {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
            });
        }

        // Keep track of the advertised capabilities.
        self.capabilities_adv.clone_from(&capabilities);

        // Fill-in and send message.
        let msg = Message::Open(OpenMsg {
            version: BGP_VERSION,
            my_as: instance_cfg.asn.try_into().unwrap_or(AS_TRANS),
            holdtime: self.config.timers.holdtime,
            identifier,
            capabilities,
        });
        self.message_send(msg);
    }

    // Processes the received OPEN message while in the OpenSent state.
    fn open_process(
        &mut self,
        instance: &mut InstanceUpView<'_>,
        msg: OpenMsg,
    ) -> fsm::State {
        use crate::packet::consts::OpenMessageErrorSubcode as ErrorSubcode;

        // Validate the received message.
        if let Err(error) = self.open_validate(instance, &msg) {
            error.log();

            // Close the session.
            let msg = match error {
                Error::NbrBadAs(..) => {
                    let error_code = ErrorCode::OpenMessageError;
                    let error_subcode = ErrorSubcode::BadPeerAs;
                    let msg = NotificationMsg::new(error_code, error_subcode);
                    Some(msg)
                }
                Error::NbrBadIdentifier(..) => {
                    let error_code = ErrorCode::OpenMessageError;
                    let error_subcode = ErrorSubcode::BadBgpIdentifier;
                    let msg = NotificationMsg::new(error_code, error_subcode);
                    Some(msg)
                }
                _ => None,
            };
            self.session_close(&mut instance.state.rib, instance.tx, msg);

            // Transition to the Idle state.
            return fsm::State::Idle;
        }

        // Calculate negotiated hold-time.
        let holdtime_nego =
            std::cmp::min(msg.holdtime, self.config.timers.holdtime);

        // Set the ConnectRetryTimer to zero.
        self.connect_retry_stop();

        // Send Keepalive message.
        self.message_send(Message::Keepalive(KeepaliveMsg {}));

        // Start Keepalive interval and session hold timer.
        if holdtime_nego != 0 {
            self.keepalive_interval_start(holdtime_nego);
            self.holdtime_start(
                holdtime_nego,
                &instance.tx.protocol_input.nbr_timer,
            );
        } else {
            self.holdtime_stop();
        }

        // Keep track of the received data.
        self.identifier = Some(msg.identifier);
        self.holdtime_nego = (holdtime_nego != 0).then_some(holdtime_nego);
        self.capabilities_rcvd = msg.capabilities;

        // TODO: collision detection

        // Transition to the OpenConfirm state.
        fsm::State::OpenConfirm
    }

    // Performs semantic validation of the received BGP OPEN message.
    // Syntactic errors are detected during the decoding phase.
    fn open_validate(
        &self,
        instance: &InstanceUpView<'_>,
        msg: &OpenMsg,
    ) -> Result<(), Error> {
        // Validate ASN.
        if self.config.peer_as != msg.real_as() {
            return Err(Error::NbrBadAs(
                self.remote_addr,
                msg.real_as(),
                self.config.peer_as,
            ));
        }

        // Validate BGP identifier for internal peers.
        if self.peer_type == PeerType::Internal
            && msg.identifier == instance.state.router_id
        {
            return Err(Error::NbrBadIdentifier(
                self.remote_addr,
                msg.identifier,
            ));
        }

        Ok(())
    }

    // Returns the neighbor's Tx-TTL value based on the peer type and
    // configuration.
    pub(crate) fn tx_ttl(&self) -> u8 {
        match self.peer_type {
            PeerType::Internal => TTL_MAX,
            PeerType::External => {
                if self.config.transport.ttl_security.is_some() {
                    TTL_MAX
                } else if self.config.transport.ebgp_multihop_enabled
                    && let Some(ttl) = self.config.transport.ebgp_multihop_ttl
                {
                    ttl
                } else {
                    1
                }
            }
        }
    }

    // Starts the auto-start timer.
    fn autostart_start(&mut self, nbr_timerp: &Sender<NbrTimerMsg>) {
        let idle_hold_time = 1;
        let task = tasks::nbr_timer(
            self,
            fsm::Timer::AutoStart,
            idle_hold_time,
            nbr_timerp,
        );
        self.tasks.autostart = Some(task);
    }

    // Stops the auto-start timer.
    fn autostart_stop(&mut self) {
        self.tasks.autostart = None;
    }

    // Starts a TCP connection task to the neighbor's remote address.
    fn connect(&mut self, tcp_connectp: &Sender<TcpConnectMsg>) {
        let task = tasks::tcp_connect(self, tcp_connectp);
        self.tasks.connect = Some(task);
    }

    // Starts the Keepalive Tx interval.
    fn keepalive_interval_start(&mut self, holdtime_nego: u16) {
        let interval =
            self.config.timers.keepalive.unwrap_or(holdtime_nego / 3);
        let task = tasks::nbr_kalive_interval(self, interval);
        self.tasks.keepalive = Some(task);
    }

    // Starts the session hold timer.
    fn holdtime_start(
        &mut self,
        seconds: u16,
        nbr_timerp: &Sender<NbrTimerMsg>,
    ) {
        let task =
            tasks::nbr_timer(self, fsm::Timer::Hold, seconds, nbr_timerp);
        self.tasks.holdtime = Some(task);
    }

    // Restarts the session hold timer if the negotiated HoldTime value is
    // non-zero.
    fn holdtime_restart(&mut self) {
        if let Some(holdtime) = self.tasks.holdtime.as_mut() {
            holdtime.reset(None);
        }
    }

    // Stops the session hold timer.
    fn holdtime_stop(&mut self) {
        self.tasks.holdtime = None;
    }

    // Starts the connect retry timer.
    fn connect_retry_start(&mut self, nbr_timerp: &Sender<NbrTimerMsg>) {
        let task = tasks::nbr_timer(
            self,
            fsm::Timer::ConnectRetry,
            self.config.timers.connect_retry_interval,
            nbr_timerp,
        );
        self.tasks.connect_retry = Some(task);
    }

    // Stops the connect retry timer.
    fn connect_retry_stop(&mut self) {
        self.tasks.connect_retry = None;
    }

    // Sends an initial routing update for the specified address-family after
    // the session is established.
    fn initial_routing_update<A>(&mut self, instance: &mut InstanceUpView<'_>)
    where
        A: AddressFamily,
    {
        // Check if the address-family is enabled for this session.
        if !self.is_af_enabled(A::AFI, A::SAFI) {
            return;
        }

        // Get list of best routes for this address-family.
        let table = A::table(&mut instance.state.rib.tables);
        let routes = table
            .prefixes
            .iter()
            .filter_map(|(prefix, dest)| {
                dest.local.as_ref().map(|route| {
                    let route = Route {
                        origin: route.origin,
                        attrs: route.attrs.clone(),
                        route_type: route.route_type,
                        igp_cost: None,
                        last_modified: route.last_modified,
                        ineligible_reason: None,
                        reject_reason: None,
                    };
                    (*prefix, Box::new(route))
                })
            })
            .filter(|(_, route)| self.distribute_filter(route))
            .collect::<Vec<_>>();

        // Advertise the best routes.
        events::advertise_routes::<A>(
            self,
            table,
            routes,
            instance.shared,
            &mut instance.state.rib.attr_sets,
            &instance.state.policy_apply_tasks,
        );
    }

    // Re-send the current Adj-RIB-Out.
    pub(crate) fn resend_adj_rib_out<A>(
        &mut self,
        instance: &mut InstanceUpView<'_>,
    ) where
        A: AddressFamily,
    {
        let table = A::table(&mut instance.state.rib.tables);
        for (prefix, dest) in &table.prefixes {
            let Some(adj_rib) = dest.adj_rib.get(&self.remote_addr) else {
                continue;
            };
            let Some(route) = adj_rib.out_post() else {
                continue;
            };

            // Update route's attributes before transmission.
            let mut attrs = route.attrs.get();
            rib::attrs_tx_update::<A>(
                &mut attrs,
                self,
                instance.config.asn,
                route.origin.is_local(),
            );

            // Update neighbor's Tx queue.
            let update_queue = A::update_queue(&mut self.update_queues);
            update_queue.reach.entry(attrs).or_default().insert(*prefix);
        }
    }

    // Clears the Adj-RIB-In and Adj-RIB-Out for the given address family.
    fn clear_routes<A>(&mut self, rib: &mut Rib, ibus_tx: &IbusSender)
    where
        A: AddressFamily,
    {
        let table = A::table(&mut rib.tables);
        for (prefix, dest) in table.prefixes.iter_mut() {
            // Clear the Adj-RIB-In and Adj-RIB-Out.
            if let Some(mut adj_rib) = dest.adj_rib.remove(&self.remote_addr) {
                // Update nexthop tracking.
                if let Some(adj_in_route) = adj_rib.in_post() {
                    rib::nexthop_untrack(
                        &mut table.nht,
                        prefix,
                        adj_in_route,
                        ibus_tx,
                    );
                }

                adj_rib.remove_in_pre(&mut rib.attr_sets);
                adj_rib.remove_in_post(&mut rib.attr_sets);
                adj_rib.remove_out_pre(&mut rib.attr_sets);
                adj_rib.remove_out_post(&mut rib.attr_sets);
            }

            // Enqueue prefix for the BGP Decision Process.
            table.queued_prefixes.insert(*prefix);
        }
    }

    // Clears the neighbor session.
    pub(crate) fn clear_session(
        &mut self,
        instance: &mut InstanceUpView<'_>,
        clear_type: ClearType,
    ) {
        match clear_type {
            ClearType::Admin => {
                // Close the session with the "Administrative Reset" subcode.
                let msg = NotificationMsg::new(
                    ErrorCode::Cease,
                    CeaseSubcode::AdministrativeReset,
                );
                self.fsm_event(instance, fsm::Event::Stop(Some(msg)));
            }
            ClearType::Hard => {
                // Close the session with the "Hard Reset" subcode.
                let msg = NotificationMsg::new(
                    ErrorCode::Cease,
                    CeaseSubcode::HardReset,
                );
                self.fsm_event(instance, fsm::Event::Stop(Some(msg)));
            }
            ClearType::Soft => {
                // Re-send the current Adj-RIB-Out to this neighbor.
                self.resend_adj_rib_out::<Ipv4Unicast>(instance);
                self.resend_adj_rib_out::<Ipv6Unicast>(instance);
                let msg_list = self.update_queues.build_updates();
                if !msg_list.is_empty() {
                    self.message_list_send(msg_list);
                }
            }
            ClearType::SoftInbound => {
                // Request the Adj-RIB-In for this neighbor to be re-sent.
                for (afi, safi) in self
                    .capabilities_nego
                    .iter()
                    .filter_map(|cap| {
                        if let NegotiatedCapability::MultiProtocol {
                            afi,
                            safi,
                        } = cap
                        {
                            Some((afi.to_u16().unwrap(), safi.to_u8().unwrap()))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                {
                    let msg = RouteRefreshMsg { afi, safi };
                    self.message_send(Message::RouteRefresh(msg));
                }
            }
        }
    }

    // Determines whether the given route is eligible for distribution.
    pub(crate) fn distribute_filter(&self, route: &Route) -> bool {
        // Suppress advertisements to peers if their AS number is present
        // in the AS path of the route, unless overridden by configuration.
        if !self.config.as_path_options.disable_peer_as_filter
            && route.attrs.base.value.as_path.contains(self.config.peer_as)
        {
            return false;
        }

        // RFC 4271 - Section 9.2:
        // "When a BGP speaker receives an UPDATE message from an internal
        // peer, the receiving BGP speaker SHALL NOT re-distribute the
        // routing information contained in that UPDATE message to other
        // internal peers".
        if route.route_type == RouteType::Internal
            && let RouteOrigin::Neighbor { remote_addr, .. } = &route.origin
            && *remote_addr == self.remote_addr
        {
            return false;
        }

        // Handle well-known communities.
        if let Some(comm) = &route.attrs.comm {
            for comm in comm
                .value
                .iter()
                .filter_map(|comm| WellKnownCommunities::from_u32(comm.0))
            {
                // Do not advertise to any other peer.
                if comm == WellKnownCommunities::NoAdvertise {
                    return false;
                }

                // Do not advertise to external peers.
                if self.peer_type == PeerType::External
                    && (comm == WellKnownCommunities::NoExport
                        || comm == WellKnownCommunities::NoExportSubconfed)
                {
                    return false;
                }
            }
        }

        true
    }

    // Check if the given address-family is enabled for this session.
    pub(crate) fn is_af_enabled(&self, afi: Afi, safi: Safi) -> bool {
        // Check if the corresponding multi-protocol capability has been
        // negotiated.
        let cap = NegotiatedCapability::MultiProtocol { afi, safi };
        if self.capabilities_nego.contains(&cap) {
            return true;
        }

        // If the peer doesn't support BGP capabilities, the IPv4 unicast
        // address-family is enabled by default.
        if self.capabilities_nego.is_empty()
            && afi == Afi::Ipv4
            && safi == Safi::Unicast
        {
            return true;
        }

        false
    }
}

// ===== impl MessageStatistics =====

impl MessageStatistics {
    pub(crate) fn update(&mut self, msg: &Message) {
        self.total.fetch_add(1, atomic::Ordering::Relaxed);
        match msg {
            Message::Update(_) => {
                self.updates += 1;
            }
            Message::Notification(_) => {
                self.notifications += 1;
            }
            Message::RouteRefresh(_) => {
                self.route_refreshes += 1;
            }
            _ => {}
        }
    }
}

// ===== impl NeighborUpdateQueues =====

impl NeighborUpdateQueues {
    pub(crate) fn build_updates(&mut self) -> Vec<Message> {
        [
            self.ipv4_unicast.build_updates(),
            self.ipv6_unicast.build_updates(),
        ]
        .concat()
    }
}

// ===== impl NeighborUpdateQueue =====

impl<A> NeighborUpdateQueue<A>
where
    A: AddressFamily,
{
    fn build_updates(&mut self) -> Vec<Message> {
        A::build_updates(self)
    }
}

impl<A> Default for NeighborUpdateQueue<A>
where
    A: AddressFamily,
{
    fn default() -> NeighborUpdateQueue<A> {
        NeighborUpdateQueue {
            reach: Default::default(),
            unreach: Default::default(),
        }
    }
}
