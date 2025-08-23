//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;
use std::sync::Arc;

use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::bgp::AfiSafi;
use holo_utils::ibus::IbusMsg;
use holo_utils::ip::AddressFamily;
use holo_utils::policy::PolicyType;
use holo_utils::protocol::Protocol;
use holo_utils::socket::TcpListener;
use holo_utils::task::{Task, TimeoutTask};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};

use crate::af::{Ipv4Unicast, Ipv6Unicast};
use crate::debug::{Debug, InstanceInactiveReason};
use crate::error::{Error, IoError};
use crate::neighbor::{Neighbors, fsm};
use crate::northbound::configuration::InstanceCfg;
use crate::packet::consts::{CeaseSubcode, ErrorCode};
use crate::packet::message::NotificationMsg;
use crate::rib::Rib;
use crate::tasks::messages::input::{
    NbrRxMsg, NbrTimerMsg, PolicyResultMsg, TcpAcceptMsg, TcpConnectMsg,
};
use crate::tasks::messages::output::PolicyApplyMsg;
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, ibus, network, tasks};

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
    // Instance neighbors.
    pub neighbors: Neighbors,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug, Default)]
pub struct InstanceSys {
    // System Router ID.
    pub router_id: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub struct InstanceState {
    // Instance Router ID.
    pub router_id: Ipv4Addr,
    // TCP listening sockets.
    pub listening_sockets: Vec<TcpListenerTask>,
    // Policy tasks.
    pub policy_apply_tasks: PolicyApplyTasks,
    // Timeout to trigger the decision process.
    pub decision_process_task: Option<TimeoutTask>,
    // BGP RIB.
    pub rib: Rib,
}

#[derive(Debug)]
pub struct TcpListenerTask {
    pub af: AddressFamily,
    pub socket: Arc<TcpListener>,
    _task: Task<()>,
}

#[derive(Debug)]
pub struct PolicyApplyTasks {
    pub tx: crossbeam_channel::Sender<PolicyApplyMsg>,
    _tasks: Vec<Task<()>>,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // TCP accept event.
    pub tcp_accept: Sender<TcpAcceptMsg>,
    // TCP connect event.
    pub tcp_connect: Sender<TcpConnectMsg>,
    // TCP neighbor message.
    pub nbr_msg_rx: Sender<NbrRxMsg>,
    // Neighbor timeout event.
    pub nbr_timer: Sender<NbrTimerMsg>,
    // Policy result message.
    pub policy_result: UnboundedSender<PolicyResultMsg>,
    // Decision Process triggering message.
    pub decision_process: Sender<()>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // TCP accept event.
    pub tcp_accept: Receiver<TcpAcceptMsg>,
    // TCP connect event.
    pub tcp_connect: Receiver<TcpConnectMsg>,
    // TCP neighbor message.
    pub nbr_msg_rx: Receiver<NbrRxMsg>,
    // Neighbor timeout event.
    pub nbr_timer: Receiver<NbrTimerMsg>,
    // Policy result message.
    pub policy_result: UnboundedReceiver<PolicyResultMsg>,
    // Decision Process triggering message.
    pub decision_process: Receiver<()>,
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
    //
    // Note: Router ID updates are ignored if the instance is already active.
    pub(crate) fn update(&mut self) {
        let router_id = self.get_router_id();

        match self.is_ready(router_id) {
            Ok(()) if !self.is_active() => {
                self.start(router_id.unwrap());
            }
            Err(reason) if self.is_active() => {
                self.stop(reason);
            }
            _ => (),
        }
    }

    // Starts the BGP instance.
    fn start(&mut self, router_id: Ipv4Addr) {
        Debug::InstanceStart.log();

        match InstanceState::new(router_id, &self.tx) {
            Ok(state) => {
                // Store instance initial state.
                self.state = Some(state);
            }
            Err(error) => {
                Error::InstanceStartError(Box::new(error)).log();
            }
        }
    }

    // Stops the BGP instance.
    fn stop(&mut self, reason: InstanceInactiveReason) {
        let Some((mut instance, neighbors)) = self.as_up() else {
            return;
        };

        Debug::InstanceStop(reason).log();

        // Stop neighbors.
        let error_code = ErrorCode::Cease;
        let error_subcode = CeaseSubcode::AdministrativeShutdown;
        for nbr in neighbors.values_mut() {
            let msg = NotificationMsg::new(error_code, error_subcode);
            nbr.fsm_event(&mut instance, fsm::Event::Stop(Some(msg)));
        }

        // Clear instance state.
        self.state = None;
    }

    // Returns whether the BGP instance is operational.
    fn is_active(&self) -> bool {
        self.state.is_some()
    }

    // Returns whether the instance is ready for BGP operation.
    fn is_ready(
        &self,
        router_id: Option<Ipv4Addr>,
    ) -> Result<(), InstanceInactiveReason> {
        if router_id.is_none() {
            return Err(InstanceInactiveReason::MissingRouterId);
        }

        Ok(())
    }

    // Retrieves the Router ID from configuration or system information.
    // Prioritizes the configured Router ID, using the system's Router ID as a
    // fallback.
    fn get_router_id(&self) -> Option<Ipv4Addr> {
        self.config.identifier.or(self.system.router_id)
    }

    // Returns a view struct for the instance if it is operational.
    pub(crate) fn as_up(
        &mut self,
    ) -> Option<(InstanceUpView<'_>, &mut Neighbors)> {
        if let Some(state) = &mut self.state {
            let instance = InstanceUpView {
                name: &self.name,
                system: &self.system,
                config: &self.config,
                state,
                tx: &self.tx,
                shared: &self.shared,
            };
            Some((instance, &mut self.neighbors))
        } else {
            None
        }
    }
}

impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::BGP;

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
            neighbors: Default::default(),
            tx,
            shared,
        }
    }

    fn init(&mut self) {
        // Request information about the system Router ID.
        ibus::tx::router_id_sub(&self.tx.ibus);
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
        if let Some((mut instance, neighbors)) = self.as_up()
            && let Err(error) =
                process_protocol_msg(&mut instance, neighbors, msg)
        {
            error.log();
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (tcp_acceptp, tcp_acceptc) = mpsc::channel(4);
        let (tcp_connectp, tcp_connectc) = mpsc::channel(4);
        let (nbr_msg_rxp, nbr_msg_rxc) = mpsc::channel(4);
        let (nbr_timerp, nbr_timerc) = mpsc::channel(4);
        let (policy_resultp, policy_resultc) = mpsc::unbounded_channel();
        let (decision_processp, decision_processc) = mpsc::channel(1);

        let tx = ProtocolInputChannelsTx {
            tcp_accept: tcp_acceptp,
            tcp_connect: tcp_connectp,
            nbr_msg_rx: nbr_msg_rxp,
            nbr_timer: nbr_timerp,
            policy_result: policy_resultp,
            decision_process: decision_processp,
        };
        let rx = ProtocolInputChannelsRx {
            tcp_accept: tcp_acceptc,
            tcp_connect: tcp_connectc,
            nbr_msg_rx: nbr_msg_rxc,
            nbr_timer: nbr_timerc,
            policy_result: policy_resultc,
            decision_process: decision_processc,
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
    fn new(
        router_id: Ipv4Addr,
        instance_tx: &InstanceChannelsTx<Instance>,
    ) -> Result<InstanceState, Error> {
        let mut listening_sockets = Vec::new();

        // Create TCP listeners.
        for af in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let socket = network::listen_socket(af)
                .map(Arc::new)
                .map_err(IoError::TcpSocketError)?;
            let task = tasks::tcp_listener(
                &socket,
                &instance_tx.protocol_input.tcp_accept,
            );
            listening_sockets.push(TcpListenerTask {
                af,
                socket,
                _task: task,
            });
        }

        // Create routing policy tasks, spawning as many tasks as the number of
        // available CPUs for efficient use of all cores. In testing mode, spawn
        // a single task.
        let (policy_tx, policy_rx) = crossbeam_channel::unbounded();
        let num_cpus = {
            #[cfg(not(feature = "testing"))]
            {
                std::thread::available_parallelism().unwrap().get()
            }
            #[cfg(feature = "testing")]
            {
                1
            }
        };
        let tasks = (0..num_cpus)
            .map(|_| {
                tasks::policy_apply(
                    policy_rx.clone(),
                    &instance_tx.protocol_input.policy_result,
                    #[cfg(feature = "testing")]
                    &instance_tx.protocol_output,
                )
            })
            .collect();
        let policy_apply_tasks = PolicyApplyTasks {
            tx: policy_tx,
            _tasks: tasks,
        };

        Ok(InstanceState {
            router_id,
            listening_sockets,
            policy_apply_tasks,
            decision_process_task: None,
            rib: Default::default(),
        })
    }

    // Schedules the BGP Decision Process to happen 100 milliseconds
    // from now, renewing the timeout if called before expiry.
    pub(crate) fn schedule_decision_process(
        &mut self,
        instance_tx: &InstanceChannelsTx<Instance>,
    ) {
        let task = tasks::schedule_decision_process(
            &instance_tx.protocol_input.decision_process,
        );
        self.decision_process_task = Some(task);
    }
}

// ===== impl ProtocolInputChannelsTx =====

impl ProtocolInputChannelsTx {
    // Triggers the BGP Decision Process.
    pub(crate) fn trigger_decision_process(&self) {
        let _ = self.decision_process.try_send(());
    }
}

// ===== impl ProtocolInputChannelsRx =====

impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            biased;
            msg = self.tcp_accept.recv() => {
                msg.map(ProtocolInputMsg::TcpAccept)
            }
            msg = self.tcp_connect.recv() => {
                msg.map(ProtocolInputMsg::TcpConnect)
            }
            msg = self.nbr_msg_rx.recv() => {
                msg.map(ProtocolInputMsg::NbrRx)
            }
            msg = self.nbr_timer.recv() => {
                msg.map(ProtocolInputMsg::NbrTimer)
            }
            msg = self.policy_result.recv() => {
                msg.map(ProtocolInputMsg::PolicyResult)
            }
            msg = self.decision_process.recv() => {
                msg.map(ProtocolInputMsg::TriggerDecisionProcess)
            }
        }
    }
}

// ===== impl PolicyApplyTasks, =====

impl PolicyApplyTasks {
    pub(crate) fn enqueue(&self, msg: PolicyApplyMsg) {
        let _ = self.tx.send(msg);
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
        IbusMsg::NexthopUpd { addr, metric } => {
            // Nexthop tracking update notification.
            ibus::rx::process_nht_update(instance, addr, metric);
        }
        IbusMsg::RouterIdUpdate(router_id) => {
            // Router ID update notification.
            ibus::rx::process_router_id_update(instance, router_id);
        }
        IbusMsg::PolicyMatchSetsUpd(match_sets) => {
            // Update the local copy of the policy match sets.
            instance.shared.policy_match_sets = match_sets;
        }
        IbusMsg::PolicyUpd(policy) => {
            // Update the local copy of the policy definition.
            instance
                .shared
                .policies
                .insert(policy.name.clone(), policy.clone());
        }
        IbusMsg::PolicyDel(policy_name) => {
            // Remove the local copy of the policy definition.
            instance.shared.policies.remove(&policy_name);
        }
        IbusMsg::RouteRedistributeAdd(msg) => {
            // Route redistribute update notification.
            ibus::rx::process_route_add(instance, msg);
        }
        IbusMsg::RouteRedistributeDel(msg) => {
            // Route redistribute delete notification.
            ibus::rx::process_route_del(instance, msg);
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    msg: ProtocolInputMsg,
) -> Result<(), Error> {
    match msg {
        // Accepted TCP connection request.
        ProtocolInputMsg::TcpAccept(mut msg) => {
            events::process_tcp_accept(
                instance,
                neighbors,
                msg.stream(),
                msg.conn_info,
            )?;
        }
        // Established TCP connection.
        ProtocolInputMsg::TcpConnect(mut msg) => {
            events::process_tcp_connect(
                instance,
                neighbors,
                msg.stream(),
                msg.conn_info,
            )?;
        }
        // Received message from neighbor.
        ProtocolInputMsg::NbrRx(msg) => {
            events::process_nbr_msg(
                instance,
                neighbors,
                msg.nbr_addr,
                msg.msg,
            )?;
        }
        // Neighbor's timeout has expired.
        ProtocolInputMsg::NbrTimer(msg) => {
            events::process_nbr_timer(
                instance,
                neighbors,
                msg.nbr_addr,
                msg.timer,
            )?;
        }
        // Policy result.
        ProtocolInputMsg::PolicyResult(msg) => match msg {
            PolicyResultMsg::Neighbor {
                policy_type,
                afi_safi,
                nbr_addr,
                routes,
            } => match (policy_type, afi_safi) {
                (PolicyType::Import, AfiSafi::Ipv4Unicast) => {
                    events::process_nbr_policy_import::<Ipv4Unicast>(
                        instance, neighbors, nbr_addr, routes,
                    )?
                }
                (PolicyType::Import, AfiSafi::Ipv6Unicast) => {
                    events::process_nbr_policy_import::<Ipv6Unicast>(
                        instance, neighbors, nbr_addr, routes,
                    )?
                }
                (PolicyType::Export, AfiSafi::Ipv4Unicast) => {
                    events::process_nbr_policy_export::<Ipv4Unicast>(
                        instance, neighbors, nbr_addr, routes,
                    )?
                }
                (PolicyType::Export, AfiSafi::Ipv6Unicast) => {
                    events::process_nbr_policy_export::<Ipv6Unicast>(
                        instance, neighbors, nbr_addr, routes,
                    )?
                }
            },
            PolicyResultMsg::Redistribute {
                afi_safi,
                prefix,
                result,
            } => match afi_safi {
                AfiSafi::Ipv4Unicast => {
                    events::process_redistribute_policy_import::<Ipv4Unicast>(
                        instance, prefix, result,
                    )?
                }
                AfiSafi::Ipv6Unicast => {
                    events::process_redistribute_policy_import::<Ipv6Unicast>(
                        instance, prefix, result,
                    )?
                }
            },
        },
        // Decision process.
        ProtocolInputMsg::TriggerDecisionProcess(_) => {
            events::decision_process::<Ipv4Unicast>(instance, neighbors)?;
            events::decision_process::<Ipv6Unicast>(instance, neighbors)?;
        }
    }

    Ok(())
}
