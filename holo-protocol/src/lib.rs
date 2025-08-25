//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod event_recorder;
#[cfg(feature = "testing")]
pub mod test;

use std::sync::{Arc, Mutex};

use derive_new::new;
use holo_northbound as northbound;
use holo_northbound::{
    NbDaemonReceiver, NbDaemonSender, NbProviderSender, process_northbound_msg,
};
use holo_utils::Database;
use holo_utils::bier::BierCfg;
use holo_utils::ibus::{IbusChannelsTx, IbusMsg, IbusReceiver, IbusSender};
use holo_utils::keychain::Keychains;
use holo_utils::mpls::LabelManager;
use holo_utils::policy::{MatchSets, Policies};
use holo_utils::protocol::Protocol;
use holo_utils::sr::SrCfg;
use holo_utils::task::Task;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::event_recorder::EventRecorder;
#[cfg(feature = "testing")]
use crate::test::{OutputChannelsRx, process_test_msg, stub::TestMsg};

/// A trait for protocol instances.
pub trait ProtocolInstance
where
    Self: Send
        + northbound::configuration::Provider
        + northbound::rpc::Provider
        + northbound::state::Provider,
{
    /// Protocol type.
    const PROTOCOL: Protocol;

    type ProtocolInputMsg: Send + std::fmt::Debug + Serialize + DeserializeOwned;
    type ProtocolOutputMsg: Send + std::fmt::Debug + Serialize;
    type ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx: MessageReceiver<Self::ProtocolInputMsg>;

    /// Create protocol instance.
    fn new(
        name: String,
        shared: InstanceShared,
        channels_tx: InstanceChannelsTx<Self>,
    ) -> Self;

    /// Optional protocol instance initialization routine.
    fn init(&mut self) {}

    /// Optional protocol instance shutdown routine.
    fn shutdown(self) {}

    /// Process ibus message.
    fn process_ibus_msg(&mut self, msg: IbusMsg);

    /// Process protocol message.
    fn process_protocol_msg(&mut self, msg: Self::ProtocolInputMsg);

    /// Create channels for all protocol input events.
    fn protocol_input_channels()
    -> (Self::ProtocolInputChannelsTx, Self::ProtocolInputChannelsRx);

    /// Return test directory used for unit testing.
    #[cfg(feature = "testing")]
    fn test_dir() -> String;
}

/// Shared data among all protocol instances.
#[derive(Clone, Default, new)]
pub struct InstanceShared {
    // Non-volatile storage.
    pub db: Option<Database>,
    // Hostname.
    pub hostname: Option<String>,
    // MPLS Label Manager.
    pub label_manager: Arc<Mutex<LabelManager>>,
    // List of key-chains.
    pub keychains: Keychains,
    // List of policy match sets.
    pub policy_match_sets: Arc<MatchSets>,
    // List of routing policies.
    pub policies: Policies,
    // Global Segment Routing configuration.
    pub sr_config: Arc<SrCfg>,
    // Global BIER configuration.
    pub bier_config: Arc<BierCfg>,
    // Event recorder configuration.
    pub event_recorder_config: Option<event_recorder::Config>,
}

/// Instance input message.
#[derive(Debug, Deserialize, Serialize)]
pub enum InstanceMsg<P: ProtocolInstance> {
    Northbound(Option<northbound::api::daemon::Request>),
    Ibus(IbusMsg),
    Protocol(P::ProtocolInputMsg),
    #[serde(skip)]
    #[cfg(feature = "testing")]
    Test(TestMsg<P::ProtocolOutputMsg>),
}

/// Instance output channels.
#[derive(Debug, new)]
pub struct InstanceChannelsTx<P: ProtocolInstance> {
    pub nb: NbProviderSender,
    pub ibus: IbusChannelsTx,
    pub protocol_input: P::ProtocolInputChannelsTx,
    #[cfg(feature = "testing")]
    pub protocol_output: Sender<P::ProtocolOutputMsg>,
}

/// Instance input channels.
#[derive(Debug, new)]
pub struct InstanceChannelsRx<P: ProtocolInstance> {
    pub nb: NbDaemonReceiver,
    pub ibus: IbusReceiver,
    pub protocol_input: P::ProtocolInputChannelsRx,
    #[cfg(feature = "testing")]
    pub test: Receiver<TestMsg<P::ProtocolOutputMsg>>,
}

#[derive(Debug)]
pub struct InstanceAggChannels<P: ProtocolInstance> {
    pub tx: Sender<InstanceMsg<P>>,
    pub rx: Receiver<InstanceMsg<P>>,
}

pub trait MessageReceiver<T: Send>
where
    Self: Send,
{
    fn recv(&mut self) -> impl Future<Output = Option<T>> + Send;
}

// ===== impl InstanceShared =====

impl std::fmt::Debug for InstanceShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceShared")
            .field("label_manager", &self.label_manager)
            .field("keychains", &self.keychains)
            .field("policy_match_sets", &self.policy_match_sets)
            .field("policies", &self.policies)
            .field("sr_config", &self.sr_config)
            .field("bier_config", &self.bier_config)
            .finish()
    }
}

// ===== impl InstanceAggChannels =====

impl<P> Default for InstanceAggChannels<P>
where
    P: ProtocolInstance,
{
    fn default() -> Self {
        let (tx, rx) = mpsc::channel(4);
        InstanceAggChannels { tx, rx }
    }
}

// ===== helper functions =====

// Protocol instance input-event aggregator.
fn event_aggregator<P>(
    mut instance_channels_rx: InstanceChannelsRx<P>,
    agg_tx: Sender<InstanceMsg<P>>,
) -> Task<()>
where
    P: ProtocolInstance,
{
    #[cfg(not(feature = "testing"))]
    {
        Task::spawn(async move {
            loop {
                let msg = tokio::select! {
                    msg = instance_channels_rx.nb.recv() => {
                        InstanceMsg::Northbound(msg)
                    }
                    Some(msg) = instance_channels_rx.ibus.recv() => {
                        InstanceMsg::Ibus(msg)
                    }
                    Some(msg) = instance_channels_rx.protocol_input.recv() => {
                        InstanceMsg::Protocol(msg)
                    }
                };

                let _ = agg_tx.send(msg).await;
            }
        })
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move {
            let mut ignore_protocol_input = true;
            loop {
                let msg = tokio::select! {
                    biased;
                    msg = instance_channels_rx.nb.recv() => {
                        InstanceMsg::Northbound(msg)
                    }
                    Some(msg) = instance_channels_rx.protocol_input.recv() => {
                        if ignore_protocol_input {
                            continue;
                        }
                        InstanceMsg::Protocol(msg)
                    }
                    Some(msg) = instance_channels_rx.test.recv() => {
                        // Stop ignoring internal protocol events as soon as the
                        // unit test starts (after loading the topology).
                        ignore_protocol_input = false;
                        InstanceMsg::Test(msg)
                    }
                };

                let _ = agg_tx.send(msg).await;
            }
        })
    }
}

async fn event_loop<P>(
    instance: &mut P,
    instance_channels_rx: InstanceChannelsRx<P>,
    mut agg_channels: InstanceAggChannels<P>,
    #[cfg(feature = "testing")] mut output_channels_rx: Option<
        OutputChannelsRx<P::ProtocolOutputMsg>,
    >,
    mut event_recorder: Option<EventRecorder>,
) where
    P: ProtocolInstance,
{
    let mut resources = vec![];

    // Spawn event aggregator task.
    let _event_aggregator =
        event_aggregator(instance_channels_rx, agg_channels.tx);

    // Main event loop.
    loop {
        // Receive event message.
        let msg = agg_channels.rx.recv().await.unwrap();

        // Record event message.
        if let Some(event_recorder) = &mut event_recorder {
            event_recorder.record(&msg);
        }

        // Process event message.
        match msg {
            InstanceMsg::Northbound(Some(msg)) => {
                process_northbound_msg(instance, &mut resources, msg);
            }
            InstanceMsg::Northbound(None) => {
                // Instance was unconfigured.
                return;
            }
            InstanceMsg::Ibus(msg) => {
                instance.process_ibus_msg(msg);
            }
            InstanceMsg::Protocol(msg) => {
                instance.process_protocol_msg(msg);
            }
            #[cfg(feature = "testing")]
            InstanceMsg::Test(msg) => {
                process_test_msg::<P>(msg, &mut output_channels_rx);
            }
        }
    }
}

#[cfg_attr(not(feature = "testing"), allow(unused_mut))]
async fn run<P>(
    name: String,
    nb_tx: NbProviderSender,
    nb_rx: NbDaemonReceiver,
    ibus_tx: IbusChannelsTx,
    ibus_instance_rx: IbusReceiver,
    agg_channels: InstanceAggChannels<P>,
    #[cfg(feature = "testing")] test_rx: Receiver<
        TestMsg<P::ProtocolOutputMsg>,
    >,
    shared: InstanceShared,
) where
    P: ProtocolInstance,
{
    // Start protocol channels.
    let (proto_input_tx, proto_input_rx) = P::protocol_input_channels();
    #[cfg(feature = "testing")]
    let (proto_output_tx, proto_output_rx) = mpsc::channel(4);

    // Get output channels.
    #[cfg(feature = "testing")]
    let output_channels_rx = OutputChannelsRx::new(proto_output_rx);

    // Create instance Tx/Rx channels.
    let instance_channels_tx = InstanceChannelsTx::new(
        nb_tx,
        ibus_tx.clone(),
        proto_input_tx,
        #[cfg(feature = "testing")]
        proto_output_tx,
    );
    let instance_channels_rx = InstanceChannelsRx::new(
        nb_rx,
        ibus_instance_rx,
        proto_input_rx,
        #[cfg(feature = "testing")]
        test_rx,
    );

    // Get event recorder.
    let event_record = shared
        .event_recorder_config
        .clone()
        .filter(|config| config.enabled)
        .and_then(|config| EventRecorder::new(P::PROTOCOL, &name, config));

    // Create protocol instance.
    let mut instance = P::new(name, shared, instance_channels_tx);
    instance.init();

    // Run event loop.
    event_loop(
        &mut instance,
        instance_channels_rx,
        agg_channels,
        #[cfg(feature = "testing")]
        Some(output_channels_rx),
        event_record,
    )
    .await;

    // Cancel ibus subscriptions.
    ibus_tx.disconnect();

    // Ensure instance is shut down before exiting.
    instance.shutdown();
}

// ===== global functions =====

pub fn spawn_protocol_task<P>(
    name: String,
    nb_provider_tx: &NbProviderSender,
    ibus_tx: &IbusChannelsTx,
    ibus_instance_tx: IbusSender,
    ibus_instance_rx: IbusReceiver,
    agg_channels: InstanceAggChannels<P>,
    #[cfg(feature = "testing")] test_rx: Receiver<
        TestMsg<P::ProtocolOutputMsg>,
    >,
    shared: InstanceShared,
) -> NbDaemonSender
where
    P: ProtocolInstance,
{
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);
    let nb_provider_tx = nb_provider_tx.clone();
    let ibus_tx = IbusChannelsTx::with_subscriber(ibus_tx, ibus_instance_tx);
    let fut = async move {
        let span = P::debug_span(&name);
        let _span_guard = span.enter();
        run::<P>(
            name,
            nb_provider_tx,
            nb_daemon_rx,
            ibus_tx,
            ibus_instance_rx,
            agg_channels,
            #[cfg(feature = "testing")]
            test_rx,
            shared,
        )
        .await;
    };

    // In testing, protocol instances are spawned as async tasks so they run
    // under Tokio's single-threaded cooperative scheduler. This ensures
    // deterministic ordering of message send/receive operations.
    //
    // In production, processing individual events in the main protocol task
    // may take longer than is appropriate for async tasks. To avoid starving
    // other tasks on the cooperative scheduler, protocol instances are spawned
    // as blocking tasks backed by OS threads, relying on the OS for preemptive
    // scheduling.
    #[cfg(not(feature = "testing"))]
    tokio::task::spawn_blocking(|| {
        tokio::runtime::Handle::current().block_on(fut)
    });
    #[cfg(feature = "testing")]
    tokio::spawn(fut);

    nb_daemon_tx
}
