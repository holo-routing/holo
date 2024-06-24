//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod collector;
mod northbound;

use std::collections::BTreeMap;
use std::sync::LazyLock as Lazy;

use derive_new::new;
use holo_utils::{Responder, Sender};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug_span, info};

use crate::test::stub::collector::MessageCollector;
use crate::test::stub::northbound::NorthboundStub;
use crate::test::{setup, OutputChannelsRx};
use crate::{
    spawn_protocol_task, InstanceAggChannels, InstanceMsg, InstanceShared,
    ProtocolInstance,
};

// Environment variable that controls if the test data needs to be updated or
// verified.
pub(crate) static UPDATE_OUTPUTS: Lazy<bool> =
    Lazy::new(|| std::env::var("HOLO_UPDATE_TEST_OUTPUTS").is_ok());

// Stub used to communicate with protocol instance under test.
#[derive(new)]
pub struct Stub<P: ProtocolInstance> {
    nb: NorthboundStub,
    messages: MessageCollector,
    tx: Sender<InstanceMsg<P>>,
    test_tx: Sender<TestMsg<P::ProtocolOutputMsg>>,
}

#[derive(Debug)]
pub enum TestMsg<P> {
    Synchronize(SynchronizeMsg),
    GetOutputChannelsRx(GetOutputChannelsRxMsg<P>),
}

#[derive(Debug)]
pub struct SynchronizeMsg {
    pub responder: Option<Responder<()>>,
}

#[derive(Debug)]
pub struct GetOutputChannelsRxMsg<P> {
    pub responder: Option<Responder<OutputChannelsRx<P>>>,
}

#[derive(Debug)]
enum TestOp {
    Input(TestOpInput),
    Output(TestOpOutput),
}

#[derive(Debug)]
enum TestOpInput {
    NorthboundConfigChange,
    NorthboundConfigReplace,
    NorthboundRpc,
    Ibus,
    Protocol,
}

#[derive(Debug)]
enum TestOpOutput {
    NorthboundNotif,
    NorthboundState,
    Ibus,
    Protocol,
}

#[derive(Debug, Default)]
struct TestStep {
    input: Option<(TestOpInput, String)>,
    output_nb_notif: String,
    output_nb_state: Option<String>,
    output_ibus: String,
    output_protocol: String,
}

// ===== impl Stub =====

impl<P> Stub<P>
where
    P: ProtocolInstance,
{
    // Sends an instance message to the test instance.
    pub async fn send(&self, msg: InstanceMsg<P>) {
        self.tx.send(msg).await.unwrap();
    }

    // Synchronizes the protocol instance to ensure all previously sent instance
    // messages were already received and processed.
    async fn sync(&self) {
        let (responder_tx, responder_rx) = oneshot::channel();
        let msg = TestMsg::Synchronize(SynchronizeMsg {
            responder: Some(responder_tx),
        });
        self.test_tx.send(msg).await.unwrap();
        responder_rx
            .await
            .expect("failed to receive Synchronize response");
    }

    fn assert_nb_notifications(
        &self,
        expected: &str,
        path: &impl AsRef<std::path::Path>,
    ) {
        let actual = self.messages.nb_notifications().join("\n");
        self.assert_output(expected, &actual, path);
    }

    fn assert_ibus_output(
        &self,
        expected: &str,
        path: &impl AsRef<std::path::Path>,
    ) {
        let actual = self.messages.ibus_output().join("\n");
        self.assert_output(expected, &actual, path);
    }

    fn assert_protocol_output(
        &self,
        expected: &str,
        path: &impl AsRef<std::path::Path>,
    ) {
        let actual = self.messages.protocol_output().join("\n");
        self.assert_output(expected, &actual, path);
    }

    fn assert_output(
        &self,
        expected: &str,
        actual: &str,
        path: &impl AsRef<std::path::Path>,
    ) {
        // Update or verify output.
        if *UPDATE_OUTPUTS {
            if actual.is_empty() {
                let _ = std::fs::remove_file(path);
            } else {
                std::fs::write(path, actual).unwrap();
            }
        } else {
            assert_eq!(expected, actual);
        }
    }

    // Closes the test instance.
    pub async fn close(self) {
        // Close northbound channel.
        std::mem::drop(self.nb);
        // Wait for the test instance to exit.
        let _ = self.messages.rx_task.await;
    }
}

// ===== impl TestOp =====

impl TestOp {
    fn from_filename(filename: &str) -> Result<Self, ()> {
        match filename {
            "input-northbound-config-change.json" => {
                Ok(TestOp::Input(TestOpInput::NorthboundConfigChange))
            }
            "input-northbound-config-replace.json" => {
                Ok(TestOp::Input(TestOpInput::NorthboundConfigReplace))
            }
            "input-northbound-rpc.json" => {
                Ok(TestOp::Input(TestOpInput::NorthboundRpc))
            }
            "input-ibus.jsonl" => Ok(TestOp::Input(TestOpInput::Ibus)),
            "input-protocol.jsonl" => Ok(TestOp::Input(TestOpInput::Protocol)),
            "output-northbound-notif.jsonl" => {
                Ok(TestOp::Output(TestOpOutput::NorthboundNotif))
            }
            "output-northbound-state.json" => {
                Ok(TestOp::Output(TestOpOutput::NorthboundState))
            }
            "output-ibus.jsonl" => Ok(TestOp::Output(TestOpOutput::Ibus)),
            "output-protocol.jsonl" => {
                Ok(TestOp::Output(TestOpOutput::Protocol))
            }
            _ => Err(()),
        }
    }
}

// ===== impl TestOpOutput =====

impl TestOpOutput {
    fn to_filename(&self) -> &'static str {
        match self {
            TestOpOutput::NorthboundNotif => "output-northbound-notif.jsonl",
            TestOpOutput::NorthboundState => "output-northbound-state.json",
            TestOpOutput::Ibus => "output-ibus.jsonl",
            TestOpOutput::Protocol => "output-protocol.jsonl",
        }
    }
}

// ===== helper functions =====

fn topology_dir<P>(topology: &str, router: &str) -> String
where
    P: ProtocolInstance,
{
    format!("{}/topologies/{}/{}", P::test_dir(), topology, router)
}

fn output_path(dir: &str, step: usize, op: TestOpOutput) -> String {
    format!("{}/{:0width$}-{}", dir, step, op.to_filename(), width = 2)
}

// Loads instance snapshot of the provided topology and router.
async fn load_snapshot<P>(topology: &str, router: &str) -> Stub<P>
where
    P: ProtocolInstance,
{
    // Get topology base directory.
    let topo_dir = topology_dir::<P>(topology, router);

    // Spawn protocol instance.
    let mut stub = start_test_instance::<P>("test").await;

    // Push configuration through stub northbound.
    let path = format!("{}/{}", topo_dir, "config.json");
    let config = std::fs::read_to_string(&path)
        .expect("unable to read configuration file");
    stub.nb.commit_replace(&config).await;

    // Push events.
    let path = format!("{}/{}", topo_dir, "events.jsonl");
    let events =
        std::fs::read_to_string(&path).expect("unable to read events file");
    for msg in events.lines() {
        let msg = serde_json::from_str(msg)
            .expect("failed to parse instance message");
        stub.send(msg).await;
    }

    stub.sync().await;

    stub
}

// ===== global functions =====

// Starts test instance.
pub async fn start_test_instance<P>(name: &str) -> Stub<P>
where
    P: ProtocolInstance,
{
    // Spawn protocol task.
    let (nb_provider_tx, nb_provider_rx) = mpsc::unbounded_channel();
    let (ibus_tx, ibus_rx) = broadcast::channel(1024);
    let channels = InstanceAggChannels::default();
    let instance_tx = channels.tx.clone();
    let (test_tx, test_rx) = mpsc::channel(4);
    let nb_daemon_tx = spawn_protocol_task::<P>(
        name.to_owned(),
        &nb_provider_tx,
        &ibus_tx,
        channels,
        test_rx,
        InstanceShared::default(),
    );

    // Get northbound stub.
    let nb_stub = NorthboundStub::new(nb_daemon_tx);

    // Get output channels.
    let (responder_tx, responder_rx) = oneshot::channel();
    instance_tx
        .send(InstanceMsg::Test(TestMsg::GetOutputChannelsRx(
            GetOutputChannelsRxMsg {
                responder: Some(responder_tx),
            },
        )))
        .await
        .unwrap();
    let output_channels_rx = responder_rx
        .await
        .expect("failed to receive GetOutputChannelsRx response");

    // Create message collector.
    let messages = MessageCollector::new::<P>(
        nb_provider_rx,
        ibus_rx,
        output_channels_rx.protocol_txc,
    );

    Stub::new(nb_stub, messages, instance_tx, test_tx)
}

// Starts test instance based on a preset state and runs all tests specified in
// the corresponding test directory.
pub async fn run_test<P>(test: &str, topology: &str, router: &str)
where
    P: ProtocolInstance,
{
    setup();

    // Load instance snapshot.
    let span = debug_span!("test", name = %test, %router);
    let _span_guard = span.enter();
    info!("loading instance snapshot...");
    let mut stub: Stub<P> = load_snapshot(topology, router).await;
    stub.nb.init_state_cache(P::STATE_PATH).await;

    // Read files from the test directory.
    info!("reading test files...");
    let mut test_steps: BTreeMap<usize, TestStep> = BTreeMap::new();
    let test_dir = format!("{}/{}", P::test_dir(), test);
    for entry in std::fs::read_dir(test_dir.clone())
        .expect("failed to read test directory")
        .map(|entry| entry.unwrap())
    {
        let filename = entry.file_name().into_string().unwrap();
        let data = std::fs::read_to_string(&entry.path())
            .expect("failed to read test file");

        // Get test step and operation from the filename.
        let step_num = filename[0..2]
            .parse::<usize>()
            .expect("failed to parse step number from filename");
        let op = TestOp::from_filename(&filename[3..])
            .expect("failed to parse test operation from filename");

        let step = test_steps.entry(step_num).or_default();
        match op {
            TestOp::Input(op) => {
                if step.input.is_some() {
                    panic!("test input is already defined for this step");
                }
                step.input = Some((op, data));
            }
            TestOp::Output(TestOpOutput::NorthboundNotif) => {
                step.output_nb_notif = data;
            }
            TestOp::Output(TestOpOutput::NorthboundState) => {
                step.output_nb_state = Some(data);
            }
            TestOp::Output(TestOpOutput::Ibus) => step.output_ibus = data,
            TestOp::Output(TestOpOutput::Protocol) => {
                step.output_protocol = data;
            }
        }
    }

    // Process test steps in order.
    for (step_num, step) in test_steps.into_iter() {
        // Process input.
        let (op, data) = step.input.expect("missing test input for this step");
        stub.messages.reset_output();
        match op {
            TestOpInput::NorthboundConfigChange => {
                stub.nb.commit_changes(&data).await;
            }
            TestOpInput::NorthboundConfigReplace => {
                stub.nb.commit_replace(&data).await;
            }
            TestOpInput::NorthboundRpc => {
                stub.nb.rpc(&data).await;
            }
            TestOpInput::Ibus => {
                for data in data.lines() {
                    let msg = serde_json::from_str(data)
                        .expect("failed to parse ibus input message");
                    stub.send(InstanceMsg::Ibus(msg)).await;
                }
            }
            TestOpInput::Protocol => {
                for data in data.lines() {
                    let msg = serde_json::from_str(data)
                        .expect("failed to parse protocol input message");
                    stub.send(InstanceMsg::Protocol(msg)).await;
                }
            }
        }
        stub.sync().await;

        // Check output: northbound notifications.
        let path =
            output_path(&test_dir, step_num, TestOpOutput::NorthboundNotif);
        stub.assert_nb_notifications(&step.output_nb_notif, &path);

        // Check output: northbound state.
        let path =
            output_path(&test_dir, step_num, TestOpOutput::NorthboundState);
        stub.nb
            .assert_state(step.output_nb_state.as_deref(), &path, P::STATE_PATH)
            .await;

        // Check output: ibus messages.
        let path = output_path(&test_dir, step_num, TestOpOutput::Ibus);
        stub.assert_ibus_output(&step.output_ibus, &path);

        // Check output: protocol messages.
        let path = output_path(&test_dir, step_num, TestOpOutput::Protocol);
        stub.assert_protocol_output(&step.output_protocol, &path);
    }

    // Finish test instance.
    info!("test finished");
    stub.close().await;
}

// Loads topology snapshot and checks if the initial network convergence went as
// expected.
pub async fn run_test_topology<P>(topology: &str, router: &str)
where
    P: ProtocolInstance,
{
    setup();

    // Load instance snapshot.
    let span = debug_span!("test-topology", name = %topology, %router);
    let _span_guard = span.enter();
    info!("loading instance snapshot...");
    let mut stub: Stub<P> = load_snapshot(topology, router).await;

    // Get topology base directory.
    let topo_dir = topology_dir::<P>(topology, router);

    // Check initial convergence: northbound state.
    let path = format!("{}/{}", topo_dir, "output/northbound-state.json");
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    stub.nb
        .assert_state(Some(&expected), &path, P::STATE_PATH)
        .await;

    // Check initial convergence: northbound notifications.
    let path = format!("{}/{}", topo_dir, "output/northbound-notif.jsonl");
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    stub.assert_nb_notifications(&expected, &path);

    // Check initial convergence: ibus output.
    let path = format!("{}/{}", topo_dir, "output/ibus.jsonl");
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    stub.assert_ibus_output(&expected, &path);

    // Check initial convergence: protocol output.
    let path = format!("{}/{}", topo_dir, "output/protocol.jsonl");
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    stub.assert_protocol_output(&expected, &path);

    // Finish test instance.
    info!("test finished");
    stub.close().await;
}
