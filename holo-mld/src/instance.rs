use std::marker::PhantomData;

use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;

use crate::debug::Debug;
use crate::northbound::configuration::InstanceCfg;
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::version::Version;

#[derive(Debug)]
pub struct Instance<V: Version> {
    // Instance name.
    pub name: String,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: Option<InstanceState<V>>,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance<V>>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug)]
pub struct InstanceState<V: Version> {
    _phantom: PhantomData<V>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx<V: Version> {
    _phantom: PhantomData<V>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsTx<V: Version> {
    _phantom: PhantomData<V>,
}

impl<V> MessageReceiver<ProtocolInputMsg<V>> for ProtocolInputChannelsRx<V>
where
    V: Version,
{
    async fn recv(&mut self) -> Option<ProtocolInputMsg<V>> {
        None
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
        Debug::InstanceCreate.log();

        Instance {
            name,
            config: Default::default(),
            state: None,
            tx,
            shared,
        }
    }

    fn init(&mut self) {}

    fn shutdown(self) {}

    fn process_ibus_msg(&mut self, msg: IbusMsg) {
        match msg {
            _ => {}
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg<V>) {
        match msg {
            _ => {}
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx<V>, ProtocolInputChannelsRx<V>) {
        let tx = ProtocolInputChannelsTx {
            _phantom: Default::default(),
        };
        let rx = ProtocolInputChannelsRx {
            _phantom: Default::default(),
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
