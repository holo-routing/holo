//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod stub;

use std::sync::{Arc, Once};

use derive_new::new;
use holo_southbound::zclient::messages::ZapiTxMsg;
use holo_utils::{Receiver, UnboundedReceiver};
use holo_yang as yang;
use holo_yang::{YANG_CTX, YANG_IMPLEMENTED_MODULES};
use tracing::info;

use crate::test::stub::TestMsg;
use crate::ProtocolInstance;

static INIT: Once = Once::new();

#[derive(Debug, new)]
pub struct OutputChannelsRx<T> {
    sb_txc: UnboundedReceiver<ZapiTxMsg>,
    protocol_txc: Receiver<T>,
}

// ===== helper functions =====

// Initializes tracing subscriber.
fn init_tracing() {
    tracing_subscriber::fmt::Subscriber::builder()
        .with_target(false)
        .with_ansi(false)
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    info!("starting");
}

// Creates YANG context and load all implemented modules.
fn init_yang() {
    let mut yang_ctx = yang::new_context();
    for module_name in YANG_IMPLEMENTED_MODULES.iter() {
        yang::load_module(&mut yang_ctx, module_name);
    }
    for module_name in YANG_IMPLEMENTED_MODULES.iter().rev() {
        yang::load_deviations(&mut yang_ctx, module_name);
    }
    YANG_CTX.set(Arc::new(yang_ctx)).unwrap();
}

// ===== global functions =====

// Processes protocol instance test message.
pub(crate) fn process_test_msg<P>(
    msg: TestMsg<P::ProtocolOutputMsg>,
    output_channels_rx: &mut Option<OutputChannelsRx<P::ProtocolOutputMsg>>,
) where
    P: ProtocolInstance,
{
    match msg {
        TestMsg::Synchronize(msg) => msg.responder.unwrap().send(()).unwrap(),
        TestMsg::GetOutputChannelsRx(msg) => {
            let output_channels_rx = output_channels_rx.take().unwrap();
            msg.responder.unwrap().send(output_channels_rx).unwrap()
        }
    }
}

// Common initialization required by all tests.
pub fn setup() {
    INIT.call_once(|| {
        init_tracing();
        init_yang();
    });
}
