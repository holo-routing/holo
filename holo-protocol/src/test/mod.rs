//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod stub;

use std::sync::{Arc, Once};

use derive_new::new;
use holo_utils::yang::ContextExt;
use holo_yang as yang;
use holo_yang::{YANG_CTX, YANG_IMPLEMENTED_MODULES};
use tokio::sync::mpsc::Receiver;
use tracing::info;

use crate::ProtocolInstance;
use crate::test::stub::TestMsg;

static INIT: Once = Once::new();

#[derive(Debug, new)]
pub struct OutputChannelsRx<T> {
    protocol_txc: Receiver<T>,
}

// ===== macros =====

/// Asserts that two byte slices are equal, printing differences in hex format
/// if they are not.
#[macro_export]
macro_rules! assert_eq_hex {
    ($left:expr, $right:expr) => {
        if $left != $right {
            panic!(
                "assertion `left == right` failed\n  left: [{}]\n right: [{}]",
                $left
                    .iter()
                    .map(|b| format!("0x{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(", "),
                $right
                    .iter()
                    .map(|b| format!("0x{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    };
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
    yang_ctx.cache_data_paths();
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
