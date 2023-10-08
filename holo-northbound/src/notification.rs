//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_yang::{YangPath, YANG_CTX};
use yang2::data::DataTree;

use crate::api::provider::Notification;
use crate::debug::Debug;
use crate::NbProviderSender;

pub fn send(
    nb_tx: &NbProviderSender,
    path: YangPath,
    args: &[(YangPath, Option<&str>)],
) {
    let yang_ctx = YANG_CTX.get().unwrap();
    let mut data = DataTree::new(yang_ctx);

    // Add arguments.
    for (arg, value) in args {
        data.new_path(arg.as_str(), *value, false).unwrap();
    }

    Debug::Notification(path, args).log();

    nb_tx.send(Notification { data }).unwrap();
}
