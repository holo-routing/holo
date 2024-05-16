//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_yang::{YangObject, YANG_CTX};
use yang2::data::DataTree;

use crate::api::provider::Notification;
use crate::NbProviderSender;

pub fn send(
    nb_tx: &NbProviderSender,
    path: impl AsRef<str>,
    data: impl YangObject,
) {
    let yang_ctx = YANG_CTX.get().unwrap();
    let mut dtree = DataTree::new(yang_ctx);
    let mut dnode =
        dtree.new_path(path.as_ref(), None, false).unwrap().unwrap();
    data.into_data_node(&mut dnode);
    nb_tx.send(Notification { data: dtree }).unwrap();
}
