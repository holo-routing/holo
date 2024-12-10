//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::borrow::Cow;
use std::net::Ipv4Addr;

use holo_northbound::{notification, yang, NbProviderSender};
use holo_yang::ToYang;

use crate::instance::MasterReason;

// ===== global functions =====

#[expect(unused)]
pub(crate) fn new_master_event(
    nb_tx: &NbProviderSender,
    addr: Ipv4Addr,
    reason: MasterReason,
) {
    use yang::vrrp_new_master_event::{self, VrrpNewMasterEvent};

    let data = VrrpNewMasterEvent {
        master_ip_address: Some(Cow::Owned(addr.into())),
        new_master_reason: Some(reason.to_yang()),
    };
    notification::send(nb_tx, vrrp_new_master_event::PATH, data);
}
