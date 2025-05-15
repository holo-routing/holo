//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::borrow::Cow;
use std::net::IpAddr;

use holo_northbound::{NbProviderSender, notification, yang};
use holo_yang::ToYang;

use crate::error::{GlobalError, VirtualRouterError};
use crate::instance::MasterReason;

// ===== global functions =====

pub(crate) fn new_master_event(
    nb_tx: &NbProviderSender,
    addr: IpAddr,
    reason: MasterReason,
) {
    use yang::vrrp_new_master_event::{self, VrrpNewMasterEvent};

    let data = VrrpNewMasterEvent {
        master_ip_address: Some(Cow::Owned(addr)),
        new_master_reason: Some(reason.to_yang()),
    };
    notification::send(nb_tx, vrrp_new_master_event::PATH, data);
}

pub(crate) fn protocol_error_event(
    nb_tx: &NbProviderSender,
    error: &GlobalError,
) {
    use yang::vrrp_protocol_error_event::{self, VrrpProtocolErrorEvent};

    let data = VrrpProtocolErrorEvent {
        protocol_error_reason: Some(error.to_yang()),
    };
    notification::send(nb_tx, vrrp_protocol_error_event::PATH, data);
}

pub(crate) fn virtual_router_error_event(
    nb_tx: &NbProviderSender,
    interface: &str,
    error: &VirtualRouterError,
) {
    use yang::vrrp_virtual_router_error_event::{
        self, VrrpVirtualRouterErrorEvent,
    };

    let data = VrrpVirtualRouterErrorEvent {
        interface: Some(interface.into()),
        virtual_router_error_reason: Some(error.to_yang()),
    };
    notification::send(nb_tx, vrrp_virtual_router_error_event::PATH, data);
}
