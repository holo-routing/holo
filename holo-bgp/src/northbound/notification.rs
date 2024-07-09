//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_northbound::notification;
use holo_northbound::yang::control_plane_protocol;
use holo_northbound::yang::control_plane_protocol::bgp;
use holo_utils::protocol::Protocol;
use holo_yang::{ToYang, YangObject};

use crate::instance::InstanceUpView;
use crate::neighbor::Neighbor;

// ===== global functions =====

pub(crate) fn established(instance: &InstanceUpView<'_>, nbr: &Neighbor) {
    use bgp::neighbors::established::{self, Established};

    let path = notification_path(instance.name, established::RELATIVE_PATH);
    let data = Established {
        remote_address: Some(Cow::Borrowed(&nbr.remote_addr)),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn backward_transition(
    instance: &InstanceUpView<'_>,
    nbr: &Neighbor,
) {
    use bgp::neighbors::backward_transition::notification_received::NotificationReceived;
    use bgp::neighbors::backward_transition::notification_sent::NotificationSent;
    use bgp::neighbors::backward_transition::{self, BackwardTransition};

    let path =
        notification_path(instance.name, backward_transition::RELATIVE_PATH);
    let data = BackwardTransition {
        remote_addr: Some(Cow::Borrowed(&nbr.remote_addr)),
        notification_received: nbr.notification_rcvd.as_ref().map(
            |(time, notif)| {
                Box::new(NotificationReceived {
                    last_notification: Some(Cow::Borrowed(time)),
                    last_error: Some(notif.to_yang()),
                    last_error_code: Some(notif.error_code),
                    last_error_subcode: Some(notif.error_subcode),
                })
            },
        ),
        notification_sent: nbr.notification_sent.as_ref().map(
            |(time, notif)| {
                Box::new(NotificationSent {
                    last_notification: Some(Cow::Borrowed(time)),
                    last_error: Some(notif.to_yang()),
                    last_error_code: Some(notif.error_code),
                    last_error_subcode: Some(notif.error_subcode),
                })
            },
        ),
    };
    notification::send(&instance.tx.nb, path, data);
}

// ===== global functions =====

fn notification_path(instance_name: &str, notification: &str) -> String {
    use control_plane_protocol::ControlPlaneProtocol;

    let control_plane_protocol = ControlPlaneProtocol {
        r#type: Protocol::BGP.to_yang(),
        name: instance_name.into(),
    };
    format!(
        "{}{}{}",
        control_plane_protocol::PATH,
        control_plane_protocol.list_keys(),
        notification,
    )
}
