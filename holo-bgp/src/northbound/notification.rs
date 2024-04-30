//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::notification;
use holo_northbound::paths::control_plane_protocol;
use holo_northbound::paths::control_plane_protocol::bgp;
use holo_utils::protocol::Protocol;
use holo_yang::ToYang;

use crate::instance::InstanceUpView;
use crate::neighbor::Neighbor;

// ===== global functions =====

pub(crate) fn established(instance: &InstanceUpView<'_>, nbr: &Neighbor) {
    use bgp::neighbors::established::{self, Established};

    let path = format!(
        "{}{}{}",
        control_plane_protocol::PATH,
        control_plane_protocol::list_keys(
            Protocol::BGP.to_yang(),
            instance.name
        ),
        established::RELATIVE_PATH,
    );
    let data = Established {
        remote_address: Some(nbr.remote_addr.to_string().into()),
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

    let path = format!(
        "{}{}{}",
        control_plane_protocol::PATH,
        control_plane_protocol::list_keys(
            Protocol::BGP.to_yang(),
            instance.name
        ),
        backward_transition::RELATIVE_PATH,
    );
    let data = BackwardTransition {
        remote_addr: Some(nbr.remote_addr.to_string().into()),
        notification_received: nbr.notification_rcvd.as_ref().map(
            |(time, notif)| NotificationReceived {
                last_notification: Some(time.to_rfc3339().into()),
                last_error: Some(notif.to_yang()),
                last_error_code: Some(notif.error_code.to_string().into()),
                last_error_subcode: Some(
                    notif.error_subcode.to_string().into(),
                ),
            },
        ),
        notification_sent: nbr.notification_sent.as_ref().map(
            |(time, notif)| NotificationSent {
                last_notification: Some(time.to_rfc3339().into()),
                last_error: Some(notif.to_yang()),
                last_error_code: Some(notif.error_code.to_string().into()),
                last_error_subcode: Some(
                    notif.error_subcode.to_string().into(),
                ),
            },
        ),
    };
    notification::send(&instance.tx.nb, path, data);
}
