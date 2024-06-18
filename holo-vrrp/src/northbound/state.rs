//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::{atomic, Arc, LazyLock as Lazy};

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::{interfaces, vrrp};
use holo_utils::option::OptionExt;
use holo_yang::ToYang;

use crate::instance::Instance;

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use interfaces::interface::ipv4::vrrp::vrrp_instance::VrrpInstance;
            Box::new(VrrpInstance {
                vrid: todo!(),
                state: todo!(),
                is_owner: todo!(),
                last_adv_source: todo!(),
                up_datetime: todo!(),
                master_down_interval: todo!(),
                skew_time: todo!(),
                last_event: todo!(),
                new_master_reason: todo!(),
            })
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::statistics::PATH)
        .get_object(|_instance, _args| {
            use interfaces::interface::ipv4::vrrp::vrrp_instance::statistics::Statistics;
            Box::new(Statistics {
                discontinuity_datetime: todo!(),
                master_transitions: todo!(),
                advertisement_rcvd: todo!(),
                advertisement_sent: todo!(),
                priority_zero_pkts_rcvd: todo!(),
                priority_zero_pkts_sent: todo!(),
                invalid_type_pkts_rcvd: todo!(),
                packet_length_errors: todo!(),
            })
        })
        .path(vrrp::PATH)
        .get_object(|_instance, _args| {
            use vrrp::Vrrp;
            Box::new(Vrrp {
                virtual_routers: todo!(),
                interfaces: todo!(),
            })
        })
        .path(vrrp::statistics::PATH)
        .get_object(|_instance, _args| {
            use vrrp::statistics::Statistics;
            Box::new(Statistics {
                discontinuity_datetime: todo!(),
                checksum_errors: todo!(),
                version_errors: todo!(),
                vrid_errors: todo!(),
                ip_ttl_errors: todo!(),
            })
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    // TODO
    const STATE_PATH: &'static str = "";

    type ListEntry<'a> = ListEntry;

    fn callbacks() -> Option<&'static Callbacks<Instance>> {
        Some(&CALLBACKS)
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry {}
