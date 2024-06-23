//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::interfaces;
use holo_utils::option::OptionExt;
use holo_yang::ToYang;

use crate::instance::Instance;
use crate::interface::Interface;

pub static CALLBACKS: Lazy<Callbacks<Interface>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Instance(u8, &'a Instance),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Interface> {
    CallbacksBuilder::<Interface>::default()
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::PATH)
        .get_iterate(|interface, _args| {
            let iter = interface.instances.iter().map(|(vrid, instance)| ListEntry::Instance(*vrid, instance));
            Some(Box::new(iter))
        })
        .get_object(|_interface, args| {
            use interfaces::interface::ipv4::vrrp::vrrp_instance::VrrpInstance;
            let (vrid, instance) = args.list_entry.as_instance().unwrap();
            Box::new(VrrpInstance {
                vrid: *vrid,
                state: Some(instance.state.state.to_yang()),
                // TODO
                is_owner: None,
                last_adv_source: instance.state.last_adv_src.map(std::convert::Into::into).map(Cow::Owned).ignore_in_testing(),
                up_datetime: instance.state.up_time.as_ref().ignore_in_testing(),
                // TODO
                master_down_interval: None,
                // TODO
                skew_time: None,
                last_event: Some(instance.state.last_event.to_yang()).ignore_in_testing(),
                new_master_reason: Some(instance.state.new_master_reason.to_yang()),
            })
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::statistics::PATH)
        .get_object(|_interface, args| {
            use interfaces::interface::ipv4::vrrp::vrrp_instance::statistics::Statistics;
            let (_, instance) = args.list_entry.as_instance().unwrap();
            let statistics = &instance.state.statistics;
            Box::new(Statistics {
                discontinuity_datetime: Some(&statistics.discontinuity_time).ignore_in_testing(),
                master_transitions: Some(statistics.master_transitions).ignore_in_testing(),
                advertisement_rcvd: Some(statistics.adv_rcvd).ignore_in_testing(),
                advertisement_sent: Some(statistics.adv_sent).ignore_in_testing(),
                interval_errors: Some(statistics.interval_errors).ignore_in_testing(),
                priority_zero_pkts_rcvd: Some(statistics.priority_zero_pkts_rcvd).ignore_in_testing(),
                priority_zero_pkts_sent: Some(statistics.priority_zero_pkts_sent).ignore_in_testing(),
                invalid_type_pkts_rcvd: Some(statistics.invalid_type_pkts_rcvd).ignore_in_testing(),
                packet_length_errors: Some(statistics.pkt_length_errors).ignore_in_testing(),
            })
        })
        .build()
}

// ===== impl Interface =====

impl Provider for Interface {
    // TODO
    const STATE_PATH: &'static str = "";

    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> Option<&'static Callbacks<Interface>> {
        Some(&CALLBACKS)
    }
}

// ===== impl ListEntry =====

impl<'a> ListEntryKind for ListEntry<'a> {}
