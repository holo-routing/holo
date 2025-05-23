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
use holo_northbound::yang::control_plane_protocol::igmp;
use holo_utils::option::OptionExt;

//use holo_yang::ToYang;
use crate::instance::Instance;
use crate::interface::Interface;

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Interface(&'a Interface),
}

// ===== callbacks =====

#[allow(unreachable_code)]
fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(igmp::global::PATH)
        .get_object(|_instance, _args| {
            use igmp::global::Global;
            Box::new(Global {
                entries_count: todo!(),
                groups_count: todo!(),
            })
        })
        .path(igmp::global::statistics::PATH)
        .get_object(|instance, _args| {
            use igmp::global::statistics::Statistics;
            Box::new(Statistics {
                discontinuity_time: Some(Cow::Borrowed(
                    &instance.state.statistics.discontinuity_time,
                ))
                .ignore_in_testing(),
            })
        })
        .path(igmp::global::statistics::error::PATH)
        .get_object(|instance, _args| {
            use igmp::global::statistics::error::Error;
            Box::new(Error {
                total: Some(instance.state.statistics.errors.total)
                    .ignore_in_testing(),
                query: Some(instance.state.statistics.errors.query)
                    .ignore_in_testing(),
                report: Some(instance.state.statistics.errors.report)
                    .ignore_in_testing(),
                leave: Some(instance.state.statistics.errors.leave)
                    .ignore_in_testing(),
                checksum: Some(instance.state.statistics.errors.checksum)
                    .ignore_in_testing(),
                too_short: Some(instance.state.statistics.errors.too_short)
                    .ignore_in_testing(),
            })
        })
        .path(igmp::global::statistics::received::PATH)
        .get_object(|instance, _args| {
            use igmp::global::statistics::received::Received;
            Box::new(Received {
                total: Some(instance.state.statistics.msgs_rcvd.total)
                    .ignore_in_testing(),
                query: Some(instance.state.statistics.msgs_rcvd.query)
                    .ignore_in_testing(),
                report: Some(instance.state.statistics.msgs_rcvd.report)
                    .ignore_in_testing(),
                leave: Some(instance.state.statistics.msgs_rcvd.leave)
                    .ignore_in_testing(),
            })
        })
        .path(igmp::global::statistics::sent::PATH)
        .get_object(|instance, _args| {
            use igmp::global::statistics::sent::Sent;
            Box::new(Sent {
                total: Some(instance.state.statistics.msgs_sent.total)
                    .ignore_in_testing(),
                query: Some(instance.state.statistics.msgs_sent.query)
                    .ignore_in_testing(),
                report: Some(instance.state.statistics.msgs_sent.report)
                    .ignore_in_testing(),
                leave: Some(instance.state.statistics.msgs_sent.leave)
                    .ignore_in_testing(),
            })
        })
        .path(igmp::interfaces::interface::PATH)
        .get_iterate(|instance, _args| {
            let iter = instance.interfaces.values().map(ListEntry::Interface);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use igmp::interfaces::interface::Interface;
            let iface = args.list_entry.as_interface().unwrap();
            Box::new(Interface {
                interface_name: Cow::Borrowed(&iface.name),
                oper_status: todo!(),
                querier: todo!(),
                joined_group: todo!(),
            })
        })
        .path(igmp::interfaces::interface::group::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use igmp::interfaces::interface::group::Group;
            Box::new(Group {
                group_address: todo!(),
                expire: todo!(),
                filter_mode: todo!(),
                up_time: todo!(),
                last_reporter: todo!(),
            })
        })
        .path(igmp::interfaces::interface::group::source::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_object(|_instance, _args| {
            use igmp::interfaces::interface::group::source::Source;
            Box::new(Source {
                source_address: todo!(),
                expire: todo!(),
                up_time: todo!(),
                last_reporter: todo!(),
            })
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> &'static Callbacks<Instance> {
        &CALLBACKS
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry<'_> {}
