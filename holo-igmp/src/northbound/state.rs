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
            let mut discontinuity_time = None;
            if let Some(state) = &instance.state {
                discontinuity_time =
                    Some(Cow::Borrowed(&state.statistics.discontinuity_time));
            }

            Box::new(Statistics {
                discontinuity_time: discontinuity_time.ignore_in_testing(),
            })
        })
        .path(igmp::global::statistics::error::PATH)
        .get_object(|instance, _args| {
            use igmp::global::statistics::error::Error;
            let mut total = None;
            let mut query = None;
            let mut report = None;
            let mut leave = None;
            let mut checksum = None;
            let mut too_short = None;
            if let Some(state) = &instance.state {
                total = Some(state.statistics.errors.total);
                query = Some(state.statistics.errors.query);
                report = Some(state.statistics.errors.report);
                leave = Some(state.statistics.errors.leave);
                checksum = Some(state.statistics.errors.checksum);
                too_short = Some(state.statistics.errors.too_short);
            }
            Box::new(Error {
                total: total.ignore_in_testing(),
                query: query.ignore_in_testing(),
                report: report.ignore_in_testing(),
                leave: leave.ignore_in_testing(),
                checksum: checksum.ignore_in_testing(),
                too_short: too_short.ignore_in_testing(),
            })
        })
        .path(igmp::global::statistics::received::PATH)
        .get_object(|instance, _args| {
            use igmp::global::statistics::received::Received;
            let mut total = None;
            let mut query = None;
            let mut report = None;
            let mut leave = None;
            if let Some(state) = &instance.state {
                total = Some(state.statistics.msgs_rcvd.total);
                query = Some(state.statistics.msgs_rcvd.query);
                report = Some(state.statistics.msgs_rcvd.report);
                leave = Some(state.statistics.msgs_rcvd.leave);
            }
            Box::new(Received {
                total: total.ignore_in_testing(),
                query: query.ignore_in_testing(),
                report: report.ignore_in_testing(),
                leave: leave.ignore_in_testing(),
            })
        })
        .path(igmp::global::statistics::sent::PATH)
        .get_object(|instance, _args| {
            use igmp::global::statistics::sent::Sent;
            let mut total = None;
            let mut query = None;
            let mut report = None;
            let mut leave = None;
            if let Some(state) = &instance.state {
                total = Some(state.statistics.msgs_sent.total);
                query = Some(state.statistics.msgs_sent.query);
                report = Some(state.statistics.msgs_sent.report);
                leave = Some(state.statistics.msgs_sent.leave);
            }
            Box::new(Sent {
                total: total.ignore_in_testing(),
                query: query.ignore_in_testing(),
                report: report.ignore_in_testing(),
                leave: leave.ignore_in_testing(),
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
