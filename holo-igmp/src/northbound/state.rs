//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangList, YangOps};
use holo_utils::option::OptionExt;

//use holo_yang::ToYang;
use crate::instance::Instance;
use crate::interface::Interface;
use crate::northbound::yang_gen::{self, igmp};

impl Provider for Instance {
    type ListEntry<'a> = ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Interface(&'a Interface),
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry<'a>> + 'a>;

impl ListEntryKind for ListEntry<'_> {}

// ===== YANG impls =====

impl<'a> YangContainer<'a, Instance> for igmp::global::Global {
    fn new(_instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<Self> {
        Some(Self {
            entries_count: todo!(),
            groups_count: todo!(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for igmp::global::statistics::Statistics<'a> {
    fn new(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<Self> {
        let statistics = &instance.state.as_ref()?.statistics;
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&statistics.discontinuity_time)).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for igmp::global::statistics::error::Error {
    fn new(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<Self> {
        let errors = &instance.state.as_ref()?.statistics.errors;
        Some(Self {
            total: Some(errors.total),
            query: Some(errors.query),
            report: Some(errors.report),
            leave: Some(errors.leave),
            checksum: Some(errors.checksum),
            too_short: Some(errors.too_short),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangContainer<'a, Instance> for igmp::global::statistics::received::Received {
    fn new(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<Self> {
        let msgs_rcvd = &instance.state.as_ref()?.statistics.msgs_rcvd;
        Some(Self {
            total: Some(msgs_rcvd.total),
            query: Some(msgs_rcvd.query),
            report: Some(msgs_rcvd.report),
            leave: Some(msgs_rcvd.leave),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangContainer<'a, Instance> for igmp::global::statistics::sent::Sent {
    fn new(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<Self> {
        let msgs_sent = &instance.state.as_ref()?.statistics.msgs_sent;
        Some(Self {
            total: Some(msgs_sent.total),
            query: Some(msgs_sent.query),
            report: Some(msgs_sent.report),
            leave: Some(msgs_sent.leave),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangList<'a, Instance> for igmp::interfaces::interface::Interface<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = instance.interfaces.values().map(ListEntry::Interface);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let iface = list_entry.as_interface().unwrap();
        Self {
            interface_name: Cow::Borrowed(&iface.name),
            oper_status: todo!(),
            querier: todo!(),
            joined_group: todo!(),
        }
    }
}

impl<'a> YangList<'a, Instance> for igmp::interfaces::interface::group::Group<'a> {
    fn iter(_instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        todo!()
    }

    fn new(_instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Self {
        Self {
            group_address: todo!(),
            expire: todo!(),
            filter_mode: todo!(),
            up_time: todo!(),
            last_reporter: todo!(),
        }
    }
}

impl<'a> YangList<'a, Instance> for igmp::interfaces::interface::group::source::Source<'a> {
    fn iter(_instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        todo!()
    }

    fn new(_instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Self {
        Self {
            source_address: todo!(),
            expire: todo!(),
            up_time: todo!(),
            last_reporter: todo!(),
        }
    }
}
