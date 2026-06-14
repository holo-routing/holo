//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_northbound::state::{ListIterator, Provider, YangContainer, YangList, YangOps};
use holo_utils::option::OptionExt;
use holo_utils::protocol::Protocol;
use holo_yang::ToYang;

use crate::instance::Instance;
use crate::interface::Interface;
use crate::northbound::yang_gen::{self, igmp};

impl Provider for Instance {
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-igmp-mld:igmp",
            Protocol::IGMP.to_yang(),
            self.name
        )
    }
}

// ===== YANG impls =====

impl<'a> YangContainer<'a, Instance> for igmp::global::Global {
    type ParentListEntry = ();

    fn new(_instance: &'a Instance, _: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            entries_count: todo!(),
            groups_count: todo!(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for igmp::global::statistics::Statistics {
    type ParentListEntry = ();

    fn new(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<Self> {
        let statistics = &instance.state.as_ref()?.statistics;
        Some(Self {
            discontinuity_time: Some(statistics.discontinuity_time).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for igmp::global::statistics::error::Error {
    type ParentListEntry = ();

    fn new(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<Self> {
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
    type ParentListEntry = ();

    fn new(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<Self> {
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
    type ParentListEntry = ();

    fn new(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<Self> {
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
    type ParentListEntry = ();
    type ListEntry = &'a Interface;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = instance.interfaces.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, iface: &Self::ListEntry) -> Self {
        Self {
            interface_name: Cow::Borrowed(&iface.name),
            oper_status: todo!(),
            querier: todo!(),
            joined_group: todo!(),
        }
    }
}

impl<'a> YangList<'a, Instance> for igmp::interfaces::interface::group::Group<'a> {
    type ParentListEntry = &'a Interface;
    type ListEntry = ();

    fn iter(_instance: &'a Instance, _iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        None::<std::iter::Empty<_>>
    }

    fn new(_instance: &'a Instance, _: &Self::ListEntry) -> Self {
        Self {
            group_address: todo!(),
            expire: todo!(),
            filter_mode: todo!(),
            up_time: todo!(),
            last_reporter: todo!(),
        }
    }
}

impl<'a> YangList<'a, Instance> for igmp::interfaces::interface::group::source::Source {
    type ParentListEntry = ();
    type ListEntry = ();

    fn iter(_instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        None::<std::iter::Empty<_>>
    }

    fn new(_instance: &'a Instance, _: &Self::ListEntry) -> Self {
        Self {
            source_address: todo!(),
            expire: todo!(),
            up_time: todo!(),
            last_reporter: todo!(),
        }
    }
}
