//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::borrow::Cow;
use std::sync::atomic::Ordering;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangList, YangOps};
use holo_utils::option::OptionExt;
use holo_yang::ToYang;

use crate::instance::Instance;
use crate::interface::Interface;
use crate::northbound::yang_gen::{self, interfaces};

impl Provider for Interface {
    type ListEntry<'a> = ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Instance(u8, &'a Instance),
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry<'a>> + 'a>;

impl ListEntryKind for ListEntry<'_> {}

// ===== YANG impls =====

impl<'a> YangList<'a, Interface> for interfaces::interface::ipv4::vrrp::vrrp_instance::VrrpInstance<'a> {
    fn iter(interface: &'a Interface, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = interface.vrrp_ipv4_instances.iter().map(|(vrid, instance)| ListEntry::Instance(*vrid, instance));
        Some(Box::new(iter))
    }

    fn new(_interface: &'a Interface, list_entry: &ListEntry<'a>) -> Self {
        let (vrid, instance) = list_entry.as_instance().unwrap();
        Self {
            vrid: *vrid,
            state: Some(instance.state.state.to_yang()), // TODO
            is_owner: None,
            last_adv_source: instance.state.last_adv_src.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            up_datetime: instance.state.up_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            master_down_interval: instance.state.timer.as_master_down_timer().map(|task| task.remaining().as_millis() as u32 / 10).ignore_in_testing(),
            skew_time: None, // TODO
            last_event: Some(instance.state.last_event.to_yang()).ignore_in_testing(),
            new_master_reason: Some(instance.state.new_master_reason.to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Interface> for interfaces::interface::ipv4::vrrp::vrrp_instance::statistics::Statistics<'a> {
    fn new(_interface: &'a Interface, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, instance) = list_entry.as_instance().unwrap();
        let statistics = &instance.state.statistics;
        Some(Self {
            discontinuity_datetime: Some(Cow::Borrowed(&statistics.discontinuity_time)),
            master_transitions: Some(statistics.master_transitions),
            advertisement_rcvd: Some(statistics.adv_rcvd),
            advertisement_sent: Some(statistics.adv_sent.load(Ordering::Relaxed)),
            interval_errors: Some(statistics.interval_errors),
            priority_zero_pkts_rcvd: Some(statistics.priority_zero_pkts_rcvd),
            priority_zero_pkts_sent: Some(statistics.priority_zero_pkts_sent),
            invalid_type_pkts_rcvd: Some(statistics.invalid_type_pkts_rcvd),
            packet_length_errors: Some(statistics.pkt_length_errors),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangList<'a, Interface> for interfaces::interface::ipv6::vrrp::vrrp_instance::VrrpInstance<'a> {
    fn iter(interface: &'a Interface, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = interface.vrrp_ipv6_instances.iter().map(|(vrid, instance)| ListEntry::Instance(*vrid, instance));
        Some(Box::new(iter))
    }

    fn new(_interface: &'a Interface, list_entry: &ListEntry<'a>) -> Self {
        let (vrid, instance) = list_entry.as_instance().unwrap();
        Self {
            vrid: *vrid,
            state: Some(instance.state.state.to_yang()),
            is_owner: None, // TODO
            last_adv_source: instance.state.last_adv_src.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            up_datetime: instance.state.up_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            master_down_interval: instance.state.timer.as_master_down_timer().map(|task| task.remaining().as_millis() as u32 / 10).ignore_in_testing(),
            skew_time: None, // TODO
            last_event: Some(instance.state.last_event.to_yang()).ignore_in_testing(),
            new_master_reason: Some(instance.state.new_master_reason.to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Interface> for interfaces::interface::ipv6::vrrp::vrrp_instance::statistics::Statistics<'a> {
    fn new(_interface: &'a Interface, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, instance) = list_entry.as_instance().unwrap();
        let statistics = &instance.state.statistics;
        Some(Self {
            discontinuity_datetime: Some(Cow::Borrowed(&statistics.discontinuity_time)),
            master_transitions: Some(statistics.master_transitions),
            advertisement_rcvd: Some(statistics.adv_rcvd),
            advertisement_sent: Some(statistics.adv_sent.load(Ordering::Relaxed)),
            interval_errors: Some(statistics.interval_errors),
            priority_zero_pkts_rcvd: Some(statistics.priority_zero_pkts_rcvd),
            priority_zero_pkts_sent: Some(statistics.priority_zero_pkts_sent),
            invalid_type_pkts_rcvd: Some(statistics.invalid_type_pkts_rcvd),
            packet_length_errors: Some(statistics.pkt_length_errors),
        })
        .ignore_in_testing()
    }
}
