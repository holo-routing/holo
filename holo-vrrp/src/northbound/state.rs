//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::sync::atomic::Ordering;

use holo_northbound::state::{ListIterator, Provider, YangContainer, YangList, YangOps};
use holo_utils::option::OptionExt;
use holo_yang::ToYang;

use crate::instance::Instance;
use crate::interface::Interface;
use crate::northbound::yang_gen::{self, interfaces};

impl Provider for Interface {
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        format!("/ietf-interfaces:interfaces/interface[name='{}']", self.name)
    }
}

// ===== YANG impls =====

impl<'a> YangList<'a, Interface> for interfaces::interface::ipv4::vrrp::vrrp_instance::VrrpInstance<'a> {
    type ParentListEntry = ();
    type ListEntry = (u8, &'a Instance);

    fn iter(interface: &'a Interface, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = interface.vrrp_ipv4_instances.iter().map(|(vrid, instance)| (*vrid, instance));
        Some(iter)
    }

    fn new(_interface: &'a Interface, (vrid, instance): &Self::ListEntry) -> Self {
        Self {
            vrid: *vrid,
            state: Some(instance.state.state.to_yang()), // TODO
            is_owner: None,
            last_adv_source: instance.state.last_adv_src.ignore_in_testing(),
            up_datetime: instance.state.up_time.ignore_in_testing(),
            master_down_interval: instance.state.timer.as_master_down_timer().map(|task| task.remaining().as_millis() as u32 / 10).ignore_in_testing(),
            skew_time: None, // TODO
            last_event: Some(instance.state.last_event.to_yang()).ignore_in_testing(),
            new_master_reason: Some(instance.state.new_master_reason),
        }
    }
}

impl<'a> YangContainer<'a, Interface> for interfaces::interface::ipv4::vrrp::vrrp_instance::statistics::Statistics {
    type ParentListEntry = (u8, &'a Instance);

    fn new(_interface: &'a Interface, (_, instance): &Self::ParentListEntry) -> Option<Self> {
        let statistics = &instance.state.statistics;
        Some(Self {
            discontinuity_datetime: Some(statistics.discontinuity_time),
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
    type ParentListEntry = ();
    type ListEntry = (u8, &'a Instance);

    fn iter(interface: &'a Interface, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = interface.vrrp_ipv6_instances.iter().map(|(vrid, instance)| (*vrid, instance));
        Some(iter)
    }

    fn new(_interface: &'a Interface, (vrid, instance): &Self::ListEntry) -> Self {
        Self {
            vrid: *vrid,
            state: Some(instance.state.state.to_yang()),
            is_owner: None, // TODO
            last_adv_source: instance.state.last_adv_src.ignore_in_testing(),
            up_datetime: instance.state.up_time.ignore_in_testing(),
            master_down_interval: instance.state.timer.as_master_down_timer().map(|task| task.remaining().as_millis() as u32 / 10).ignore_in_testing(),
            skew_time: None, // TODO
            last_event: Some(instance.state.last_event.to_yang()).ignore_in_testing(),
            new_master_reason: Some(instance.state.new_master_reason),
        }
    }
}

impl<'a> YangContainer<'a, Interface> for interfaces::interface::ipv6::vrrp::vrrp_instance::statistics::Statistics {
    type ParentListEntry = (u8, &'a Instance);

    fn new(_interface: &'a Interface, (_, instance): &Self::ParentListEntry) -> Option<Self> {
        let statistics = &instance.state.statistics;
        Some(Self {
            discontinuity_datetime: Some(statistics.discontinuity_time),
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
