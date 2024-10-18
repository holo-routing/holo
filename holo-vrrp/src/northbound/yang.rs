//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::borrow::Cow;

use holo_yang::ToYang;

use crate::instance::{Event, MasterReason, State};

// ===== ToYang implementations =====

impl ToYang for State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            State::Initialize => "ietf-vrrp:initialize".into(),
            State::Backup => "ietf-vrrp:backup".into(),
            State::Master => "ietf-vrrp:master".into(),
        }
    }
}

impl ToYang for Event {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            Event::None => "ietf-vrrp:vrrp-event-none".into(),
            Event::Startup => "ietf-vrrp:vrrp-event-startup".into(),
            Event::Shutdown => "ietf-vrrp:vrrp-event-shutdown".into(),
            Event::HigherPriorityBackup => {
                "ietf-vrrp:vrrp-event-higher-priority-backup".into()
            }
            Event::MasterTimeout => {
                "ietf-vrrp:vrrp-event-master-timeout".into()
            }
            Event::InterfaceUp => "ietf-vrrp:vrrp-event-interface-up".into(),
            Event::InterfaceDown => {
                "ietf-vrrp:vrrp-event-interface-down".into()
            }
            Event::NoPrimaryIpAddress => {
                "ietf-vrrp:vrrp-event-no-primary-ip-address".into()
            }
            Event::PrimaryIpAddress => {
                "ietf-vrrp:vrrp-event-primary-ip-address".into()
            }
            Event::NoVirtualIpAddresses => {
                "ietf-vrrp:vrrp-event-no-virtual-ip-addresses".into()
            }
            Event::VirtualIpAddresses => {
                "ietf-vrrp:vrrp-event-virtual-ip-addresses".into()
            }
            Event::PreemptHoldTimeout => {
                "ietf-vrrp:vrrp-event-preempt-hold-timeout".into()
            }
            Event::LowerPriorityMaster => {
                "ietf-vrrp:vrrp-event-lower-priority-master".into()
            }
            Event::OwnerPreempt => "ietf-vrrp:vrrp-event-owner-preempt".into(),
        }
    }
}

impl ToYang for MasterReason {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            MasterReason::NotMaster => "not-master".into(),
            MasterReason::Priority => "priority".into(),
            MasterReason::Preempted => "preempted".into(),
            MasterReason::NoResponse => "no-response".into(),
        }
    }
}
