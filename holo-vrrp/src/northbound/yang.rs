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

use crate::instance::{MasterReason, fsm};

// ===== ToYang implementations =====

impl ToYang for fsm::State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            fsm::State::Initialize => "ietf-vrrp:initialize".into(),
            fsm::State::Backup => "ietf-vrrp:backup".into(),
            fsm::State::Master => "ietf-vrrp:master".into(),
        }
    }
}

impl ToYang for fsm::Event {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            fsm::Event::None => "ietf-vrrp:vrrp-event-none".into(),
            fsm::Event::Startup => "ietf-vrrp:vrrp-event-startup".into(),
            fsm::Event::Shutdown => "ietf-vrrp:vrrp-event-shutdown".into(),
            fsm::Event::HigherPriorityBackup => {
                "ietf-vrrp:vrrp-event-higher-priority-backup".into()
            }
            fsm::Event::MasterTimeout => {
                "ietf-vrrp:vrrp-event-master-timeout".into()
            }
            fsm::Event::InterfaceUp => {
                "ietf-vrrp:vrrp-event-interface-up".into()
            }
            fsm::Event::InterfaceDown => {
                "ietf-vrrp:vrrp-event-interface-down".into()
            }
            fsm::Event::NoPrimaryIpAddress => {
                "ietf-vrrp:vrrp-event-no-primary-ip-address".into()
            }
            fsm::Event::PrimaryIpAddress => {
                "ietf-vrrp:vrrp-event-primary-ip-address".into()
            }
            fsm::Event::NoVirtualIpAddresses => {
                "ietf-vrrp:vrrp-event-no-virtual-ip-addresses".into()
            }
            fsm::Event::VirtualIpAddresses => {
                "ietf-vrrp:vrrp-event-virtual-ip-addresses".into()
            }
            fsm::Event::PreemptHoldTimeout => {
                "ietf-vrrp:vrrp-event-preempt-hold-timeout".into()
            }
            fsm::Event::LowerPriorityMaster => {
                "ietf-vrrp:vrrp-event-lower-priority-master".into()
            }
            fsm::Event::OwnerPreempt => {
                "ietf-vrrp:vrrp-event-owner-preempt".into()
            }
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
