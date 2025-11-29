//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
//
// IGMP Multicast Group Management
//
// This module implements dynamic multicast group membership tracking based on
// RFC 2236 (IGMPv2). There are two types of group memberships:
//
// 1. **Dynamic Group Membership** (this module):
//    - Learned from IGMP Membership Reports received from hosts
//    - Tracked with state machine (NoMembersPresent, MembersPresent, CheckingMembership)
//    - Stored in Interface.groups: BTreeMap<Ipv4Addr, Group>
//
// 2. **Static Group Membership** (InterfaceCfg.join_group):
//    - Administratively configured via YANG

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use holo_utils::task::TimeoutTask;
use serde::{Deserialize, Serialize};

use crate::debug::Debug;
use crate::instance::InstanceUpView;
use crate::interface::Interface;

/// Multicast group membership state on an interface.
///
/// This represents a multicast group that has been joined by at least
/// one host on the attached network (learned dynamically via IGMP Reports).
/// This is separate from statically configured groups (InterfaceCfg.join_group).
#[derive(Debug)]
pub struct Group {
    /// Multicast group address
    pub group_addr: Ipv4Addr,
    /// Current state of the group
    pub state: State,
    /// Group membership timer
    /// When this timer expires, the router assumes there are no more members
    pub group_timer: Option<TimeoutTask>,
    /// Time when group was created
    pub created: DateTime<Utc>,
    /// Last time a report was received for this group
    pub last_reporter: Option<Ipv4Addr>,
    /// Version of last report received (for tracking compatibility)
    pub version: u8,
    /// Filter mode (for IGMPv3 compatibility, always EXCLUDE for v2)
    pub filter_mode: FilterMode,
}

/// Group membership state machine states (RFC 2236 Section 6).
///
/// The state machine transitions based on receiving reports and
/// group membership interval timer expiration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum State {
    /// No local members present.
    /// This is the initial state when no reports have been received,
    /// or when the Group Membership Interval has expired.
    #[default]
    NoMembersPresent,

    /// Members are present.
    /// At least one Membership Report has been received and the
    /// Group Membership Interval timer has not expired.
    MembersPresent,

    /// Checking membership.
    /// A Leave message was received, and the router is sending
    /// Group-Specific Queries to verify if members remain.
    CheckingMembership,
}

/// Filter mode for group (from IGMPv3, dumbed down for v2).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum FilterMode {
    /// Include mode - only receive from specific sources (IGMPv3)
    Include,
    /// Exclude mode - receive from all except specific sources
    /// This is the only mode supported in IGMPv2
    #[default]
    Exclude,
}

/// Events that can trigger state transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum Event {
    /// A Membership Report was received for this group
    ReportReceived,
    /// A Leave Group message was received for this group
    LeaveReceived,
    /// The Group Membership Interval timer expired
    TimerExpired,
    /// Response received to a Group-Specific Query
    QueryResponseReceived,
    /// Last Member Query timer expired with no responses
    LastMemberTimerExpired,
}

// ===== impl Group =====

impl Group {
    /// Create a new group in NoMembersPresent state.
    pub(crate) fn new(group_addr: Ipv4Addr) -> Self {
        Debug::GroupCreate(group_addr).log();

        Group {
            group_addr,
            state: State::NoMembersPresent,
            group_timer: None,
            created: Utc::now(),
            last_reporter: None,
            version: 2, // IGMPv2
            filter_mode: FilterMode::Exclude,
        }
    }

    /// Run the group state machine.
    ///
    /// This processes events and transitions the group between states
    /// according to RFC 2236 Section 6.
    pub(crate) fn fsm(
        &mut self,
        iface: &mut Interface,
        instance: &InstanceUpView<'_>,
        event: Event,
    ) -> Option<State> {
        Debug::GroupEvent(self.group_addr, &self.state, &event).log();

        let old_state = self.state;

        let new_state = match (self.state, event) {
            // State: No Members Present
            // Event: Report Received
            // Action: Start Group Timer, transition to Members Present
            (State::NoMembersPresent, Event::ReportReceived) => {
                self.start_group_timer(iface, instance);
                Some(State::MembersPresent)
            }

            // State: Members Present
            // Event: Report Received
            // Action: Restart Group Timer, stay in Members Present
            (State::MembersPresent, Event::ReportReceived) => {
                self.start_group_timer(iface, instance);
                None // Stay in same state
            }

            // State: Members Present
            // Event: Leave Received
            // Action: Send Group-Specific Query, Start Last Member Timer,
            //         transition to Checking Membership
            (State::MembersPresent, Event::LeaveReceived) => {
                self.start_last_member_query(iface, instance);
                Some(State::CheckingMembership)
            }

            // State: Members Present
            // Event: Timer Expired
            // Action: Transition to No Members Present
            (State::MembersPresent, Event::TimerExpired) => {
                self.group_timer = None;
                Some(State::NoMembersPresent)
            }

            // State: Checking Membership
            // Event: Report Received (response to query)
            // Action: Cancel Last Member Timer, Start Group Timer,
            //         transition to Members Present
            (State::CheckingMembership, Event::ReportReceived) => {
                self.cancel_last_member_timer();
                self.start_group_timer(iface, instance);
                Some(State::MembersPresent)
            }

            // State: Checking Membership
            // Event: Last Member Timer Expired (no responses to queries)
            // Action: Transition to No Members Present
            (State::CheckingMembership, Event::LastMemberTimerExpired) => {
                self.group_timer = None;
                Some(State::NoMembersPresent)
            }

            // All other (state, event) combinations are invalid
            // Stay in current state
            _ => None,
        };

        if let Some(new_state) = new_state {
            Debug::GroupStateChange(self.group_addr, &old_state, &new_state)
                .log();
            self.state = new_state;
        }

        new_state
    }

    /// FSM with configuration values (for report events).
    pub(crate) fn fsm_with_config(
        &mut self,
        instance: &InstanceUpView<'_>,
        event: Event,
        robustness: u8,
        query_interval: u16,
        query_response: u16,
    ) -> Option<State> {
        Debug::GroupEvent(self.group_addr, &self.state, &event).log();

        let old_state = self.state;

        let new_state = match (self.state, event) {
            // State: No Members Present or Members Present
            // Event: Report Received
            // Action: Start/Restart Group Timer, transition to Members Present
            (
                State::NoMembersPresent | State::MembersPresent,
                Event::ReportReceived,
            ) => {
                self.start_group_timer_with_config(
                    robustness,
                    query_interval,
                    query_response,
                );
                if self.state == State::NoMembersPresent {
                    Some(State::MembersPresent)
                } else {
                    None // Stay in Members Present
                }
            }

            // State: Checking Membership
            // Event: Report Received (response to query)
            // Action: Cancel Last Member Timer, Start Group Timer,
            //         transition to Members Present
            (State::CheckingMembership, Event::ReportReceived) => {
                self.cancel_last_member_timer();
                self.start_group_timer_with_config(
                    robustness,
                    query_interval,
                    query_response,
                );
                Some(State::MembersPresent)
            }

            _ => None,
        };

        if let Some(new_state) = new_state {
            Debug::GroupStateChange(self.group_addr, &old_state, &new_state)
                .log();
            self.state = new_state;
        }

        new_state
    }

    /// FSM with configuration values (for leave events).
    pub(crate) fn fsm_with_leave_config(
        &mut self,
        instance: &InstanceUpView<'_>,
        event: Event,
        robustness: u8,
        last_member_interval: u16,
    ) -> Option<State> {
        Debug::GroupEvent(self.group_addr, &self.state, &event).log();

        let old_state = self.state;

        let new_state = match (self.state, event) {
            // State: Members Present
            // Event: Leave Received
            // Action: Send Group-Specific Query, Start Last Member Timer,
            //         transition to Checking Membership
            (State::MembersPresent, Event::LeaveReceived) => {
                self.start_last_member_query_with_config(
                    robustness,
                    last_member_interval,
                );
                Some(State::CheckingMembership)
            }

            _ => None,
        };

        if let Some(new_state) = new_state {
            Debug::GroupStateChange(self.group_addr, &old_state, &new_state)
                .log();
            self.state = new_state;
        }

        new_state
    }

    /// Start or restart the group membership timer.
    ///
    /// This timer is set to the Group Membership Interval when a report
    /// is received. If it expires, the group transitions to No Members Present.
    fn start_group_timer(
        &mut self,
        iface: &Interface,
        instance: &InstanceUpView<'_>,
    ) {
        // Cancel existing timer if any
        self.group_timer = None;

        // Calculate timeout: Group Membership Interval
        // = (Robustness Variable × Query Interval) + (Query Response Interval)
        let robustness = iface.config.robustness_variable as u32;
        let query_interval = iface.config.query_interval as u32;
        let query_response = iface.config.query_max_response_time as u32;

        let timeout_secs = (robustness * query_interval) + (query_response / 2);

        // TODO: Start actual timer task

        Debug::GroupTimerStart(self.group_addr, timeout_secs).log();
    }

    /// Start group timer with explicit config values
    fn start_group_timer_with_config(
        &mut self,
        robustness: u8,
        query_interval: u16,
        query_response: u16,
    ) {
        self.group_timer = None;

        let robustness = robustness as u32;
        let query_interval = query_interval as u32;
        let query_response = query_response as u32;

        let timeout_secs =
            (robustness * query_interval) + (query_response / 10);

        // TODO: Start actual timer task

        Debug::GroupTimerStart(self.group_addr, timeout_secs).log();
    }

    /// Start the Last Member Query timer and send Group-Specific Queries.
    ///
    /// When a Leave is received, the router sends Last Member Query Count
    /// Group-Specific Queries, separated by Last Member Query Interval.
    fn start_last_member_query(
        &mut self,
        iface: &Interface,
        instance: &InstanceUpView<'_>,
    ) {
        // RFC 2236: Last Member Query Count defaults to Robustness Variable
        let last_member_query_count = iface.config.robustness_variable as u32;
        let last_member_query_interval =
            iface.config.last_member_query_interval as u32;

        // TODO: Send Group-Specific Query

        // TODO: Start Last Member timer

        Debug::GroupLastMemberQuery(
            self.group_addr,
            last_member_query_count,
            last_member_query_interval,
        )
        .log();
    }

    /// Start last member query with explicit config
    fn start_last_member_query_with_config(
        &mut self,
        robustness: u8,
        last_member_interval: u16,
    ) {
        let last_member_query_count = robustness as u32;
        let last_member_query_interval = last_member_interval as u32;

        // TODO: Send Group-Specific Query and start timer

        Debug::GroupLastMemberQuery(
            self.group_addr,
            last_member_query_count,
            last_member_query_interval,
        )
        .log();
    }

    /// Cancel the last member query timer.
    fn cancel_last_member_timer(&mut self) {
        if self.group_timer.is_some() {
            Debug::GroupTimerCancel(self.group_addr).log();
            self.group_timer = None;
        }
    }

    /// Update the last reporter information.
    pub(crate) fn update_reporter(&mut self, reporter: Ipv4Addr) {
        self.last_reporter = Some(reporter);
    }
}

// ===== impl State =====

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::NoMembersPresent => write!(f, "No Members Present"),
            State::MembersPresent => write!(f, "Members Present"),
            State::CheckingMembership => write!(f, "Checking Membership"),
        }
    }
}

// ===== impl Event =====

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::ReportReceived => write!(f, "Report Received"),
            Event::LeaveReceived => write!(f, "Leave Received"),
            Event::TimerExpired => write!(f, "Timer Expired"),
            Event::QueryResponseReceived => {
                write!(f, "Query Response Received")
            }
            Event::LastMemberTimerExpired => {
                write!(f, "Last Member Timer Expired")
            }
        }
    }
}
