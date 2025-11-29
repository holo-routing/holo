//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use crate::error::Error;
use crate::group::Event as GroupEvent;
use crate::instance::Instance;
use crate::packet::{DecodeResult, Packet};

// ===== Network packet receipt =====

pub(crate) fn process_packet(
    instance: &mut Instance,
    ifindex: u32,
    src: Ipv4Addr,
    packet: DecodeResult<Packet>,
) -> Result<(), Error> {
    // Lookup interface.
    let Some((mut instance_view, interfaces)) = instance.as_up() else {
        return Ok(());
    };
    let Some(iface) = interfaces
        .values_mut()
        .find(|iface| iface.system.ifindex == Some(ifindex))
    else {
        return Ok(());
    };

    // Decode packet.
    let packet = match packet {
        Ok(packet) => packet,
        Err(error) => {
            tracing::warn!(
                ifname = %iface.name,
                %src,
                ?error,
                "failed to decode IGMP packet"
            );
            // TODO: Update error statistics
            return Ok(());
        }
    };

    tracing::debug!(
        ifname = %iface.name,
        %src,
        ?packet,
        "received IGMP packet"
    );

    // Process packet based on type.
    match packet {
        Packet::MembershipReport(report) => {
            process_membership_report(
                iface,
                &mut instance_view,
                src,
                report.group_address,
            )?;
        }
        Packet::LeaveGroup(leave) => {
            process_leave_group(
                iface,
                &mut instance_view,
                src,
                leave.group_address,
            )?;
        }
    }

    Ok(())
}

/// Process an IGMP Membership Report 
///
/// When a router receives a Membership Report for a group, it creates
/// or updates the group state and transitions to Members Present state.
fn process_membership_report(
    iface: &mut crate::interface::Interface,
    instance: &mut crate::instance::InstanceUpView<'_>,
    src: Ipv4Addr,
    group_addr: Option<Ipv4Addr>,
) -> Result<(), Error> {
    let Some(group_addr) = group_addr else {
        tracing::warn!(
            ifname = %iface.name,
            %src,
            "membership report missing group address"
        );
        return Ok(());
    };

    tracing::debug!(
        ifname = %iface.name,
        %src,
        %group_addr,
        "processing membership report"
    );

    // Get interface configuration values before borrowing group
    let robustness = iface.config.robustness_variable;
    let query_interval = iface.config.query_interval;
    let query_response = iface.config.query_max_response_time;

    // Get or create the group.
    let group = iface.get_or_create_group(group_addr);

    // Update reporter information.
    group.update_reporter(src);

    // Trigger state machine event.
    group.fsm_with_config(
        instance,
        GroupEvent::ReportReceived,
        robustness,
        query_interval,
        query_response,
    );

    // Update statistics
    instance.state.statistics.msgs_rcvd.report += 1;
    instance.state.statistics.msgs_rcvd.total += 1;

    Ok(())
}

/// Process an IGMP Leave Group message.
///
/// When a router receives a Leave message, it transitions the group
/// to Checking Membership state and sends Group-Specific Queries.
fn process_leave_group(
    iface: &mut crate::interface::Interface,
    instance: &mut crate::instance::InstanceUpView<'_>,
    src: Ipv4Addr,
    group_addr: Option<Ipv4Addr>,
) -> Result<(), Error> {
    let Some(group_addr) = group_addr else {
        tracing::warn!(
            ifname = %iface.name,
            %src,
            "leave group missing group address"
        );
        return Ok(());
    };

    tracing::debug!(
        ifname = %iface.name,
        %src,
        %group_addr,
        "processing leave group"
    );

    // Get configuration
    let robustness = iface.config.robustness_variable;
    let query_interval = iface.config.query_interval;
    let query_response = iface.config.query_max_response_time;
    let last_member_interval = iface.config.last_member_query_interval;

    // Look up the group.
    let Some(group) = iface.get_group_mut(&group_addr) else {
        // No group state exists, ignore the leave.
        tracing::debug!(
            ifname = %iface.name,
            %group_addr,
            "ignoring leave for unknown group"
        );
        return Ok(());
    };

    // TODO Only process Leave if we're the querier.


    // Trigger state machine event.
    group.fsm_with_leave_config(
        instance,
        GroupEvent::LeaveReceived,
        robustness,
        last_member_interval,
    );

    // Update statistics
    instance.state.statistics.msgs_rcvd.leave += 1;
    instance.state.statistics.msgs_rcvd.total += 1;

    Ok(())
}
