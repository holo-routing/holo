//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::borrow::Cow;

use bytes::Bytes;
use holo_northbound::{notification, yang};
use holo_utils::option::OptionExt;
use holo_yang::ToYang;

use crate::adjacency::{Adjacency, AdjacencyEvent, AdjacencyState};
use crate::error::AdjacencyRejectError;
use crate::instance::InstanceUpView;
use crate::interface::Interface;
use crate::packet::SystemId;
use crate::packet::pdu::Lsp;

// ===== global functions =====

pub(crate) fn database_overload(instance: &InstanceUpView<'_>, overload: bool) {
    use yang::database_overload::{self, DatabaseOverload};

    let path = database_overload::PATH;
    let overload = if overload { "on" } else { "off" };
    let data = DatabaseOverload {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        overload: Some(Cow::Borrowed(overload)),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn lsp_too_large(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    lsp: &Lsp,
) {
    use yang::lsp_too_large::{self, LspTooLarge};

    let path = lsp_too_large::PATH;
    let data = LspTooLarge {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        pdu_size: Some(lsp.raw.len() as u32),
        lsp_id: Some(lsp.lsp_id.to_yang()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn if_state_change(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    up: bool,
) {
    use yang::isis_if_state_change::{self, IsisIfStateChange};

    let path = isis_if_state_change::PATH;
    let state = if up { "up" } else { "down" };
    let data = IsisIfStateChange {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        state: Some(state.into()),
    };
    notification::send(&instance.tx.nb, path, data);
}

#[expect(unused)]
pub(crate) fn corrupted_lsp_detected(instance: &InstanceUpView<'_>, lsp: &Lsp) {
    use yang::corrupted_lsp_detected::{self, CorruptedLspDetected};

    let path = corrupted_lsp_detected::PATH;
    let data = CorruptedLspDetected {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        lsp_id: Some(lsp.lsp_id.to_yang()),
    };
    notification::send(&instance.tx.nb, path, data);
}

#[expect(unused)]
pub(crate) fn attempt_to_exceed_max_sequence(
    instance: &InstanceUpView<'_>,
    lsp: &Lsp,
) {
    use yang::attempt_to_exceed_max_sequence::{
        self, AttemptToExceedMaxSequence,
    };

    let path = attempt_to_exceed_max_sequence::PATH;
    let data = AttemptToExceedMaxSequence {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        lsp_id: Some(lsp.lsp_id.to_yang()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn id_len_mismatch(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    pdu_id_len: u8,
    raw_pdu: &Bytes,
) {
    use yang::id_len_mismatch::{self, IdLenMismatch};

    let path = id_len_mismatch::PATH;
    let data = IdLenMismatch {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        pdu_field_len: Some(pdu_id_len),
        raw_pdu: Some(raw_pdu.as_ref()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn max_area_addresses_mismatch(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    pdu_max_area_addrs: u8,
    raw_pdu: &Bytes,
) {
    use yang::max_area_addresses_mismatch::{self, MaxAreaAddressesMismatch};

    let path = max_area_addresses_mismatch::PATH;
    let data = MaxAreaAddressesMismatch {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        max_area_addresses: Some(pdu_max_area_addrs),
        raw_pdu: Some(raw_pdu.as_ref()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn own_lsp_purge(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    lsp: &Lsp,
) {
    use yang::own_lsp_purge::{self, OwnLspPurge};

    let path = own_lsp_purge::PATH;
    let data = OwnLspPurge {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        lsp_id: Some(lsp.lsp_id.to_yang()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn sequence_number_skipped(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    lsp: &Lsp,
) {
    use yang::sequence_number_skipped::{self, SequenceNumberSkipped};

    let path = sequence_number_skipped::PATH;
    let data = SequenceNumberSkipped {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        lsp_id: Some(lsp.lsp_id.to_yang()),
    };
    notification::send(&instance.tx.nb, path, data);
}

#[expect(unused)]
pub(crate) fn authentication_type_failure(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    raw_pdu: &Bytes,
) {
    use yang::authentication_type_failure::{self, AuthenticationTypeFailure};

    let path = authentication_type_failure::PATH;
    let data = AuthenticationTypeFailure {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        raw_pdu: Some(raw_pdu.as_ref()),
    };
    notification::send(&instance.tx.nb, path, data);
}

#[expect(unused)]
pub(crate) fn authentication_failure(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    raw_pdu: &Bytes,
) {
    use yang::authentication_failure::{self, AuthenticationFailure};

    let path = authentication_failure::PATH;
    let data = AuthenticationFailure {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        raw_pdu: Some(raw_pdu.as_ref()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn version_skew(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    version: u8,
    raw_pdu: &Bytes,
) {
    use yang::version_skew::{self, VersionSkew};

    let path = version_skew::PATH;
    let data = VersionSkew {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        protocol_version: Some(version),
        raw_pdu: Some(raw_pdu.as_ref()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn area_mismatch(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    raw_pdu: &Bytes,
) {
    use yang::area_mismatch::{self, AreaMismatch};

    let path = area_mismatch::PATH;
    let data = AreaMismatch {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        raw_pdu: Some(raw_pdu.as_ref()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn rejected_adjacency(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    raw_pdu: &Bytes,
    reason: &AdjacencyRejectError,
) {
    use yang::rejected_adjacency::{self, RejectedAdjacency};

    let path = rejected_adjacency::PATH;
    let data = RejectedAdjacency {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        raw_pdu: Some(raw_pdu.as_ref()),
        reason: Some(reason.to_yang()),
    };
    notification::send(&instance.tx.nb, path, data);
}

#[expect(unused)]
pub(crate) fn protocols_supported_mismatch(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    raw_pdu: &Bytes,
) {
    use yang::protocols_supported_mismatch::{
        self, ProtocolsSupportedMismatch,
    };

    let path = protocols_supported_mismatch::PATH;
    let data = ProtocolsSupportedMismatch {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        raw_pdu: Some(raw_pdu.as_ref()),
        protocols: None,
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn lsp_error_detected(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    lsp: &Lsp,
) {
    use yang::lsp_error_detected::{self, LspErrorDetected};

    let path = lsp_error_detected::PATH;
    let data = LspErrorDetected {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        lsp_id: Some(lsp.lsp_id.to_yang()),
        raw_pdu: Some(lsp.raw.as_ref()),
        error_offset: None,
        tlv_type: None,
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn adjacency_state_change(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    adj: &Adjacency,
    state: AdjacencyState,
    event: AdjacencyEvent,
) {
    use yang::adjacency_state_change::{self, AdjacencyStateChange};

    let path = adjacency_state_change::PATH;
    let data = AdjacencyStateChange {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        neighbor: None,
        neighbor_system_id: Some(adj.system_id.to_yang()),
        state: Some(state.to_yang()),
        reason: (state == AdjacencyState::Up).then_some(event.to_yang()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn lsp_received(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    lsp: &Lsp,
    system_id: &SystemId,
) {
    use yang::lsp_received::{self, LspReceived};

    let path = lsp_received::PATH;
    let data = LspReceived {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        interface_name: Some(Cow::Borrowed(&iface.name)),
        interface_level: Some(iface.config.level_type.resolved.to_yang()),
        extended_circuit_id: None,
        lsp_id: Some(lsp.lsp_id.to_yang()),
        sequence: Some(lsp.seqno),
        received_timestamp: lsp
            .base_time
            .as_ref()
            .map(Cow::Borrowed)
            .ignore_in_testing(),
        neighbor_system_id: Some(system_id.to_yang()),
    };
    notification::send(&instance.tx.nb, path, data);
}

pub(crate) fn lsp_generation(instance: &InstanceUpView<'_>, lsp: &Lsp) {
    use yang::lsp_generation::{self, LspGeneration};

    let path = lsp_generation::PATH;
    let data = LspGeneration {
        routing_protocol_name: Some(Cow::Borrowed(instance.name)),
        isis_level: Some(instance.config.level_type.to_yang()),
        lsp_id: Some(lsp.lsp_id.to_yang()),
        sequence: Some(lsp.seqno),
        send_timestamp: lsp.base_time.as_ref().map(Cow::Borrowed),
    };
    notification::send(&instance.tx.nb, path, data);
}
