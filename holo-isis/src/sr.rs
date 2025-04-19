//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::IpAddr;

use holo_utils::ip::AddressFamily;
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};

use crate::adjacency::{Adjacency, AdjacencySid};
use crate::collections::Arena;
use crate::error::Error;
use crate::instance::InstanceUpView;
use crate::interface::{Interface, InterfaceType};
use crate::lsdb::LspEntry;
use crate::northbound::notification;
use crate::packet::subtlvs::capability::{
    LabelBlockEntry, SrCapabilitiesFlags,
};
use crate::packet::subtlvs::prefix::{PrefixSidFlags, PrefixSidStlv};
use crate::packet::{LanId, LevelNumber, SystemId};
use crate::route::Route;
use crate::southbound;

// ===== global functions =====

// Update the Prefix-SID labels of the provided route.
pub(crate) fn prefix_sid_update(
    instance: &InstanceUpView<'_>,
    level: LevelNumber,
    adv_rtr: LanId,
    af: AddressFamily,
    route: &mut Route,
    local: bool,
    last_hop: bool,
    lsp_entries: &Arena<LspEntry>,
) {
    let Some(prefix_sid) = &route.prefix_sid else {
        return;
    };

    // A router receiving a Prefix-SID from a remote node and with an algorithm
    // value that the remote node has not advertised in the SR-Algorithm TLV
    // MUST ignore the Prefix-SID Sub-TLV.
    let lsdb = instance.state.lsdb.get(level);
    if !lsdb
        .iter_for_lan_id(lsp_entries, adv_rtr)
        .map(|lse| &lse.data)
        .filter(|lsp| lsp.rem_lifetime != 0)
        .filter(|lsp| lsp.seqno != 0)
        .filter_map(|lsp| lsp.tlvs.sr_algos())
        .any(|sr_algos| sr_algos.get().contains(&IgpAlgoType::Spf))
    {
        return;
    }

    // Update SR input label.
    match prefix_sid_input_label(
        instance,
        level,
        prefix_sid,
        local,
        lsp_entries,
    ) {
        Ok(label) => route.sr_label = label,
        Err(_error) => {
            // TODO: log error.
        }
    }

    // Update SR output labels.
    for nexthop in route.nexthops.values_mut() {
        match prefix_sid_output_label(
            instance,
            level,
            af,
            prefix_sid,
            nexthop.system_id,
            last_hop,
            lsp_entries,
        ) {
            Ok(label) => nexthop.sr_label = Some(label),
            Err(_error) => {
                // TODO: log error.
            }
        }
    }
}

// Adds SR Adjacency SIDs to the given adjacency.
pub(crate) fn adj_sids_add(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    adj: &mut Adjacency,
) {
    let mut label_manager = instance.shared.label_manager.lock().unwrap();

    // Include neighbor System ID if the interface is broadcast.
    let nbr_system_id = (iface.config.interface_type
        == InterfaceType::Broadcast)
        .then_some(adj.system_id);

    // Iterate over enabled address families for the interface.
    for af in [AddressFamily::Ipv4, AddressFamily::Ipv6]
        .into_iter()
        .filter(|af| iface.config.is_af_enabled(*af, instance.config))
    {
        // Allocate a label and create a new Adjacency SID.
        let label = label_manager.label_request().unwrap();
        let adj_sid = AdjacencySid::new(af, label, nbr_system_id);
        adj.adj_sids.push(adj_sid);

        // Get the first IP address for the current address family.
        let addr = match af {
            AddressFamily::Ipv4 => {
                adj.ipv4_addrs.first().copied().map(IpAddr::from)
            }
            AddressFamily::Ipv6 => {
                adj.ipv6_addrs.first().copied().map(IpAddr::from)
            }
        };

        // Install the Adjacency SID if we have an address.
        if let Some(addr) = addr {
            southbound::tx::adj_sid_install(
                &instance.tx.ibus,
                iface,
                addr,
                label,
            );
        }
    }
}

// Deletes all SR Adjacency SIDs from the given adjacency.
pub(crate) fn adj_sids_del(instance: &InstanceUpView<'_>, adj: &mut Adjacency) {
    let mut label_manager = instance.shared.label_manager.lock().unwrap();

    // Remove and process each existing Adjacency SID.
    for adj_sid in std::mem::take(&mut adj.adj_sids) {
        let label = adj_sid.label;

        // Release and uninstall the Adjacency SID label.
        label_manager.label_release(label);
        southbound::tx::adj_sid_uninstall(&instance.tx.ibus, label);
    }
}

// ===== helper functions =====

// Resolves Prefix-SID to MPLS input label.
fn prefix_sid_input_label(
    instance: &InstanceUpView<'_>,
    level: LevelNumber,
    prefix_sid: &PrefixSidStlv,
    local: bool,
    lsp_entries: &Arena<LspEntry>,
) -> Result<Option<Label>, Error> {
    // Do not assign a label for local Prefix-SIDs unless the N-Flag is
    // set and the E-Flag is unset.
    if local
        && (!prefix_sid.flags.contains(PrefixSidFlags::N)
            || prefix_sid.flags.contains(PrefixSidFlags::E))
    {
        return Ok(None);
    }

    // Get resolved MPLS label.
    let label = match prefix_sid.sid {
        Sid::Index(index) => {
            // Get local SRGB.
            let system_id = instance.config.system_id.unwrap();
            let lsdb = instance.state.lsdb.get(level);
            let Some(sr_cap) = lsdb
                .iter_for_system_id(lsp_entries, system_id)
                .map(|lse| &lse.data)
                .filter(|lsp| lsp.rem_lifetime != 0)
                .filter(|lsp| lsp.seqno != 0)
                .find_map(|lsp| lsp.tlvs.sr_cap())
            else {
                return Err(Error::SrCapNotFound(level, system_id));
            };
            index_to_label(instance, system_id, index, &sr_cap.srgb_entries)?
        }
        Sid::Label(label) => {
            // Absolute label (V/L flags are set).
            label
        }
    };

    Ok(Some(label))
}

// Resolves Prefix-SID to MPLS output label.
fn prefix_sid_output_label(
    instance: &InstanceUpView<'_>,
    level: LevelNumber,
    af: AddressFamily,
    prefix_sid: &PrefixSidStlv,
    nexthop_system_id: SystemId,
    last_hop: bool,
    lsp_entries: &Arena<LspEntry>,
) -> Result<Label, Error> {
    // Handle the N-Flag.
    if last_hop && !prefix_sid.flags.contains(PrefixSidFlags::N) {
        let label = Label::IMPLICIT_NULL;
        return Ok(Label::new(label));
    }

    // Get SR capabilities of the next-hop router.
    let lsdb = instance.state.lsdb.get(level);
    let Some(sr_cap) = lsdb
        .iter_for_system_id(lsp_entries, nexthop_system_id)
        .map(|lse| &lse.data)
        .filter(|lsp| lsp.rem_lifetime != 0)
        .filter(|lsp| lsp.seqno != 0)
        .find_map(|lsp| lsp.tlvs.sr_cap())
    else {
        return Err(Error::SrCapNotFound(level, nexthop_system_id));
    };

    // Check whether the next-hop router supports SR-MPLS for the given address
    // family.
    let af_flag = match af {
        AddressFamily::Ipv4 => SrCapabilitiesFlags::I,
        AddressFamily::Ipv6 => SrCapabilitiesFlags::V,
    };
    if !sr_cap.flags.contains(af_flag) {
        return Err(Error::SrCapUnsupportedAf(level, nexthop_system_id, af));
    }

    // Handle the E-Flag.
    if last_hop && prefix_sid.flags.contains(PrefixSidFlags::E) {
        let label = match af {
            AddressFamily::Ipv4 => Label::IPV4_EXPLICIT_NULL,
            AddressFamily::Ipv6 => Label::IPV6_EXPLICIT_NULL,
        };
        return Ok(Label::new(label));
    }

    // Get resolved MPLS label.
    match prefix_sid.sid {
        Sid::Index(index) => index_to_label(
            instance,
            nexthop_system_id,
            index,
            &sr_cap.srgb_entries,
        ),
        Sid::Label(label) => {
            // V/L SIDs have local significance, so only adjacent routers can
            // use them.
            if last_hop {
                Ok(label)
            } else {
                Ok(Label::new(Label::IMPLICIT_NULL))
            }
        }
    }
}

// Maps SID index to MPLS label value.
fn index_to_label(
    instance: &InstanceUpView<'_>,
    system_id: SystemId,
    mut index: u32,
    srgbs: &[LabelBlockEntry],
) -> Result<Label, Error> {
    for srgb in srgbs {
        let first = match srgb.first {
            Sid::Label(label) => label,
            Sid::Index(_) => {
                // SID ranges are rather obscure. What are they useful for?
                continue;
            }
        };

        if index >= srgb.range {
            // SID index falls outside the MPLS label range. Check the next one.
            index -= srgb.range;
            continue;
        }

        // Compute the MPLS label by adding the SID index (minus the previous
        // SRGB ranges sizes) to the current SRGB lower bound.
        let label = first.get() + index;
        return Ok(Label::new(label));
    }

    notification::sr_index_out_of_range(instance, system_id, index);
    Err(Error::InvalidSidIndex(index))
}
