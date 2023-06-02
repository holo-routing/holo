//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock as Lazy, Mutex};

use holo_utils::ip::AddressFamily;
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid, SrCfg};

use crate::area::Area;
use crate::collections::Arena;
use crate::error::Error;
use crate::instance::InstanceUpView;
use crate::interface::Interface;
use crate::lsdb::LsaEntry;
use crate::neighbor::Neighbor;
use crate::northbound::notification;
use crate::packet::lsa::{AdjSidVersion, PrefixSidVersion};
use crate::packet::tlv::{PrefixSidFlags, SidLabelRangeTlv};
use crate::route::RouteNet;
use crate::version::Version;

// Segment Routing global configuration.
pub static CONFIG: Lazy<Mutex<Arc<SrCfg>>> =
    Lazy::new(|| Mutex::new(Arc::new(SrCfg::default())));

// ===== global functions =====

// Update the Prefix-SID labels of the provided route.
pub(crate) fn prefix_sid_update<V>(
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    adv_rtr: Ipv4Addr,
    route: &mut RouteNet<V>,
    prefix_sid: &V::PrefixSid,
    local: bool,
    last_hop: bool,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    // A router receiving a Prefix-SID from a remote node and with an algorithm
    // value that the remote node has not advertised in the SR-Algorithm TLV
    // MUST ignore the Prefix-SID Sub- TLV.
    let ri = V::area_router_information(&area.state.lsdb, adv_rtr, lsa_entries);
    if ri
        .sr_algo
        .map(|sr_algo| sr_algo.get().contains(&IgpAlgoType::Spf))
        .is_none()
    {
        return;
    }

    // Update SR Prefix-SID.
    route.prefix_sid = Some(*prefix_sid);

    // Update SR input label.
    match prefix_sid_input_label(area, instance, prefix_sid, local, lsa_entries)
    {
        Ok(label) => route.sr_label = label,
        Err(error) => error.log(),
    }

    // Update SR output labels.
    for nexthop in route.nexthops.values_mut() {
        match prefix_sid_output_label(
            area,
            instance,
            nexthop.nbr_router_id.unwrap(),
            prefix_sid,
            last_hop,
            lsa_entries,
        ) {
            Ok(label) => nexthop.sr_label = Some(label),
            Err(error) => error.log(),
        }
    }
}

// Adds SR Adj-SID.
pub(crate) fn adj_sid_add<V>(
    nbr: &mut Neighbor<V>,
    iface: &Interface<V>,
    instance: &InstanceUpView<'_, V>,
) where
    V: Version,
{
    let label = dynamic_label_request();
    let nbr_router_id = iface.is_broadcast_or_nbma().then_some(nbr.router_id);
    let adj_sid = V::AdjSid::new(label, 0, nbr_router_id);
    instance.tx.sb.adj_sid_install(iface, nbr.src, label);
    nbr.adj_sids.push(adj_sid);
}

// Deletes all Adj-SIDs associated to the provided neighbor.
pub(crate) fn adj_sid_del_all<V>(
    nbr: &mut Neighbor<V>,
    instance: &InstanceUpView<'_, V>,
) where
    V: Version,
{
    let adj_sids = std::mem::take(&mut nbr.adj_sids);
    for label in adj_sids
        .into_iter()
        .filter_map(|adj_sid| adj_sid.sid().as_label().copied())
    {
        dynamic_label_release(label);
        instance.tx.sb.adj_sid_uninstall(label);
    }
}

// ===== helper functions =====

// Resolve Prefix-SID to MPLS input label.
fn prefix_sid_input_label<V>(
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    prefix_sid: &V::PrefixSid,
    local: bool,
    lsa_entries: &Arena<LsaEntry<V>>,
) -> Result<Option<Label>, Error<V>>
where
    V: Version,
{
    // Do not assign a label for local Prefix-SIDs unless the NP-Flag is
    // set and the E-Flag is unset.
    if local
        && (!prefix_sid.flags().contains(PrefixSidFlags::NP)
            || prefix_sid.flags().contains(PrefixSidFlags::E))
    {
        return Ok(None);
    }

    // Get resolved MPLS label.
    let label = match prefix_sid.sid() {
        Sid::Index(index) => {
            // Get local SRGB.
            let router_id = instance.state.router_id;
            let ri = V::area_router_information(
                &area.state.lsdb,
                router_id,
                lsa_entries,
            );
            if ri.srgb.is_empty() {
                return Err(Error::SrgbNotFound(area.area_id, router_id));
            }
            index_to_label(instance, router_id, index, &ri.srgb)?
        }
        Sid::Label(label) => {
            // Absolute label (V/L flags are set).
            label
        }
    };

    Ok(Some(label))
}

// Resolve Prefix-SID to MPLS output label.
fn prefix_sid_output_label<V>(
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    nbr_router_id: Ipv4Addr,
    prefix_sid: &V::PrefixSid,
    last_hop: bool,
    lsa_entries: &Arena<LsaEntry<V>>,
) -> Result<Label, Error<V>>
where
    V: Version,
{
    if last_hop {
        // TODO: handle the M-Flag (Mapping Server Flag).

        // Handle the NP-Flag.
        if !prefix_sid.flags().contains(PrefixSidFlags::NP) {
            let label = Label::IMPLICIT_NULL;
            return Ok(Label::new(label));
        }

        // Handle the E-Flag.
        if prefix_sid.flags().contains(PrefixSidFlags::E) {
            let label = match instance.state.af {
                AddressFamily::Ipv4 => Label::IPV4_EXPLICIT_NULL,
                AddressFamily::Ipv6 => Label::IPV6_EXPLICIT_NULL,
            };
            return Ok(Label::new(label));
        }
    }

    // Get resolved MPLS label.
    match prefix_sid.sid() {
        Sid::Index(index) => {
            // Get SRGB of the nexthop router.
            let ri = V::area_router_information(
                &area.state.lsdb,
                nbr_router_id,
                lsa_entries,
            );
            if ri.srgb.is_empty() {
                return Err(Error::SrgbNotFound(area.area_id, nbr_router_id));
            }
            index_to_label(instance, nbr_router_id, index, &ri.srgb)
        }
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
fn index_to_label<V>(
    instance: &InstanceUpView<'_, V>,
    nbr_router_id: Ipv4Addr,
    mut index: u32,
    srgbs: &[&SidLabelRangeTlv],
) -> Result<Label, Error<V>>
where
    V: Version,
{
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

    notification::sr_index_out_of_range(instance, nbr_router_id, index);
    Err(Error::InvalidSidIndex(index))
}

// Requests dynamic MPLS label to the label manager.
//
// TODO: write actual label manager :)
fn dynamic_label_request() -> Label {
    static NEXT: AtomicU32 = AtomicU32::new(*Label::UNRESERVED_RANGE.start());

    Label::new(NEXT.fetch_add(1, Ordering::Relaxed))
}

// Releases dynamic MPLS label from the label manager.
//
// TODO: write actual label manager :)
fn dynamic_label_release(_label: Label) {}
