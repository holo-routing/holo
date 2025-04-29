//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::time::Duration;

use crate::area::Area;
use crate::debug::{Debug, GrRejectReason};
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{Interface, ism};
use crate::lsdb::LsaOriginateEvent;
use crate::neighbor::{Neighbor, NeighborGrHelper, nsm};
use crate::northbound::notification;
use crate::packet::lsa::{LsaHdrVersion, LsaTypeVersion};
use crate::packet::tlv::GrReason;
use crate::tasks;
use crate::version::Version;

// OSPF Graceful Restart exit reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrExitReason {
    Completed,
    TimedOut,
    TopologyChanged,
}

// ===== impl GrExitReason =====

impl std::fmt::Display for GrExitReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrExitReason::Completed => {
                write!(f, "completed")
            }
            GrExitReason::TimedOut => {
                write!(f, "timed out")
            }
            GrExitReason::TopologyChanged => {
                write!(f, "topology changed")
            }
        }
    }
}

// ===== global functions =====

pub(crate) fn helper_process_grace_lsa<V>(
    nbr: &mut Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    lsa_hdr: &V::LsaHdr,
    grace_period: u32,
    reason: GrReason,
    instance: &mut InstanceUpView<'_, V>,
) where
    V: Version,
{
    if lsa_hdr.is_maxage() {
        // Exit from the helper mode.
        if nbr.gr.is_some() {
            helper_exit(nbr, iface, area, GrExitReason::Completed, instance);
        }
    } else {
        // Calculate the remaining grace period.
        let remn_grace_period = grace_period - lsa_hdr.age() as u32;

        // If we're already helping this neighbor, just restart the grace period
        // timeout.
        if let Some(gr) = &mut nbr.gr {
            gr.grace_period
                .reset(Some(Duration::from_secs(remn_grace_period.into())));
            return;
        }

        // Check if the neighbor is fully adjacent.
        if nbr.state != nsm::State::Full {
            let reason = GrRejectReason::NeighborNotFull;
            Debug::<V>::GrHelperReject(nbr.router_id, reason).log();
            return;
        }

        // Check for topology changes in the LSDB since the neighbor restarted.
        if instance.config.gr.helper_strict_lsa_checking
            && nbr
                .lists
                .ls_rxmt
                .values()
                .any(|lsa| lsa.hdr.lsa_type().is_gr_topology_info())
        {
            let reason = GrRejectReason::TopologyChange;
            Debug::<V>::GrHelperReject(nbr.router_id, reason).log();
            return;
        }

        // Check if the grace period has already expired.
        if lsa_hdr.age() as u32 >= grace_period {
            let reason = GrRejectReason::GracePeriodExpired;
            Debug::<V>::GrHelperReject(nbr.router_id, reason).log();
            return;
        }

        // Check if helper mode is enabled in the configuration.
        if !instance.config.gr.helper_enabled {
            let reason = GrRejectReason::HelperDisabled;
            Debug::<V>::GrHelperReject(nbr.router_id, reason).log();
            return;
        }

        // All checks have passed. Enter helper mode.
        helper_enter(nbr, iface, area, remn_grace_period, reason, instance);
    }
}

pub(crate) fn helper_process_topology_change<V>(
    lsa_type: Option<V::LsaType>,
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
) where
    V: Version,
{
    // Iterate over all neighbors.
    for area in arenas.areas.iter() {
        let area_type = area.config.area_type;
        for iface in area.interfaces.iter(&arenas.interfaces) {
            for nbr_idx in iface.state.neighbors.indexes() {
                let nbr = &mut arenas.neighbors[nbr_idx];
                if nbr.gr.is_none() {
                    continue;
                }

                // Check if the LSA was flooded to the neighbor.
                if let Some(lsa_type) = lsa_type
                    && !V::lsa_type_is_valid(Some(area_type), None, lsa_type)
                {
                    continue;
                }

                // Exit from the helper mode for this neighbor.
                helper_exit(
                    nbr,
                    iface,
                    area,
                    GrExitReason::TopologyChanged,
                    instance,
                );
            }
        }
    }
}

pub(crate) fn helper_exit<V>(
    nbr: &mut Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    reason: GrExitReason,
    instance: &mut InstanceUpView<'_, V>,
) where
    V: Version,
{
    Debug::<V>::GrHelperExit(nbr.router_id, reason).log();
    notification::nbr_restart_helper_exit(instance, iface, nbr, reason);

    // Stop the grace period timeout.
    nbr.gr = None;

    // Recalculate the Designated Router for the segment.
    if iface.is_broadcast_or_nbma() {
        instance.tx.protocol_input.ism_event(
            area.id,
            iface.id,
            ism::Event::NbrChange,
        );
    }

    // Reoriginate the Router-LSA and, if needed, the Network-LSA for the
    // segment's OSPF area.
    instance.tx.protocol_input.lsa_orig_event(
        LsaOriginateEvent::GrHelperExit {
            area_id: area.id,
            iface_id: iface.id,
        },
    );

    // Decrement the count of neighbors performing a graceful restart.
    instance.state.gr_helper_count -= 1;
}

// ===== helper functions =====

fn helper_enter<V>(
    nbr: &mut Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    grace_period: u32,
    restart_reason: GrReason,
    instance: &mut InstanceUpView<'_, V>,
) where
    V: Version,
{
    Debug::<V>::GrHelperEnter(nbr.router_id, restart_reason, grace_period)
        .log();
    notification::nbr_restart_helper_enter(instance, iface, nbr, grace_period);

    // Start the grace period timeout.
    let grace_period =
        tasks::grace_period_timer(nbr, iface, area, instance, grace_period);

    // Store information that this neighbor is undergoing a graceful restart.
    nbr.gr = Some(NeighborGrHelper {
        restart_reason,
        grace_period,
    });

    // Increment the count of neighbors performing a graceful restart.
    instance.state.gr_helper_count += 1;
}
