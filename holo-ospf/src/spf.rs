//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use derive_new::new;
use holo_utils::ip::AddressFamily;
use holo_utils::sr::IgpAlgoType;

use crate::area::Area;
use crate::collections::{Areas, Arena, Lsdb};
use crate::debug::Debug;
use crate::error::Error;
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::Interface;
use crate::lsdb::{LsaEntry, LsaLogId};
use crate::neighbor::Neighbor;
use crate::packet::lsa::{Lsa, LsaKey};
use crate::packet::tlv::{SidLabelRangeTlv, SrAlgoTlv};
use crate::route::{Nexthops, PathType, RouteRtr};
use crate::version::Version;
use crate::{area, route, tasks};

// Maximum size of the SPF log record.
const SPF_LOG_MAX_SIZE: usize = 32;
// Maximum number of trigger LSAs per entry in the SPF log record.
const SPF_LOG_TRIGGER_LSAS_MAX_SIZE: usize = 8;

#[derive(Debug, new)]
pub struct Vertex<V: Version> {
    pub id: V::VertexId,
    pub lsa: V::VertexLsa,
    pub distance: u16,
    pub hops: u16,
    #[new(default)]
    pub nexthops: Nexthops<V::IpAddr>,
}

#[derive(Debug)]
pub enum SpfComputation<V: Version> {
    Full,
    Partial(SpfPartialComputation<V>),
}

#[derive(Debug)]
pub struct SpfPartialComputation<V: Version> {
    pub intra: BTreeSet<V::IpNetwork>,
    pub inter_network: BTreeSet<V::IpNetwork>,
    pub inter_router: BTreeSet<Ipv4Addr>,
    pub external: BTreeSet<V::IpNetwork>,
}

#[derive(Debug, new)]
pub struct SpfLink<'a, V: Version> {
    pub parent: Option<(usize, &'a V::LsaRouterLink)>,
    pub id: V::VertexId,
    pub lsa: V::VertexLsa,
    pub cost: u16,
}

#[derive(Debug)]
pub struct SpfIntraAreaNetwork<'a, V: Version> {
    pub vertex: &'a Vertex<V>,
    pub prefix: V::IpNetwork,
    pub prefix_options: V::PrefixOptions,
    pub metric: u16,
    pub prefix_sids: BTreeMap<IgpAlgoType, V::PrefixSid>,
}

#[derive(Debug)]
pub struct SpfInterAreaNetwork<V: Version> {
    pub adv_rtr: Ipv4Addr,
    pub prefix: V::IpNetwork,
    pub prefix_options: V::PrefixOptions,
    pub metric: u32,
    pub prefix_sids: BTreeMap<IgpAlgoType, V::PrefixSid>,
}

#[derive(Debug)]
pub struct SpfInterAreaRouter<V: Version> {
    pub adv_rtr: Ipv4Addr,
    pub router_id: Ipv4Addr,
    pub options: V::PacketOptions,
    pub flags: V::LsaRouterFlags,
    pub metric: u32,
}

#[derive(Debug)]
pub struct SpfExternalNetwork<V: Version> {
    pub adv_rtr: Ipv4Addr,
    pub e_bit: bool,
    pub prefix: V::IpNetwork,
    pub prefix_options: V::PrefixOptions,
    pub metric: u32,
    pub fwd_addr: Option<V::IpAddr>,
    pub tag: Option<u32>,
}

#[derive(Debug, Default)]
pub struct SpfRouterInfo<'a> {
    pub sr_algo: Option<&'a SrAlgoTlv>,
    pub srgb: Vec<&'a SidLabelRangeTlv>,
}

#[derive(Debug, new)]
pub struct SpfTriggerLsa<V: Version> {
    pub old: Option<Arc<Lsa<V>>>,
    pub new: Arc<Lsa<V>>,
    pub log_id: LsaLogId<V>,
}

#[derive(Debug)]
pub enum SpfLogType {
    Full,
    Intra,
    Inter,
    External,
}

#[derive(Debug, new)]
pub struct SpfLogEntry<V: Version> {
    pub id: u32,
    pub spf_type: SpfLogType,
    pub schedule_time: Instant,
    pub start_time: Instant,
    pub end_time: Instant,
    pub trigger_lsas: Vec<LsaLogId<V>>,
}

// OSPF version-specific code.
pub trait SpfVersion<V: Version> {
    type VertexId: VertexIdVersion;
    type VertexLsa: VertexLsaVersion<V>;

    // Determine which computations are necessary to handle the trigger LSAs
    // that are provided as input.
    fn spf_computation_type(
        trigger_lsas: &[SpfTriggerLsa<V>],
    ) -> SpfComputation<V>;

    // Compute the set of nexthops that should be used to reach the given
    // destination.
    fn calc_nexthops(
        area: &Area<V>,
        parent: &Vertex<V>,
        parent_link: Option<(usize, &V::LsaRouterLink)>,
        dest_id: V::VertexId,
        dest_lsa: &V::VertexLsa,
        interfaces: &Arena<Interface<V>>,
        neighbors: &Arena<Neighbor<V>>,
        extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<V>>,
    ) -> Result<Nexthops<V::IpAddr>, Error<V>>;

    // Find SPF vertex.
    fn vertex_lsa_find(
        af: AddressFamily,
        id: V::VertexId,
        area: &Area<V>,
        extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<V>>,
    ) -> Option<V::VertexLsa>;

    // Return iterator over all links of the provided SPF vertex.
    fn vertex_lsa_links<'a>(
        vertex_lsa: &'a Self::VertexLsa,
        af: AddressFamily,
        area: &'a Area<V>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<V>>,
    ) -> Box<dyn Iterator<Item = SpfLink<'a, V>> + 'a>;

    // Return iterator over all intra-area networks.
    fn intra_area_networks<'a>(
        area: &'a Area<V>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<V>>,
    ) -> Box<dyn Iterator<Item = SpfIntraAreaNetwork<'a, V>> + 'a>;

    // Return iterator over all inter-area networks.
    fn inter_area_networks<'a>(
        area: &'a Area<V>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<V>>,
    ) -> Box<dyn Iterator<Item = SpfInterAreaNetwork<V>> + 'a>;

    // Return iterator over all inter-area routers.
    fn inter_area_routers<'a>(
        lsdb: &'a Lsdb<V>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<V>>,
    ) -> Box<dyn Iterator<Item = SpfInterAreaRouter<V>> + 'a>;

    // Return iterator over all AS external networks.
    fn external_networks<'a>(
        lsdb: &'a Lsdb<V>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<V>>,
    ) -> Box<dyn Iterator<Item = SpfExternalNetwork<V>> + 'a>;

    // Locate the Router Information LSA for the specified area.
    fn area_router_information<'a>(
        lsdb: &'a Lsdb<V>,
        router_id: Ipv4Addr,
        lsa_entries: &'a Arena<LsaEntry<V>>,
    ) -> SpfRouterInfo<'a>;

    // This function is specific to OSPFv2 and has the purpose of gathering
    // information from Opaque-LSAs and organizing it in a way that is more
    // accessible and easier to use.
    fn area_opaque_data_compile(
        _area: &mut Area<V>,
        _lsa_entries: &Arena<LsaEntry<V>>,
    ) {
    }
}

// OSPF version-specific code.
//
// NOTE: network vertices should be ordered before router vertices in order for
// the SPF algorithm to find all equal-cost paths.
pub trait VertexIdVersion
where
    Self: Send
        + Sync
        + Clone
        + Copy
        + std::fmt::Debug
        + Eq
        + Ord
        + PartialEq
        + PartialOrd,
{
    // Create root SPF vertex.
    fn new_root(router_id: Ipv4Addr) -> Self;
}

// OSPF version-specific code.
pub trait VertexLsaVersion<V: Version>
where
    Self: Send + Sync + std::fmt::Debug,
{
    // Return whether this is a router vertex.
    fn is_router(&self) -> bool;

    // Return whether the V-bit of this router vertex is set.
    fn router_v_bit(&self) -> bool;

    // Return the Router-ID of this router vertex.
    fn router_id(&self) -> Ipv4Addr;

    // Return the options of this router vertex.
    fn router_options(&self) -> V::PacketOptions;

    // Return the flags of this router vertex.
    fn router_flags(&self) -> V::LsaRouterFlags;

    // Return the Link State Origin of this vertex.
    fn origin(&self) -> LsaKey<V::LsaType>;
}

// SPF Delay State Machine.
pub mod fsm {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
    #[derive(Deserialize, Serialize)]
    pub enum State {
        #[default]
        Quiet,
        ShortWait,
        LongWait,
    }

    #[derive(Debug, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    pub enum Event {
        Igp,
        DelayTimer,
        HoldDownTimer,
        LearnTimer,
        ConfigChange,
    }
}

// ===== global functions =====

pub(crate) fn fsm<V>(
    event: fsm::Event,
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    Debug::<V>::SpfDelayFsmEvent(&instance.state.spf_delay_state, &event).log();

    // Update time of last SPF triggering event.
    instance.state.spf_last_event_rcvd = Some(Instant::now());

    let new_fsm_state = match (instance.state.spf_delay_state, &event) {
        // Transition 1: IGP event while in QUIET state.
        (fsm::State::Quiet, fsm::Event::Igp) => {
            // If SPF_TIMER is not already running, start it with value
            // INITIAL_SPF_DELAY.
            if instance.state.spf_delay_timer.is_none() {
                let task = tasks::spf_delay_timer(
                    instance,
                    fsm::Event::DelayTimer,
                    instance.config.spf_initial_delay,
                );
                instance.state.spf_delay_timer = Some(task);
            }

            // Start LEARN_TIMER with TIME_TO_LEARN_INTERVAL.
            let task = tasks::spf_delay_timer(
                instance,
                fsm::Event::LearnTimer,
                instance.config.spf_time_to_learn,
            );
            instance.state.spf_learn_timer = Some(task);

            // Start HOLDDOWN_TIMER with HOLDDOWN_INTERVAL.
            let task = tasks::spf_delay_timer(
                instance,
                fsm::Event::HoldDownTimer,
                instance.config.spf_hold_down,
            );
            instance.state.spf_hold_down_timer = Some(task);

            // Transition to SHORT_WAIT state.
            Some(fsm::State::ShortWait)
        }
        // Transition 2: IGP event while in SHORT_WAIT.
        (fsm::State::ShortWait, fsm::Event::Igp) => {
            // Reset HOLDDOWN_TIMER to HOLDDOWN_INTERVAL.
            if let Some(timer) = &mut instance.state.spf_hold_down_timer {
                let timeout =
                    Duration::from_millis(instance.config.spf_hold_down.into());
                timer.reset(Some(timeout));
            }

            // If SPF_TIMER is not already running, start it with value
            // SHORT_SPF_DELAY.
            if instance.state.spf_delay_timer.is_none() {
                let task = tasks::spf_delay_timer(
                    instance,
                    fsm::Event::DelayTimer,
                    instance.config.spf_short_delay,
                );
                instance.state.spf_delay_timer = Some(task);
            }

            // Remain in current state.
            None
        }
        // Transition 3: LEARN_TIMER expiration.
        (fsm::State::ShortWait, fsm::Event::LearnTimer) => {
            instance.state.spf_learn_timer = None;

            // Transition to LONG_WAIT state.
            Some(fsm::State::LongWait)
        }
        // Transition 4: IGP event while in LONG_WAIT.
        (fsm::State::LongWait, fsm::Event::Igp) => {
            // Reset HOLDDOWN_TIMER to HOLDDOWN_INTERVAL.
            if let Some(timer) = &mut instance.state.spf_hold_down_timer {
                let timeout =
                    Duration::from_millis(instance.config.spf_hold_down.into());
                timer.reset(Some(timeout));
            }

            // If SPF_TIMER is not already running, start it with value
            // LONG_SPF_DELAY.
            if instance.state.spf_delay_timer.is_none() {
                let task = tasks::spf_delay_timer(
                    instance,
                    fsm::Event::DelayTimer,
                    instance.config.spf_long_delay,
                );
                instance.state.spf_delay_timer = Some(task);
            }

            // Remain in current state.
            None
        }
        // Transition 5: HOLDDOWN_TIMER expiration while in LONG_WAIT.
        (fsm::State::LongWait, fsm::Event::HoldDownTimer) => {
            instance.state.spf_hold_down_timer = None;

            // Transition to QUIET state.
            Some(fsm::State::Quiet)
        }
        // Transition 6: HOLDDOWN_TIMER expiration while in SHORT_WAIT.
        (fsm::State::ShortWait, fsm::Event::HoldDownTimer) => {
            instance.state.spf_hold_down_timer = None;

            // Deactivate LEARN_TIMER.
            instance.state.spf_learn_timer = None;

            // Transition to QUIET state.
            Some(fsm::State::Quiet)
        }
        // Transition 7: SPF_TIMER expiration while in QUIET.
        // Transition 8: SPF_TIMER expiration while in SHORT_WAIT.
        // Transition 9: SPF_TIMER expiration while in LONG_WAIT
        (
            fsm::State::Quiet | fsm::State::ShortWait | fsm::State::LongWait,
            fsm::Event::DelayTimer,
        ) => {
            instance.state.spf_delay_timer = None;

            // Compute SPF.
            compute_spf(
                instance,
                &mut arenas.areas,
                &arenas.interfaces,
                &arenas.neighbors,
                &arenas.lsa_entries,
                false,
            );

            // Remain in current state.
            None
        }
        // Custom FSM transition.
        (
            fsm::State::Quiet | fsm::State::ShortWait | fsm::State::LongWait,
            fsm::Event::ConfigChange,
        ) => {
            // Cancel the next scheduled SPF run, but preserve the other timers.
            instance.state.spf_delay_timer = None;

            // Compute SPF.
            compute_spf(
                instance,
                &mut arenas.areas,
                &arenas.interfaces,
                &arenas.neighbors,
                &arenas.lsa_entries,
                true,
            );

            // Remain in current state.
            None
        }
        _ => {
            return Err(Error::SpfDelayUnexpectedEvent(
                instance.state.spf_delay_state,
                event,
            ));
        }
    };

    if let Some(new_fsm_state) = new_fsm_state {
        if new_fsm_state != instance.state.spf_delay_state {
            // Effectively transition to the new FSM state.
            Debug::<V>::SpfDelayFsmTransition(
                &instance.state.spf_delay_state,
                &new_fsm_state,
            )
            .log();
            instance.state.spf_delay_state = new_fsm_state;
        }
    }

    Ok(())
}

// ===== helper functions =====

// This is the SPF main function.
fn compute_spf<V>(
    instance: &mut InstanceUpView<'_, V>,
    areas: &mut Areas<V>,
    interfaces: &Arena<Interface<V>>,
    neighbors: &Arena<Neighbor<V>>,
    lsa_entries: &Arena<LsaEntry<V>>,
    force_full_run: bool,
) where
    V: Version,
{
    // Get time the SPF was scheduled.
    let schedule_time = instance
        .state
        .spf_schedule_time
        .take()
        .unwrap_or_else(Instant::now);

    // Record time the SPF computation was started.
    let start_time = Instant::now();

    // Get list of new or updated LSAs that triggered the SPF computation.
    let trigger_lsas = std::mem::take(&mut instance.state.spf_trigger_lsas);

    // Check the required SPF computations depending on which LSAs have changed.
    let mut spf_computation_type = match force_full_run {
        true => SpfComputation::Full,
        false => V::spf_computation_type(&trigger_lsas),
    };
    match &mut spf_computation_type {
        SpfComputation::Full => {
            // Calculate shortest-path trees.
            for area in areas.iter_mut() {
                run_area(area, instance, interfaces, neighbors, lsa_entries);
            }

            // Update routing table.
            route::update_rib_full(instance, areas, interfaces, lsa_entries);
        }
        SpfComputation::Partial(partial) => {
            // Update routing table.
            route::update_rib_partial(
                partial,
                instance,
                areas,
                interfaces,
                lsa_entries,
            );
        }
    }

    // Update summary LSAs.
    area::update_summary_lsas(instance, areas, interfaces, lsa_entries);

    // Update time of last SPF computation.
    let end_time = Instant::now();
    instance.state.spf_last_time = Some(end_time);

    // Add entry to SPF log.
    log_spf_run(
        instance,
        &spf_computation_type,
        schedule_time,
        start_time,
        end_time,
        trigger_lsas,
    );
}

// Runs SPF in the provided area.
fn run_area<V>(
    area: &mut Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &Arena<Interface<V>>,
    neighbors: &Arena<Neighbor<V>>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    let af = instance.state.af;
    let extended_lsa = instance.config.extended_lsa;
    area.state.transit_capability = false;

    // Parse and compile opaque data that is relevant to the SPF computation.
    V::area_opaque_data_compile(area, lsa_entries);

    // Get root vertex.
    let root_vid = V::VertexId::new_root(instance.state.router_id);
    let root_vlsa =
        match V::vertex_lsa_find(af, root_vid, area, extended_lsa, lsa_entries)
        {
            Some(vertex) => vertex,
            None => {
                Error::<V>::SpfRootNotFound(area.area_id).log();
                return;
            }
        };
    let root_v = Vertex::<V>::new(root_vid, root_vlsa, 0, 0);

    // Initialize SPT and candidate list.
    let mut spt = BTreeMap::new();
    let mut cand_list = BTreeMap::new();
    cand_list.insert((root_v.distance, root_v.id), root_v);

    // Clear router's routing table.
    area.state.routers.clear();

    // Main SPF loop.
    while let Some(((_, vertex_id), vertex)) = cand_list.pop_first() {
        // Add vertex to SPT.
        spt.insert(vertex.id, vertex);
        let vertex = spt.get(&vertex_id).unwrap();

        if vertex.lsa.is_router() {
            // Add "router" routing table entry.
            let route = RouteRtr::new(
                area.area_id,
                PathType::IntraArea,
                vertex.lsa.router_options(),
                vertex.lsa.router_flags(),
                vertex.distance.into(),
                vertex.nexthops.clone(),
            );
            area.state.routers.insert(vertex.lsa.router_id(), route);

            // Set TransitCapability.
            if vertex.lsa.router_v_bit() {
                area.state.transit_capability = true;
            }
        }

        // Iterate over all links described by the vertex's LSA.
        for link in V::vertex_lsa_links(
            &vertex.lsa,
            af,
            area,
            extended_lsa,
            lsa_entries,
        ) {
            // Check if the LSAs are mutually linked.
            if !V::vertex_lsa_links(
                &link.lsa,
                af,
                area,
                extended_lsa,
                lsa_entries,
            )
            .any(|link| link.id == vertex.id)
            {
                continue;
            }

            // Check if the link's vertex is already on the shortest-path tree.
            if spt.get(&link.id).is_some() {
                continue;
            }

            // Calculate distance to the link's vertex.
            let distance = vertex.distance.saturating_add(link.cost);

            // Increment number of hops to the root.
            let mut hops = vertex.hops;
            if link.lsa.is_router() {
                hops = hops.saturating_add(1);
            }

            // Check if this vertex is already present on the candidate list.
            // TODO: optimize lookup.
            if let Some((cand_key, cand_v)) = cand_list
                .iter_mut()
                .find(|(_, cand_v)| cand_v.id == link.id)
            {
                match distance.cmp(&cand_v.distance) {
                    Ordering::Less => {
                        // Remove vertex since its key has changed. It will be
                        // re-added with the correct key below.
                        let cand_key = *cand_key;
                        cand_list.remove(&cand_key);
                    }
                    Ordering::Equal => {}
                    Ordering::Greater => {
                        // Ignore higher cost path.
                        continue;
                    }
                }
            }
            let cand_v =
                cand_list.entry((distance, link.id)).or_insert_with(|| {
                    Vertex::new(link.id, link.lsa, distance, hops)
                });

            // Update vertex's nexthops.
            match calc_nexthops(
                area,
                vertex,
                link.parent,
                link.id,
                &cand_v.lsa,
                interfaces,
                neighbors,
                extended_lsa,
                lsa_entries,
            ) {
                Ok(nexthops) => cand_v.nexthops.extend(nexthops),
                Err(error) => error.log(),
            }
        }
    }

    // Update area's SPT.
    area.state.spt = spt;

    // Update statistics.
    area.state.spf_run_count += 1;
    area.state.discontinuity_time = Utc::now();
}

// Computes the set of nexthops that should be used to reach the given
// destination.
fn calc_nexthops<V>(
    area: &Area<V>,
    parent: &Vertex<V>,
    parent_link: Option<(usize, &V::LsaRouterLink)>,
    dest_id: V::VertexId,
    dest_lsa: &V::VertexLsa,
    interfaces: &Arena<Interface<V>>,
    neighbors: &Arena<Neighbor<V>>,
    extended_lsa: bool,
    lsa_entries: &Arena<LsaEntry<V>>,
) -> Result<Nexthops<V::IpAddr>, Error<V>>
where
    V: Version,
{
    if parent.hops == 0 {
        // The parent vertex is the root or a network that directly connects the
        // calculating router to the destination router.
        V::calc_nexthops(
            area,
            parent,
            parent_link,
            dest_id,
            dest_lsa,
            interfaces,
            neighbors,
            extended_lsa,
            lsa_entries,
        )
    } else {
        // If there is at least one intervening router in the current shortest
        // path between the destination and the root, the destination simply
        // inherits the set of next hops from the parent.
        Ok(parent.nexthops.clone())
    }
}

// Adds log entry for the SPF run.
fn log_spf_run<V>(
    instance: &mut InstanceUpView<'_, V>,
    spf_computation_type: &SpfComputation<V>,
    schedule_time: Instant,
    start_time: Instant,
    end_time: Instant,
    trigger_lsas: Vec<SpfTriggerLsa<V>>,
) where
    V: Version,
{
    // Get next log ID.
    let log_id = &mut instance.state.spf_log_next_id;
    *log_id += 1;

    // Get SPF computation type in log format.
    let spf_log_type = match spf_computation_type {
        SpfComputation::Full => SpfLogType::Full,
        SpfComputation::Partial(partial) => {
            if !partial.intra.is_empty() {
                SpfLogType::Intra
            } else if !partial.inter_network.is_empty() {
                SpfLogType::Inter
            } else {
                SpfLogType::External
            }
        }
    };

    // Get trigger LSAs in log format.
    let trigger_lsas = trigger_lsas
        .into_iter()
        .take(SPF_LOG_TRIGGER_LSAS_MAX_SIZE)
        .map(|tlsa| tlsa.log_id)
        .collect();

    // Add new log entry.
    let log_entry = SpfLogEntry::new(
        *log_id,
        spf_log_type,
        schedule_time,
        start_time,
        end_time,
        trigger_lsas,
    );
    instance.state.spf_log.push_front(log_entry);

    // Remove old entries if necessary.
    instance.state.spf_log.truncate(SPF_LOG_MAX_SIZE);
}
