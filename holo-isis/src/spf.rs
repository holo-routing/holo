//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use chrono::Utc;
use derive_new::new;
use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::mac_addr::MacAddr;
use holo_utils::sr::IgpAlgoType;
use holo_utils::task::TimeoutTask;
use ipnetwork::IpNetwork;
use tracing::debug_span;

use crate::adjacency::{Adjacency, AdjacencyState};
use crate::collections::{Arena, InterfaceIndex, Interfaces, Lsdb};
use crate::debug::Debug;
use crate::error::Error;
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::InterfaceType;
use crate::lsdb::{LspEntry, LspLogId};
use crate::northbound::configuration::MetricType;
use crate::packet::consts::{MtId, Nlpid};
use crate::packet::pdu::Lsp;
use crate::packet::subtlvs::prefix::{PrefixAttrFlags, PrefixSidStlv};
use crate::packet::tlv::IpReachTlvEntry;
use crate::packet::{LanId, LevelNumber, LevelType, LspId, SystemId};
use crate::route::Route;
use crate::{route, sr, tasks};

// Maximum size of the SPF log record.
const SPF_LOG_MAX_SIZE: usize = 32;
// Maximum number of trigger LSPs per entry in the SPF log record.
const SPF_LOG_TRIGGER_LSPS_MAX_SIZE: usize = 8;
// Maximum total metric value for a complete path (standard metrics).
const MAX_PATH_METRIC_STANDARD: u32 = 1023;
// Maximum total metric value for a complete path (wide metrics).
const MAX_PATH_METRIC_WIDE: u32 = 0xFE000000;

// A macro to chain multiple `Option<Iterator<Item = T>>` into a single
// iterator.
macro_rules! chain_option_iterators {
    ($($opt:expr),* $(,)?) => {{
        itertools::chain!($($opt.into_iter().flatten(),)*)
    }};
}

// Container for storing separate values for each topology.
#[derive(Debug, Default)]
pub struct Topologies<T> {
    pub standard: T,
    pub ipv6_unicast: T,
}

// Shortest Path Tree.
pub type Spt = BTreeMap<VertexId, Vertex>;

// Represents a vertex in the IS-IS topology graph.
//
// A `Vertex` corresponds to a router or pseudonode.
#[derive(Debug)]
#[derive(new)]
pub struct Vertex {
    pub id: VertexId,
    pub distance: u32,
    pub hops: u16,
    #[new(default)]
    pub nexthops: Vec<VertexNexthop>,
}

// Represents a unique identifier for a vertex in the IS-IS topology graph.
//
// `VertexId` is designed to serve as a key in collections, such as `BTreeMap`,
// that store vertices for the SPT and the tentative list. The `non_pseudonode`
// flag ensures that non-pseudonode vertices are given priority and processed
// first during the SPF algorithm.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VertexId {
    pub non_pseudonode: bool,
    pub lan_id: LanId,
}

// Represents a next-hop used to reach a vertex in the IS-IS topology graph.
//
// During the SPF computation, protocol-specific addresses (IPv4 and/or IPv6)
// are resolved and stored in this structure. This information is later used
// during route computation.
#[derive(Clone, Debug)]
#[derive(new)]
pub struct VertexNexthop {
    pub system_id: SystemId,
    pub iface_idx: InterfaceIndex,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

// Represents an IS reachability entry attached to a vertex.
#[derive(Debug, Eq, PartialEq)]
#[derive(new)]
pub struct VertexEdge {
    pub id: VertexId,
    pub cost: u32,
}

// Represents an IP reachability entry attached to a vertex.
#[derive(Clone, Debug)]
#[derive(new)]
pub struct VertexNetwork {
    pub prefix: IpNetwork,
    pub metric: u32,
    pub external: bool,
    pub prefix_sid: Option<PrefixSidStlv>,
}

// Container containing scheduling and timing information of SPF computations.
#[derive(Debug, Default)]
pub struct SpfScheduler {
    pub last_event_rcvd: Option<Instant>,
    pub last_time: Option<Instant>,
    pub spf_type: SpfType,
    pub delay_state: fsm::State,
    pub delay_timer: Option<TimeoutTask>,
    pub hold_down_timer: Option<TimeoutTask>,
    pub learn_timer: Option<TimeoutTask>,
    pub trigger_lsps: BTreeMap<LspId, LspLogId>,
    pub schedule_time: Option<Instant>,
}

// Type of SPF computation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SpfType {
    // Full SPF computation.
    Full,
    // "SPF computation of route reachability only.
    #[default]
    RouteOnly,
}

// SPF log entry.
#[derive(Debug, new)]
pub struct SpfLogEntry {
    pub id: u32,
    pub spf_type: SpfType,
    pub level: LevelNumber,
    pub schedule_time: Option<Instant>,
    pub start_time: Instant,
    pub end_time: Instant,
    pub trigger_lsps: Vec<LspLogId>,
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    pub enum Event {
        Igp,
        DelayTimer,
        HoldDownTimer,
        LearnTimer,
        AdjacencyChange,
        ConfigChange,
    }
}

// ===== impl Topologies =====

impl<T> Topologies<T> {
    pub(crate) fn get(&self, mt_id: MtId) -> &T {
        match mt_id {
            MtId::Standard => &self.standard,
            MtId::Ipv6Unicast => &self.ipv6_unicast,
        }
    }

    pub(crate) fn get_mut(&mut self, mt_id: MtId) -> &mut T {
        match mt_id {
            MtId::Standard => &mut self.standard,
            MtId::Ipv6Unicast => &mut self.ipv6_unicast,
        }
    }
}

// ===== impl VertexId =====

impl VertexId {
    pub(crate) fn new(lan_id: LanId) -> VertexId {
        VertexId {
            non_pseudonode: !lan_id.is_pseudonode(),
            lan_id,
        }
    }
}

// ===== global functions =====

// Invokes an event in the SPF delay state machine.
pub(crate) fn fsm(
    level: LevelNumber,
    event: fsm::Event,
    instance: &mut InstanceUpView<'_>,
    arenas: &mut InstanceArenas,
) -> Result<(), Error> {
    // Begin a debug span for logging within the SPF context.
    let span = debug_span!("spf", %level);
    let _span_guard = span.enter();

    // Retrieve the SPF scheduling container for the current level.
    let spf_sched = instance.state.spf_sched.get_mut(level);

    // Log the received event.
    if instance.config.trace_opts.spf {
        Debug::SpfDelayFsmEvent(spf_sched.delay_state, event).log();
    }

    // Update time of last SPF triggering event.
    spf_sched.last_event_rcvd = Some(Instant::now());

    let new_fsm_state = match (spf_sched.delay_state, &event) {
        // Transition 1: IGP event while in QUIET state.
        (fsm::State::Quiet, fsm::Event::Igp) => {
            // If SPF_TIMER is not already running, start it with value
            // INITIAL_SPF_DELAY.
            if spf_sched.delay_timer.is_none() {
                let task = tasks::spf_delay_timer(
                    level,
                    fsm::Event::DelayTimer,
                    instance.config.spf_initial_delay,
                    &instance.tx.protocol_input.spf_delay_event,
                );
                spf_sched.delay_timer = Some(task);
            }

            // Start LEARN_TIMER with TIME_TO_LEARN_INTERVAL.
            let task = tasks::spf_delay_timer(
                level,
                fsm::Event::LearnTimer,
                instance.config.spf_time_to_learn,
                &instance.tx.protocol_input.spf_delay_event,
            );
            spf_sched.learn_timer = Some(task);

            // Start HOLDDOWN_TIMER with HOLDDOWN_INTERVAL.
            let task = tasks::spf_delay_timer(
                level,
                fsm::Event::HoldDownTimer,
                instance.config.spf_hold_down,
                &instance.tx.protocol_input.spf_delay_event,
            );
            spf_sched.hold_down_timer = Some(task);

            // Transition to SHORT_WAIT state.
            Some(fsm::State::ShortWait)
        }
        // Transition 2: IGP event while in SHORT_WAIT.
        (fsm::State::ShortWait, fsm::Event::Igp) => {
            // Reset HOLDDOWN_TIMER to HOLDDOWN_INTERVAL.
            if let Some(timer) = &mut spf_sched.hold_down_timer {
                let timeout =
                    Duration::from_millis(instance.config.spf_hold_down.into());
                timer.reset(Some(timeout));
            }

            // If SPF_TIMER is not already running, start it with value
            // SHORT_SPF_DELAY.
            if spf_sched.delay_timer.is_none() {
                let task = tasks::spf_delay_timer(
                    level,
                    fsm::Event::DelayTimer,
                    instance.config.spf_short_delay,
                    &instance.tx.protocol_input.spf_delay_event,
                );
                spf_sched.delay_timer = Some(task);
            }

            // Remain in current state.
            None
        }
        // Transition 3: LEARN_TIMER expiration.
        (fsm::State::ShortWait, fsm::Event::LearnTimer) => {
            spf_sched.learn_timer = None;

            // Transition to LONG_WAIT state.
            Some(fsm::State::LongWait)
        }
        // Transition 4: IGP event while in LONG_WAIT.
        (fsm::State::LongWait, fsm::Event::Igp) => {
            // Reset HOLDDOWN_TIMER to HOLDDOWN_INTERVAL.
            if let Some(timer) = &mut spf_sched.hold_down_timer {
                let timeout =
                    Duration::from_millis(instance.config.spf_hold_down.into());
                timer.reset(Some(timeout));
            }

            // If SPF_TIMER is not already running, start it with value
            // LONG_SPF_DELAY.
            if spf_sched.delay_timer.is_none() {
                let task = tasks::spf_delay_timer(
                    level,
                    fsm::Event::DelayTimer,
                    instance.config.spf_long_delay,
                    &instance.tx.protocol_input.spf_delay_event,
                );
                spf_sched.delay_timer = Some(task);
            }

            // Remain in current state.
            None
        }
        // Transition 5: HOLDDOWN_TIMER expiration while in LONG_WAIT.
        (fsm::State::LongWait, fsm::Event::HoldDownTimer) => {
            spf_sched.hold_down_timer = None;

            // Transition to QUIET state.
            Some(fsm::State::Quiet)
        }
        // Transition 6: HOLDDOWN_TIMER expiration while in SHORT_WAIT.
        (fsm::State::ShortWait, fsm::Event::HoldDownTimer) => {
            spf_sched.hold_down_timer = None;

            // Deactivate LEARN_TIMER.
            spf_sched.learn_timer = None;

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
            spf_sched.delay_timer = None;

            // Compute SPF.
            compute_spf(
                level,
                instance,
                &arenas.interfaces,
                &arenas.adjacencies,
                &arenas.lsp_entries,
            );

            // Remain in current state.
            None
        }
        // Custom FSM transition.
        (
            fsm::State::Quiet | fsm::State::ShortWait | fsm::State::LongWait,
            fsm::Event::AdjacencyChange | fsm::Event::ConfigChange,
        ) => {
            // Cancel the next scheduled SPF run, but preserve the other timers.
            spf_sched.delay_timer = None;

            // Compute SPF.
            compute_spf(
                level,
                instance,
                &arenas.interfaces,
                &arenas.adjacencies,
                &arenas.lsp_entries,
            );

            // Remain in current state.
            None
        }
        _ => {
            return Err(Error::SpfDelayUnexpectedEvent(
                level,
                spf_sched.delay_state,
                event,
            ));
        }
    };

    if let Some(new_fsm_state) = new_fsm_state {
        let spf_sched = instance.state.spf_sched.get_mut(level);
        if new_fsm_state != spf_sched.delay_state {
            // Effectively transition to the new FSM state.
            if instance.config.trace_opts.spf {
                Debug::SpfDelayFsmTransition(
                    spf_sched.delay_state,
                    new_fsm_state,
                )
                .log();
            }
            spf_sched.delay_state = new_fsm_state;
        }
    }

    Ok(())
}

// ===== helper functions =====

// Main function for SPF computation.
//
// Based on the LSDB changes that triggered SPF, either a full or partial run is
// performed. A full run is necessary when topological changes are detected, and
// involves recomputing the shortest-path tree (SPT). Otherwise, a partial run
// is sufficient, and the SPT recalculation is skipped.
fn compute_spf(
    level: LevelNumber,
    instance: &mut InstanceUpView<'_>,
    interfaces: &Interfaces,
    adjacencies: &Arena<Adjacency>,
    lsp_entries: &Arena<LspEntry>,
) {
    let spf_sched = instance.state.spf_sched.get_mut(level);

    // Get time the SPF was scheduled.
    let schedule_time = spf_sched.schedule_time.take();

    // Record time the SPF computation was started.
    let start_time = Instant::now();

    // Get list of new or updated LSPs that triggered the SPF computation.
    let trigger_lsps = std::mem::take(&mut spf_sched.trigger_lsps);

    // Log SPF computation start.
    let spf_type = std::mem::take(&mut spf_sched.spf_type);
    if instance.config.trace_opts.spf {
        Debug::SpfStart(spf_type).log();
    }

    // Compute shortest-path tree(s) if necessary.
    if spf_type == SpfType::Full {
        for mt_id in [MtId::Standard, MtId::Ipv6Unicast] {
            if instance.config.is_topology_enabled(mt_id) {
                let spt = compute_spt(
                    level,
                    mt_id,
                    instance,
                    interfaces,
                    adjacencies,
                    lsp_entries,
                );
                *instance.state.spt.get_mut(mt_id).get_mut(level) = spt;
            }
        }
    }

    // Compute the new RIB for the current level.
    //
    // Since multiple topologies per address family aren't currently supported,
    // a single RIB is sufficient as there's no risk of prefix overlap.
    let mut new_rib = BTreeMap::new();
    for mt_id in [MtId::Standard, MtId::Ipv6Unicast] {
        if instance.config.is_topology_enabled(mt_id) {
            compute_routes(
                level,
                mt_id,
                instance,
                interfaces,
                adjacencies,
                lsp_entries,
                &mut new_rib,
            );
        }
    }

    // Update the local RIB and global RIB.
    route::update_rib(level, new_rib, instance, interfaces);

    // If this is an L1 LSP in an L1/L2 router, schedule LSP reorigination at L2
    // to propagate updates. This happens only after SPF, as the SPT tree is
    // needed to compute distances to L1 routers.
    if level == LevelNumber::L1 && instance.config.level_type == LevelType::All
    {
        instance.schedule_lsp_origination(LevelType::L2);
    }

    // Update statistics.
    instance.state.counters.get_mut(level).spf_runs += 1;
    instance.state.discontinuity_time = Utc::now();

    // Update time of last SPF computation.
    let end_time = Instant::now();
    let spf_sched = instance.state.spf_sched.get_mut(level);
    spf_sched.last_time = Some(end_time);

    // Log SPF completion and duration.
    if instance.config.trace_opts.spf {
        let run_duration = end_time - start_time;
        Debug::SpfFinish(run_duration).log();
    }

    // Add entry to SPF log.
    log_spf_run(
        level,
        instance,
        spf_type,
        schedule_time,
        start_time,
        end_time,
        trigger_lsps.into_values().collect(),
    );
}

// Computes the shortest-path tree.
//
// According to the ISO specification, the algorithm should begin by pre-loading
// the candidate list (TENT) with the local adjacency database. However, in this
// implementation, the local adjacency information is fetched directly from the
// local LSP instead. This is done to ensure that the algorithm can be run with
// any node as the root, which will be required later for implementing the
// TI-LFA feature.
fn compute_spt(
    level: LevelNumber,
    mt_id: MtId,
    instance: &InstanceUpView<'_>,
    interfaces: &Interfaces,
    adjacencies: &Arena<Adjacency>,
    lsp_entries: &Arena<LspEntry>,
) -> Spt {
    let lsdb = instance.state.lsdb.get(level);
    let metric_type = instance.config.metric_type.get(level);
    let mut used_adjs = BTreeSet::new();

    // Get root vertex.
    let root_lan_id = LanId::from((instance.config.system_id.unwrap(), 0));
    let root_vid = VertexId::new(root_lan_id);
    let root_v = Vertex::new(root_vid, 0, 0);

    // Initialize SPT and candidate list.
    let mut spt = BTreeMap::new();
    let mut cand_list = BTreeMap::new();
    cand_list.insert((root_v.distance, root_v.id), root_v);

    // Main SPF loop.
    'spf_loop: while let Some(((_, vertex_id), vertex)) = cand_list.pop_first()
    {
        // Add vertex to SPT.
        spt.insert(vertex.id, vertex);
        let vertex = spt.get(&vertex_id).unwrap();

        // Skip if the zeroth LSP is missing.
        let Some(zeroth_lsp) = zeroth_lsp(vertex.id.lan_id, lsdb, lsp_entries)
        else {
            continue;
        };

        // If the overload bit is set, we skip the links from it.
        if !zeroth_lsp.lsp_id.is_pseudonode() && zeroth_lsp.overload_bit(mt_id)
        {
            continue;
        }

        // In dual-stack single-topology networks, traffic blackholing can occur
        // if any IS or link has IPv4 enabled but not IPv6, or vice versa.
        // To minimize the likelihood of such issues, this check ensures that
        // the IS supports all configured protocols. We can't check address
        // family information from the links since that information isn't
        // available in the LSPDB.
        if mt_id == MtId::Standard && !zeroth_lsp.lsp_id.is_pseudonode() {
            let Some(protocols_supported) =
                &zeroth_lsp.tlvs.protocols_supported
            else {
                if instance.config.trace_opts.spf {
                    Debug::SpfMissingProtocolsTlv(vertex).log();
                }
                continue;
            };
            for af in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
                if instance.config.is_af_enabled(af)
                    && !protocols_supported.contains(Nlpid::from(af))
                {
                    if instance.config.trace_opts.spf {
                        Debug::SpfUnsupportedProtocol(vertex, af).log();
                    }
                    continue 'spf_loop;
                }
            }
        }

        // Iterate over all links described by the vertex's LSPs.
        for link in
            vertex_edges(&vertex.id, mt_id, metric_type, lsdb, lsp_entries)
        {
            // Check if the LSPs are mutually linked.
            if !vertex_edges(&link.id, mt_id, metric_type, lsdb, lsp_entries)
                .any(|link| link.id == vertex.id)
            {
                continue;
            }

            // Check if the link's vertex is already on the shortest-path tree.
            if spt.contains_key(&link.id) {
                continue;
            }

            // Calculate distance to the link's vertex.
            let distance = vertex.distance.saturating_add(link.cost);

            // Check maximum total metric value.
            let max_path_metric = match metric_type {
                MetricType::Wide | MetricType::Both => MAX_PATH_METRIC_WIDE,
                MetricType::Standard => MAX_PATH_METRIC_STANDARD,
            };
            if distance > max_path_metric {
                if instance.config.trace_opts.spf {
                    Debug::SpfMaxPathMetric(vertex, &link, distance).log();
                }
                continue;
            }

            // Increment number of hops to the root.
            let mut hops = vertex.hops;
            if !link.id.lan_id.is_pseudonode() {
                hops = hops.saturating_add(1);
            }

            // Check if this vertex is already present on the candidate list.
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
            let cand_v = cand_list
                .entry((distance, link.id))
                .or_insert_with(|| Vertex::new(link.id, distance, hops));

            // Update vertex's nexthops.
            if vertex.hops == 0 {
                if !link.id.lan_id.is_pseudonode()
                    && let Some(nexthop) = compute_nexthop(
                        level,
                        mt_id,
                        vertex,
                        &link,
                        &mut used_adjs,
                        interfaces,
                        adjacencies,
                    )
                {
                    cand_v.nexthops.push(nexthop);
                }
            } else {
                cand_v.nexthops.extend(vertex.nexthops.clone());
            };
        }
    }

    spt
}

// Computes routing table based on the SPT and IP prefix information extracted
// from the vertices.
fn compute_routes(
    level: LevelNumber,
    mt_id: MtId,
    instance: &InstanceUpView<'_>,
    interfaces: &Interfaces,
    adjacencies: &Arena<Adjacency>,
    lsp_entries: &Arena<LspEntry>,
    rib: &mut BTreeMap<IpNetwork, Route>,
) {
    let lsdb = instance.state.lsdb.get(level);
    let metric_type = instance.config.metric_type.get(level);

    // Populate RIB.
    let is_l2_attached_to_backbone =
        instance.is_l2_attached_to_backbone(mt_id, interfaces, adjacencies);
    let ipv4_enabled = instance.config.is_af_enabled(AddressFamily::Ipv4)
        && mt_id == MtId::Standard;
    let ipv6_enabled = instance.config.is_af_enabled(AddressFamily::Ipv6)
        && match mt_id {
            MtId::Standard => {
                !instance.config.is_topology_enabled(MtId::Ipv6Unicast)
            }
            MtId::Ipv6Unicast => true,
        };
    for vertex in instance.state.spt.get(mt_id).get(level).values() {
        // Skip if the zeroth LSP is missing.
        let Some(zeroth_lsp) = zeroth_lsp(vertex.id.lan_id, lsdb, lsp_entries)
        else {
            continue;
        };
        let att_bit = !instance.config.att_ignore && zeroth_lsp.att_bit(mt_id);

        for network in vertex_networks(
            instance.config.level_type,
            level,
            mt_id,
            vertex,
            att_bit,
            is_l2_attached_to_backbone,
            metric_type,
            ipv4_enabled,
            ipv6_enabled,
            lsdb,
            lsp_entries,
        ) {
            let route = match rib.entry(network.prefix) {
                btree_map::Entry::Vacant(v) => {
                    // If the route does not exist, create a new entry.
                    let route = Route::new(vertex, &network, level);
                    v.insert(route)
                }
                btree_map::Entry::Occupied(o) => {
                    let curr_route = o.into_mut();

                    let route_metric = vertex.distance + network.metric;
                    match route_metric.cmp(&curr_route.metric) {
                        Ordering::Less => {
                            // Replace route with a better one.
                            *curr_route = Route::new(vertex, &network, level);
                        }
                        Ordering::Equal => {
                            // Merge nexthops (anycast route).
                            curr_route.merge_nexthops(vertex, &network);
                        }
                        Ordering::Greater => {
                            // Ignore less preferred route.
                            continue;
                        }
                    }

                    curr_route
                }
            };

            // Honor configured maximum number of ECMP paths.
            let max_paths = instance.config.max_paths;
            if route.nexthops.len() > max_paths as usize {
                route.nexthops = route
                    .nexthops
                    .iter()
                    .map(|(k, v)| (*k, *v))
                    .take(max_paths as usize)
                    .collect();
            }

            // Update route's Prefix-SID (if any).
            if instance.config.sr.enabled && route.prefix_sid.is_some() {
                let af = network.prefix.address_family();
                let local = vertex.hops == 0;
                let last_hop = vertex.hops == 1;
                sr::prefix_sid_update(
                    instance,
                    level,
                    vertex.id.lan_id,
                    af,
                    route,
                    local,
                    last_hop,
                    lsp_entries,
                );
            }
        }
    }
}

// Computes the next-hop for reaching a vertex via the specified edge.
fn compute_nexthop(
    level: LevelNumber,
    mt_id: MtId,
    vertex: &Vertex,
    link: &VertexEdge,
    used_adjs: &mut BTreeSet<MacAddr>,
    interfaces: &Interfaces,
    adjacencies: &Arena<Adjacency>,
) -> Option<VertexNexthop> {
    // Check expected interface type.
    let interface_type = if vertex.id.lan_id.is_pseudonode() {
        InterfaceType::Broadcast
    } else {
        InterfaceType::PointToPoint
    };

    let mt_id = mt_id as u16;
    let (iface, adj) = interfaces
        .iter()
        .filter(|iface| iface.config.interface_type == interface_type)
        .filter_map(|iface| {
            let adj = match iface.config.interface_type {
                InterfaceType::Broadcast => iface
                    .state
                    .lan_adjacencies
                    .get(level)
                    .get_by_system_id(adjacencies, &link.id.lan_id.system_id)
                    .map(|(_, adj)| adj)
                    .filter(|adj| adj.topologies.contains(&mt_id))
                    .filter(|adj| adj.state == AdjacencyState::Up),
                InterfaceType::PointToPoint => {
                    if iface.config.metric.get(level) != link.cost {
                        return None;
                    }
                    iface
                        .state
                        .p2p_adjacency
                        .as_ref()
                        .filter(|adj| adj.topologies.contains(&mt_id))
                        .filter(|adj| adj.level_usage.intersects(level))
                        .filter(|adj| adj.system_id == link.id.lan_id.system_id)
                        .filter(|adj| adj.state == AdjacencyState::Up)
                }
            }?;
            Some((iface, adj))
        })
        // The same adjacency shouldn't be used more than once.
        .find(|(_, adj)| used_adjs.insert(adj.snpa))?;

    Some(VertexNexthop {
        system_id: adj.system_id,
        iface_idx: iface.index,
        ipv4: adj.ipv4_addrs.first().copied(),
        ipv6: adj.ipv6_addrs.first().copied(),
    })
}

// Iterate over all IS reachability entries attached to a vertex.
fn vertex_edges<'a>(
    vertex_id: &VertexId,
    mt_id: MtId,
    metric_type: MetricType,
    lsdb: &'a Lsdb,
    lsp_entries: &'a Arena<LspEntry>,
) -> impl Iterator<Item = VertexEdge> + 'a {
    // Iterate over all LSP fragments.
    lsdb.iter_for_lan_id(lsp_entries, vertex_id.lan_id)
        .map(|lse| &lse.data)
        .filter(|lsp| lsp.seqno != 0)
        .filter(|lsp| lsp.rem_lifetime != 0)
        .flat_map(move |lsp| {
            let mut standard_iter = None;
            let mut wide_iter = None;
            let mut mt_iter = None;

            if mt_id == MtId::Standard && metric_type.is_standard_enabled() {
                let iter = lsp.tlvs.is_reach().map(|reach| VertexEdge {
                    id: VertexId::new(reach.neighbor),
                    cost: reach.metric.into(),
                });
                standard_iter = Some(iter);
            }
            if (mt_id == MtId::Standard || lsp.lsp_id.is_pseudonode())
                && metric_type.is_wide_enabled()
            {
                let iter = lsp
                    .tlvs
                    .ext_is_reach()
                    // RFC 5305 - Section 3:
                    // "If a link is advertised with the maximum link metric,
                    // this link MUST NOT be considered during the normal SPF
                    // computation".
                    .filter(|reach| reach.metric < MAX_PATH_METRIC_WIDE)
                    .map(|reach| VertexEdge {
                        id: VertexId::new(reach.neighbor),
                        cost: reach.metric,
                    });
                wide_iter = Some(iter);
            }
            if mt_id != MtId::Standard {
                let iter = lsp
                    .tlvs
                    .mt_is_reach_by_id(mt_id)
                    // RFC 5305 - Section 3:
                    // "If a link is advertised with the maximum link metric,
                    // this link MUST NOT be considered during the normal SPF
                    // computation".
                    .filter(|reach| reach.metric < MAX_PATH_METRIC_WIDE)
                    .map(|reach| VertexEdge {
                        id: VertexId::new(reach.neighbor),
                        cost: reach.metric,
                    });
                mt_iter = Some(iter);
            }

            chain_option_iterators!(standard_iter, wide_iter, mt_iter)
        })
}

// Iterate over all IP reachability entries attached to a vertex.
fn vertex_networks<'a>(
    level_type: LevelType,
    level: LevelNumber,
    mt_id: MtId,
    vertex: &Vertex,
    att_bit: bool,
    is_l2_attached_to_backbone: bool,
    metric_type: MetricType,
    ipv4_enabled: bool,
    ipv6_enabled: bool,
    lsdb: &'a Lsdb,
    lsp_entries: &'a Arena<LspEntry>,
) -> impl Iterator<Item = VertexNetwork> + 'a {
    // Iterate over all LSP fragments.
    lsdb.iter_for_lan_id(lsp_entries, vertex.id.lan_id)
        .map(|lse| &lse.data)
        .filter(|lsp| lsp.seqno != 0)
        .filter(|lsp| lsp.rem_lifetime != 0)
        .flat_map(move |lsp| {
            let mut inter_area_defaults_iter = None;
            let mut ipv4_standard_iter = None;
            let mut ipv4_wide_iter = None;
            let mut ipv6_iter = None;

            // If the L1 LSP has the ATT bit set, add a default route if the
            // router is L1, or if the router is L1/L2 but not attached to the
            // L2 backbone.
            if att_bit
                && level == LevelNumber::L1
                && (level_type == LevelType::L1 || !is_l2_attached_to_backbone)
            {
                let mut inter_area_defaults = vec![];
                if ipv4_enabled {
                    inter_area_defaults.push(VertexNetwork {
                        prefix: IpNetwork::default(AddressFamily::Ipv4),
                        metric: 0,
                        external: false,
                        prefix_sid: None,
                    });
                }
                if ipv6_enabled {
                    inter_area_defaults.push(VertexNetwork {
                        prefix: IpNetwork::default(AddressFamily::Ipv6),
                        metric: 0,
                        external: false,
                        prefix_sid: None,
                    });
                }
                inter_area_defaults_iter =
                    Some(inter_area_defaults.into_iter());
            }

            // Iterate over IPv4 reachability entries.
            if mt_id == MtId::Standard && ipv4_enabled {
                if metric_type.is_standard_enabled() {
                    let internal =
                        lsp.tlvs.ipv4_internal_reach().map(|reach| {
                            VertexNetwork {
                                prefix: reach.prefix.into(),
                                metric: reach.metric(),
                                external: false,
                                prefix_sid: None,
                            }
                        });
                    // NOTE: RFC 1195 initially restricted the IP External
                    // Reachability Information TLV to L2 LSPs, but RFC 5302
                    // later lifted this restriction.
                    let external =
                        lsp.tlvs.ipv4_external_reach().map(|reach| {
                            VertexNetwork {
                                prefix: reach.prefix.into(),
                                metric: reach.metric(),
                                external: true,
                                prefix_sid: None,
                            }
                        });
                    ipv4_standard_iter = Some(internal.chain(external));
                }
                if metric_type.is_wide_enabled() {
                    let iter = lsp
                        .tlvs
                        .ext_ipv4_reach()
                        // RFC 5305 - Section 4:
                        // "If a prefix is advertised with a metric larger then
                        // MAX_PATH_METRIC this prefix MUST NOT be considered
                        // during the normal SPF computation".
                        .filter(|reach| reach.metric <= MAX_PATH_METRIC_WIDE)
                        .map(|reach| {
                            VertexNetwork {
                                prefix: reach.prefix.into(),
                                metric: reach.metric,
                                // For some reason, TLV 135 doesn't have a flag
                                // specifying whether the prefix has an external
                                // origin, unlike TLV 235 (the IPv6 equivalent).
                                // RFC 7794 specifies the Prefix Attributes
                                // Sub-TLV, which contains the External Prefix
                                // Flag (X-flag) to address this omission.
                                external: reach
                                    .prefix_attr_flags_get(PrefixAttrFlags::X)
                                    .unwrap_or(false),
                                prefix_sid: reach
                                    .sub_tlvs
                                    .prefix_sids
                                    .get(&IgpAlgoType::Spf)
                                    .cloned(),
                            }
                        });
                    ipv4_wide_iter = Some(iter);
                }
            }

            // Iterate over IPv6 reachability entries.
            if ipv6_enabled {
                let iter: Box<dyn Iterator<Item = &_>> = if mt_id
                    == MtId::Ipv6Unicast
                {
                    Box::new(lsp.tlvs.mt_ipv6_reach_by_id(MtId::Ipv6Unicast))
                } else {
                    Box::new(lsp.tlvs.ipv6_reach())
                };
                let iter = iter.map(|reach| VertexNetwork {
                    prefix: reach.prefix.into(),
                    metric: reach.metric,
                    external: reach.external,
                    prefix_sid: reach
                        .sub_tlvs
                        .prefix_sids
                        .get(&IgpAlgoType::Spf)
                        .cloned(),
                });
                ipv6_iter = Some(iter);
            }

            chain_option_iterators!(
                inter_area_defaults_iter,
                ipv4_standard_iter,
                ipv4_wide_iter,
                ipv6_iter,
            )
        })
}

// Retrieves the zeroth LSP for a given LAN ID.
fn zeroth_lsp<'a>(
    lan_id: LanId,
    lsdb: &'a Lsdb,
    lsp_entries: &'a Arena<LspEntry>,
) -> Option<&'a Lsp> {
    let lspid = LspId::from((lan_id, 0));
    lsdb.get_by_lspid(lsp_entries, &lspid)
        .map(|(_, lse)| &lse.data)
        .filter(|lsp| lsp.seqno != 0)
        .filter(|lsp| lsp.rem_lifetime != 0)
}

// Adds log entry for the SPF run.
fn log_spf_run(
    level: LevelNumber,
    instance: &mut InstanceUpView<'_>,
    spf_type: SpfType,
    schedule_time: Option<Instant>,
    start_time: Instant,
    end_time: Instant,
    mut trigger_lsps: Vec<LspLogId>,
) {
    // Get next log ID.
    let log_id = &mut instance.state.spf_log_next_id;
    *log_id += 1;

    // Get trigger LSPs in log format.
    trigger_lsps.truncate(SPF_LOG_TRIGGER_LSPS_MAX_SIZE);

    // Add new log entry.
    let log_entry = SpfLogEntry::new(
        *log_id,
        spf_type,
        level,
        schedule_time,
        start_time,
        end_time,
        trigger_lsps,
    );
    instance.state.spf_log.push_front(log_entry);

    // Remove old entries if necessary.
    instance.state.spf_log.truncate(SPF_LOG_MAX_SIZE);
}
