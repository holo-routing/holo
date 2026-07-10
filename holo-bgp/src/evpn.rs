//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use holo_utils::bgp::{
    EthernetSegmentId, EvpnEsiLabel, EvpnMacMobility, ExtComm,
    evpn_es_import_route_target, evpn_esi_label_ext_comm,
    evpn_esi_label_from_ext_comm, evpn_mac_mobility_ext_comm,
    evpn_mac_mobility_from_ext_comm,
};

use crate::packet::message::EvpnRoute;
use crate::rib::{Route, RouteCompare, RouteRejectReason};

pub const VLAN_MAX: u16 = 4094;
pub const MAX_ETHERNET_TAG_ID: u32 = u32::MAX;
pub const MAC_DUPLICATE_MOVE_THRESHOLD: usize = 5;
pub const MAC_DUPLICATE_WINDOW: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DfElection {
    pub df: IpAddr,
    pub self_is_df: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvpnMultihomingMode {
    AllActive,
    SingleActive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacMobilityDecision {
    None,
    Preferred,
    LessPreferred,
    StickyConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacMoveState {
    Stable,
    Duplicate,
}

#[derive(Debug)]
pub struct MacMoveTracker<T> {
    threshold: usize,
    window: Duration,
    moves: VecDeque<T>,
    duplicate: bool,
}

pub fn ead_per_es(ethernet_tag_id: u32, label: u32) -> bool {
    ethernet_tag_id == MAX_ETHERNET_TAG_ID && label == 0
}

pub fn esi_label_ext_comm(mode: EvpnMultihomingMode, label: u32) -> ExtComm {
    evpn_esi_label_ext_comm(EvpnEsiLabel {
        single_active: mode == EvpnMultihomingMode::SingleActive,
        label,
    })
}

pub fn esi_label_from_ext_comm(
    comm: &ExtComm,
) -> Option<(EvpnMultihomingMode, u32)> {
    let esi_label = evpn_esi_label_from_ext_comm(comm)?;
    let mode = if esi_label.single_active {
        EvpnMultihomingMode::SingleActive
    } else {
        EvpnMultihomingMode::AllActive
    };
    Some((mode, esi_label.label))
}

pub fn mac_mobility_ext_comm(sticky: bool, sequence: u32) -> ExtComm {
    evpn_mac_mobility_ext_comm(EvpnMacMobility { sticky, sequence })
}

pub fn mac_mobility_from_ext_comm(comm: &ExtComm) -> Option<EvpnMacMobility> {
    evpn_mac_mobility_from_ext_comm(comm)
}

pub fn mac_mobility_from_route(route: &Route) -> EvpnMacMobility {
    route
        .attrs
        .ext_comm
        .as_ref()
        .and_then(|ext_comms| {
            ext_comms
                .value
                .0
                .iter()
                .find_map(mac_mobility_from_ext_comm)
        })
        .unwrap_or(EvpnMacMobility {
            sticky: false,
            sequence: 0,
        })
}

pub fn mac_mobility_decision(
    route: EvpnMacMobility,
    best_route: EvpnMacMobility,
) -> MacMobilityDecision {
    match (route.sticky, best_route.sticky) {
        (true, false) => return MacMobilityDecision::Preferred,
        (false, true) => return MacMobilityDecision::StickyConflict,
        _ => {}
    }

    match route.sequence.cmp(&best_route.sequence) {
        std::cmp::Ordering::Greater => MacMobilityDecision::Preferred,
        std::cmp::Ordering::Less => MacMobilityDecision::LessPreferred,
        std::cmp::Ordering::Equal => MacMobilityDecision::None,
    }
}

pub fn mac_mobility_compare(
    prefix: EvpnRoute,
    route: &Route,
    best_route: &Route,
) -> Option<RouteCompare> {
    if !matches!(prefix, EvpnRoute::MacIpAdvertisement(_)) {
        return None;
    }

    match mac_mobility_decision(
        mac_mobility_from_route(route),
        mac_mobility_from_route(best_route),
    ) {
        MacMobilityDecision::Preferred => Some(RouteCompare::Preferred(
            RouteRejectReason::EvpnMacMobilityLowerSequence,
        )),
        MacMobilityDecision::LessPreferred => {
            Some(RouteCompare::LessPreferred(
                RouteRejectReason::EvpnMacMobilityLowerSequence,
            ))
        }
        MacMobilityDecision::StickyConflict => {
            Some(RouteCompare::LessPreferred(
                RouteRejectReason::EvpnMacMobilitySticky,
            ))
        }
        MacMobilityDecision::None => None,
    }
}

pub fn has_matching_es_import_rt<'a>(
    local_esis: impl IntoIterator<Item = &'a EthernetSegmentId>,
    ext_comms: impl IntoIterator<Item = &'a ExtComm>,
) -> bool {
    let import_rts = local_esis
        .into_iter()
        .map(|esi| evpn_es_import_route_target(*esi))
        .collect::<BTreeSet<_>>();

    ext_comms.into_iter().any(|comm| import_rts.contains(comm))
}

impl<T> MacMoveTracker<T>
where
    T: Copy + Ord + std::ops::Sub<Output = Duration>,
{
    pub fn new(threshold: usize, window: Duration) -> Self {
        MacMoveTracker {
            threshold,
            window,
            moves: VecDeque::new(),
            duplicate: false,
        }
    }

    pub fn record_move(&mut self, now: T) -> MacMoveState {
        while self
            .moves
            .front()
            .is_some_and(|oldest| now - *oldest > self.window)
        {
            self.moves.pop_front();
        }
        self.moves.push_back(now);
        if self.moves.len() >= self.threshold {
            self.duplicate = true;
        }

        if self.duplicate {
            MacMoveState::Duplicate
        } else {
            MacMoveState::Stable
        }
    }

    pub fn duplicate(&self) -> bool {
        self.duplicate
    }
}

impl<T> Default for MacMoveTracker<T>
where
    T: Copy + Ord + std::ops::Sub<Output = Duration>,
{
    fn default() -> Self {
        MacMoveTracker::new(MAC_DUPLICATE_MOVE_THRESHOLD, MAC_DUPLICATE_WINDOW)
    }
}

pub fn elect_df(
    self_originator: IpAddr,
    remote_originators: impl IntoIterator<Item = IpAddr>,
    vlan: u16,
) -> Option<DfElection> {
    if vlan > VLAN_MAX {
        return None;
    }

    let candidates = std::iter::once(self_originator)
        .chain(remote_originators)
        .collect::<BTreeSet<_>>();
    if candidates.is_empty() {
        return None;
    }

    let ordinal = vlan as usize % candidates.len();
    let df = candidates.into_iter().nth(ordinal)?;
    Some(DfElection {
        df,
        self_is_df: df == self_originator,
    })
}

pub fn mass_withdraw_match(
    route_peer: IpAddr,
    route_esi: EthernetSegmentId,
    withdrawn_peer: IpAddr,
    withdrawn_esi: EthernetSegmentId,
) -> bool {
    route_peer == withdrawn_peer && route_esi == withdrawn_esi
}

pub fn mass_withdraw_mac_routes(
    routes: impl IntoIterator<Item = (IpAddr, EvpnRoute)>,
    withdrawn_peer: IpAddr,
    withdrawn_esi: EthernetSegmentId,
) -> Vec<EvpnRoute> {
    routes
        .into_iter()
        .filter_map(|(peer, route)| {
            let EvpnRoute::MacIpAdvertisement(mac) = route else {
                return None;
            };
            mass_withdraw_match(peer, mac.esi, withdrawn_peer, withdrawn_esi)
                .then_some(route)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use const_addrs::ip4;
    use holo_utils::bgp::{
        ExtComm, Origin, RouteType, evpn_es_import_route_target,
    };
    use holo_utils::protocol::Protocol;

    use super::*;
    use crate::packet::attribute::{AsPath, BaseAttrs, CommList, ExtComms};
    use crate::packet::message::{
        EvpnEthernetAutoDiscovery, EvpnMacIpAdvertisement,
    };
    use crate::rib::{AttrSet, Route, RouteAttrs, RouteOrigin};

    const ESI: EthernetSegmentId =
        [0x03, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0, 1];

    #[test]
    fn es_import_rt_is_derived_from_esi_value_high_order_six_octets() {
        assert_eq!(
            evpn_es_import_route_target(ESI),
            ExtComm([0x06, 0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn es_import_rt_matches_local_esi() {
        let local_esis = [ESI];
        let ext_comms = [
            ExtComm([0x00, 0x02, 0xfd, 0xe8, 0, 0, 0, 100]),
            evpn_es_import_route_target(ESI),
        ];

        assert!(has_matching_es_import_rt(&local_esis, &ext_comms));
    }

    #[test]
    fn es_import_rt_miss_is_fail_closed() {
        let local_esis = [ESI];
        let ext_comms =
            [ExtComm([0x06, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])];

        assert!(!has_matching_es_import_rt(&local_esis, &ext_comms));
    }

    #[test]
    fn ead_per_es_identifies_max_et_and_label_zero_only() {
        assert!(ead_per_es(MAX_ETHERNET_TAG_ID, 0));
        assert!(!ead_per_es(100, 0));
        assert!(!ead_per_es(MAX_ETHERNET_TAG_ID, 16000));
    }

    #[test]
    fn esi_label_ext_community_roundtrips_redundancy_mode() {
        let all_active = esi_label_from_ext_comm(&esi_label_ext_comm(
            EvpnMultihomingMode::AllActive,
            16000,
        ))
        .unwrap();
        assert_eq!(all_active, (EvpnMultihomingMode::AllActive, 16000));

        let single_active = esi_label_from_ext_comm(&esi_label_ext_comm(
            EvpnMultihomingMode::SingleActive,
            16001,
        ))
        .unwrap();
        assert_eq!(single_active, (EvpnMultihomingMode::SingleActive, 16001));
    }

    #[test]
    fn mac_mobility_ext_community_roundtrips_sticky_and_sequence() {
        assert_eq!(
            mac_mobility_from_ext_comm(&mac_mobility_ext_comm(false, 42)),
            Some(EvpnMacMobility {
                sticky: false,
                sequence: 42,
            })
        );
        assert_eq!(
            mac_mobility_from_ext_comm(&mac_mobility_ext_comm(true, 43)),
            Some(EvpnMacMobility {
                sticky: true,
                sequence: 43,
            })
        );
    }

    #[test]
    fn mac_mobility_malformed_or_absent_is_ignored() {
        assert_eq!(
            mac_mobility_from_ext_comm(&ExtComm([
                0x06, 0xff, 0, 0, 0, 0, 0, 1
            ])),
            None
        );
        assert_eq!(
            mac_mobility_from_route(&route(None)),
            EvpnMacMobility {
                sticky: false,
                sequence: 0,
            }
        );
    }

    #[test]
    fn mac_mobility_higher_sequence_wins() {
        let low = route(Some(mac_mobility_ext_comm(false, 1)));
        let high = route(Some(mac_mobility_ext_comm(false, 2)));

        assert_eq!(
            mac_mobility_compare(mac_prefix(), &high, &low),
            Some(RouteCompare::Preferred(
                RouteRejectReason::EvpnMacMobilityLowerSequence
            ))
        );
        assert_eq!(
            mac_mobility_compare(mac_prefix(), &low, &high),
            Some(RouteCompare::LessPreferred(
                RouteRejectReason::EvpnMacMobilityLowerSequence
            ))
        );
    }

    #[test]
    fn mac_mobility_equal_sequence_falls_through() {
        let a = route(Some(mac_mobility_ext_comm(false, 7)));
        let b = route(Some(mac_mobility_ext_comm(false, 7)));

        assert_eq!(mac_mobility_compare(mac_prefix(), &a, &b), None);
    }

    #[test]
    fn mac_mobility_sticky_route_is_not_silently_superseded() {
        let sticky = route(Some(mac_mobility_ext_comm(true, 1)));
        let moved = route(Some(mac_mobility_ext_comm(false, 100)));

        assert_eq!(
            mac_mobility_compare(mac_prefix(), &moved, &sticky),
            Some(RouteCompare::LessPreferred(
                RouteRejectReason::EvpnMacMobilitySticky
            ))
        );
        assert_eq!(
            mac_mobility_compare(mac_prefix(), &sticky, &moved),
            Some(RouteCompare::Preferred(
                RouteRejectReason::EvpnMacMobilityLowerSequence
            ))
        );
    }

    #[test]
    fn duplicate_detection_uses_injected_time_window() {
        let start = Instant::now();
        let mut tracker = MacMoveTracker::new(5, Duration::from_secs(180));

        for second in [0, 10, 20, 30] {
            assert_eq!(
                tracker.record_move(start + Duration::from_secs(second)),
                MacMoveState::Stable
            );
        }
        assert_eq!(
            tracker.record_move(start + Duration::from_secs(40)),
            MacMoveState::Duplicate
        );
        assert!(tracker.duplicate());
    }

    #[test]
    fn duplicate_detection_ignores_moves_outside_window() {
        let start = Instant::now();
        let mut tracker = MacMoveTracker::new(5, Duration::from_secs(30));

        for second in [0, 10, 20, 40, 80] {
            assert_eq!(
                tracker.record_move(start + Duration::from_secs(second)),
                MacMoveState::Stable
            );
        }
        assert!(!tracker.duplicate());
    }

    #[test]
    fn mass_withdraw_matches_exact_peer_and_esi_only() {
        assert!(mass_withdraw_match(
            ip4!("192.0.2.1").into(),
            ESI,
            ip4!("192.0.2.1").into(),
            ESI,
        ));
        assert!(!mass_withdraw_match(
            ip4!("192.0.2.2").into(),
            ESI,
            ip4!("192.0.2.1").into(),
            ESI,
        ));
        assert!(!mass_withdraw_match(
            ip4!("192.0.2.1").into(),
            [0; 10],
            ip4!("192.0.2.1").into(),
            ESI,
        ));
    }

    #[test]
    fn mass_withdraw_selects_only_type2_routes_from_peer_and_esi() {
        let peer = ip4!("192.0.2.1").into();
        let other_peer = ip4!("192.0.2.2").into();
        let other_esi = [9; 10];
        let matching = EvpnRoute::MacIpAdvertisement(EvpnMacIpAdvertisement {
            rd: rd(),
            esi: ESI,
            ethernet_tag_id: 100,
            mac: [0, 1, 2, 3, 4, 5],
            ip: None,
            label: 16000,
        });
        let different_peer =
            EvpnRoute::MacIpAdvertisement(EvpnMacIpAdvertisement {
                rd: rd(),
                esi: ESI,
                ethernet_tag_id: 100,
                mac: [0, 1, 2, 3, 4, 6],
                ip: None,
                label: 16001,
            });
        let different_esi =
            EvpnRoute::MacIpAdvertisement(EvpnMacIpAdvertisement {
                rd: rd(),
                esi: other_esi,
                ethernet_tag_id: 100,
                mac: [0, 1, 2, 3, 4, 7],
                ip: None,
                label: 16002,
            });
        let non_mac =
            EvpnRoute::EthernetAutoDiscovery(EvpnEthernetAutoDiscovery {
                rd: rd(),
                esi: ESI,
                ethernet_tag_id: MAX_ETHERNET_TAG_ID,
                label: 0,
            });

        let withdrawn = mass_withdraw_mac_routes(
            [
                (peer, matching),
                (other_peer, different_peer),
                (peer, different_esi),
                (peer, non_mac),
            ],
            peer,
            ESI,
        );

        assert_eq!(withdrawn, vec![matching]);
    }

    #[test]
    fn df_election_uses_ordered_originators_and_vlan_modulo() {
        let election = elect_df(
            ip4!("192.0.2.3").into(),
            [ip4!("192.0.2.1").into(), ip4!("192.0.2.2").into()],
            101,
        )
        .unwrap();

        assert_eq!(election.df, ip4!("192.0.2.3"));
        assert!(election.self_is_df);
    }

    #[test]
    fn df_election_recomputes_after_current_df_withdraws() {
        let election = elect_df(
            ip4!("192.0.2.3").into(),
            [ip4!("192.0.2.1").into(), ip4!("192.0.2.2").into()],
            100,
        )
        .unwrap();
        assert_eq!(election.df, ip4!("192.0.2.2"));

        let election =
            elect_df(ip4!("192.0.2.3").into(), [ip4!("192.0.2.1").into()], 100)
                .unwrap();
        assert_eq!(election.df, ip4!("192.0.2.1"));
        assert!(!election.self_is_df);
    }

    #[test]
    fn df_election_rejects_invalid_vlan() {
        assert_eq!(elect_df(ip4!("192.0.2.1").into(), [], 4095), None);
    }

    fn rd() -> holo_utils::bgp::RouteDistinguisher {
        holo_utils::bgp::RouteDistinguisher::As2Administrator {
            asn: 65000,
            number: 1,
        }
    }

    fn mac_prefix() -> EvpnRoute {
        EvpnRoute::MacIpAdvertisement(EvpnMacIpAdvertisement {
            rd: rd(),
            esi: ESI,
            ethernet_tag_id: 100,
            mac: [0, 1, 2, 3, 4, 5],
            ip: None,
            label: 16000,
        })
    }

    fn route(mobility: Option<ExtComm>) -> Route {
        let base_attrs = BaseAttrs {
            origin: Origin::Igp,
            as_path: AsPath::default(),
            as4_path: None,
            nexthop: Some(ip4!("192.0.2.1").into()),
            ll_nexthop: None,
            med: None,
            local_pref: Some(100),
            aggregator: None,
            as4_aggregator: None,
            atomic_aggregate: None,
            originator_id: None,
            cluster_list: None,
        };
        let ext_comm = mobility.map(|comm| {
            Arc::new(AttrSet {
                index: 0,
                value: CommList([comm].into()),
            })
        });
        Route {
            origin: RouteOrigin::Protocol(Protocol::STATIC),
            attrs: RouteAttrs {
                base: Arc::new(AttrSet {
                    index: 0,
                    value: base_attrs,
                }),
                comm: None,
                ext_comm,
                extv6_comm: None,
                large_comm: None,
                unknown: None,
            },
            route_type: RouteType::Internal,
            vpn_label: None,
            igp_cost: None,
            last_modified: Instant::now(),
            ineligible_reason: None,
            reject_reason: None,
        }
    }
}
