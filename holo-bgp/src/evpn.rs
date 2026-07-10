//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::IpAddr;

use holo_utils::bgp::{
    EthernetSegmentId, EvpnEsiLabel, ExtComm, evpn_es_import_route_target,
    evpn_esi_label_ext_comm, evpn_esi_label_from_ext_comm,
};

use crate::packet::message::EvpnRoute;

pub const VLAN_MAX: u16 = 4094;
pub const MAX_ETHERNET_TAG_ID: u32 = u32::MAX;

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
    use const_addrs::ip4;
    use holo_utils::bgp::{ExtComm, evpn_es_import_route_target};

    use super::*;
    use crate::packet::message::{
        EvpnEthernetAutoDiscovery, EvpnMacIpAdvertisement,
    };

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
}
