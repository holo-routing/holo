//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::IpAddr;

use holo_utils::bgp::{
    EthernetSegmentId, ExtComm, evpn_es_import_route_target,
};

pub const VLAN_MAX: u16 = 4094;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DfElection {
    pub df: IpAddr,
    pub self_is_df: bool,
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

#[cfg(test)]
mod tests {
    use const_addrs::ip4;
    use holo_utils::bgp::{ExtComm, evpn_es_import_route_target};

    use super::*;

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
}
