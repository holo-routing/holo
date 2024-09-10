//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::bier::{BierInfo, Bsl, UnderlayProtocolType};
use holo_utils::ip::IpNetworkKind;

use crate::instance::InstanceUpView;
use crate::packet::tlv::BierSubSubTlv;
use crate::route::RouteNet;
use crate::spf::SpfIntraAreaNetwork;
use crate::version::Version;

pub(crate) fn bier_route_add<V>(
    instance: &InstanceUpView<'_, V>,
    new_route: &mut RouteNet<V>,
    stub: &SpfIntraAreaNetwork<'_, V>,
) where
    V: Version,
{
    let bier_cfg = &instance.shared.bier_config;

    // 1. Does the BFR match a locally configured BIER sub-domain?
    stub.bier.iter().for_each(|tlv| {
        if instance.config.bier.mt_id == tlv.mt_id
            && let Some(sd_cfg) = bier_cfg
                .sd_cfg
                .get(&(tlv.sub_domain_id, stub.prefix.address_family()))
            && sd_cfg.underlay_protocol == UnderlayProtocolType::Ospf
        {
            // 2. Register entry in BIRT for each supported bitstring length by the BFR prefix
            // TODO: Use BAR and IPA

            // TODO: Sanity check on bitstring lengths upon LSA reception

            let bfr_bss: Vec<Bsl> = tlv
                .subtlvs
                .iter()
                .filter_map(|stlv| match stlv {
                    BierSubSubTlv::BierEncapSubSubTlv(encap) => {
                        Bsl::try_from(encap.bs_len).ok()
                    }
                })
                .collect();

            if !bfr_bss.is_empty() {
                new_route.bier_info = Some(BierInfo {
                    bfr_bss,
                    sd_id: tlv.sub_domain_id,
                    bfr_id: tlv.bfr_id,
                })
            }
        }
    });
}
