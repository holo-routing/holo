//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangList, YangOps};
use holo_utils::ip::IpAddrKind;
use holo_utils::num::SaturatingInto;
use holo_utils::option::OptionExt;
use holo_utils::protocol::Protocol;
use holo_utils::sr::IgpAlgoType;
use holo_yang::{ToYang, ToYangBits};
use num_traits::FromPrimitive;

use crate::area::Area;
use crate::collections::LsdbSingleType;
use crate::instance::Instance;
use crate::interface::{Interface, ism};
use crate::lsdb::{LsaEntry, LsaLogEntry, LsaLogId};
use crate::neighbor::Neighbor;
use crate::northbound::yang_gen::ospf;
use crate::packet::lsa::{LsaBodyVersion, LsaHdrVersion};
use crate::packet::tlv::{BierEncapSubStlv, BierStlv, GrReason, NodeAdminTagTlv, SidLabelRangeTlv, SrLocalBlockTlv, UnknownTlv};
use crate::route::{Nexthop, RouteNet};
use crate::spf::SpfLogEntry;
use crate::version::{Ospfv2, Ospfv3, Version};
use crate::{ospfv2, ospfv3};

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry<'a> = ListEntry<'a, V>;
    const YANG_OPS: YangOps<Self> = V::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a, V: Version> {
    #[default]
    None,
    SpfLog(&'a SpfLogEntry<V>),
    SpfTriggerLsa(&'a LsaLogId<V>),
    LsaLog(&'a LsaLogEntry<V>),
    Route(&'a V::IpNetwork, &'a RouteNet<V>),
    Nexthop(&'a Nexthop<V::IpAddr>),
    Hostname(&'a Ipv4Addr, &'a String),
    AsStatsLsaType(&'a LsdbSingleType<V>),
    AsLsaType(&'a LsdbSingleType<V>),
    AsLsa(&'a LsaEntry<V>),
    Area(&'a Area<V>),
    AreaStatsLsaType(&'a LsdbSingleType<V>),
    AreaLsaType(&'a LsdbSingleType<V>),
    AreaLsa(&'a LsaEntry<V>),
    Interface(&'a Interface<V>),
    InterfaceStatsLsaType(&'a LsdbSingleType<V>),
    InterfaceLsaType(&'a LsdbSingleType<V>),
    InterfaceLsa(&'a LsaEntry<V>),
    Neighbor(&'a Interface<V>, &'a Neighbor<V>),
    Msd(u8, u8),
    Srgb(&'a SidLabelRangeTlv),
    Srlb(&'a SrLocalBlockTlv),
    NodeAdminTagTlv(&'a NodeAdminTagTlv),
    NodeAdminTag(&'a u32),
    UnknownTlv(&'a UnknownTlv),
    FlagU32(u32),
    // OSPFv2
    Ospfv2RouterLsaLink(&'a ospfv2::packet::lsa::LsaRouterLink),
    Ospfv2ExtPrefixTlv(&'a ospfv2::packet::lsa_opaque::ExtPrefixTlv),
    Ospfv2AdjSid(&'a ospfv2::packet::lsa_opaque::AdjSid),
    Ospfv2PrefixSid(&'a ospfv2::packet::lsa_opaque::PrefixSid),
    // OSPFv3
    Ospfv3RouterLsaLink(&'a ospfv3::packet::lsa::LsaRouterLink),
    Ospfv3LinkLsaPrefix(&'a ospfv3::packet::lsa::LsaLinkPrefix),
    Ospfv3AdjSids(&'a Vec<ospfv3::packet::lsa::AdjSid>),
    Ospfv3AdjSid(&'a ospfv3::packet::lsa::AdjSid),
    Ospfv3IntraAreaLsaPrefix(&'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry),
    Ospfv3PrefixSids(&'a BTreeMap<IgpAlgoType, ospfv3::packet::lsa::PrefixSid>),
    Ospfv3PrefixSid(&'a ospfv3::packet::lsa::PrefixSid),
    Ospfv3LinkLocalAddr(IpAddr),
    Ospfv3Biers(&'a Vec<BierStlv>),
    Ospfv3Bier(&'a BierStlv),
    Ospfv3BierEncaps(&'a Vec<BierEncapSubStlv>),
    Ospfv3BierEncap(&'a BierEncapSubStlv),
}

pub type ListIterator<'a, V> = Box<dyn Iterator<Item = ListEntry<'a, V>> + 'a>;

impl<V> ListEntryKind for ListEntry<'_, V> where V: Version {}

// ===== YANG impls =====

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::Ospf<'a> {
    fn new(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<Self> {
        Some(Self {
            router_id: instance.state.as_ref().map(|state| Cow::Owned(state.router_id)),
        })
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::spf_control::ietf_spf_delay::IetfSpfDelay<'a> {
    fn new(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let state = instance.state.as_ref()?;
        Some(Self {
            current_state: Some(state.spf_delay_state.to_yang()),
            remaining_time_to_learn: state.spf_learn_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
            remaining_hold_down: state.spf_hold_down_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
            last_event_received: state.spf_last_event_rcvd.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            next_spf_time: state.spf_delay_timer.as_ref().map(|timer| Instant::now() + timer.remaining()).map(Cow::Owned).ignore_in_testing(),
            last_spf_time: state.spf_last_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::local_rib::route::Route<'a> {
    fn iter(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.iter().map(|(destination, route)| ListEntry::Route(destination, route));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let (prefix, route) = list_entry.as_route().unwrap();
        Self {
            prefix: Cow::Owned((**prefix).into()),
            metric: Some(route.metric),
            route_type: Some(route.path_type.to_yang()),
            route_tag: route.tag,
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::local_rib::route::next_hops::next_hop::NextHop<'a> {
    fn iter(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let (_, route) = list_entry.as_route().unwrap();
        let iter = route.nexthops.values().map(ListEntry::Nexthop);
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let nexthop = list_entry.as_nexthop().unwrap();
        let iface = &instance.arenas.interfaces[nexthop.iface_idx];
        Self {
            outgoing_interface: Some(iface.name.as_str().into()),
            next_hop: nexthop.addr.map(std::convert::Into::into).map(Cow::Owned),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::statistics::Statistics<'a> {
    fn new(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let state = instance.state.as_ref()?;
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&state.discontinuity_time)).ignore_in_testing(),
            originate_new_lsa_count: Some(state.orig_lsa_count).ignore_in_testing(),
            rx_new_lsas_count: Some(state.rx_lsa_count).ignore_in_testing(),
            as_scope_lsa_count: Some(state.lsdb.lsa_count()),
            as_scope_lsa_chksum_sum: Some(state.lsdb.cksum_sum()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::statistics::database::as_scope_lsa_type::AsScopeLsaType {
    fn iter(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let lsdb = &instance.state.as_ref()?.lsdb;
        let iter = lsdb.iter_types().map(ListEntry::AsStatsLsaType);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lsdb_type = list_entry.as_as_stats_lsa_type().unwrap();
        Self {
            lsa_type: Some(lsdb_type.lsa_type().into()),
            lsa_count: Some(lsdb_type.lsa_count()),
            lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::database::as_scope_lsa_type::AsScopeLsaType {
    fn iter(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let lsdb = &instance.state.as_ref()?.lsdb;
        let iter = lsdb.iter_types().map(ListEntry::AsLsaType);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lsdb_type = list_entry.as_as_lsa_type().unwrap();
        Self {
            lsa_type: lsdb_type.lsa_type().into(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::AsScopeLsa<'a> {
    fn iter(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let lsdb_type = list_entry.as_as_lsa_type().unwrap();
        let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| ListEntry::AsLsa(lse));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        Self {
            lsa_id: lsa.hdr.lsa_id().to_string().into(),
            adv_router: Cow::Owned(lsa.hdr.adv_rtr()),
            decode_completed: Some(!lsa.body.is_unknown()),
            raw_data: Some(lsa.raw.as_ref()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::Header<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
        Some(Self {
            lsa_id: Some(Cow::Owned(lsa.hdr.lsa_id)),
            opaque_type,
            opaque_id,
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let iter = lsa.hdr.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::External<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        Some(Self {
            network_mask: lsa.body.as_as_external().map(|lsa_body| lsa_body.mask).map(Cow::Owned),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::Topology<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse: &LsaEntry<Ospfv2> = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let _lsa_body = lsa.body.as_as_external()?;
        let iter = std::iter::once(lse).map(ListEntry::AsLsa);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_as_external().unwrap();
        Self {
            mt_id: Some(0),
            flags: Some(lsa_body.flags.to_yang()),
            metric: Some(lsa_body.metric),
            forwarding_address: lsa_body.fwd_addr.map(Cow::Owned),
            external_route_tag: Some(lsa_body.tag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_as()?.as_router_info()?.info_caps.as_ref()?;
        let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            informational_capabilities: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_as()?.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let func_caps = lsa.body.as_opaque_as()?.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::dynamic_hostname_tlv::DynamicHostnameTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let hostname = lsa.body.as_opaque_as()?.as_router_info()?.info_hostname.as_ref()?;
        Some(Self {
            hostname: Some(Cow::Borrowed(hostname.get())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_as()?.as_router_info()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let (msd_type, msd_value) = list_entry.as_msd().unwrap();
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_as()?.as_router_info()?;
        let iter = lsa_body.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::SrAlgorithmTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_router_info()?;
        let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::SidRangeTlv {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_as()?.as_router_info()?;
        let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let srgb = list_entry.as_srgb().unwrap();
        Self {
            range_size: Some(srgb.range),
            label_value: srgb.first.as_label().map(|label| label.get()),
            index_value: srgb.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::LocalBlockTlv {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_router_info()?;
        let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let srlb = list_entry.as_srlb().unwrap();
        Self {
            range_size: Some(srlb.range),
            label_value: srlb.first.as_label().map(|label| label.get()),
            index_value: srlb.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::SrmsPreferenceTlv {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_as()?.as_router_info()?;
        Some(Self {
            preference: lsa_body.srms_pref.as_ref().map(|tlv| tlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::ExtendedPrefixTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_as()?.as_ext_prefix()?;
        let iter = lsa_body.prefixes.values().map(ListEntry::Ospfv2ExtPrefixTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tlv = list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
        Self {
            route_type: Some(tlv.route_type.to_yang()),
            prefix: Some(Cow::Owned(tlv.prefix.into())),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::Flags<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let tlv = list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
        let iter = tlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            extended_prefix_flags: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let tlv = list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
        let iter = tlv.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let tlv = list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
        let iter = tlv.prefix_sids.values().map(ListEntry::Ospfv2PrefixSid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let stlv = list_entry.as_ospfv2_prefix_sid().unwrap();
        Self {
            mt_id: Some(0),
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let prefix_sid = list_entry.as_ospfv2_prefix_sid().unwrap();
        let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::Header<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id.into()),
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::AsExternal<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_as_external()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            flags: Some(lsa_body.flags.to_yang()),
            referenced_ls_type: lsa_body.ref_lsa_type.map(|lsa_type| lsa_type.to_yang()),
            unknown_referenced_ls_type: lsa_body.ref_lsa_type.and_then(|ref_lsa_type| if ref_lsa_type.function_code().is_none() { Some(ref_lsa_type.0) } else { None }),
            prefix: Some(Cow::Borrowed(&lsa_body.prefix)),
            forwarding_address: lsa_body.fwd_addr.map(|addr| {
                Cow::Owned(match addr {
                    IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                    IpAddr::V6(addr) => addr,
                })
            }),
            external_route_tag: lsa_body.tag,
            referenced_link_state_id: lsa_body.ref_lsa_id.map(|lsa_id| lsa_id.into()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::prefix_options::PrefixOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_as_external()?;
        let iter = lsa_body.prefix_options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            prefix_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            informational_capabilities: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let func_caps = lsa.body.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::dynamic_hostname_tlv::DynamicHostnameTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let info_hostname = lsa.body.as_router_info()?.info_hostname.as_ref()?;
        Some(Self {
            hostname: Some(Cow::Borrowed(info_hostname.get())),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::SrAlgorithmTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::SidRangeTlv {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let srgb = list_entry.as_srgb().unwrap();
        Self {
            range_size: Some(srgb.range),
            label_value: srgb.first.as_label().map(|label| label.get()),
            index_value: srgb.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::LocalBlockTlv {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let srlb = list_entry.as_srlb().unwrap();
        Self {
            range_size: Some(srlb.range),
            label_value: srlb.first.as_label().map(|label| label.get()),
            index_value: srlb.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::SrmsPreferenceTlv {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        Some(Self {
            preference: lsa_body.srms_pref.as_ref().map(|tlv| tlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::EExternalTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse: &LsaEntry<Ospfv3> = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let _ = lsa.body.as_ext_as_external()?;
        let iter = std::iter::once(lse).map(ListEntry::AsLsa);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::ExternalPrefixTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_as_external()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            prefix: Some(Cow::Borrowed(&lsa_body.prefix)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::flags::Flags<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_as_external()?;
        let iter = lsa_body.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            ospfv3_e_external_prefix_bits: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix_options::PrefixOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_as_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_as_external()?;
        let iter = lsa_body.prefix_options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            prefix_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::SubTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        None // TODO
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv6_fwd_addr_sub_tlv::Ipv6FwdAddrSubTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        Some(Self {
            forwarding_address: None, // TODO
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv4_fwd_addr_sub_tlv::Ipv4FwdAddrSubTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        Some(Self {
            forwarding_address: None, // TODO
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::route_tag_sub_tlv::RouteTagSubTlv {
    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        Some(Self {
            route_tag: None, // TODO
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let prefix_sids = list_entry.as_ospfv3_prefix_sids()?;
        let iter = prefix_sids.values().map(ListEntry::Ospfv3PrefixSid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let stlv = list_entry.as_ospfv3_prefix_sid().unwrap();
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let prefix_sid = list_entry.as_ospfv3_prefix_sid().unwrap();
        let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::spf_log::event::Event<'a> {
    fn iter(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let spf_log = &instance.state.as_ref()?.spf_log;
        let iter = spf_log.iter().map(ListEntry::SpfLog);
        Some(Box::new(iter) as _).ignore_in_testing()
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let log = list_entry.as_spf_log().unwrap();
        Self {
            id: log.id,
            spf_type: Some(log.spf_type.to_yang()),
            schedule_timestamp: Some(Cow::Borrowed(&log.schedule_time)),
            start_timestamp: Some(Cow::Borrowed(&log.start_time)),
            end_timestamp: Some(Cow::Borrowed(&log.end_time)),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::spf_log::event::trigger_lsa::TriggerLsa<'a> {
    fn iter(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let log = list_entry.as_spf_log().unwrap();
        let iter = log.trigger_lsas.iter().map(ListEntry::SpfTriggerLsa);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lsa_id = list_entry.as_spf_trigger_lsa().unwrap();
        Self {
            area_id: lsa_id.area_id.map(Cow::Owned),
            r#type: Some(lsa_id.lsa_type.into()),
            lsa_id: Some(lsa_id.lsa_id.to_string().into()),
            adv_router: Some(Cow::Owned(lsa_id.adv_rtr)),
            seq_num: Some(lsa_id.seq_no).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::lsa_log::event::Event<'a> {
    fn iter(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let lsa_log = &instance.state.as_ref()?.lsa_log;
        let iter = lsa_log.iter().map(ListEntry::LsaLog);
        Some(Box::new(iter) as _).ignore_in_testing()
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let log = list_entry.as_lsa_log().unwrap();
        Self {
            id: log.id,
            received_timestamp: log.rcvd_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            reason: Some(log.reason.to_yang()),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::lsa_log::event::lsa::Lsa<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let log = list_entry.as_lsa_log().unwrap();
        Some(Self {
            area_id: log.lsa.area_id.map(Cow::Owned),
            r#type: Some(log.lsa.lsa_type.into()),
            lsa_id: Some(log.lsa.lsa_id.to_string().into()),
            adv_router: Some(Cow::Owned(log.lsa.adv_rtr)),
            seq_num: Some(log.lsa.seq_no).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::Area<'a> {
    fn iter(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let iter = instance.arenas.areas.iter().map(ListEntry::Area);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let area = list_entry.as_area().unwrap();
        Self {
            area_id: Cow::Owned(area.area_id),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::statistics::Statistics<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let area = list_entry.as_area().unwrap();
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&area.state.discontinuity_time)).ignore_in_testing(),
            spf_runs_count: Some(area.state.spf_run_count).ignore_in_testing(),
            abr_count: Some(area.abr_count() as _),
            asbr_count: Some(area.asbr_count() as _),
            area_scope_lsa_count: Some(area.state.lsdb.lsa_count()),
            area_scope_lsa_cksum_sum: Some(area.state.lsdb.cksum_sum()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::statistics::database::area_scope_lsa_type::AreaScopeLsaType {
    fn iter(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let area = list_entry.as_area().unwrap();
        let iter = area.state.lsdb.iter_types().map(ListEntry::AreaStatsLsaType);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lsdb_type = list_entry.as_area_stats_lsa_type().unwrap();
        Self {
            lsa_type: Some(lsdb_type.lsa_type().into()),
            lsa_count: Some(lsdb_type.lsa_count()),
            lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::database::area_scope_lsa_type::AreaScopeLsaType {
    fn iter(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let area = list_entry.as_area().unwrap();
        let iter = area.state.lsdb.iter_types().map(ListEntry::AreaLsaType);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lsdb_type = list_entry.as_area_lsa_type().unwrap();
        Self {
            lsa_type: lsdb_type.lsa_type().into(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::AreaScopeLsa<'a> {
    fn iter(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let lsdb_type = list_entry.as_area_lsa_type().unwrap();
        let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| ListEntry::AreaLsa(lse));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        Self {
            lsa_id: lsa.hdr.lsa_id().to_string().into(),
            adv_router: Cow::Owned(lsa.hdr.adv_rtr()),
            decode_completed: Some(!lsa.body.is_unknown()),
            raw_data: Some(lsa.raw.as_ref()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::Header<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
        Some(Self {
            lsa_id: Some(Cow::Owned(lsa.hdr.lsa_id)),
            opaque_type,
            opaque_id,
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let iter = lsa.hdr.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::Router {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router()?;
        Some(Self {
            num_of_links: Some(lsa_body.links.len() as u16),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::router_bits::RouterBits<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router()?;
        let iter = lsa_body.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            rtr_lsa_bits: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::Link<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router()?;
        let iter = lsa_body.links.iter().map(ListEntry::Ospfv2RouterLsaLink);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let rtr_link = list_entry.as_ospfv2_router_lsa_link().unwrap();
        Self {
            link_id: Some(rtr_link.link_id.to_string().into()),
            link_data: Some(rtr_link.link_data.to_string().into()),
            r#type: Some(rtr_link.link_type.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::topologies::topology::Topology {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let rtr_link = list_entry.as_ospfv2_router_lsa_link().unwrap();
        let iter = std::iter::once(*rtr_link).map(ListEntry::Ospfv2RouterLsaLink);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let rtr_link = list_entry.as_ospfv2_router_lsa_link().unwrap();
        Self {
            mt_id: Some(0),
            metric: Some(rtr_link.metric),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::Network<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_network()?;
        Some(Self {
            network_mask: Some(Cow::Owned(lsa_body.mask)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::attached_routers::AttachedRouters<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_network()?;
        let iter = lsa_body.attached_rtrs.iter().map(Cow::Borrowed);
        Some(Self {
            attached_router: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::Summary<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_summary()?;
        Some(Self {
            network_mask: Some(Cow::Owned(lsa_body.mask)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::topologies::topology::Topology {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse: &LsaEntry<Ospfv2> = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let _ = lsa.body.as_summary()?;
        let iter = std::iter::once(lse).map(ListEntry::AreaLsa);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_summary().unwrap();
        Self {
            mt_id: Some(0),
            metric: Some(lsa_body.metric),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_area()?.as_router_info()?.info_caps.as_ref()?;
        let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            informational_capabilities: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_area()?.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let func_caps = lsa.body.as_opaque_area()?.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::node_tag_tlvs::node_tag_tlv::NodeTagTlv {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.node_tags.iter().map(ListEntry::NodeAdminTagTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, _list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        Self {}
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::node_tag_tlvs::node_tag_tlv::node_tag::NodeTag {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let tlv = list_entry.as_node_admin_tag_tlv().unwrap();
        let iter = tlv.tags.iter().map(ListEntry::NodeAdminTag);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tag = list_entry.as_node_admin_tag().unwrap();
        Self {
            tag: Some(**tag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::dynamic_hostname_tlv::DynamicHostnameTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let hostname = lsa.body.as_opaque_area()?.as_router_info()?.info_hostname.as_ref()?;
        Some(Self {
            hostname: Some(Cow::Borrowed(hostname.get())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_area()?.as_router_info()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let (msd_type, msd_value) = list_entry.as_msd().unwrap();
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::SrAlgorithmTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::SidRangeTlv {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let srgb = list_entry.as_srgb().unwrap();
        Self {
            range_size: Some(srgb.range),
            label_value: srgb.first.as_label().map(|label| label.get()),
            index_value: srgb.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::LocalBlockTlv {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let srlb = list_entry.as_srlb().unwrap();
        Self {
            range_size: Some(srlb.range),
            label_value: srlb.first.as_label().map(|label| label.get()),
            index_value: srlb.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::SrmsPreferenceTlv {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        Some(Self {
            preference: lsa_body.srms_pref.as_ref().map(|tlv| tlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::ExtendedPrefixTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_ext_prefix()?;
        let iter = lsa_body.prefixes.values().map(ListEntry::Ospfv2ExtPrefixTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tlv = list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
        Self {
            route_type: Some(tlv.route_type.to_yang()),
            prefix: Some(Cow::Owned(tlv.prefix.into())),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::Flags<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let tlv = list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
        let flags = tlv.flags.to_yang_bits();
        let iter = flags.into_iter().map(|flag| flag.to_string().into());
        Some(Self {
            extended_prefix_flags: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let tlv = list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
        let iter = tlv.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let tlv = list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
        let iter = tlv.prefix_sids.values().map(ListEntry::Ospfv2PrefixSid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let stlv = list_entry.as_ospfv2_prefix_sid().unwrap();
        Self {
            mt_id: Some(0),
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let prefix_sid = list_entry.as_ospfv2_prefix_sid().unwrap();
        let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::ExtendedLinkTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let tlv = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?;
        Some(Self {
            link_id: Some(tlv.link_id.to_string().into()),
            link_data: Some(tlv.link_data.to_string().into()),
            r#type: Some(tlv.link_type.to_yang()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::MsdType {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let (msd_type, msd_value) = list_entry.as_msd().unwrap();
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let tlv = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?;
        let iter = tlv.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let tlv = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?;
        let iter = tlv.adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_none()).map(ListEntry::Ospfv2AdjSid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let stlv = list_entry.as_ospfv2_adj_sid().unwrap();
        Self {
            mt_id: Some(0),
            weight: Some(stlv.weight),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let adj_sid = list_entry.as_ospfv2_adj_sid().unwrap();
        let iter = adj_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::LanAdjSidSubTlv<'a>
{
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let tlv = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?;
        let iter = tlv.adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_some()).map(ListEntry::Ospfv2AdjSid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let stlv = list_entry.as_ospfv2_adj_sid().unwrap();
        Self {
            mt_id: Some(0),
            weight: Some(stlv.weight),
            neighbor_router_id: Some(Cow::Owned(stlv.nbr_router_id.unwrap())),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::LanAdjSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let adj_sid = list_entry.as_ospfv2_adj_sid().unwrap();
        let iter = adj_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::Header<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id.into()),
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::router_bits::RouterBits<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_router()?;
        let iter = lsa_body.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            rtr_lsa_bits: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_router()?;
        let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::Link<'a> {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_router()?;
        let iter = lsa_body.links.iter().map(ListEntry::Ospfv3RouterLsaLink);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let rtr_link = list_entry.as_ospfv3_router_lsa_link().unwrap();
        Self {
            interface_id: Some(rtr_link.iface_id),
            neighbor_interface_id: Some(rtr_link.nbr_iface_id),
            neighbor_router_id: Some(Cow::Owned(rtr_link.nbr_router_id)),
            r#type: Some(rtr_link.link_type.to_yang()),
            metric: Some(rtr_link.metric),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_network()?;
        let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::attached_routers::AttachedRouters<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_network()?;
        let iter = lsa_body.attached_rtrs.iter().map(Cow::Borrowed);
        Some(Self {
            attached_router: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::InterAreaPrefix<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_inter_area_prefix()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            prefix: Some(Cow::Borrowed(&lsa_body.prefix)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::prefix_options::PrefixOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_inter_area_prefix()?;
        let iter = lsa_body.prefix_options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            prefix_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::InterAreaRouter<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_inter_area_router()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            destination_router_id: Some(Cow::Owned(lsa_body.router_id)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_inter_area_router()?;
        let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::IntraAreaPrefix<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_intra_area_prefix()?;
        Some(Self {
            referenced_ls_type: Some(lsa_body.ref_lsa_type.to_yang()),
            unknown_referenced_ls_type: if lsa_body.ref_lsa_type.function_code().is_none() { Some(lsa_body.ref_lsa_type.0) } else { None },
            referenced_link_state_id: Some(lsa_body.ref_lsa_id.into()),
            referenced_adv_router: Some(Cow::Owned(lsa_body.ref_adv_rtr)),
            num_of_prefixes: Some(lsa_body.prefixes.len() as _),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::Prefix<'a> {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_intra_area_prefix()?;
        let iter = lsa_body.prefixes.iter().map(ListEntry::Ospfv3IntraAreaLsaPrefix);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let prefix = list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
        Self {
            prefix: Some(Cow::Borrowed(&prefix.value)),
            metric: Some(prefix.metric),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix_options::PrefixOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let prefix = list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
        let iter = prefix.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            prefix_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            informational_capabilities: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let func_caps = lsa.body.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::node_tag_tlvs::node_tag_tlv::NodeTagTlv {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.node_tags.iter().map(ListEntry::NodeAdminTagTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::node_tag_tlvs::node_tag_tlv::node_tag::NodeTag {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let tlv = list_entry.as_node_admin_tag_tlv().unwrap();
        let iter = tlv.tags.iter().map(ListEntry::NodeAdminTag);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let tag = list_entry.as_node_admin_tag().unwrap();
        Self {
            tag: Some(**tag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::dynamic_hostname_tlv::DynamicHostnameTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let info_hostname = lsa.body.as_router_info()?.info_hostname.as_ref()?;
        Some(Self {
            hostname: Some(Cow::Borrowed(info_hostname.get())),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::SrAlgorithmTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::SidRangeTlv {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let srgb = list_entry.as_srgb().unwrap();
        Self {
            range_size: Some(srgb.range),
            label_value: srgb.first.as_label().map(|label| label.get()),
            index_value: srgb.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::LocalBlockTlv {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let srlb = list_entry.as_srlb().unwrap();
        Self {
            range_size: Some(srlb.range),
            label_value: srlb.first.as_label().map(|label| label.get()),
            index_value: srlb.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::SrmsPreferenceTlv {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        Some(Self {
            preference: lsa_body.srms_pref.as_ref().map(|tlv| tlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::router_bits::RouterBits<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_router()?;
        let iter = lsa_body.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            rtr_lsa_bits: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_router()?;
        let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::ERouterTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_router()?;
        let iter = lsa_body.links.iter().map(ListEntry::Ospfv3RouterLsaLink);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::LinkTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let rtr_link = list_entry.as_ospfv3_router_lsa_link().unwrap();
        Some(Self {
            interface_id: Some(rtr_link.iface_id),
            neighbor_interface_id: Some(rtr_link.nbr_iface_id),
            neighbor_router_id: Some(Cow::Owned(rtr_link.nbr_router_id)),
            r#type: Some(rtr_link.link_type.to_yang()),
            metric: Some(rtr_link.metric),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::SubTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let tlv = list_entry.as_ospfv3_router_lsa_link().unwrap();
        let iter = tlv.unknown_stlvs.iter().map(ListEntry::UnknownTlv).chain(std::iter::once(ListEntry::Ospfv3AdjSids(&tlv.adj_sids)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let adj_sids = list_entry.as_ospfv3_adj_sids()?;
        let iter = adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_none()).map(ListEntry::Ospfv3AdjSid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let stlv = list_entry.as_ospfv3_adj_sid().unwrap();
        Self {
            weight: Some(stlv.weight),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let adj_sid = list_entry.as_ospfv3_adj_sid().unwrap();
        let iter = adj_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::LanAdjSidSubTlv<'a>
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let adj_sids = list_entry.as_ospfv3_adj_sids()?;
        let iter = adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_some()).map(ListEntry::Ospfv3AdjSid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let stlv = list_entry.as_ospfv3_adj_sid().unwrap();
        Self {
            weight: Some(stlv.weight),
            neighbor_router_id: Some(Cow::Owned(stlv.nbr_router_id.unwrap())),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::LanAdjSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let adj_sid = list_entry.as_ospfv3_adj_sid().unwrap();
        let iter = adj_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_network()?;
        let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::ENetworkTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        // Nothing to do.
        None
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::attached_router_tlv::AttachedRouterTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_network()?;
        let iter = lsa_body.attached_rtrs.iter().map(Cow::Borrowed);
        Some(Self {
            adjacent_neighbor_router_id: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::EInterPrefixTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse: &LsaEntry<Ospfv3> = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let _ = lsa.body.as_ext_inter_area_prefix()?;
        let iter = std::iter::once(lse).map(ListEntry::AreaLsa);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::InterPrefixTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_prefix()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            prefix: Some(Cow::Borrowed(&lsa_body.prefix)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix_options::PrefixOptions<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_prefix()?;
        let iter = lsa_body.prefix_options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            prefix_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::SubTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_prefix()?;
        let iter = lsa_body.unknown_stlvs.iter().map(ListEntry::UnknownTlv).chain(std::iter::once(ListEntry::Ospfv3PrefixSids(&lsa_body.prefix_sids)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let prefix_sids = list_entry.as_ospfv3_prefix_sids()?;
        let iter = prefix_sids.values().map(ListEntry::Ospfv3PrefixSid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let stlv = list_entry.as_ospfv3_prefix_sid().unwrap();
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let prefix_sid = list_entry.as_ospfv3_prefix_sid().unwrap();
        let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::EInterRouterTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse: &LsaEntry<Ospfv3> = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let _ = lsa.body.as_ext_inter_area_router()?;
        let iter = std::iter::once(lse).map(ListEntry::AreaLsa);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::InterRouterTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_router()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            destination_router_id: Some(Cow::Owned(lsa_body.router_id)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_router()?;
        let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::SubTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_router()?;
        let iter = lsa_body.unknown_stlvs.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::EIntraAreaPrefix<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_intra_area_prefix()?;
        Some(Self {
            referenced_ls_type: Some(lsa_body.ref_lsa_type.into()),
            referenced_link_state_id: Some(lsa_body.ref_lsa_id.into()),
            referenced_adv_router: Some(Cow::Owned(lsa_body.ref_adv_rtr)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::EIntraPrefixTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_area_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_intra_area_prefix()?;
        let iter = lsa_body.prefixes.iter().map(ListEntry::Ospfv3IntraAreaLsaPrefix);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::IntraPrefixTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let prefix = list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
        Some(Self {
            metric: Some(prefix.metric as u32),
            prefix: Some(Cow::Borrowed(&prefix.value)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix_options::PrefixOptions<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let prefix = list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
        let iter = prefix.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            prefix_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::SubTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let prefix = list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
        let iter = prefix
            .unknown_stlvs
            .iter()
            .map(ListEntry::UnknownTlv)
            .chain((!prefix.prefix_sids.is_empty()).then_some(ListEntry::Ospfv3PrefixSids(&prefix.prefix_sids)))
            .chain((!prefix.bier.is_empty()).then_some(ListEntry::Ospfv3Biers(&prefix.bier)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::BierInfoSubTlv
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let biers = list_entry.as_ospfv3_biers()?;
        let iter = biers.iter().map(ListEntry::Ospfv3Bier);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let bier = list_entry.as_ospfv3_bier().unwrap();
        Self {
            sub_domain_id: Some(bier.sub_domain_id),
            mt_id: Some(bier.mt_id),
            bfr_id: Some(bier.bfr_id),
            bar: Some(bier.bar),
            ipa: Some(bier.ipa),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::SubSubTlvs
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let bier = list_entry.as_ospfv3_bier().unwrap();
        let iter = bier.unknown_sstlvs.iter().map(ListEntry::UnknownTlv).chain(std::iter::once(ListEntry::Ospfv3BierEncaps(&bier.encaps)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::bier_encap_sub_sub_tlvs::bier_encap_sub_sub_tlv::BierEncapSubSubTlv
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let bier_encaps = list_entry.as_ospfv3_bier_encaps()?;
        let iter = bier_encaps.iter().map(ListEntry::Ospfv3BierEncap);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let bier_encap = list_entry.as_ospfv3_bier_encap().unwrap();
        Self {
            max_si: Some(bier_encap.max_si),
            id: Some(bier_encap.id.clone().get()),
            bs_len: Some(bier_encap.bs_len)
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let prefix_sids = list_entry.as_ospfv3_prefix_sids()?;
        let iter = prefix_sids.values().map(ListEntry::Ospfv3PrefixSid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let stlv = list_entry.as_ospfv3_prefix_sid().unwrap();
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let prefix_sid = list_entry.as_ospfv3_prefix_sid().unwrap();
        let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::VirtualLink<'a> {
    fn iter(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let area = list_entry.as_area().unwrap();
        let iter = area.interfaces.iter(&instance.arenas.interfaces).filter(|iface| iface.is_virtual_link()).map(ListEntry::Interface);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let iface = list_entry.as_interface().unwrap();
        let vlink_key = iface.vlink_key.unwrap();
        Self {
            transit_area_id: Cow::Owned(vlink_key.transit_area_id),
            router_id: Cow::Owned(vlink_key.router_id),
            cost: iface.state.vlink.as_ref().map(|vlink| vlink.cost as u16),
            state: Some(iface.state.ism_state.to_yang()),
            hello_timer: iface.state.tasks.hello_interval.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
            wait_timer: iface.state.tasks.wait_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
            dr_router_id: None,
            dr_ip_addr: None,
            bdr_router_id: None,
            bdr_ip_addr: None,
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::statistics::Statistics<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let iface = list_entry.as_interface().unwrap();
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&iface.state.discontinuity_time)).ignore_in_testing(),
            if_event_count: Some(iface.state.event_count).ignore_in_testing(),
            link_scope_lsa_count: Some(iface.state.lsdb.lsa_count()),
            link_scope_lsa_cksum_sum: Some(iface.state.lsdb.cksum_sum()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::statistics::database::link_scope_lsa_type::LinkScopeLsaType {
    fn iter(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = iface.state.lsdb.iter_types().map(ListEntry::InterfaceStatsLsaType);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lsdb_type = list_entry.as_interface_stats_lsa_type().unwrap();
        Self {
            lsa_type: Some(lsdb_type.lsa_type().into()),
            lsa_count: Some(lsdb_type.lsa_count()),
            lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::neighbors::neighbor::Neighbor<'a> {
    fn iter(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = iface.state.neighbors.iter(&instance.arenas.neighbors).map(|nbr| ListEntry::Neighbor(iface, nbr));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let (_iface, nbr) = list_entry.as_neighbor().unwrap();
        Self {
            neighbor_router_id: Cow::Owned(nbr.router_id),
            address: Some(Cow::Owned(nbr.src.into())),
            dr_router_id: None,
            dr_ip_addr: None,
            bdr_router_id: None,
            bdr_ip_addr: None,
            state: Some(nbr.state.to_yang()),
            cost: None,
            dead_timer: nbr.tasks.inactivity_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::neighbors::neighbor::statistics::Statistics<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let (_, nbr) = list_entry.as_neighbor().unwrap();
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&nbr.discontinuity_time)).ignore_in_testing(),
            nbr_event_count: Some(nbr.event_count).ignore_in_testing(),
            nbr_retrans_qlen: Some(nbr.lists.ls_rxmt.len() as u32),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::LinkScopeLsaType {
    fn iter(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = iface.state.lsdb.iter_types().map(ListEntry::InterfaceLsaType);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lsdb_type = list_entry.as_interface_lsa_type().unwrap();
        Self {
            lsa_type: lsdb_type.lsa_type().into(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::LinkScopeLsa<'a> {
    fn iter(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let lsdb_type = list_entry.as_interface_lsa_type().unwrap();
        let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| ListEntry::InterfaceLsa(lse));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        Self {
            lsa_id: lsa.hdr.lsa_id().to_string().into(),
            adv_router: Cow::Owned(lsa.hdr.adv_rtr()),
            decode_completed: Some(!lsa.body.is_unknown()),
            raw_data: Some(lsa.raw.as_ref()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::Header<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
        Some(Self {
            lsa_id: Some(Cow::Owned(lsa.hdr.lsa_id)),
            opaque_type,
            opaque_id,
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let iter = lsa.hdr.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_link()?.as_router_info()?.info_caps.as_ref()?;
        let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            informational_capabilities: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_link()?.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities
{
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let func_caps = lsa.body.as_opaque_link()?.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_link()?.as_ext_link()?.link.as_ref()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let (msd_type, msd_value) = list_entry.as_msd().unwrap();
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_router_info()?;
        let iter = lsa_body.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::Header<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id.into()),
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            informational_capabilities: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let func_caps = lsa.body.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::Interface<'a> {
    fn iter(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let area = list_entry.as_area().unwrap();
        let iter = area.interfaces.iter(&instance.arenas.interfaces).filter(|iface| !iface.is_virtual_link()).map(ListEntry::Interface);
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let iface = list_entry.as_interface().unwrap();
        let mut dr_router_id = None;
        let mut dr_ip_addr = None;
        let mut bdr_router_id = None;
        let mut bdr_ip_addr = None;
        if let Some(instance_state) = &instance.state {
            if iface.state.ism_state == ism::State::Dr {
                dr_router_id = Some(instance_state.router_id);
                dr_ip_addr = Some(iface.state.src_addr.unwrap().into());
            } else if let Some(dr_net_id) = iface.state.dr
                && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, dr_net_id)
            {
                dr_router_id = Some(nbr.router_id);
                dr_ip_addr = Some(nbr.src.into());
            }
            if iface.state.ism_state == ism::State::Backup {
                bdr_router_id = Some(instance_state.router_id);
                bdr_ip_addr = Some(iface.state.src_addr.unwrap().into());
            } else if let Some(bdr_net_id) = iface.state.bdr
                && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, bdr_net_id)
            {
                bdr_router_id = Some(nbr.router_id);
                bdr_ip_addr = Some(nbr.src.into());
            }
        }
        Self {
            name: Cow::Borrowed(&iface.name),
            state: Some(iface.state.ism_state.to_yang()),
            hello_timer: iface.state.tasks.hello_interval.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
            wait_timer: iface.state.tasks.wait_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
            dr_router_id: dr_router_id.map(Cow::Owned),
            dr_ip_addr: dr_ip_addr.map(Cow::Owned),
            bdr_router_id: bdr_router_id.map(Cow::Owned),
            bdr_ip_addr: bdr_ip_addr.map(Cow::Owned),
            interface_id: if V::PROTOCOL == Protocol::OSPFV3 { iface.system.ifindex } else { None },
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::interfaces::interface::statistics::Statistics<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let iface = list_entry.as_interface().unwrap();
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&iface.state.discontinuity_time)).ignore_in_testing(),
            if_event_count: Some(iface.state.event_count).ignore_in_testing(),
            link_scope_lsa_count: Some(iface.state.lsdb.lsa_count()),
            link_scope_lsa_cksum_sum: Some(iface.state.lsdb.cksum_sum()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::statistics::database::link_scope_lsa_type::LinkScopeLsaType {
    fn iter(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = iface.state.lsdb.iter_types().map(ListEntry::InterfaceStatsLsaType);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lsdb_type = list_entry.as_interface_stats_lsa_type().unwrap();
        Self {
            lsa_type: Some(lsdb_type.lsa_type().into()),
            lsa_count: Some(lsdb_type.lsa_count()),
            lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::neighbors::neighbor::Neighbor<'a> {
    fn iter(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = iface.state.neighbors.iter(&instance.arenas.neighbors).map(|nbr| ListEntry::Neighbor(iface, nbr));
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let (iface, nbr) = list_entry.as_neighbor().unwrap();
        let mut dr_router_id = None;
        let mut dr_ip_addr = None;
        let mut bdr_router_id = None;
        let mut bdr_ip_addr = None;
        if let Some(instance_state) = &instance.state {
            if let Some(dr_net_id) = nbr.dr
                && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, dr_net_id)
            {
                dr_router_id = Some(nbr.router_id);
                dr_ip_addr = Some(nbr.src.into());
            } else {
                let iface_src_addr = iface.state.src_addr.unwrap();
                let iface_net_id = V::network_id(&iface_src_addr, instance_state.router_id);
                if nbr.dr == Some(iface_net_id) {
                    dr_router_id = Some(instance_state.router_id);
                    dr_ip_addr = Some(iface_src_addr.into());
                }
            }
            if let Some(bdr_net_id) = nbr.bdr
                && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, bdr_net_id)
            {
                bdr_router_id = Some(nbr.router_id);
                bdr_ip_addr = Some(nbr.src.into());
            } else {
                let iface_src_addr = iface.state.src_addr.unwrap();
                let iface_net_id = V::network_id(&iface_src_addr, instance_state.router_id);
                if nbr.bdr == Some(iface_net_id) {
                    bdr_router_id = Some(instance_state.router_id);
                    bdr_ip_addr = Some(iface_src_addr.into());
                }
            }
        }
        Self {
            neighbor_router_id: Cow::Owned(nbr.router_id),
            address: Some(Cow::Owned(nbr.src.into())),
            dr_router_id: dr_router_id.map(Cow::Owned),
            dr_ip_addr: dr_ip_addr.map(Cow::Owned),
            bdr_router_id: bdr_router_id.map(Cow::Owned),
            bdr_ip_addr: bdr_ip_addr.map(Cow::Owned),
            state: Some(nbr.state.to_yang()),
            dead_timer: nbr.tasks.inactivity_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::interfaces::interface::neighbors::neighbor::statistics::Statistics<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let (_, nbr) = list_entry.as_neighbor().unwrap();
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&nbr.discontinuity_time)).ignore_in_testing(),
            nbr_event_count: Some(nbr.event_count).ignore_in_testing(),
            nbr_retrans_qlen: Some(nbr.lists.ls_rxmt.len() as u32),
        })
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::interfaces::interface::neighbors::neighbor::graceful_restart::GracefulRestart<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let (_, nbr) = list_entry.as_neighbor().unwrap();
        let gr = nbr.gr.as_ref()?;
        Some(Self {
            restart_reason: Some(gr.restart_reason.to_yang()),
            grace_timer: Some(gr.grace_period.remaining().as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::LinkScopeLsaType {
    fn iter(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = iface.state.lsdb.iter_types().map(ListEntry::InterfaceLsaType);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lsdb_type = list_entry.as_interface_lsa_type().unwrap();
        Self {
            lsa_type: lsdb_type.lsa_type().into(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::LinkScopeLsa<'a> {
    fn iter(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let lsdb_type = list_entry.as_interface_lsa_type().unwrap();
        let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| ListEntry::InterfaceLsa(lse));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        Self {
            lsa_id: lsa.hdr.lsa_id().to_string().into(),
            adv_router: Cow::Owned(lsa.hdr.adv_rtr()),
            decode_completed: Some(!lsa.body.is_unknown()),
            raw_data: Some(lsa.raw.as_ref()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::Header<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
        Some(Self {
            lsa_id: Some(Cow::Owned(lsa.hdr.lsa_id)),
            opaque_type,
            opaque_id,
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let iter = lsa.hdr.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<
        'a,
    >
{
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_link()?.as_router_info()?.info_caps.as_ref()?;
        let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            informational_capabilities: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_link()?.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities
{
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let func_caps = lsa.body.as_opaque_link()?.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_link()?.as_ext_link()?.link.as_ref()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let (msd_type, msd_value) = list_entry.as_msd().unwrap();
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<ListIterator<'a, Ospfv2>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_router_info()?;
        let iter = lsa_body.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::grace::Grace<'a> {
    fn new(_instance: &'a Instance<Ospfv2>, list_entry: &ListEntry<'a, Ospfv2>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_grace()?;
        Some(Self {
            grace_period: lsa_body.grace_period.as_ref().map(|tlv| tlv.get()),
            graceful_restart_reason: lsa_body.gr_reason.as_ref().and_then(|tlv| GrReason::from_u8(tlv.get())).map(|reason| reason.to_yang()),
            ip_interface_address: lsa_body.addr.as_ref().map(|tlv| Cow::Owned(tlv.get())),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::Header<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id.into()),
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::Link<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_link()?;
        Some(Self {
            rtr_priority: Some(lsa_body.priority),
            link_local_interface_address: Some(Cow::Owned(match lsa_body.linklocal {
                IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                IpAddr::V6(addr) => addr,
            })),
            num_of_prefixes: Some(lsa_body.prefixes.len() as _),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_link()?;
        let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::Prefix<'a> {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_link()?;
        let iter = lsa_body.prefixes.iter().map(ListEntry::Ospfv3LinkLsaPrefix);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let prefix = list_entry.as_ospfv3_link_lsa_prefix().unwrap();
        Self {
            prefix: Some(Cow::Borrowed(&prefix.value)),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix_options::PrefixOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let prefix = list_entry.as_ospfv3_link_lsa_prefix().unwrap();
        let iter = prefix.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            prefix_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<
        'a,
    >
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            informational_capabilities: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities
{
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let func_caps = lsa.body.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let flag = list_entry.as_flag_u32().unwrap();
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::grace::Grace<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_grace()?;
        Some(Self {
            grace_period: lsa_body.grace_period.as_ref().map(|tlv| tlv.get()),
            graceful_restart_reason: lsa_body.gr_reason.as_ref().and_then(|tlv| GrReason::from_u8(tlv.get())).map(|reason| reason.to_yang()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::ELink {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        Some(Self {
            rtr_priority: lsa.body.as_ext_link().map(|lsa_body| lsa_body.priority),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::lsa_options::LsaOptions<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_link()?;
        let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsa_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ELinkTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let lse = list_entry.as_interface_lsa().unwrap();
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_link()?;
        let iter_prefixes = lsa_body.prefixes.iter().map(ListEntry::Ospfv3LinkLsaPrefix);
        let iter_linklocal = std::iter::once(lsa_body.linklocal).map(ListEntry::Ospfv3LinkLocalAddr);
        Some(Box::new(iter_prefixes.chain(iter_linklocal)))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::IntraPrefixTlv<'a> {
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lsa_prefix = list_entry.as_ospfv3_link_lsa_prefix()?;
        Some(Self {
            metric: None, // TODO
            prefix: Some(Cow::Borrowed(&lsa_prefix.value)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix_options::PrefixOptions<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let prefix = list_entry.as_ospfv3_link_lsa_prefix()?;
        let iter = prefix.options.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            prefix_options: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::SubTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        let prefix = list_entry.as_ospfv3_link_lsa_prefix()?;
        let iter = prefix.unknown_stlvs.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    fn iter(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        None
    }

    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        let stlv = list_entry.as_ospfv3_prefix_sid().unwrap();
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        None
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::Ipv6LinkLocalAddrTlv<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lladdr = list_entry.as_ospfv3_link_local_addr()?;
        Some(Self {
            link_local_address: Ipv6Addr::get(*lladdr).map(Cow::Owned),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::sub_tlvs::SubTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        None // TODO
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::Ipv4LinkLocalAddrTlv<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let lladdr = list_entry.as_ospfv3_link_local_addr()?;
        Some(Self {
            link_local_address: Ipv4Addr::get(*lladdr).map(Cow::Owned),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::sub_tlvs::SubTlvs {
    fn iter(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Option<ListIterator<'a, Ospfv3>> {
        None // TODO
    }

    fn new(_instance: &'a Instance<Ospfv3>, _list_entry: &ListEntry<'a, Ospfv3>) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    fn new(_instance: &'a Instance<Ospfv3>, list_entry: &ListEntry<'a, Ospfv3>) -> Option<Self> {
        let tlv = list_entry.as_unknown_tlv()?;
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(tlv.value.as_ref()),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::hostnames::hostname::Hostname<'a> {
    fn iter(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        let hostnames = &instance.state.as_ref()?.hostnames;
        let iter = hostnames.iter().map(|(router_id, hostname)| ListEntry::Hostname(router_id, hostname));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let (router_id, hostname) = list_entry.as_hostname().unwrap();
        Self {
            router_id: Cow::Borrowed(router_id),
            hostname: Some(Cow::Borrowed(hostname)),
        }
    }
}

// ===== helper functions =====

fn lsa_hdr_opaque_data(lsa_hdr: &ospfv2::packet::lsa::LsaHdr) -> (Option<u8>, Option<u32>) {
    let mut opaque_type = None;
    let mut opaque_id = None;
    if lsa_hdr.lsa_type.is_opaque() {
        let mut lsa_id = lsa_hdr.lsa_id.octets();
        lsa_id[0] = 0;
        opaque_type = Some(lsa_hdr.lsa_id.octets()[0]);
        opaque_id = Some(u32::from_be_bytes(lsa_id));
    }
    (opaque_type, opaque_id)
}
