//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use holo_southbound::zclient;
use holo_utils::mpls::Label;
use ipnetwork::IpNetwork;

use crate::debug::Debug;
use crate::neighbor::Neighbor;

// LDP Forwarding Equivalence Class.
#[derive(Debug)]
pub struct Fec {
    pub inner: FecInner,
    pub nexthops: BTreeMap<IpAddr, Nexthop>,
}

#[derive(Debug)]
pub struct FecInner {
    pub prefix: Arc<IpNetwork>,
    pub downstream: BTreeMap<Ipv4Addr, LabelMapping>,
    pub upstream: BTreeMap<Ipv4Addr, LabelMapping>,
    pub local_label: Option<Label>,
    pub owner: Option<FecOwner>,
}

#[derive(Debug)]
pub struct FecOwner {
    pub proto: zclient::ffi::RouteType,
    pub instance: u16,
}

#[derive(Clone, Debug)]
pub struct Nexthop {
    // FEC prefix (used for logging).
    pub prefix: Arc<IpNetwork>,
    // Nexthop address and ifindex (as learned from the southbound).
    pub addr: IpAddr,
    pub ifindex: Option<u32>,
    // Optional remote label.
    label: Option<Label>,
}

#[derive(Clone, Copy, Debug)]
pub struct LabelMapping {
    pub label: Label,
    // Might contain additional parameters in the future (e.g. PW attributes).
}

#[derive(Debug)]
pub struct LabelRequest {
    pub id: u32,
}

// ===== impl Fec =====

impl Fec {
    pub(crate) fn new(prefix: IpNetwork) -> Fec {
        let fec = Fec {
            inner: FecInner {
                prefix: Arc::new(prefix),
                downstream: Default::default(),
                upstream: Default::default(),
                local_label: None,
                owner: None,
            },
            nexthops: Default::default(),
        };

        Debug::FecCreate(&fec).log();

        fec
    }

    pub(crate) fn nexthop_add(&mut self, addr: IpAddr, ifindex: Option<u32>) {
        let nexthop = Nexthop {
            prefix: self.inner.prefix.clone(),
            addr,
            ifindex,
            label: None,
        };

        Debug::NexthopCreate(&nexthop).log();

        self.nexthops.insert(addr, nexthop);
    }

    pub(crate) fn is_nbr_nexthop(&self, nbr: &Neighbor) -> bool {
        self.nexthops
            .values()
            .any(|nexthop| nbr.addr_list.get(&nexthop.addr).is_some())
    }

    pub(crate) fn is_operational(&self) -> bool {
        /*
         * RFC 9070 - Section 7:
         * "It is to be noted that an LDP FEC is treated as operational (up)
         * as long as it has at least 1 NHLFE (Next Hop Label Forwarding
         * Entry) with outgoing label".
         */
        self.nexthops
            .values()
            .any(|nexthop| nexthop.get_label().is_some())
    }
}

impl Drop for Fec {
    fn drop(&mut self) {
        Debug::FecDelete(self).log();
    }
}

// ===== impl Nexthop =====

impl Nexthop {
    pub(crate) fn get_label(&self) -> Option<Label> {
        self.label
    }

    pub(crate) fn set_label(&mut self, label: Option<Label>) {
        Debug::NexthopLabelUpdate(self, &label).log();

        self.label = label;
    }
}

impl Drop for Nexthop {
    fn drop(&mut self) {
        Debug::NexthopDelete(self).log();
    }
}
