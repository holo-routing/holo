//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};

use crate::af::{AddressFamily, Ipv4Unicast, Ipv6Unicast};
use crate::debug::Debug;
use crate::instance::{Instance, InstanceUpView};

// ===== global functions =====

pub(crate) async fn process_router_id_update(
    instance: &mut Instance,
    router_id: Option<Ipv4Addr>,
) {
    instance.system.router_id = router_id;
    instance.update().await;
}

pub(crate) fn process_nht_update(
    instance: &mut Instance,
    addr: IpAddr,
    metric: Option<u32>,
) {
    let Some((mut instance, _)) = instance.as_up() else {
        return;
    };

    Debug::NhtUpdate(addr, metric).log();

    process_nht_update_af::<Ipv4Unicast>(&mut instance, addr, metric);
    process_nht_update_af::<Ipv6Unicast>(&mut instance, addr, metric);
}

// ===== helper functions =====

fn process_nht_update_af<A>(
    instance: &mut InstanceUpView<'_>,
    addr: IpAddr,
    metric: Option<u32>,
) where
    A: AddressFamily,
{
    let table = A::table(&mut instance.state.rib.tables);
    if let Some(nht) = table.nht.get_mut(&addr) {
        nht.metric = metric;
        table.queued_prefixes.extend(nht.prefixes.keys());
        instance.state.schedule_decision_process(instance.tx);
    }
}
