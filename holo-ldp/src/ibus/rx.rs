//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;
use std::sync::Mutex;

use holo_utils::mpls::{Label, LabelManager};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    AddressFlags, AddressMsg, InterfaceUpdateMsg, Nexthop, RouteKeyMsg,
    RouteMsg,
};
use ipnetwork::IpNetwork;
use maplit::btreeset;

use crate::debug::Debug;
use crate::fec::Fec;
use crate::instance::{Instance, InstanceUpView};
use crate::northbound::notification;
use crate::packet::AddressMessageType;
use crate::{events, ibus};

// ===== helper functions =====

fn local_label_update(fec: &mut Fec, label_manager: &Mutex<LabelManager>) {
    if fec.inner.local_label.is_some() {
        return;
    }

    let protocol = fec.inner.protocol.unwrap();
    let label = if protocol == Protocol::DIRECT {
        Label::implicit_null()
    } else {
        let mut label_manager = label_manager.lock().unwrap();
        label_manager.label_request().unwrap()
    };
    let label = Some(label);

    Debug::FecLabelUpdate(fec, &label).log();
    fec.inner.local_label = label;
}

fn process_new_fec(instance: &mut InstanceUpView<'_>, prefix: IpNetwork) {
    let fec = instance.state.fecs.get_mut(&prefix).unwrap();

    // FEC.1: perform lsr label distribution procedure.
    let msg_id = &instance.state.msg_id;
    for nbr in instance
        .state
        .neighbors
        .iter_mut()
        .filter(|nbr| nbr.is_operational())
    {
        nbr.send_label_mapping(msg_id, fec);
    }

    for nexthop_addr in fec.nexthops.keys().copied().collect::<Vec<_>>() {
        if let Some((nbr_idx, nbr)) =
            instance.state.neighbors.get_by_adv_addr(&nexthop_addr)
        {
            // FEC.2.
            if let Some(mapping) = nbr.rcvd_mappings.get(&prefix).copied() {
                // FEC.5.
                let fec_elem = prefix.into();
                events::process_nbr_msg_label_mapping(
                    instance,
                    nbr_idx,
                    mapping.label,
                    fec_elem,
                );
            }
        }
    }
}

// ===== global functions =====

pub(crate) fn process_router_id_update(
    instance: &mut Instance,
    router_id: Option<Ipv4Addr>,
) {
    instance.system.router_id = router_id;
    instance.update();
}

pub(crate) fn process_iface_update(
    instance: &mut Instance,
    msg: InterfaceUpdateMsg,
) {
    let Some((mut instance, interfaces, _)) = instance.as_up() else {
        return;
    };

    if let Some((_, iface)) =
        interfaces.update_ifindex(&msg.ifname, Some(msg.ifindex))
    {
        iface.system.flags = msg.flags;
        iface.update(&mut instance);
    }
}

pub(crate) fn process_addr_add(instance: &mut Instance, msg: AddressMsg) {
    let Some((mut instance, interfaces, _)) = instance.as_up() else {
        return;
    };

    // Add address to global list.
    match msg.addr {
        IpNetwork::V4(addr) => {
            if !msg.flags.contains(AddressFlags::UNNUMBERED)
                && instance.system.ipv4_addr_list.insert(addr)
            {
                // Inform neighbors about new address.
                for nbr in instance
                    .state
                    .neighbors
                    .iter_mut()
                    .filter(|nbr| nbr.is_operational())
                {
                    nbr.send_address(
                        &instance.state.msg_id,
                        AddressMessageType::Address,
                        btreeset![addr.ip()],
                    )
                }
            }
        }
        IpNetwork::V6(addr) => {
            instance.system.ipv6_addr_list.insert(addr);
        }
    }

    if let Some((_, iface)) = interfaces.get_mut_by_name(&msg.ifname) {
        match msg.addr {
            IpNetwork::V4(addr) => {
                if iface.system.ipv4_addr_list.insert(addr) {
                    // Check if LDP needs to be activated on this interface.
                    iface.update(&mut instance);
                }
            }
            IpNetwork::V6(addr) => {
                iface.system.ipv6_addr_list.insert(addr);
            }
        }
    }
}

pub(crate) fn process_addr_del(instance: &mut Instance, msg: AddressMsg) {
    let Some((mut instance, interfaces, _)) = instance.as_up() else {
        return;
    };

    // Remove address from global list.
    match msg.addr {
        IpNetwork::V4(addr) => {
            if !msg.flags.contains(AddressFlags::UNNUMBERED)
                && instance.system.ipv4_addr_list.remove(&addr)
            {
                // Inform neighbors about deleted address.
                for nbr in instance
                    .state
                    .neighbors
                    .iter_mut()
                    .filter(|nbr| nbr.is_operational())
                {
                    nbr.send_address(
                        &instance.state.msg_id,
                        AddressMessageType::AddressWithdraw,
                        btreeset![addr.ip()],
                    )
                }
            }
        }
        IpNetwork::V6(addr) => {
            instance.system.ipv6_addr_list.remove(&addr);
        }
    }

    if let Some((_, iface)) = interfaces.get_mut_by_name(&msg.ifname) {
        match msg.addr {
            IpNetwork::V4(addr) => {
                if iface.system.ipv4_addr_list.remove(&addr) {
                    // Check if LDP needs to be disabled on this interface.
                    iface.update(&mut instance);
                }
            }
            IpNetwork::V6(addr) => {
                iface.system.ipv6_addr_list.remove(&addr);
            }
        }
    }
}

pub(crate) fn process_route_add(instance: &mut Instance, msg: RouteMsg) {
    let Some((mut instance, _, _)) = instance.as_up() else {
        return;
    };

    // Find or create new FEC.
    let prefix = msg.prefix;
    let fec = instance
        .state
        .fecs
        .entry(prefix)
        .or_insert_with(|| Fec::new(prefix));
    let old_fec_status = fec.is_operational();
    fec.inner.protocol = Some(msg.protocol);

    // Find the nexthops that were deleted.
    for nexthop_addr in fec.nexthops.keys().copied().collect::<Vec<_>>() {
        if !msg.nexthops.iter().any(|msg_nexthop| {
            if let Nexthop::Address { addr, .. } = *msg_nexthop {
                addr == nexthop_addr
            } else {
                false
            }
        }) {
            let nexthop = &fec.nexthops[&nexthop_addr];
            ibus::tx::label_uninstall(&instance.tx.ibus, &fec.inner, nexthop);
            fec.nexthops.remove(&nexthop_addr);
        }
    }

    if old_fec_status != fec.is_operational() {
        notification::mpls_ldp_fec_event(&instance.tx.nb, instance.name, fec);
    }

    // Find newly added nexthops.
    for msg_nexthop in &msg.nexthops {
        let (msg_nexthop_ifindex, msg_nexthop_addr) = match *msg_nexthop {
            Nexthop::Address { ifindex, addr, .. } => (ifindex, addr),
            // Ignore nexthops that don't contain an IP address.
            _ => continue,
        };

        if !fec.nexthops.contains_key(&msg_nexthop_addr) {
            fec.nexthop_add(msg_nexthop_addr, Some(msg_nexthop_ifindex));
        }
    }

    // Allocate new label if necessary.
    local_label_update(fec, &instance.shared.label_manager);
    process_new_fec(&mut instance, prefix);
}

pub(crate) fn process_route_del(instance: &mut Instance, msg: RouteKeyMsg) {
    let Some((instance, _, _)) = instance.as_up() else {
        return;
    };

    let prefix = msg.prefix;
    if let Some(fec) = instance.state.fecs.get_mut(&prefix) {
        let old_fec_status = fec.is_operational();

        // Withdraw previously allocated label.
        let msg_id = &instance.state.msg_id;
        for nbr in instance
            .state
            .neighbors
            .iter_mut()
            .filter(|nbr| nbr.is_operational())
        {
            nbr.send_label_withdraw(msg_id, fec);
        }

        // Uninstall learned labels.
        for nexthop in fec.nexthops.values() {
            ibus::tx::label_uninstall(&instance.tx.ibus, &fec.inner, nexthop);
        }

        // Release FEC's local label.
        if let Some(local_label) = fec.inner.local_label {
            let mut label_manager =
                instance.shared.label_manager.lock().unwrap();
            label_manager.label_release(local_label);
        }

        // Delete nexthops.
        fec.nexthops.clear();

        if old_fec_status != fec.is_operational() {
            notification::mpls_ldp_fec_event(
                &instance.tx.nb,
                instance.name,
                fec,
            );
        }
    }
}
