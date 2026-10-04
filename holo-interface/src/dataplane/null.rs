//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use futures::stream;
use holo_utils::mac_addr::MacAddr;
use ipnetwork::IpNetwork;

use crate::Master;
use crate::dataplane::{Dataplane, DataplaneMonitor};

// The null dataplane generates no events.
#[derive(Debug)]
pub struct NullEvent;

// Handle used to program the null dataplane.
//
// There's no dataplane to program, so all operations are no-ops.
#[derive(Debug)]
pub struct NullDataplane;

// ===== impl NullDataplane =====

impl Dataplane for NullDataplane {
    type Event = NullEvent;

    fn init() -> NullDataplane {
        NullDataplane
    }

    fn monitor() -> DataplaneMonitor {
        Box::pin(stream::pending())
    }

    async fn interfaces_fetch(_master: &mut Master) {}

    fn process_msg(_master: &mut Master, _msg: NullEvent) {}

    fn admin_status_change(&self, _ifindex: u32, _enabled: bool) {}

    fn mtu_change(&self, _ifindex: u32, _mtu: u32) {}

    fn vlan_create(&self, _name: String, _parent_ifindex: u32, _vlan_id: u16) {}

    fn macvlan_create(
        &self,
        _name: String,
        _mac_address: Option<MacAddr>,
        _parent_ifindex: u32,
    ) {
    }

    fn iface_delete(&self, _ifindex: u32) {}

    fn addr_install(&self, _ifindex: u32, _addr: &IpNetwork) {}

    fn addr_uninstall(&self, _ifindex: u32, _addr: &IpNetwork) {}

    fn flush(self) {}
}
