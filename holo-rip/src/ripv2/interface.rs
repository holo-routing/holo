//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use crate::interface::{
    Interface, InterfaceIndex, InterfaceVersion, Interfaces,
};
use crate::version::{Ripv2, Version};

// ===== impl Ripv2 =====

impl InterfaceVersion<Self> for Ripv2 {
    fn get_iface_by_source(
        interfaces: &mut Interfaces<Self>,
        source: <Self as Version>::SocketAddr,
    ) -> Option<(InterfaceIndex, &mut Interface<Self>)> {
        for (iface_idx, iface) in interfaces.arena.iter_mut() {
            if iface.core().system.contains_addr(source.ip()) {
                return Some((iface_idx, iface));
            }
        }

        None
    }
}
