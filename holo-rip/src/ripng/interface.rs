//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use crate::interface::{
    Interface, InterfaceIndex, InterfaceVersion, Interfaces,
};
use crate::version::{Ripng, Version};

// ===== impl Ripng =====

impl InterfaceVersion<Self> for Ripng {
    fn get_iface_by_source(
        interfaces: &mut Interfaces<Self>,
        source: <Self as Version>::SocketAddr,
    ) -> Option<(InterfaceIndex, &mut Interface<Self>)> {
        if !source.ip().is_unicast_link_local() {
            return None;
        }

        for (iface_idx, iface) in interfaces.arena.iter_mut() {
            if let Some(ifindex) = iface.core().system.ifindex
                && source.scope_id() == ifindex
            {
                return Some((iface_idx, iface));
            }
        }

        None
    }
}
