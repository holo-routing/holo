//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use crate::interface::{Interface, InterfaceVersion, Interfaces};
use crate::version::{Ripng, Version};

// ===== impl Ripng =====

impl InterfaceVersion<Self> for Ripng {
    fn get_iface_by_source(
        interfaces: &mut Interfaces<Self>,
        source: <Self as Version>::SocketAddr,
    ) -> Option<&mut Interface<Self>> {
        if !source.ip().is_unicast_link_local() {
            return None;
        }

        interfaces
            .iter_mut()
            .find(|iface| iface.system.ifindex == Some(source.scope_id()))
    }
}
