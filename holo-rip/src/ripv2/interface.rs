//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use crate::interface::{Interface, InterfaceVersion, Interfaces};
use crate::version::{Ripv2, Version};

// ===== impl Ripv2 =====

impl InterfaceVersion<Self> for Ripv2 {
    fn get_iface_by_source(
        interfaces: &mut Interfaces<Self>,
        source: <Self as Version>::SocketAddr,
    ) -> Option<&mut Interface<Self>> {
        interfaces
            .iter_mut()
            .find(|iface| iface.system.contains_addr(source.ip()))
    }
}
