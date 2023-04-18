//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod configuration;
pub mod rpc;
pub mod state;
pub mod yang;

use holo_northbound as northbound;
use holo_northbound::ProviderBase;
use holo_yang::ToYang;
use tracing::{debug_span, Span};

use crate::instance::Instance;
use crate::version::{Ripng, Ripv2, Version};

// RIP version-specific code.
pub trait NorthboundVersion<V: Version> {
    const STATE_PATH: &'static str;

    fn debug_span(name: &str) -> Span;
    fn validation_callbacks(
    ) -> Option<&'static northbound::configuration::ValidationCallbacks>;
    fn configuration_callbacks(
    ) -> Option<&'static northbound::configuration::Callbacks<Instance<V>>>;
    fn rpc_callbacks(
    ) -> Option<&'static northbound::rpc::Callbacks<Instance<V>>>;
    fn state_callbacks(
    ) -> Option<&'static northbound::state::Callbacks<Instance<V>>>;
}

// ===== impl Instance =====

impl<V> ProviderBase for Instance<V>
where
    V: Version,
{
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-rip"]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-rip:rip",
            V::PROTOCOL.to_yang(),
            self.core().name
        )
    }

    fn debug_span(name: &str) -> Span {
        V::debug_span(name)
    }
}

// ===== impl Ripv2 =====

impl NorthboundVersion<Self> for Ripv2 {
    const STATE_PATH: &'static str = "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripv2'][name='main']/ietf-rip:rip";

    fn debug_span(name: &str) -> Span {
        debug_span!("ripv2-instance", %name)
    }

    fn validation_callbacks(
    ) -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_RIPV2)
    }

    fn configuration_callbacks(
    ) -> Option<&'static northbound::configuration::Callbacks<Instance<Self>>>
    {
        Some(&configuration::CALLBACKS_RIPV2)
    }

    fn rpc_callbacks(
    ) -> Option<&'static northbound::rpc::Callbacks<Instance<Self>>> {
        Some(&rpc::CALLBACKS_RIPV2)
    }

    fn state_callbacks(
    ) -> Option<&'static northbound::state::Callbacks<Instance<Self>>> {
        Some(&state::CALLBACKS_RIPV2)
    }
}

// ===== impl Ripng =====

impl NorthboundVersion<Self> for Ripng {
    const STATE_PATH: &'static str = "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-rip:ripng'][name='main']/ietf-rip:rip";

    fn debug_span(name: &str) -> Span {
        debug_span!("ripng-instance", %name)
    }

    fn validation_callbacks(
    ) -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_RIPNG)
    }

    fn configuration_callbacks(
    ) -> Option<&'static northbound::configuration::Callbacks<Instance<Self>>>
    {
        Some(&configuration::CALLBACKS_RIPNG)
    }

    fn rpc_callbacks(
    ) -> Option<&'static northbound::rpc::Callbacks<Instance<Self>>> {
        Some(&rpc::CALLBACKS_RIPNG)
    }

    fn state_callbacks(
    ) -> Option<&'static northbound::state::Callbacks<Instance<Self>>> {
        Some(&state::CALLBACKS_RIPNG)
    }
}
