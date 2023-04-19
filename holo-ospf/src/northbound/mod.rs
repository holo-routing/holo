//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod configuration;
pub mod notification;
pub mod rpc;
pub mod state;
pub mod yang;

use holo_northbound as northbound;
use holo_northbound::ProviderBase;
use holo_yang::ToYang;
use tracing::{debug_span, Span};

use crate::instance::Instance;
use crate::version::{Ospfv2, Ospfv3, Version};

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
        &[
            "ietf-ospf",
            "ietf-ospf-sr",
            "ietf-ospfv3-extended-lsa",
            "ietf-ospfv3-sr",
            "holo-ospf",
            "holo-ospf-dev",
        ]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-ospf:ospf",
            V::PROTOCOL.to_yang(),
            self.name
        )
    }

    fn debug_span(name: &str) -> Span {
        V::debug_span(name)
    }
}

// ===== impl Ospfv2 =====

impl NorthboundVersion<Self> for Ospfv2 {
    const STATE_PATH: &'static str = "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-ospf:ospfv2'][name='test']/ietf-ospf:ospf";

    fn debug_span(name: &str) -> Span {
        debug_span!("ospfv2-instance", %name)
    }

    fn validation_callbacks(
    ) -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_OSPFV2)
    }

    fn configuration_callbacks(
    ) -> Option<&'static northbound::configuration::Callbacks<Instance<Self>>>
    {
        Some(&configuration::CALLBACKS_OSPFV2)
    }

    fn rpc_callbacks(
    ) -> Option<&'static northbound::rpc::Callbacks<Instance<Self>>> {
        Some(&rpc::CALLBACKS_OSPFV2)
    }

    fn state_callbacks(
    ) -> Option<&'static northbound::state::Callbacks<Instance<Self>>> {
        Some(&state::CALLBACKS_OSPFV2)
    }
}

// ===== impl Ospfv3 =====

impl NorthboundVersion<Self> for Ospfv3 {
    const STATE_PATH: &'static str = "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-ospf:ospfv3'][name='test']/ietf-ospf:ospf";

    fn debug_span(name: &str) -> Span {
        debug_span!("ospfv3-instance", %name)
    }

    fn validation_callbacks(
    ) -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_OSPFV3)
    }

    fn configuration_callbacks(
    ) -> Option<&'static northbound::configuration::Callbacks<Instance<Self>>>
    {
        Some(&configuration::CALLBACKS_OSPFV3)
    }

    fn rpc_callbacks(
    ) -> Option<&'static northbound::rpc::Callbacks<Instance<Self>>> {
        Some(&rpc::CALLBACKS_OSPFV3)
    }

    fn state_callbacks(
    ) -> Option<&'static northbound::state::Callbacks<Instance<Self>>> {
        Some(&state::CALLBACKS_OSPFV3)
    }
}
