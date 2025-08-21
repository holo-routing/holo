//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod configuration;
pub mod notification;
pub mod rpc;
pub mod state;
pub mod yang;

use holo_northbound as northbound;
use holo_northbound::ProviderBase;
use holo_yang::ToYang;
use tracing::{Span, debug_span};

use crate::instance::Instance;
use crate::version::{Ospfv2, Ospfv3, Version};

pub trait NorthboundVersion<V: Version> {
    fn debug_span(name: &str) -> Span;
    fn validation_callbacks()
    -> Option<&'static northbound::configuration::ValidationCallbacks>;
    fn configuration_callbacks()
    -> &'static northbound::configuration::Callbacks<Instance<V>>;
    fn rpc_callbacks() -> &'static northbound::rpc::Callbacks<Instance<V>>;
    fn state_callbacks() -> &'static northbound::state::Callbacks<Instance<V>>;
}

// ===== impl Instance =====

impl<V> ProviderBase for Instance<V>
where
    V: Version,
{
    fn yang_modules() -> &'static [&'static str] {
        &[
            "ietf-ospf",
            "ietf-ospf-sr-mpls",
            "ietf-ospfv3-extended-lsa",
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
    fn debug_span(name: &str) -> Span {
        debug_span!("ospfv2-instance", %name)
    }

    fn validation_callbacks()
    -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_OSPFV2)
    }

    fn configuration_callbacks()
    -> &'static northbound::configuration::Callbacks<Instance<Self>> {
        &configuration::CALLBACKS_OSPFV2
    }

    fn rpc_callbacks() -> &'static northbound::rpc::Callbacks<Instance<Self>> {
        &rpc::CALLBACKS_OSPFV2
    }

    fn state_callbacks() -> &'static northbound::state::Callbacks<Instance<Self>>
    {
        &state::CALLBACKS_OSPFV2
    }
}

// ===== impl Ospfv3 =====

impl NorthboundVersion<Self> for Ospfv3 {
    fn debug_span(name: &str) -> Span {
        debug_span!("ospfv3-instance", %name)
    }

    fn validation_callbacks()
    -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_OSPFV3)
    }

    fn configuration_callbacks()
    -> &'static northbound::configuration::Callbacks<Instance<Self>> {
        &configuration::CALLBACKS_OSPFV3
    }

    fn rpc_callbacks() -> &'static northbound::rpc::Callbacks<Instance<Self>> {
        &rpc::CALLBACKS_OSPFV3
    }

    fn state_callbacks() -> &'static northbound::state::Callbacks<Instance<Self>>
    {
        &state::CALLBACKS_OSPFV3
    }
}
