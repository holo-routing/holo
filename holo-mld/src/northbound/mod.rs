pub mod configuration;
pub mod notification;
pub mod rpc;
pub mod state;
pub mod yang;

use holo_northbound::{self as northbound, ProviderBase};
use holo_yang::ToYang;
use tracing::{Span, debug_span};

use crate::{
    instance::Instance,
    version::{Mldv1, Mldv2, Version},
};

pub trait NorthboundVersion<V: Version> {
    fn debug_span(name: &str) -> Span;
    fn validation_callbacks()
    -> Option<&'static northbound::configuration::ValidationCallbacks>;
    fn configuration_callbacks()
    -> &'static northbound::configuration::Callbacks<Instance<V>>;
    fn rpc_callbacks() -> &'static northbound::rpc::Callbacks<Instance<V>>;
    fn state_callbacks() -> &'static northbound::state::Callbacks<Instance<V>>;
}

impl<V> ProviderBase for Instance<V>
where
    V: Version,
{
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-igmp-mld"]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type={}]/ietf-igmp-mld:mld",
            V::PROTOCOL.to_yang()
        )
    }

    fn debug_span(name: &str) -> Span {
        V::debug_span(name)
    }
}

impl NorthboundVersion<Self> for Mldv2 {
    fn debug_span(name: &str) -> Span {
        debug_span!("mldv2-instance", %name)
    }

    fn validation_callbacks()
    -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_MLDV2)
    }

    fn configuration_callbacks()
    -> &'static northbound::configuration::Callbacks<Instance<Self>> {
        &configuration::CALLBACKS_MLDV2
    }

    fn rpc_callbacks() -> &'static northbound::rpc::Callbacks<Instance<Self>> {
        &rpc::CALLBACKS_MLDV2
    }

    fn state_callbacks() -> &'static northbound::state::Callbacks<Instance<Self>>
    {
        &state::CALLBACKS_MLDV2
    }
}

impl NorthboundVersion<Self> for Mldv1 {
    fn debug_span(name: &str) -> Span {
        debug_span!("mldv1-instance", %name)
    }

    fn validation_callbacks()
    -> Option<&'static northbound::configuration::ValidationCallbacks> {
        Some(&configuration::VALIDATION_CALLBACKS_MLDV1)
    }

    fn configuration_callbacks()
    -> &'static northbound::configuration::Callbacks<Instance<Self>> {
        &configuration::CALLBACKS_MLDV1
    }

    fn rpc_callbacks() -> &'static northbound::rpc::Callbacks<Instance<Self>> {
        &rpc::CALLBACKS_MLDV1
    }

    fn state_callbacks() -> &'static northbound::state::Callbacks<Instance<Self>>
    {
        &state::CALLBACKS_MLDV1
    }
}
