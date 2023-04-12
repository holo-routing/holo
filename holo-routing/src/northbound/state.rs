//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::sync::LazyLock as Lazy;

use derive_new::new;
use holo_northbound::paths::control_plane_protocol;
use holo_northbound::paths::routing::segment_routing::sr_mpls;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::{CallbackKey, NbDaemonSender};
use holo_yang::ToYang;

use crate::{InstanceId, Master};

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default)]
pub enum ListEntry<'a> {
    #[default]
    None,
    ProtocolInstance(ProtocolInstance<'a>),
}

#[derive(Debug, new)]
pub struct ProtocolInstance<'a> {
    id: &'a InstanceId,
    nb_tx: &'a NbDaemonSender,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(control_plane_protocol::PATH)
        .get_iterate(|master, _args| {
            let iter = master
                .instances
                .iter()
                .map(|(instance_id, nb_tx)| {
                    ProtocolInstance::new(instance_id, nb_tx)
                })
                .map(ListEntry::ProtocolInstance);
            Some(Box::new(iter))
        })
        .path(sr_mpls::bindings::connected_prefix_sid_map::connected_prefix_sid::PATH)
        .get_iterate(|_context, _args| {
            // No operational data under this list.
            None
        })
        .path(sr_mpls::srgb::srgb::PATH)
        .get_iterate(|_context, _args| {
            // No operational data under this list.
            None
        })
        .path(sr_mpls::srlb::srlb::PATH)
        .get_iterate(|_context, _args| {
            // No operational data under this list.
            None
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    const STATE_PATH: &'static str = "/ietf-routing:routing";

    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        let keys = [
            holo_bfd::northbound::state::CALLBACKS.keys(),
            holo_ldp::northbound::state::CALLBACKS.keys(),
            holo_ospf::northbound::state::CALLBACKS_OSPFV2.keys(),
            holo_ospf::northbound::state::CALLBACKS_OSPFV3.keys(),
            holo_rip::northbound::state::CALLBACKS_RIPV2.keys(),
            holo_rip::northbound::state::CALLBACKS_RIPNG.keys(),
        ]
        .concat();

        Some(keys)
    }
}

// ===== impl ListEntry =====

impl<'a> ListEntryKind for ListEntry<'a> {
    fn get_keys(&self) -> Option<String> {
        match self {
            ListEntry::None => None,
            ListEntry::ProtocolInstance(instance) => {
                use control_plane_protocol::list_keys;
                let keys = list_keys(
                    instance.id.protocol.to_yang(),
                    &instance.id.name,
                );
                Some(keys)
            }
        }
    }

    fn child_task(&self) -> Option<NbDaemonSender> {
        match self {
            ListEntry::None => None,
            ListEntry::ProtocolInstance(instance) => {
                Some(instance.nb_tx.clone())
            }
        }
    }
}
