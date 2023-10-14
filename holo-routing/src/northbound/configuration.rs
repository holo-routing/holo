//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::sync::{Arc, LazyLock as Lazy};

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    self, Callbacks, CallbacksBuilder, ConfigChanges, Provider,
    ValidationCallbacks, ValidationCallbacksBuilder,
};
use holo_northbound::paths::control_plane_protocol;
use holo_northbound::paths::routing::segment_routing::sr_mpls;
use holo_northbound::{CallbackKey, NbDaemonSender};
use holo_protocol::spawn_protocol_task;
use holo_utils::ibus::{IbusMsg, SrCfgEvent};
use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::mpls::LabelRange;
use holo_utils::protocol::Protocol;
use holo_utils::sr::{IgpAlgoType, SidLastHopBehavior, SrCfgPrefixSid};
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;
use ipnetwork::IpNetwork;

use crate::northbound::REGEX_PROTOCOLS;
use crate::{InstanceId, Master};

static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
static CALLBACKS: Lazy<configuration::Callbacks<Master>> =
    Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    ProtocolInstance(InstanceId),
    SrCfgPrefixSid(IpNetwork, IgpAlgoType),
}

#[derive(Debug, EnumAsInner)]
pub enum Resource {
    SrLabelRange(LabelRange),
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceStart { protocol: Protocol, name: String },
    SrCfgUpdate,
    SrCfgLabelRangeUpdate,
    SrCfgPrefixSidUpdate(AddressFamily),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(control_plane_protocol::PATH)
        .create_prepare(|_master, args| {
            let ptype = args.dnode.get_string_relative("./type").unwrap();
            let name = args.dnode.get_string_relative("./name").unwrap();

            // Parse protocol name.
            let protocol = match Protocol::try_from_yang(&ptype) {
                Some(value) => value,
                None => {
                    return Err("unknown protocol name".to_owned());
                }
            };

            // The BFD task runs permanently.
            if protocol == Protocol::BFD {
                return Ok(());
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceStart { protocol, name });

            Ok(())
        })
        .create_abort(|master, args| {
            let instance_id = args.list_entry.into_protocol_instance().unwrap();

            // The BFD task runs permanently.
            if instance_id.protocol == Protocol::BFD {
                return;
            }

            // Remove protocol instance.
            master.instances.remove(&instance_id);
        })
        .delete_apply(|master, args| {
            let instance_id = args.list_entry.into_protocol_instance().unwrap();

            // The BFD task runs permanently.
            if instance_id.protocol == Protocol::BFD {
                return;
            }

            // Remove protocol instance.
            master.instances.remove(&instance_id);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let ptype = dnode.get_string_relative("./type").unwrap();
            let name = dnode.get_string_relative("./name").unwrap();
            let protocol = Protocol::try_from_yang(&ptype).unwrap();
            let instance_id = InstanceId::new(protocol, name);
            ListEntry::ProtocolInstance(instance_id)
        })
        .path(control_plane_protocol::description::PATH)
        .modify_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(sr_mpls::bindings::connected_prefix_sid_map::connected_prefix_sid::PATH)
        .create_apply(|master, args| {
            let prefix = args.dnode.get_prefix_relative("./prefix").unwrap();
            let algo = args.dnode.get_string_relative("./algorithm").unwrap();
            let algo = IgpAlgoType::try_from_yang(&algo).unwrap();
            let index = args.dnode.get_u32_relative("./start-sid").unwrap();
            let last_hop = args.dnode.get_string_relative("./last-hop-behavior").unwrap();
            let last_hop = SidLastHopBehavior::try_from_yang(&last_hop).unwrap();
            let psid = SrCfgPrefixSid::new(index, last_hop);
            master.sr_config.prefix_sids.insert((prefix, algo), psid);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgPrefixSidUpdate(prefix.address_family()));
        })
        .delete_apply(|master, args| {
            let prefix = args.dnode.get_prefix_relative("./prefix").unwrap();
            let algo = args.dnode.get_string_relative("./algorithm").unwrap();
            let algo = IgpAlgoType::try_from_yang(&algo).unwrap();
            master.sr_config.prefix_sids.remove(&(prefix, algo));

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgPrefixSidUpdate(prefix.address_family()));
        })
        .lookup(|_master, _list_entry, dnode| {
            let prefix = dnode.get_prefix_relative("./prefix").unwrap();
            let algo = dnode.get_string_relative("./algorithm").unwrap();
            let algo = IgpAlgoType::try_from_yang(&algo).unwrap();
            ListEntry::SrCfgPrefixSid(prefix, algo)
        })
        .path(sr_mpls::bindings::connected_prefix_sid_map::connected_prefix_sid::start_sid::PATH)
        .modify_apply(|master, args| {
            let (prefix, algo) = args.list_entry.into_sr_cfg_prefix_sid().unwrap();
            let psid = master.sr_config.prefix_sids.get_mut(&(prefix, algo)).unwrap();

            let index = args.dnode.get_u32();
            psid.index = index;

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgPrefixSidUpdate(prefix.address_family()));
        })
        .path(sr_mpls::bindings::connected_prefix_sid_map::connected_prefix_sid::last_hop_behavior::PATH)
        .modify_apply(|master, args| {
            let (prefix, algo) = args.list_entry.into_sr_cfg_prefix_sid().unwrap();
            let psid = master.sr_config.prefix_sids.get_mut(&(prefix, algo)).unwrap();

            let last_hop = args.dnode.get_string();
            let last_hop = SidLastHopBehavior::try_from_yang(&last_hop).unwrap();
            psid.last_hop = last_hop;

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgPrefixSidUpdate(prefix.address_family()));
        })
        .path(sr_mpls::srgb::srgb::PATH)
        .create_prepare(|master, args| {
            let lower_bound = args.dnode.get_u32_relative("./lower-bound").unwrap();
            let upper_bound = args.dnode.get_u32_relative("./upper-bound").unwrap();
            let range = LabelRange::new(lower_bound, upper_bound);

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager
                .range_reserve(range)
                .map_err(|error| error.to_string())?;
            *args.resource = Some(Resource::SrLabelRange(range));

            Ok(())
        })
        .create_abort(|master, args| {
            let resource = args.resource.take().unwrap();
            let range = resource.into_sr_label_range().unwrap();

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
        })
        .create_apply(|master, args| {
            let resource = args.resource.take().unwrap();
            let range = resource.into_sr_label_range().unwrap();
            master.sr_config.srgb.insert(range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgLabelRangeUpdate);
        })
        .delete_apply(|master, args| {
            let lower_bound = args.dnode.get_u32_relative("./lower-bound").unwrap();
            let upper_bound = args.dnode.get_u32_relative("./upper-bound").unwrap();
            let range = LabelRange::new(lower_bound, upper_bound);

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
            master.sr_config.srgb.remove(&range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgLabelRangeUpdate);
        })
        .lookup(|_master, _list_entry, _dnode| {
            ListEntry::None
        })
        .path(sr_mpls::srlb::srlb::PATH)
        .create_prepare(|master, args| {
            let lower_bound = args.dnode.get_u32_relative("./lower-bound").unwrap();
            let upper_bound = args.dnode.get_u32_relative("./upper-bound").unwrap();
            let range = LabelRange::new(lower_bound, upper_bound);

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager
                .range_reserve(range)
                .map_err(|error| error.to_string())?;
            *args.resource = Some(Resource::SrLabelRange(range));

            Ok(())
        })
        .create_abort(|master, args| {
            let resource = args.resource.take().unwrap();
            let range = resource.into_sr_label_range().unwrap();

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
        })
        .create_apply(|master, args| {
            let resource = args.resource.take().unwrap();
            let range = resource.into_sr_label_range().unwrap();
            master.sr_config.srlb.insert(range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgLabelRangeUpdate);
        })
        .delete_apply(|master, args| {
            let lower_bound = args.dnode.get_u32_relative("./lower-bound").unwrap();
            let upper_bound = args.dnode.get_u32_relative("./upper-bound").unwrap();
            let range = LabelRange::new(lower_bound, upper_bound);

            let mut label_manager = master.shared.label_manager.lock().unwrap();
            label_manager.range_release(range);
            master.sr_config.srlb.remove(&range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrCfgUpdate);
            event_queue.insert(Event::SrCfgLabelRangeUpdate);
        })
        .lookup(|_master, _list_entry, _dnode| {
            ListEntry::None
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(control_plane_protocol::PATH)
        .validate(|args| {
            let ptype = args.dnode.get_string_relative("./type").unwrap();
            let name = args.dnode.get_string_relative("./name").unwrap();

            // Parse protocol name.
            let protocol = match Protocol::try_from_yang(&ptype) {
                Some(value) => value,
                None => {
                    return Err("unknown protocol name".to_owned());
                }
            };

            // Validate BFD protocol instance name.
            if protocol == Protocol::BFD && name != "main" {
                return Err(
                    "BFD protocol instance should be named \"main\"".to_owned()
                );
            }

            Ok(())
        })
        .build()
}

// ===== impl Master =====

#[async_trait]
impl Provider for Master {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        Some(&VALIDATION_CALLBACKS)
    }

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        let keys = [
            holo_bfd::northbound::configuration::CALLBACKS.keys(),
            holo_ldp::northbound::configuration::CALLBACKS.keys(),
            holo_ospf::northbound::configuration::CALLBACKS_OSPFV2.keys(),
            holo_ospf::northbound::configuration::CALLBACKS_OSPFV3.keys(),
            holo_rip::northbound::configuration::CALLBACKS_RIPV2.keys(),
            holo_rip::northbound::configuration::CALLBACKS_RIPNG.keys(),
        ]
        .concat();

        Some(keys)
    }

    fn relay_changes(
        &self,
        changes: ConfigChanges,
    ) -> Vec<(ConfigChanges, NbDaemonSender)> {
        // Create hash table that maps changes to the appropriate child
        // instances.
        let mut changes_map: HashMap<InstanceId, ConfigChanges> =
            HashMap::new();
        for change in changes {
            // HACK: parse protocol type and instance name.
            let caps = REGEX_PROTOCOLS.captures(&change.1).unwrap();
            let ptype = caps.get(1).unwrap().as_str();
            let name = caps.get(2).unwrap().as_str();

            // Move configuration change to the appropriate instance bucket.
            let protocol = Protocol::try_from_yang(ptype).unwrap();
            let instance_id = InstanceId::new(protocol, name.to_owned());
            changes_map.entry(instance_id).or_default().push(change);
        }
        changes_map
            .into_iter()
            .filter_map(|(instance_id, changes)| {
                self.instances
                    .get(&instance_id)
                    .cloned()
                    .map(|nb_tx| (changes, nb_tx))
            })
            .collect::<Vec<_>>()
    }

    fn relay_validation(&self) -> Vec<NbDaemonSender> {
        self.instances.values().cloned().collect()
    }

    async fn process_event(&mut self, event: Event) {
        match event {
            Event::InstanceStart { protocol, name } => {
                let instance_id = InstanceId::new(protocol, name.clone());
                let event_recorder_config = self.event_recorder_config.clone();

                // Start protocol instance.
                let nb_daemon_tx = match protocol {
                    Protocol::BFD => {
                        // Nothing to do, the BFD task runs permanently.
                        return;
                    }
                    Protocol::LDP => {
                        use holo_ldp::instance::Instance;

                        spawn_protocol_task::<Instance>(
                            name,
                            &self.nb_tx,
                            &self.ibus_tx,
                            Default::default(),
                            self.shared.clone(),
                            Some(event_recorder_config),
                        )
                    }
                    Protocol::OSPFV2 => {
                        use holo_ospf::instance::Instance;
                        use holo_ospf::version::Ospfv2;

                        spawn_protocol_task::<Instance<Ospfv2>>(
                            name,
                            &self.nb_tx,
                            &self.ibus_tx,
                            Default::default(),
                            self.shared.clone(),
                            Some(event_recorder_config),
                        )
                    }
                    Protocol::OSPFV3 => {
                        use holo_ospf::instance::Instance;
                        use holo_ospf::version::Ospfv3;

                        spawn_protocol_task::<Instance<Ospfv3>>(
                            name,
                            &self.nb_tx,
                            &self.ibus_tx,
                            Default::default(),
                            self.shared.clone(),
                            Some(event_recorder_config),
                        )
                    }
                    Protocol::RIPV2 => {
                        use holo_rip::instance::Instance;
                        use holo_rip::version::Ripv2;

                        spawn_protocol_task::<Instance<Ripv2>>(
                            name,
                            &self.nb_tx,
                            &self.ibus_tx,
                            Default::default(),
                            self.shared.clone(),
                            Some(event_recorder_config),
                        )
                    }
                    Protocol::RIPNG => {
                        use holo_rip::instance::Instance;
                        use holo_rip::version::Ripng;

                        spawn_protocol_task::<Instance<Ripng>>(
                            name,
                            &self.nb_tx,
                            &self.ibus_tx,
                            Default::default(),
                            self.shared.clone(),
                            Some(event_recorder_config),
                        )
                    }
                };

                // Keep track of northbound channel associated to the protocol
                // type and name.
                self.instances.insert(instance_id, nb_daemon_tx);
            }
            Event::SrCfgUpdate => {
                // Update the shared SR configuration by creating a new reference-counted copy.
                self.shared.sr_config = Arc::new(self.sr_config.clone());

                // Notify protocol instances about the updated SR configuration.
                let _ = self
                    .ibus_tx
                    .send(IbusMsg::SrCfgUpd(self.shared.sr_config.clone()));
            }
            Event::SrCfgLabelRangeUpdate => {
                // Notify protocol instances about the updated SRGB/SRLB configuration.
                let _ = self
                    .ibus_tx
                    .send(IbusMsg::SrCfgEvent(SrCfgEvent::LabelRangeUpdate));
            }
            Event::SrCfgPrefixSidUpdate(af) => {
                // Notify protocol instances about the updated Prefix-SID configuration.
                let _ = self
                    .ibus_tx
                    .send(IbusMsg::SrCfgEvent(SrCfgEvent::PrefixSidUpdate(af)));
            }
        }
    }
}
