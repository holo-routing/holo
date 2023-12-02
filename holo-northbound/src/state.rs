//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use derive_new::new;
use holo_yang::{YangPath, YANG_CTX};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use yang2::data::{DataNodeRef, DataTree};
use yang2::schema::{
    DataValueType, SchemaModule, SchemaNode, SchemaNodeKind, SchemaPathFormat,
};

use crate::debug::Debug;
use crate::error::Error;
use crate::{api, CallbackKey, CallbackOp, NbDaemonSender, ProviderBase};

//
// State callbacks.
//

pub struct Callbacks<P: Provider>(HashMap<CallbackKey, CallbacksNode<P>>);

pub struct CallbacksNode<P: Provider> {
    attributes: NodeAttributes,
    get_iterate: Option<GetIterateCb<P>>,
    get_element: Option<GetElementCb<P>>,
}

pub struct CallbacksBuilder<P: Provider> {
    path: Option<YangPath>,
    attributes: NodeAttributes,
    callbacks: Callbacks<P>,
}

//
// Node attributes.
//

bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct NodeAttributes: u16 {
        // Development-specific data used by unit tests only.
        const DEV = 0x0001;
        // Time-related information (e.g. remaining time, up-time, etc).
        const TIME = 0x0002;
        // Statistics counter (e.g. number of received messages).
        const COUNTER = 0x0004;
        // Log registering events of some sort (e.g. SPF runs).
        const LOG = 0x0008;
        // Link State age.
        const LS_AGE = 0x0010;
        // Link State sequence number.
        const LS_SEQNO = 0x0020;
        // Link State checksum (or sum of Link State checksums).
        const LS_CKSUM = 0x0040;
        // Link State in raw format.
        const LS_RAW = 0x0080;
    }
}

//
// GetIterate callback.
//

pub type GetIterateCb<P: Provider> = for<'a, 'b> fn(
    &'a P,
    GetIterateArgs<'a, 'b, P>,
) -> Option<
    Box<dyn Iterator<Item = P::ListEntry<'a>> + 'a>,
>;

#[derive(Debug)]
pub struct GetIterateArgs<'a, 'b, P: Provider> {
    pub parent_list_entry: &'b P::ListEntry<'a>,
    // TODO: starting point
}

//
// GetElement callback.
//

pub type GetElementCbType<P: Provider, LeafType> =
    for<'a, 'b> fn(&'a P, GetElementArgs<'a, 'b, P>) -> Option<LeafType>;

pub enum GetElementCb<P: Provider> {
    Uint8(GetElementCbType<P, u8>),
    Uint16(GetElementCbType<P, u16>),
    Uint32(GetElementCbType<P, u32>),
    Uint64(GetElementCbType<P, u64>),
    Binary(GetElementCbType<P, Vec<u8>>),
    Bool(GetElementCbType<P, bool>),
    Empty(GetElementCbType<P, ()>),
    Container(GetElementCbType<P, ()>),
    Int8(GetElementCbType<P, i8>),
    Int16(GetElementCbType<P, i16>),
    Int32(GetElementCbType<P, i32>),
    Int64(GetElementCbType<P, i64>),
    IpAddr(GetElementCbType<P, IpAddr>),
    Ipv4Addr(GetElementCbType<P, Ipv4Addr>),
    Ipv6Addr(GetElementCbType<P, Ipv6Addr>),
    IpPrefix(GetElementCbType<P, IpNetwork>),
    Ipv4Prefix(GetElementCbType<P, Ipv4Network>),
    Ipv6Prefix(GetElementCbType<P, Ipv6Network>),
    DateAndTime(GetElementCbType<P, DateTime<Utc>>),
    TimerValueSecs16(GetElementCbType<P, Duration>),
    TimerValueSecs32(GetElementCbType<P, Duration>),
    TimerValueMillis(GetElementCbType<P, Duration>),
    Timeticks(GetElementCbType<P, Instant>),
    Timeticks64(GetElementCbType<P, Instant>),
    String(GetElementCbType<P, String>),
}

#[derive(Debug)]
pub struct GetElementArgs<'a, 'b, P: Provider> {
    pub list_entry: &'b P::ListEntry<'a>,
}

#[derive(Debug, new)]
struct RelayedRequest {
    request: api::daemon::GetRequest,
    tx: NbDaemonSender,
    rx: oneshot::Receiver<Result<api::daemon::GetResponse, Error>>,
}

//
// List entry trait.
//

pub trait ListEntryKind: std::fmt::Debug + Default {
    fn get_keys(&self) -> Option<String>;

    fn child_task(&self) -> Option<NbDaemonSender> {
        None
    }
}

//
// Provider northbound.
//

pub trait Provider: ProviderBase {
    const STATE_PATH: &'static str;

    type ListEntry<'a>: ListEntryKind + Send;

    fn callbacks() -> Option<&'static Callbacks<Self>> {
        None
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        None
    }
}

// ===== impl Callbacks =====

impl<P> Callbacks<P>
where
    P: Provider,
{
    fn get_iterate(
        &self,
        key: &CallbackKey,
        attr_filter: Option<&NodeAttributes>,
    ) -> Option<&GetIterateCb<P>> {
        let node = self.0.get(key)?;

        // Apply node attribute filter.
        if let Some(attr_filter) = attr_filter {
            if attr_filter.intersects(node.attributes) {
                return None;
            }
        }

        node.get_iterate.as_ref()
    }

    fn get_element(
        &self,
        key: &CallbackKey,
        attr_filter: Option<&NodeAttributes>,
    ) -> Option<&GetElementCb<P>> {
        let node = self.0.get(key)?;

        // Apply node attribute filter.
        if let Some(attr_filter) = attr_filter {
            if attr_filter.intersects(node.attributes) {
                return None;
            }
        }

        node.get_element.as_ref()
    }

    pub fn keys(&self) -> Vec<CallbackKey> {
        self.0.keys().cloned().collect()
    }

    pub fn extend(&mut self, callbacks: Callbacks<P>) {
        self.0.extend(callbacks.0);
    }
}

impl<P> std::fmt::Debug for Callbacks<P>
where
    P: Provider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Callbacks({:?})", self.0.keys())
    }
}

impl<P> Default for Callbacks<P>
where
    P: Provider,
{
    fn default() -> Self {
        Callbacks(HashMap::new())
    }
}

// ===== impl CallbacksNode =====

impl<P> Default for CallbacksNode<P>
where
    P: Provider,
{
    fn default() -> Self {
        CallbacksNode {
            attributes: NodeAttributes::empty(),
            get_iterate: None,
            get_element: None,
        }
    }
}

// ===== impl CallbacksBuilder =====

impl<P> CallbacksBuilder<P>
where
    P: Provider,
{
    pub fn new(callbacks: Callbacks<P>) -> Self {
        CallbacksBuilder {
            path: None,
            attributes: NodeAttributes::empty(),
            callbacks,
        }
    }

    #[must_use]
    pub fn path(mut self, path: YangPath) -> Self {
        self.path = Some(path);
        self.attributes = NodeAttributes::empty();
        self
    }

    #[must_use]
    pub fn attributes(mut self, attributes: NodeAttributes) -> Self {
        self.attributes = attributes;
        self
    }

    #[must_use]
    pub fn get_iterate(mut self, cb: GetIterateCb<P>) -> Self {
        let path = self.path.unwrap().to_string();
        let key = CallbackKey::new(path, CallbackOp::GetIterate);
        let node = self.callbacks.0.entry(key).or_default();
        node.attributes = self.attributes;
        node.get_iterate = Some(cb);
        self
    }

    #[must_use]
    fn get_element(mut self, cb: GetElementCb<P>) -> Self {
        let path = self.path.unwrap().to_string();
        let key = CallbackKey::new(path, CallbackOp::GetElement);
        let node = self.callbacks.0.entry(key).or_default();
        node.attributes = self.attributes;
        node.get_element = Some(cb);
        self
    }

    #[must_use]
    pub fn get_element_u8(self, cb: GetElementCbType<P, u8>) -> Self {
        self.get_element(GetElementCb::Uint8(cb))
    }

    #[must_use]
    pub fn get_element_u16(self, cb: GetElementCbType<P, u16>) -> Self {
        self.get_element(GetElementCb::Uint16(cb))
    }

    #[must_use]
    pub fn get_element_u32(self, cb: GetElementCbType<P, u32>) -> Self {
        self.get_element(GetElementCb::Uint32(cb))
    }

    #[must_use]
    pub fn get_element_u64(self, cb: GetElementCbType<P, u64>) -> Self {
        self.get_element(GetElementCb::Uint64(cb))
    }

    #[must_use]
    pub fn get_element_binary(self, cb: GetElementCbType<P, Vec<u8>>) -> Self {
        self.get_element(GetElementCb::Binary(cb))
    }

    #[must_use]
    pub fn get_element_bool(self, cb: GetElementCbType<P, bool>) -> Self {
        self.get_element(GetElementCb::Bool(cb))
    }

    #[must_use]
    pub fn get_element_empty(self, cb: GetElementCbType<P, ()>) -> Self {
        self.get_element(GetElementCb::Empty(cb))
    }

    #[must_use]
    pub fn get_element_container(self, cb: GetElementCbType<P, ()>) -> Self {
        self.get_element(GetElementCb::Container(cb))
    }

    #[must_use]
    pub fn get_element_i8(self, cb: GetElementCbType<P, i8>) -> Self {
        self.get_element(GetElementCb::Int8(cb))
    }

    #[must_use]
    pub fn get_element_i16(self, cb: GetElementCbType<P, i16>) -> Self {
        self.get_element(GetElementCb::Int16(cb))
    }

    #[must_use]
    pub fn get_element_i32(self, cb: GetElementCbType<P, i32>) -> Self {
        self.get_element(GetElementCb::Int32(cb))
    }

    #[must_use]
    pub fn get_element_i64(self, cb: GetElementCbType<P, i64>) -> Self {
        self.get_element(GetElementCb::Int64(cb))
    }

    #[must_use]
    pub fn get_element_ip(self, cb: GetElementCbType<P, IpAddr>) -> Self {
        self.get_element(GetElementCb::IpAddr(cb))
    }

    #[must_use]
    pub fn get_element_ipv4(self, cb: GetElementCbType<P, Ipv4Addr>) -> Self {
        self.get_element(GetElementCb::Ipv4Addr(cb))
    }

    #[must_use]
    pub fn get_element_ipv6(self, cb: GetElementCbType<P, Ipv6Addr>) -> Self {
        self.get_element(GetElementCb::Ipv6Addr(cb))
    }

    #[must_use]
    pub fn get_element_prefix(
        self,
        cb: GetElementCbType<P, IpNetwork>,
    ) -> Self {
        self.get_element(GetElementCb::IpPrefix(cb))
    }

    #[must_use]
    pub fn get_element_prefixv4(
        self,
        cb: GetElementCbType<P, Ipv4Network>,
    ) -> Self {
        self.get_element(GetElementCb::Ipv4Prefix(cb))
    }

    #[must_use]
    pub fn get_element_prefixv6(
        self,
        cb: GetElementCbType<P, Ipv6Network>,
    ) -> Self {
        self.get_element(GetElementCb::Ipv6Prefix(cb))
    }

    #[must_use]
    pub fn get_element_date_and_time(
        self,
        cb: GetElementCbType<P, DateTime<Utc>>,
    ) -> Self {
        self.get_element(GetElementCb::DateAndTime(cb))
    }

    #[must_use]
    pub fn get_element_timervalue_secs16(
        self,
        cb: GetElementCbType<P, Duration>,
    ) -> Self {
        self.get_element(GetElementCb::TimerValueSecs16(cb))
    }

    #[must_use]
    pub fn get_element_timervalue_secs32(
        self,
        cb: GetElementCbType<P, Duration>,
    ) -> Self {
        self.get_element(GetElementCb::TimerValueSecs32(cb))
    }

    #[must_use]
    pub fn get_element_timervalue_millis(
        self,
        cb: GetElementCbType<P, Duration>,
    ) -> Self {
        self.get_element(GetElementCb::TimerValueMillis(cb))
    }

    #[must_use]
    pub fn get_element_timeticks(
        self,
        cb: GetElementCbType<P, Instant>,
    ) -> Self {
        self.get_element(GetElementCb::Timeticks(cb))
    }

    #[must_use]
    pub fn get_element_timeticks64(
        self,
        cb: GetElementCbType<P, Instant>,
    ) -> Self {
        self.get_element(GetElementCb::Timeticks64(cb))
    }

    #[must_use]
    pub fn get_element_string(self, cb: GetElementCbType<P, String>) -> Self {
        self.get_element(GetElementCb::String(cb))
    }

    #[must_use]
    pub fn build(self) -> Callbacks<P> {
        self.callbacks
    }
}

impl<P> Default for CallbacksBuilder<P>
where
    P: Provider,
{
    fn default() -> Self {
        CallbacksBuilder {
            path: None,
            attributes: NodeAttributes::empty(),
            callbacks: Callbacks::default(),
        }
    }
}

// ===== impl GetElementCb =====

impl<P> GetElementCb<P>
where
    P: Provider,
{
    fn invoke<'a>(
        &self,
        provider: &'a P,
        list_entry: &P::ListEntry<'a>,
    ) -> Option<String> {
        // Build parameters.
        let args = GetElementArgs { list_entry };

        // Invoke the callback and return an optional string.
        match self {
            GetElementCb::Uint8(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Uint16(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Uint32(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Uint64(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Binary(cb) => {
                use base64::Engine;

                (*cb)(provider, args).map(|v| {
                    base64::engine::general_purpose::STANDARD.encode(v)
                })
            }
            GetElementCb::Bool(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Empty(cb) => {
                (*cb)(provider, args).map(|_| String::new())
            }
            GetElementCb::Container(cb) => {
                (*cb)(provider, args).map(|_| String::new())
            }
            GetElementCb::Int8(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Int16(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Int32(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Int64(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::IpAddr(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Ipv4Addr(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Ipv6Addr(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::IpPrefix(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Ipv4Prefix(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::Ipv6Prefix(cb) => {
                (*cb)(provider, args).map(|v| v.to_string())
            }
            GetElementCb::DateAndTime(cb) => {
                (*cb)(provider, args).map(|v| v.to_rfc3339())
            }
            GetElementCb::TimerValueSecs16(cb) => {
                (*cb)(provider, args)
                    .map(|v| {
                        let remaining = v.as_secs();
                        // Round up the remaining time to 1 in case it's less
                        // than one second.
                        let remaining =
                            if remaining == 0 { 1 } else { remaining };
                        let remaining =
                            u16::try_from(remaining).unwrap_or(u16::MAX);
                        remaining.to_string()
                    })
                    .or(Some("not-set".to_owned()))
            }
            GetElementCb::TimerValueSecs32(cb) => {
                (*cb)(provider, args)
                    .map(|v| {
                        let remaining = v.as_secs();
                        // Round up the remaining time to 1 in case it's less
                        // than one second.
                        let remaining =
                            if remaining == 0 { 1 } else { remaining };
                        let remaining =
                            u32::try_from(remaining).unwrap_or(u32::MAX);
                        remaining.to_string()
                    })
                    .or(Some("not-set".to_owned()))
            }
            GetElementCb::TimerValueMillis(cb) => {
                (*cb)(provider, args)
                    .map(|v| {
                        let remaining = v.as_millis();
                        // Round up the remaining time to 1 in case it's less
                        // than one millisecond.
                        let remaining =
                            if remaining == 0 { 1 } else { remaining };
                        let remaining =
                            u32::try_from(remaining).unwrap_or(u32::MAX);
                        remaining.to_string()
                    })
                    .or(Some("not-set".to_owned()))
            }
            GetElementCb::Timeticks(cb) => (*cb)(provider, args).map(|v| {
                let uptime = Instant::now() - v;
                let uptime =
                    u32::try_from(uptime.as_millis() / 10).unwrap_or(u32::MAX);
                uptime.to_string()
            }),
            GetElementCb::Timeticks64(cb) => (*cb)(provider, args).map(|v| {
                let uptime = Instant::now() - v;
                let uptime =
                    u64::try_from(uptime.as_millis() / 10).unwrap_or(u64::MAX);
                uptime.to_string()
            }),
            GetElementCb::String(cb) => (*cb)(provider, args),
        }
    }
}

// ===== helper functions =====

fn iterate_node<'a, P>(
    provider: &'a P,
    cbs: &Callbacks<P>,
    attr_filter: Option<&NodeAttributes>,
    dtree: &mut DataTree,
    snode: &SchemaNode<'_>,
    parent_path: &str,
    list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<RelayedRequest>,
    first: bool,
) -> Result<(), Error>
where
    P: Provider,
{
    // Update data path.
    let path = if first || snode.is_schema_only() {
        parent_path.to_owned()
    } else {
        // TODO: include the namespace only when necessary.
        //let snode_parent = snode.ancestors().next().unwrap();
        format!("{}/{}:{}", parent_path, snode.module().name(), snode.name())
    };

    match snode.kind() {
        SchemaNodeKind::Leaf => {
            iterate_leaf(
                provider,
                cbs,
                attr_filter,
                dtree,
                snode,
                &path,
                list_entry,
            )?;
        }
        SchemaNodeKind::LeafList => {
            iterate_list(
                provider,
                cbs,
                attr_filter,
                dtree,
                snode,
                &path,
                list_entry,
                relay_list,
            )?;
        }
        SchemaNodeKind::List => {
            iterate_list(
                provider,
                cbs,
                attr_filter,
                dtree,
                snode,
                &path,
                list_entry,
                relay_list,
            )?;
        }
        SchemaNodeKind::Container => {
            iterate_container(
                provider,
                cbs,
                attr_filter,
                dtree,
                snode,
                &path,
                list_entry,
                relay_list,
            )?;
        }
        SchemaNodeKind::Choice | SchemaNodeKind::Case => {
            iterate_children(
                provider,
                cbs,
                attr_filter,
                dtree,
                snode,
                &path,
                list_entry,
                relay_list,
            )?;
        }

        _ => (),
    }

    Ok(())
}

fn iterate_leaf<'a, P>(
    provider: &'a P,
    cbs: &Callbacks<P>,
    attr_filter: Option<&NodeAttributes>,
    dtree: &mut DataTree,
    snode: &SchemaNode<'_>,
    path: &str,
    list_entry: &P::ListEntry<'a>,
) -> Result<(), Error>
where
    P: Provider,
{
    // Ignore config leafs and list keys.
    if snode.is_config() || snode.is_list_key() {
        return Ok(());
    }

    // Find GetElement callback.
    let snode_path = snode.path(SchemaPathFormat::DATA);
    let cb_key = CallbackKey::new(snode_path, CallbackOp::GetElement);
    if let Some(cb) = cbs.get_element(&cb_key, attr_filter) {
        let mut value = cb.invoke(provider, list_entry);

        Debug::GetElementCallback(path, &value).log();

        if value.is_some() {
            // Empty leafs don't have a value.
            if snode.base_type().unwrap() == DataValueType::Empty {
                value = None;
            }
            let _ = dtree
                .new_path(path, value.as_deref(), false)
                .map_err(Error::YangInvalidData)?;
        }
    }

    Ok(())
}

fn iterate_list<'a, P>(
    provider: &'a P,
    cbs: &Callbacks<P>,
    attr_filter: Option<&NodeAttributes>,
    dtree: &mut DataTree,
    snode: &SchemaNode<'_>,
    path: &str,
    parent_list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<RelayedRequest>,
) -> Result<(), Error>
where
    P: Provider,
{
    let snode_path = snode.path(SchemaPathFormat::DATA);
    let cb_key = CallbackKey::new(snode_path, CallbackOp::GetIterate);

    if let Some(cb) = cbs.get_iterate(&cb_key, attr_filter) {
        Debug::GetIterateCallback(path).log();

        let args = GetIterateArgs { parent_list_entry };
        if let Some(list_iter) = (*cb)(provider, args) {
            // Used by keyless lists.
            let mut position = 1;

            for list_entry in list_iter {
                iterate_list_entry(
                    provider,
                    cbs,
                    attr_filter,
                    dtree,
                    snode,
                    path,
                    list_entry,
                    &mut position,
                    relay_list,
                )?;
            }
        }
    }

    Ok(())
}

fn iterate_list_entry<'a, P>(
    provider: &'a P,
    cbs: &Callbacks<P>,
    attr_filter: Option<&NodeAttributes>,
    dtree: &mut DataTree,
    snode: &SchemaNode<'_>,
    path: &str,
    list_entry: P::ListEntry<'a>,
    position: &mut u32,
    relay_list: &mut Vec<RelayedRequest>,
) -> Result<(), Error>
where
    P: Provider,
{
    // Build path of list entry.
    let path_entry = if !snode.is_keyless_list() {
        let keys = list_entry.get_keys();
        format!("{}{}", path, keys.unwrap_or_default())
    } else {
        let path = format!("{}[{}]", path, position);
        *position += 1;
        path
    };

    match snode.kind() {
        SchemaNodeKind::LeafList => {
            iterate_leaf(
                provider,
                cbs,
                attr_filter,
                dtree,
                snode,
                path,
                &list_entry,
            )?;
        }
        SchemaNodeKind::List => {
            // Create list entry in the data tree.
            if !snode.is_keyless_list() {
                let _ = dtree
                    .new_path(&path_entry, None, false)
                    .map_err(Error::YangInvalidData)?;
            }

            iterate_children(
                provider,
                cbs,
                attr_filter,
                dtree,
                snode,
                &path_entry,
                &list_entry,
                relay_list,
            )?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn iterate_container<'a, P>(
    provider: &'a P,
    cbs: &Callbacks<P>,
    attr_filter: Option<&NodeAttributes>,
    dtree: &mut DataTree,
    snode: &SchemaNode<'_>,
    path: &str,
    list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<RelayedRequest>,
) -> Result<(), Error>
where
    P: Provider,
{
    if snode.is_state() && !snode.is_np_container() {
        // Find GetElement callback.
        let snode_path = snode.path(SchemaPathFormat::DATA);
        let cb_key = CallbackKey::new(snode_path, CallbackOp::GetElement);
        if let Some(cb) = cbs.get_element(&cb_key, attr_filter) {
            let value = cb.invoke(provider, list_entry);

            Debug::GetElementCallback(path, &value).log();

            if value.is_some() {
                let _ = dtree
                    .new_path(path, None, false)
                    .map_err(Error::YangInvalidData)?;
            }
        }
    }

    iterate_children(
        provider,
        cbs,
        attr_filter,
        dtree,
        snode,
        path,
        list_entry,
        relay_list,
    )?;

    Ok(())
}

fn iterate_children<'a, P>(
    provider: &'a P,
    cbs: &Callbacks<P>,
    attr_filter: Option<&NodeAttributes>,
    dtree: &mut DataTree,
    snode: &SchemaNode<'_>,
    path: &str,
    list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<RelayedRequest>,
) -> Result<(), Error>
where
    P: Provider,
{
    for snode in snode.children() {
        // Check if the provider implements the child node.
        let module = snode.module();
        if !is_module_implemented::<P>(&module) {
            if let Some(child_nb_tx) = list_entry.child_task() {
                // Prepare request to child task.
                let (responder_tx, responder_rx) = oneshot::channel();
                let path =
                    format!("{}/{}:{}", path, module.name(), snode.name());
                let request = api::daemon::GetRequest {
                    path: Some(path),
                    attr_filter: attr_filter.copied(),
                    responder: Some(responder_tx),
                };
                relay_list.push(RelayedRequest::new(
                    request,
                    child_nb_tx,
                    responder_rx,
                ));
            }
            continue;
        }

        iterate_node(
            provider,
            cbs,
            attr_filter,
            dtree,
            &snode,
            path,
            list_entry,
            relay_list,
            false,
        )?;
    }

    Ok(())
}

fn lookup_list_entry<'a, P>(
    provider: &'a P,
    cbs: &Callbacks<P>,
    dnode: &DataNodeRef<'_>,
) -> P::ListEntry<'a>
where
    P: Provider,
{
    let mut list_entry = Default::default();

    // Iterate over parent list entries starting from the root.
    for dnode in dnode
        .inclusive_ancestors()
        .filter(|dnode| dnode.schema().kind() == SchemaNodeKind::List)
        .collect::<Vec<_>>()
        .iter()
        .rev()
    {
        let snode_path = dnode.schema().path(SchemaPathFormat::DATA);
        let cb_key = CallbackKey::new(snode_path, CallbackOp::GetIterate);

        // Obtain the list entry keys.
        let list_keys =
            dnode.list_keys().fold(String::new(), |mut list_keys, key| {
                let _ = write!(
                    list_keys,
                    "[{}='{}']",
                    key.schema().name(),
                    key.value_canonical().unwrap()
                );
                list_keys
            });

        // Find the list entry associated to the provided path.
        if let Some(cb) = cbs.get_iterate(&cb_key, None) {
            let args = GetIterateArgs {
                parent_list_entry: &list_entry,
            };
            if let Some(mut list_iter) = (*cb)(provider, args) {
                if let Some(entry) = list_iter
                    .find(|entry| list_keys == entry.get_keys().unwrap())
                {
                    list_entry = entry;
                }
            }
        }
    }

    list_entry
}

fn is_module_implemented<P>(module: &SchemaModule<'_>) -> bool
where
    P: Provider,
{
    let module_name = module.name();
    P::yang_modules()
        .iter()
        .any(|module| *module == module_name)
}

// ===== global functions =====

pub(crate) async fn process_get<P>(
    provider: &P,
    path: Option<String>,
    attr_filter: Option<NodeAttributes>,
) -> Result<api::daemon::GetResponse, Error>
where
    P: Provider,
{
    let yang_ctx = YANG_CTX.get().unwrap();

    // TODO: support Get without path
    let path = path.unwrap();

    // Populate data tree with path requested by the user.
    let mut dtree = DataTree::new(yang_ctx);
    let dnode = dtree
        .new_path(&path, None, false)
        .map_err(Error::YangInvalidPath)?
        .unwrap();

    if let Some(cbs) = P::callbacks() {
        let mut relay_list = vec![];

        let list_entry = lookup_list_entry(provider, cbs, &dnode);
        let snode = yang_ctx
            .find_path(&dnode.schema().path(SchemaPathFormat::DATA))
            .unwrap();

        // Check if the provider implements the child node.
        if !is_module_implemented::<P>(&snode.module()) {
            if let Some(child_nb_tx) = list_entry.child_task() {
                // Prepare request to child task.
                let (responder_tx, responder_rx) = oneshot::channel();
                let request = api::daemon::GetRequest {
                    path: Some(path),
                    attr_filter,
                    responder: Some(responder_tx),
                };
                relay_list.push(RelayedRequest::new(
                    request,
                    child_nb_tx,
                    responder_rx,
                ));
            }
        } else {
            // If a list entry was given, iterate over that list entry.
            if snode.kind() == SchemaNodeKind::List {
                iterate_children(
                    provider,
                    cbs,
                    attr_filter.as_ref(),
                    &mut dtree,
                    &snode,
                    &path,
                    &list_entry,
                    &mut relay_list,
                )?;
            } else {
                iterate_node(
                    provider,
                    cbs,
                    attr_filter.as_ref(),
                    &mut dtree,
                    &snode,
                    &path,
                    &list_entry,
                    &mut relay_list,
                    true,
                )?;
            }
        }

        // Send relayed requests.
        for relayed_req in relay_list {
            // Send request to child task.
            relayed_req
                .tx
                .send(api::daemon::Request::Get(relayed_req.request))
                .await
                .unwrap();

            // Receive response.
            let response = relayed_req.rx.await.unwrap()?;

            // Merge received data into the current data tree.
            dtree
                .merge(&response.data)
                .map_err(Error::YangInvalidData)?;
        }
    }

    Ok(api::daemon::GetResponse { data: dtree })
}
