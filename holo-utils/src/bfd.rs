//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::IpAddr;

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_yang::ToYang;
use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::protocol::Protocol;

// BFD path type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum PathType {
    IpSingleHop,
    IpMultihop,
}

// BFD session key.
#[derive(Clone, Debug, EnumAsInner, Eq, new, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum SessionKey {
    IpSingleHop { ifname: String, dst: IpAddr },
    IpMultihop { src: IpAddr, dst: IpAddr },
}

// BFD session state.
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum State {
    AdminDown = 0,
    Down = 1,
    Init = 2,
    Up = 3,
}

// BFD client ID.
#[derive(Clone, Debug, Eq, Hash, PartialEq, new)]
#[derive(Deserialize, Serialize)]
pub struct ClientId {
    pub protocol: Protocol,
    pub name: String,
}

// BFD client configuration.
#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub struct ClientCfg {
    pub local_multiplier: u8,
    pub min_tx: u32,
    pub min_rx: u32,
}

// ===== impl PathType =====

impl ToYang for PathType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            PathType::IpSingleHop => "ietf-bfd-types:path-ip-sh".into(),
            PathType::IpMultihop => "ietf-bfd-types:path-ip-mh".into(),
        }
    }
}

// ===== impl SessionKey =====

impl SessionKey {
    pub fn dst(&self) -> &IpAddr {
        match self {
            SessionKey::IpSingleHop { dst, .. }
            | SessionKey::IpMultihop { dst, .. } => dst,
        }
    }

    pub fn path_type(&self) -> PathType {
        match self {
            SessionKey::IpSingleHop { .. } => PathType::IpSingleHop,
            SessionKey::IpMultihop { .. } => PathType::IpMultihop,
        }
    }
}

// ===== impl State =====

impl ToYang for State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            State::AdminDown => "adminDown".into(),
            State::Down => "down".into(),
            State::Init => "init".into(),
            State::Up => "up".into(),
        }
    }
}

// ===== impl ClientCfg =====

impl Default for ClientCfg {
    fn default() -> ClientCfg {
        // TODO: how to fetch default values from a YANG grouping?
        ClientCfg {
            local_multiplier: 3,
            min_tx: 1000000,
            min_rx: 1000000,
        }
    }
}
