//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{Receiver, Sender};

use crate::bfd;
use crate::ip::AddressFamily;
use crate::keychain::Keychain;
use crate::policy::{MatchSets, Policy};
use crate::protocol::Protocol;
use crate::southbound::{
    AddressMsg, InterfaceUpdateMsg, LabelInstallMsg, LabelUninstallMsg,
    RouteKeyMsg, RouteMsg,
};
use crate::sr::SrCfg;

// Useful type definition(s).
pub type IbusReceiver = Receiver<IbusMsg>;
pub type IbusSender = Sender<IbusMsg>;

// Ibus message for communication among the different Holo components.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IbusMsg {
    // BFD peer registration.
    BfdSessionReg {
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
        client_config: Option<bfd::ClientCfg>,
    },
    // BFD peer unregistration.
    BfdSessionUnreg {
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
    },
    // BFD peer state update.
    BfdStateUpd {
        sess_key: bfd::SessionKey,
        state: bfd::State,
    },
    // Query the current hostname.
    HostnameQuery,
    // Hostname update notification.
    HostnameUpdate(Option<String>),
    // Request to dump information about all interfaces.
    InterfaceDump,
    // Query information about a specific interface.
    InterfaceQuery {
        ifname: String,
        af: Option<AddressFamily>,
    },
    // Interface update notification.
    InterfaceUpd(InterfaceUpdateMsg),
    // Interface delete notification.
    InterfaceDel(String),
    // Interface address addition notification.
    InterfaceAddressAdd(AddressMsg),
    // Interface address delete notification.
    InterfaceAddressDel(AddressMsg),
    // Keychain update notification.
    KeychainUpd(Arc<Keychain>),
    // Keychain delete notification.
    KeychainDel(String),
    // Nexthop tracking registration.
    NexthopTrack(IpAddr),
    // Nexthop tracking unregistration.
    NexthopUntrack(IpAddr),
    // Nexthop tracking update.
    NexthopUpd {
        addr: IpAddr,
        metric: Option<u32>,
    },
    // Policy match sets update notification.
    PolicyMatchSetsUpd(Arc<MatchSets>),
    // Policy definition update notification.
    PolicyUpd(Arc<Policy>),
    // Policy definition delete notification.
    PolicyDel(String),
    // Query the current Router ID.
    RouterIdQuery,
    // Router ID update notification.
    RouterIdUpdate(Option<Ipv4Addr>),
    // Request to install IP route in the RIB.
    RouteIpAdd(RouteMsg),
    // Request to uninstall IP route from the RIB.
    RouteIpDel(RouteKeyMsg),
    // Request to install MPLS route in the LIB.
    RouteMplsAdd(LabelInstallMsg),
    // Request to uninstall MPLS route from the LIB.
    RouteMplsDel(LabelUninstallMsg),
    // Request to redistribute routes.
    RouteRedistributeDump {
        protocol: Protocol,
        af: Option<AddressFamily>,
    },
    // Route redistribute update notification.
    RouteRedistributeAdd(RouteMsg),
    // Route redistribute delete notification.
    RouteRedistributeDel(RouteKeyMsg),
    // Segment Routing configuration update.
    SrCfgUpd(Arc<SrCfg>),
    // Segment Routing configuration event.
    SrCfgEvent(SrCfgEvent),
}

// Type of Segment Routing configuration change.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SrCfgEvent {
    LabelRangeUpdate,
    PrefixSidUpdate(AddressFamily),
}
