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
use crate::bier::BierCfg;
use crate::ip::AddressFamily;
use crate::keychain::Keychain;
use crate::policy::{MatchSets, Policy};
use crate::protocol::Protocol;
use crate::southbound::{
    AddressMsg, BierNbrInstallMsg, BierNbrUninstallMsg, InterfaceUpdateMsg,
    LabelInstallMsg, LabelUninstallMsg, RouteKeyMsg, RouteMsg,
};
use crate::sr::SrCfg;

// Useful type definition(s).
pub type IbusReceiver = Receiver<IbusMsg>;
pub type IbusSender = Sender<IbusMsg>;

// Ibus message for communication among the different Holo components.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IbusMsg {
    // BFD session
    BfdSession(BfdSessionMsg),
    // Hostname
    Hostname(HostnameMsg),
    // Interface
    Interface(InterfaceMsg),
    // Interface Address
    InterfaceAddress(InterfaceAddressMsg),
    // Keychain
    Keychain(KeychainMsg),
    // Nexthop
    Nexthop(NexthopMsg),
    // policy
    Policy(PolicyMsg),
    // Router ID
    RouterId(RouterIdMsg),
    // Route Ip
    RouteIp(RouteIpMsg),
    // Route Mpls
    RouteMpls(RouteMplsMsg),
    // Route redistribute
    RouteRedistribute(RouteRedistributeMsg),
    // SrCfg
    SrCfg(SrCfgMsg),
    // BIER
    BierCfg(BierCfgMsg),
    // ROUTE BIER
    RouteBier(RouteBierMsg),
    // Purge the BIRT.
    /* TODO: Add Protocol argument to BierPurge to specify which BIRT has to be purged.
     *  E.g., One could ask to purge the BIRT populated by a specific instance
     *  of OSPFv3 but not those populated by IS-IS.
     *  See https://github.com/holo-routing/holo/pull/16#discussion_r1729456621.
     */
    BierPurge,
}

// Bfd session ibus messages
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BfdSessionMsg {
    // BFD peer registration.
    Registration {
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
        client_config: Option<bfd::ClientCfg>,
    },

    // BFD peer unregistration.
    Unregistration {
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
    },

    // BFD peer state update.
    Update {
        sess_key: bfd::SessionKey,
        state: bfd::State,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum HostnameMsg {
    // Query the current hostname.
    Query,
    // Hostname update notification.
    Update(Option<String>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum InterfaceMsg {
    // Request to dump information about all interfaces.
    Dump,
    // Query information about a specific interface.
    Query {
        ifname: String,
        af: Option<AddressFamily>,
    },
    // Interface update notification.
    Update(InterfaceUpdateMsg),
    // Interface delete notification.
    Delete(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum InterfaceAddressMsg {
    // Interface address addition notification.
    Add(AddressMsg),

    // Interface address delete notification.
    Delete(AddressMsg),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum KeychainMsg {
    // Keychain update notification.
    Update(Arc<Keychain>),

    // Keychain delete notification.
    Delete(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum NexthopMsg {
    // Nexthop tracking registration
    Track(IpAddr),

    // Nexthop tracking unregistration
    Untrack(IpAddr),

    // Nexthop tracking update
    Update { addr: IpAddr, metric: Option<u32> },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PolicyMsg {
    // Policy match sets update notification.
    MatchSetsUpdate(Arc<MatchSets>),
    // Policy definition update notification.
    Update(Arc<Policy>),
    // Policy definition delete notification.
    Delete(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RouterIdMsg {
    // Query the current Router ID.
    Query,
    // Router ID update notification.
    Update(Option<Ipv4Addr>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RouteIpMsg {
    Add(RouteMsg),
    Delete(RouteKeyMsg),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RouteMplsMsg {
    // Request to install MPLS route in the LIB.
    Add(LabelInstallMsg),
    // Request to uninstall MPLS route from the LIB.
    Delete(LabelUninstallMsg),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RouteRedistributeMsg {
    // Request to redistribute routes.
    Dump {
        protocol: Protocol,
        af: Option<AddressFamily>,
    },
    // Route redistribute update notification.
    Add(RouteMsg),
    // Route redistribute delete notification.
    Delete(RouteKeyMsg),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SrCfgMsg {
    // Segment Routing configuration update.
    Update(Arc<SrCfg>),
    // Segment Routing configuration event.
    Event(SrCfgEvent),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BierCfgMsg {
    // BIER configuration update.
    Update(Arc<BierCfg>),
    // BIER configuration event.
    Event(BierCfgEvent),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RouteBierMsg {
    // Request to install an entry in the BIRT.
    Add(BierNbrInstallMsg),
    // Request to uninstall an entry in the BIRT.
    Delete(BierNbrUninstallMsg),
}

// Type of Segment Routing configuration change.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SrCfgEvent {
    LabelRangeUpdate,
    PrefixSidUpdate(AddressFamily),
}

// Type of BIER configuration events.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BierCfgEvent {
    SubDomainUpdate(AddressFamily),
    EncapUpdate(AddressFamily),
}
