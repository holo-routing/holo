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
    AddressMsg, BierNbrInstallMsg, BierNbrUninstallMsg,
    InterfaceIpAddRequestMsg, InterfaceIpDeleteRequestMsg, InterfaceUpdateMsg,
    LabelInstallMsg, LabelUninstallMsg, MacvlanCreateMsg, RouteKeyMsg,
    RouteMsg,
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
    // Create a Macvlan Address
    CreateMacVlan(MacvlanCreateMsg),
    // Request to add an address to an interface.
    InterfaceIpAddRequest(InterfaceIpAddRequestMsg),
    // Request to delete an address to an interface.
    InterfaceIpDeleteRequest(InterfaceIpDeleteRequestMsg),
    // Request to delete an interface
    InterfaceDeleteRequest(u32),
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
    // BIER configuration update.
    BierCfgUpd(Arc<BierCfg>),
    // BIER configuration event.
    BierCfgEvent(BierCfgEvent),
    // Request to install an entry in the BIRT.
    RouteBierAdd(BierNbrInstallMsg),
    // Request to uninstall an entry in the BIRT.
    RouteBierDel(BierNbrUninstallMsg),
    // Purge the BIRT.
    /* TODO: Add Protocol argument to BierPurge to specify which BIRT has to be purged.
     *  E.g., One could ask to purge the BIRT populated by a specific instance
     *  of OSPFv3 but not those populated by IS-IS.
     *  See https://github.com/holo-routing/holo/pull/16#discussion_r1729456621.
     */
    BierPurge,
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
