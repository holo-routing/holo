//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::bier::{BierCfg, BierCfgEvent};
use crate::ip::AddressFamily;
use crate::keychain::Keychain;
use crate::policy::{MatchSets, Policy};
use crate::protocol::Protocol;
use crate::southbound::{
    AddressMsg, BierNbrInstallMsg, BierNbrUninstallMsg,
    InterfaceIpAddRequestMsg, InterfaceIpDelRequestMsg, InterfaceUpdateMsg,
    LabelInstallMsg, LabelUninstallMsg, MacvlanAddMsg, RouteKeyMsg, RouteMsg,
};
use crate::sr::{SrCfg, SrCfgEvent};
use crate::{UnboundedReceiver, UnboundedSender, bfd};

// Useful type definition(s).
pub type IbusReceiver = UnboundedReceiver<IbusMsg>;
pub type IbusSender = UnboundedSender<IbusMsg>;

// Ibus output channels.
#[derive(Clone, Debug)]
pub struct IbusChannelsTx {
    pub routing: UnboundedSender<IbusMsg>,
    pub interface: UnboundedSender<IbusMsg>,
    pub system: UnboundedSender<IbusMsg>,
    pub keychain: UnboundedSender<IbusMsg>,
    pub policy: UnboundedSender<IbusMsg>,
}

// Ibus input channels.
#[derive(Debug)]
pub struct IbusChannelsRx {
    pub routing: UnboundedReceiver<IbusMsg>,
    pub interface: UnboundedReceiver<IbusMsg>,
    pub system: UnboundedReceiver<IbusMsg>,
    pub keychain: UnboundedReceiver<IbusMsg>,
    pub policy: UnboundedReceiver<IbusMsg>,
}

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
    // Request to add an address to an interface.
    InterfaceIpAddRequest(InterfaceIpAddRequestMsg),
    // Request to delete an address to an interface.
    InterfaceIpDelRequest(InterfaceIpDelRequestMsg),
    // Keychain update notification.
    KeychainUpd(Arc<Keychain>),
    // Keychain delete notification.
    KeychainDel(String),
    // Create a macvlan interface.
    MacvlanAdd(MacvlanAddMsg),
    // Delete a macvlan interface.
    MacvlanDel(String),
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
    // TODO: Add Protocol argument to BierPurge to specify which BIRT has to be
    // purged. E.g., One could ask to purge the BIRT populated by a specific
    // instance of OSPFv3 but not those populated by IS-IS.
    BierPurge,
}

// ===== global functions =====

pub fn ibus_channels() -> (IbusChannelsTx, IbusChannelsRx) {
    let (routing_tx, routing_rx) = mpsc::unbounded_channel();
    let (interface_tx, interface_rx) = mpsc::unbounded_channel();
    let (system_tx, system_rx) = mpsc::unbounded_channel();
    let (keychain_tx, keychain_rx) = mpsc::unbounded_channel();
    let (policy_tx, policy_rx) = mpsc::unbounded_channel();

    let tx = IbusChannelsTx {
        routing: routing_tx,
        interface: interface_tx,
        system: system_tx,
        keychain: keychain_tx,
        policy: policy_tx,
    };
    let rx = IbusChannelsRx {
        routing: routing_rx,
        interface: interface_rx,
        system: system_rx,
        keychain: keychain_rx,
        policy: policy_rx,
    };

    (tx, rx)
}
