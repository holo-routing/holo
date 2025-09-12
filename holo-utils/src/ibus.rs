//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::bfd;
use crate::bier::{BierCfg, BierCfgEvent};
use crate::ip::AddressFamily;
use crate::keychain::Keychain;
use crate::mac_addr::MacAddr;
use crate::policy::{MatchSets, Policy};
use crate::protocol::Protocol;
use crate::southbound::{
    AddressMsg, BierNbrInstallMsg, BierNbrUninstallMsg, InterfaceUpdateMsg,
    LabelInstallMsg, LabelUninstallMsg, RouteKeyMsg, RouteMsg,
};
use crate::sr::{MsdType, SrCfg, SrCfgEvent};

// Useful type definition(s).
pub type IbusReceiver = UnboundedReceiver<IbusMsg>;
pub type IbusSender = UnboundedSender<IbusMsg>;

/// Transmit channels for sending [`IbusMsg`] messages to each base component.
#[derive(Clone, Debug)]
pub struct IbusChannelsTx {
    subscriber: Option<IbusSubscriber>,
    routing: UnboundedSender<IbusMsg>,
    interface: UnboundedSender<IbusMsg>,
    system: UnboundedSender<IbusMsg>,
    keychain: UnboundedSender<IbusMsg>,
    policy: UnboundedSender<IbusMsg>,
}

/// Receive channels for receiving [`IbusMsg`] messages from each base component.
#[derive(Debug)]
pub struct IbusChannelsRx {
    pub routing: UnboundedReceiver<IbusMsg>,
    pub interface: UnboundedReceiver<IbusMsg>,
    pub system: UnboundedReceiver<IbusMsg>,
    pub keychain: UnboundedReceiver<IbusMsg>,
    pub policy: UnboundedReceiver<IbusMsg>,
}

/// Subscriber to [`IbusMsg`] messages.
#[derive(Clone, Debug)]
pub struct IbusSubscriber {
    /// Unique identifier for the subscriber.
    pub id: usize,
    /// Channel for sending messages to the subscriber.
    pub tx: IbusSender,
}

/// Ibus message for communication among the different Holo components.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum IbusMsg {
    /// BFD peer registration.
    BfdSessionReg {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
        client_config: Option<bfd::ClientCfg>,
    },
    /// BFD peer unregistration.
    BfdSessionUnreg {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
        sess_key: bfd::SessionKey,
    },
    /// BFD peer state update.
    BfdStateUpd {
        sess_key: bfd::SessionKey,
        state: bfd::State,
    },
    /// Request a subscription to hostname update notifications.
    HostnameSub {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
    },
    /// Hostname update notification.
    HostnameUpdate(Option<String>),
    /// Request a subscription to interface update notifications.
    ///
    /// The subscriber may filter updates by a specific interface or address
    /// family.
    InterfaceSub {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
        ifname: Option<String>,
        af: Option<AddressFamily>,
    },
    /// Cancel a previously requested subscription to interface updates.
    InterfaceUnsub {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
        ifname: Option<String>,
    },
    /// Interface update notification.
    InterfaceUpd(InterfaceUpdateMsg),
    /// Interface delete notification.
    InterfaceDel(String),
    /// Interface address addition notification.
    InterfaceAddressAdd(AddressMsg),
    /// Interface address delete notification.
    InterfaceAddressDel(AddressMsg),
    /// Request to add an address to an interface.
    InterfaceIpAddRequest { ifname: String, addr: IpNetwork },
    /// Request to delete an address to an interface.
    InterfaceIpDelRequest { ifname: String, addr: IpNetwork },
    /// Key-chain update notification.
    KeychainUpd(Arc<Keychain>),
    /// Key-chain delete notification.
    KeychainDel(String),
    /// Create a macvlan interface.
    MacvlanAdd {
        parent_ifname: String,
        ifname: String,
        mac_addr: Option<MacAddr>,
    },
    /// Delete a macvlan interface.
    MacvlanDel { ifname: String },
    /// Nexthop tracking registration.
    NexthopTrack {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
        addr: IpAddr,
    },
    /// Nexthop tracking unregistration.
    NexthopUntrack {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
        addr: IpAddr,
    },
    /// Nexthop tracking update.
    NexthopUpd { addr: IpAddr, metric: Option<u32> },
    /// Policy match sets update notification.
    PolicyMatchSetsUpd(Arc<MatchSets>),
    /// Policy definition update notification.
    PolicyUpd(Arc<Policy>),
    /// Policy definition delete notification.
    PolicyDel(String),
    /// Request a subscription to Router ID update notifications.
    RouterIdSub {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
    },
    /// Router ID update notification.
    RouterIdUpdate(Option<Ipv4Addr>),
    /// Request to install IP route in the RIB.
    RouteIpAdd(RouteMsg),
    /// Request to uninstall IP route from the RIB.
    RouteIpDel(RouteKeyMsg),
    /// Request to install MPLS route in the LIB.
    RouteMplsAdd(LabelInstallMsg),
    /// Request to uninstall MPLS route from the LIB.
    RouteMplsDel(LabelUninstallMsg),
    /// Request to install an entry in the BIRT.
    RouteBierAdd(BierNbrInstallMsg),
    /// Request to uninstall an entry in the BIRT.
    RouteBierDel(BierNbrUninstallMsg),
    /// Purge the BIRT.
    /// TODO: Add Protocol argument to `BierPurge` to specify which BIRT has to
    /// be purged. E.g., One could ask to purge the BIRT populated by a specific
    /// instance of OSPFv3 but not those populated by IS-IS.
    BierPurge,
    /// Requests a subscription to route update notifications for a specific
    /// protocol, with optional filtering by address family.
    RouteRedistributeSub {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
        protocol: Protocol,
        af: Option<AddressFamily>,
    },
    /// Cancel a previously requested subscription to route updates.
    RouteRedistributeUnsub {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
        protocol: Protocol,
        af: Option<AddressFamily>,
    },
    /// Route redistribute update notification.
    RouteRedistributeAdd(RouteMsg),
    /// Route redistribute delete notification.
    RouteRedistributeDel(RouteKeyMsg),
    /// Segment Routing configuration update.
    SrCfgUpd(Arc<SrCfg>),
    /// Segment Routing configuration event.
    SrCfgEvent(SrCfgEvent),
    /// Node MSD (Maximum SID Depth) update.
    NodeMsdUpd(BTreeMap<MsdType, u8>),
    /// BIER configuration update.
    BierCfgUpd(Arc<BierCfg>),
    /// BIER configuration event.
    BierCfgEvent(BierCfgEvent),
    /// Cancel all previously requested subscriptions.
    Disconnect {
        #[serde(skip)]
        subscriber: Option<IbusSubscriber>,
    },
}

// ===== impl IbusChannelsTx =====

impl IbusChannelsTx {
    /// Creates a new `IbusChannelsTx` with the provided subscriber.
    pub fn with_subscriber(
        tx: &IbusChannelsTx,
        subscriber_tx: UnboundedSender<IbusMsg>,
    ) -> Self {
        IbusChannelsTx {
            subscriber: Some(IbusSubscriber::new(subscriber_tx)),
            ..tx.clone()
        }
    }

    /// Sends an [`IbusMsg::BfdSessionReg`] message to `holo-routing`.
    pub fn bfd_session_reg(
        &self,
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
        client_config: Option<bfd::ClientCfg>,
    ) {
        let msg = IbusMsg::BfdSessionReg {
            subscriber: self.subscriber.clone(),
            sess_key,
            client_id,
            client_config,
        };
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::BfdSessionUnreg`] message to `holo-routing`.
    pub fn bfd_session_unreg(&self, sess_key: bfd::SessionKey) {
        let msg = IbusMsg::BfdSessionUnreg {
            subscriber: self.subscriber.clone(),
            sess_key,
        };
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::HostnameSub`] message to `holo-system`.
    pub fn hostname_sub(&self) {
        let msg = IbusMsg::HostnameSub {
            subscriber: self.subscriber.clone(),
        };
        let _ = self.system.send(msg);
    }

    /// Sends an [`IbusMsg::InterfaceSub`] message to `holo-interface`.
    pub fn interface_sub(
        &self,
        ifname: Option<String>,
        af: Option<AddressFamily>,
    ) {
        let msg = IbusMsg::InterfaceSub {
            subscriber: self.subscriber.clone(),
            ifname,
            af,
        };
        let _ = self.interface.send(msg);
    }

    /// Sends an [`IbusMsg::InterfaceUnsub`] message to `holo-interface`.
    pub fn interface_unsub(&self, ifname: Option<String>) {
        let msg = IbusMsg::InterfaceUnsub {
            subscriber: self.subscriber.clone(),
            ifname,
        };
        let _ = self.interface.send(msg);
    }

    /// Sends an [`IbusMsg::InterfaceIpAddRequest`] message to `holo-interface`.
    pub fn interface_ip_add(&self, ifname: String, addr: IpNetwork) {
        let msg = IbusMsg::InterfaceIpAddRequest { ifname, addr };
        let _ = self.interface.send(msg);
    }

    /// Sends an [`IbusMsg::InterfaceIpDelRequest`] message to `holo-interface`.
    pub fn interface_ip_del(&self, ifname: String, addr: IpNetwork) {
        let msg = IbusMsg::InterfaceIpDelRequest { ifname, addr };
        let _ = self.interface.send(msg);
    }

    /// Sends an [`IbusMsg::MacvlanAdd`] message to `holo-interface`.
    pub fn macvlan_add(
        &self,
        parent_ifname: String,
        ifname: String,
        mac_addr: Option<MacAddr>,
    ) {
        let msg = IbusMsg::MacvlanAdd {
            parent_ifname,
            ifname,
            mac_addr,
        };
        let _ = self.interface.send(msg);
    }

    /// Sends an [`IbusMsg::MacvlanDel`] message to `holo-interface`.
    pub fn macvlan_del(&self, ifname: String) {
        let msg = IbusMsg::MacvlanDel { ifname };
        let _ = self.interface.send(msg);
    }

    /// Sends an [`IbusMsg::RouterIdSub`] message to `holo-interface`.
    pub fn router_id_sub(&self) {
        let msg = IbusMsg::RouterIdSub {
            subscriber: self.subscriber.clone(),
        };
        let _ = self.interface.send(msg);
    }

    /// Sends an [`IbusMsg::NexthopTrack`] message to `holo-routing`.
    pub fn nexthop_track(&self, addr: IpAddr) {
        let msg = IbusMsg::NexthopTrack {
            subscriber: self.subscriber.clone(),
            addr,
        };
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::NexthopUntrack`] message to `holo-routing`.
    pub fn nexthop_untrack(&self, addr: IpAddr) {
        let msg = IbusMsg::NexthopUntrack {
            subscriber: self.subscriber.clone(),
            addr,
        };
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::RouteIpAdd`] message to `holo-routing`.
    pub fn route_ip_add(&self, route: RouteMsg) {
        let msg = IbusMsg::RouteIpAdd(route);
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::RouteIpDel`] message to `holo-routing`.
    pub fn route_ip_del(&self, route: RouteKeyMsg) {
        let msg = IbusMsg::RouteIpDel(route);
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::RouteMplsAdd`] message to `holo-routing`.
    pub fn route_mpls_add(&self, msg: LabelInstallMsg) {
        let msg = IbusMsg::RouteMplsAdd(msg);
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::RouteMplsDel`] message to `holo-routing`.
    pub fn route_mpls_del(&self, msg: LabelUninstallMsg) {
        let msg = IbusMsg::RouteMplsDel(msg);
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::RouteBierAdd`] message to `holo-routing`.
    pub fn route_bier_add(&self, msg: BierNbrInstallMsg) {
        let msg = IbusMsg::RouteBierAdd(msg);
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::RouteBierDel`] message to `holo-routing`.
    pub fn route_bier_del(&self, msg: BierNbrUninstallMsg) {
        let msg = IbusMsg::RouteBierDel(msg);
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::BierPurge`] message.
    pub fn bier_purge(&self) {
        let msg = IbusMsg::BierPurge;
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::RouteRedistributeSub`] message to `holo-routing`.
    pub fn route_redistribute_sub(
        &self,
        protocol: Protocol,
        af: Option<AddressFamily>,
    ) {
        let msg = IbusMsg::RouteRedistributeSub {
            subscriber: self.subscriber.clone(),
            protocol,
            af,
        };
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::RouteRedistributeUnsub`] message to `holo-routing`.
    pub fn route_redistribute_unsub(
        &self,
        protocol: Protocol,
        af: Option<AddressFamily>,
    ) {
        let msg = IbusMsg::RouteRedistributeUnsub {
            subscriber: self.subscriber.clone(),
            protocol,
            af,
        };
        let _ = self.routing.send(msg);
    }

    /// Sends an [`IbusMsg::Disconnect`] message to all base components.
    pub fn disconnect(&self) {
        for tx in &[
            &self.routing,
            &self.interface,
            &self.system,
            &self.keychain,
            &self.policy,
        ] {
            let msg = IbusMsg::Disconnect {
                subscriber: self.subscriber.clone(),
            };
            let _ = tx.send(msg);
        }
    }

    #[doc(hidden)]
    pub fn keychain_upd(&self, keychain: Arc<Keychain>) {
        let msg = IbusMsg::KeychainUpd(keychain);
        let _ = self.routing.send(msg);
    }

    #[doc(hidden)]
    pub fn keychain_del(&self, name: String) {
        let msg = IbusMsg::KeychainDel(name);
        let _ = self.routing.send(msg);
    }

    #[doc(hidden)]
    pub fn policy_match_sets_upd(&self, match_sets: Arc<MatchSets>) {
        let msg = IbusMsg::PolicyMatchSetsUpd(match_sets);
        let _ = self.routing.send(msg);
    }

    #[doc(hidden)]
    pub fn policy_upd(&self, policy: Arc<Policy>) {
        let msg = IbusMsg::PolicyUpd(policy);
        let _ = self.routing.send(msg);
    }

    #[doc(hidden)]
    pub fn policy_del(&self, name: String) {
        let msg = IbusMsg::PolicyDel(name);
        let _ = self.routing.send(msg);
    }
}

// ===== impl IbusSubscriber =====

impl IbusSubscriber {
    fn new(tx: IbusSender) -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        IbusSubscriber {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            tx,
        }
    }
}

// ===== global functions =====

/// Creates a set of Ibus communication channels for inter-component messaging.
///
/// Returns a tuple containing:
/// - A tuple of [`IbusChannelsTx`] instances, where each should be owned by the
///   corresponding base component.
/// - A single [`IbusChannelsRx`] instance, where each receiver should be owned
///   by the corresponding component.
pub fn ibus_channels() -> (
    (
        IbusChannelsTx,
        IbusChannelsTx,
        IbusChannelsTx,
        IbusChannelsTx,
        IbusChannelsTx,
    ),
    IbusChannelsRx,
) {
    let (routing_tx, routing_rx) = mpsc::unbounded_channel();
    let (interface_tx, interface_rx) = mpsc::unbounded_channel();
    let (system_tx, system_rx) = mpsc::unbounded_channel();
    let (keychain_tx, keychain_rx) = mpsc::unbounded_channel();
    let (policy_tx, policy_rx) = mpsc::unbounded_channel();

    let tx = IbusChannelsTx {
        subscriber: None,
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

    let tx_routing = IbusChannelsTx::with_subscriber(&tx, tx.routing.clone());
    let tx_interface =
        IbusChannelsTx::with_subscriber(&tx, tx.interface.clone());
    let tx_system = IbusChannelsTx::with_subscriber(&tx, tx.system.clone());
    let tx_keychain = IbusChannelsTx::with_subscriber(&tx, tx.keychain.clone());
    let tx_policy = IbusChannelsTx::with_subscriber(&tx, tx.policy.clone());

    (
        (tx_routing, tx_interface, tx_system, tx_keychain, tx_policy),
        rx,
    )
}
