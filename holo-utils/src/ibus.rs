//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::stream::{self, BoxStream, StreamExt};
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
pub type IbusClientId = usize;
pub type IbusConnSender = UnboundedSender<IbusConn>;
pub type IbusConnReceiver = UnboundedReceiver<IbusConn>;

/// A client's send handles to the base components.
#[derive(Clone, Debug)]
pub struct IbusChannelsTx {
    routing: IbusConnTx,
    interface: IbusConnTx,
    system: IbusConnTx,
    keychain: IbusConnTx,
    policy: IbusConnTx,
}

/// Registration channels of the base components.
///
/// Each receives an [`IbusConn`] when a client connects to that component.
#[derive(Debug)]
pub struct IbusChannelsRx {
    pub routing: IbusConnReceiver,
    pub interface: IbusConnReceiver,
    pub system: IbusConnReceiver,
    pub keychain: IbusConnReceiver,
    pub policy: IbusConnReceiver,
}

/// A client's send-side handle to one base component.
///
/// Holds the component's shared registration channel, plus the client's
/// dedicated channel once `connect` has established it.
#[derive(Clone, Debug)]
struct IbusConnTx {
    // Shared registration channel to the component.
    reg: IbusConnSender,
    // This client's dedicated channel. `None` on the base template, before
    // `connect` establishes the connection.
    tx: Option<IbusSender>,
}

/// A client of a base component, from the component's perspective.
///
/// Identifies which client a received message came from (`id`) and carries the
/// channel for sending replies and notifications back to it (`tx`).
#[derive(Clone, Debug)]
pub struct IbusClient {
    /// Unique identifier for the client.
    pub id: IbusClientId,
    /// Channel for sending messages to the client.
    pub tx: IbusSender,
}

/// A client's connection, handed to a base component when the client connects.
#[derive(Debug)]
pub struct IbusConn {
    pub id: IbusClientId,
    pub rx: IbusReceiver,
    pub tx: IbusSender,
}

/// Event produced by a base component's per-client connection stream.
#[derive(Debug)]
pub enum IbusConnEvent {
    /// A message from the client, with the channel for sending back to it.
    Msg { tx: IbusSender, msg: IbusMsg },
    /// The client disconnected (its channel was dropped).
    Disconnect,
}

/// A client's connection demultiplexed into a keyed stream of events.
///
/// Yields `(id, event)` pairs and ends with a final `Disconnect` event once the
/// connection's channel is closed. A base component merges these (e.g. in a
/// [`futures::stream::SelectAll`]) to demultiplex all of its clients.
pub type IbusConnStream = BoxStream<'static, (IbusClientId, IbusConnEvent)>;

/// Ibus message for communication among the different Holo components.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum IbusMsg {
    /// BFD peer registration.
    BfdSessionReg {
        #[serde(skip)]
        client: Option<IbusClient>,
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
        client_config: Option<bfd::ClientCfg>,
    },
    /// BFD peer unregistration.
    BfdSessionUnreg {
        #[serde(skip)]
        client: Option<IbusClient>,
        sess_key: bfd::SessionKey,
    },
    /// BFD peer state update.
    BfdStateUpd {
        sess_key: bfd::SessionKey,
        state: bfd::State,
    },
    /// Request a subscription to hostname update notifications.
    HostnameSub {},
    /// Hostname update notification.
    HostnameUpdate(Option<String>),
    /// Request a subscription to interface update notifications.
    ///
    /// The client may filter updates by a specific interface or address
    /// family.
    InterfaceSub {
        ifname: Option<String>,
        af: Option<AddressFamily>,
    },
    /// Cancel a previously requested subscription to interface updates.
    InterfaceUnsub { ifname: Option<String> },
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
    NexthopTrack { addr: IpAddr },
    /// Nexthop tracking unregistration.
    NexthopUntrack { addr: IpAddr },
    /// Nexthop tracking update.
    NexthopUpd { addr: IpAddr, metric: Option<u32> },
    /// Policy match sets update notification.
    PolicyMatchSetsUpd(Arc<MatchSets>),
    /// Policy definition update notification.
    PolicyUpd(Arc<Policy>),
    /// Policy definition delete notification.
    PolicyDel(String),
    /// Request a subscription to Router ID update notifications.
    RouterIdSub {},
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
        protocol: Protocol,
        af: Option<AddressFamily>,
    },
    /// Cancel a previously requested subscription to route updates.
    RouteRedistributeUnsub {
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
}

// ===== impl IbusChannelsTx =====

impl IbusChannelsTx {
    /// Builds the send handles for a new client, opening a connection to every
    /// component.
    ///
    /// `client_tx` is the client's own channel, where components send
    /// notifications back. Components detect the client's teardown when the
    /// returned handles are dropped.
    pub fn with_client(
        tx: &IbusChannelsTx,
        client_tx: UnboundedSender<IbusMsg>,
    ) -> Self {
        let client = IbusClient::new(client_tx);
        IbusChannelsTx {
            routing: tx.routing.connect(&client),
            interface: tx.interface.connect(&client),
            system: tx.system.connect(&client),
            keychain: tx.keychain.connect(&client),
            policy: tx.policy.connect(&client),
        }
    }

    /// Sends an [`IbusMsg::BfdSessionReg`] message to `holo-routing`.
    pub fn bfd_session_reg(
        &self,
        sess_key: bfd::SessionKey,
        client_id: bfd::ClientId,
        client_config: Option<bfd::ClientCfg>,
    ) {
        // The client is filled in by `holo-routing` when it relays the
        // message to the BFD instance, based on the connection it arrived on.
        self.routing.send(IbusMsg::BfdSessionReg {
            client: None,
            sess_key,
            client_id,
            client_config,
        });
    }

    /// Sends an [`IbusMsg::BfdSessionUnreg`] message to `holo-routing`.
    pub fn bfd_session_unreg(&self, sess_key: bfd::SessionKey) {
        self.routing.send(IbusMsg::BfdSessionUnreg {
            client: None,
            sess_key,
        });
    }

    /// Sends an [`IbusMsg::HostnameSub`] message to `holo-system`.
    pub fn hostname_sub(&self) {
        self.system.send(IbusMsg::HostnameSub {});
    }

    /// Sends an [`IbusMsg::InterfaceSub`] message to `holo-interface`.
    pub fn interface_sub(
        &self,
        ifname: Option<String>,
        af: Option<AddressFamily>,
    ) {
        self.interface.send(IbusMsg::InterfaceSub { ifname, af });
    }

    /// Sends an [`IbusMsg::InterfaceUnsub`] message to `holo-interface`.
    pub fn interface_unsub(&self, ifname: Option<String>) {
        self.interface.send(IbusMsg::InterfaceUnsub { ifname });
    }

    /// Sends an [`IbusMsg::InterfaceIpAddRequest`] message to `holo-interface`.
    pub fn interface_ip_add(&self, ifname: String, addr: IpNetwork) {
        self.interface
            .send(IbusMsg::InterfaceIpAddRequest { ifname, addr });
    }

    /// Sends an [`IbusMsg::InterfaceIpDelRequest`] message to `holo-interface`.
    pub fn interface_ip_del(&self, ifname: String, addr: IpNetwork) {
        self.interface
            .send(IbusMsg::InterfaceIpDelRequest { ifname, addr });
    }

    /// Sends an [`IbusMsg::MacvlanAdd`] message to `holo-interface`.
    pub fn macvlan_add(
        &self,
        parent_ifname: String,
        ifname: String,
        mac_addr: Option<MacAddr>,
    ) {
        self.interface.send(IbusMsg::MacvlanAdd {
            parent_ifname,
            ifname,
            mac_addr,
        });
    }

    /// Sends an [`IbusMsg::MacvlanDel`] message to `holo-interface`.
    pub fn macvlan_del(&self, ifname: String) {
        self.interface.send(IbusMsg::MacvlanDel { ifname });
    }

    /// Sends an [`IbusMsg::RouterIdSub`] message to `holo-interface`.
    pub fn router_id_sub(&self) {
        self.interface.send(IbusMsg::RouterIdSub {});
    }

    /// Sends an [`IbusMsg::NexthopTrack`] message to `holo-routing`.
    pub fn nexthop_track(&self, addr: IpAddr) {
        self.routing.send(IbusMsg::NexthopTrack { addr });
    }

    /// Sends an [`IbusMsg::NexthopUntrack`] message to `holo-routing`.
    pub fn nexthop_untrack(&self, addr: IpAddr) {
        self.routing.send(IbusMsg::NexthopUntrack { addr });
    }

    /// Sends an [`IbusMsg::RouteIpAdd`] message to `holo-routing`.
    pub fn route_ip_add(&self, route: RouteMsg) {
        self.routing.send(IbusMsg::RouteIpAdd(route));
    }

    /// Sends an [`IbusMsg::RouteIpDel`] message to `holo-routing`.
    pub fn route_ip_del(&self, route: RouteKeyMsg) {
        self.routing.send(IbusMsg::RouteIpDel(route));
    }

    /// Sends an [`IbusMsg::RouteMplsAdd`] message to `holo-routing`.
    pub fn route_mpls_add(&self, msg: LabelInstallMsg) {
        self.routing.send(IbusMsg::RouteMplsAdd(msg));
    }

    /// Sends an [`IbusMsg::RouteMplsDel`] message to `holo-routing`.
    pub fn route_mpls_del(&self, msg: LabelUninstallMsg) {
        self.routing.send(IbusMsg::RouteMplsDel(msg));
    }

    /// Sends an [`IbusMsg::RouteBierAdd`] message to `holo-routing`.
    pub fn route_bier_add(&self, msg: BierNbrInstallMsg) {
        self.routing.send(IbusMsg::RouteBierAdd(msg));
    }

    /// Sends an [`IbusMsg::RouteBierDel`] message to `holo-routing`.
    pub fn route_bier_del(&self, msg: BierNbrUninstallMsg) {
        self.routing.send(IbusMsg::RouteBierDel(msg));
    }

    /// Sends an [`IbusMsg::BierPurge`] message.
    pub fn bier_purge(&self) {
        self.routing.send(IbusMsg::BierPurge);
    }

    /// Sends an [`IbusMsg::RouteRedistributeSub`] message to `holo-routing`.
    pub fn route_redistribute_sub(
        &self,
        protocol: Protocol,
        af: Option<AddressFamily>,
    ) {
        self.routing
            .send(IbusMsg::RouteRedistributeSub { protocol, af });
    }

    /// Sends an [`IbusMsg::RouteRedistributeUnsub`] message to `holo-routing`.
    pub fn route_redistribute_unsub(
        &self,
        protocol: Protocol,
        af: Option<AddressFamily>,
    ) {
        self.routing
            .send(IbusMsg::RouteRedistributeUnsub { protocol, af });
    }

    #[doc(hidden)]
    pub fn keychain_upd(&self, keychain: Arc<Keychain>) {
        self.routing.send(IbusMsg::KeychainUpd(keychain));
    }

    #[doc(hidden)]
    pub fn keychain_del(&self, name: String) {
        self.routing.send(IbusMsg::KeychainDel(name));
    }

    #[doc(hidden)]
    pub fn policy_match_sets_upd(&self, match_sets: Arc<MatchSets>) {
        self.routing.send(IbusMsg::PolicyMatchSetsUpd(match_sets));
    }

    #[doc(hidden)]
    pub fn policy_upd(&self, policy: Arc<Policy>) {
        self.routing.send(IbusMsg::PolicyUpd(policy));
    }

    #[doc(hidden)]
    pub fn policy_del(&self, name: String) {
        self.routing.send(IbusMsg::PolicyDel(name));
    }
}

// ===== impl IbusConnTx =====

impl IbusConnTx {
    // Creates a client with no dedicated connection yet (base template).
    fn new(reg: IbusConnSender) -> Self {
        IbusConnTx { reg, tx: None }
    }

    // Establishes a dedicated connection for `client` and registers it with
    // the component.
    fn connect(&self, client: &IbusClient) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let _ = self.reg.send(IbusConn {
            id: client.id,
            rx,
            tx: client.tx.clone(),
        });
        IbusConnTx {
            reg: self.reg.clone(),
            tx: Some(tx),
        }
    }

    // Sends a message over the dedicated connection (no-op on the base
    // template, which has no connection).
    fn send(&self, msg: IbusMsg) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(msg);
        }
    }
}

// ===== impl IbusClient =====

impl IbusClient {
    fn new(tx: IbusSender) -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        IbusClient {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            tx,
        }
    }
}

// ===== global functions =====

/// Wraps a connection into a keyed [`IbusConnStream`]: the client's messages
/// (each tagged with the channel for sending back) followed by a final
/// `Disconnect` once the connection closes.
pub fn connection_stream(conn: IbusConn) -> IbusConnStream {
    let IbusConn { id, rx, tx } = conn;
    stream::unfold(
        rx,
        |mut rx| async move { rx.recv().await.map(|msg| (msg, rx)) },
    )
    .map(move |msg| {
        let event = IbusConnEvent::Msg {
            tx: tx.clone(),
            msg,
        };
        (id, event)
    })
    .chain(stream::once(async move { (id, IbusConnEvent::Disconnect) }))
    .boxed()
}

/// Creates the ibus channels.
///
/// Returns the base [`IbusChannelsTx`] template, from which each client builds
/// its own handle via [`IbusChannelsTx::with_client`], and the
/// [`IbusChannelsRx`] with the components' registration channels.
pub fn ibus_channels() -> (IbusChannelsTx, IbusChannelsRx) {
    let (routing_reg_tx, routing_reg_rx) = mpsc::unbounded_channel();
    let (interface_reg_tx, interface_reg_rx) = mpsc::unbounded_channel();
    let (system_reg_tx, system_reg_rx) = mpsc::unbounded_channel();
    let (keychain_reg_tx, keychain_reg_rx) = mpsc::unbounded_channel();
    let (policy_reg_tx, policy_reg_rx) = mpsc::unbounded_channel();

    let tx = IbusChannelsTx {
        routing: IbusConnTx::new(routing_reg_tx),
        interface: IbusConnTx::new(interface_reg_tx),
        system: IbusConnTx::new(system_reg_tx),
        keychain: IbusConnTx::new(keychain_reg_tx),
        policy: IbusConnTx::new(policy_reg_tx),
    };
    let rx = IbusChannelsRx {
        routing: routing_reg_rx,
        interface: interface_reg_rx,
        system: system_reg_rx,
        keychain: keychain_reg_rx,
        policy: policy_reg_rx,
    };

    (tx, rx)
}
