//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use chrono::{DateTime, Utc};
use enum_as_inner::EnumAsInner;
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::mac_addr::MacAddr;
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::southbound::InterfaceFlags;
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;

use crate::debug::Debug;
use crate::error::{Error, IoError};
use crate::interface::{InterfaceSys, InterfaceView};
use crate::northbound::configuration::InstanceCfg;
use crate::northbound::notification;
use crate::packet::{
    ArpHdr, EthernetHdr, Ipv4Hdr, NeighborAdvertisement, Vrrp4Packet, VrrpHdr,
};
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::{ibus, network, tasks};

#[derive(Debug)]
pub struct Instance {
    // Virtual Router ID.
    pub vrid: u8,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: InstanceState,
    // Macvlan interface.
    pub mvlan: InstanceMacvlan,
    // Interface raw sockets and Tx/Rx tasks.
    pub net: Option<InstanceNet>,
}

#[derive(Debug, Default)]
pub struct InstanceState {
    pub state: fsm::State,
    pub last_event: fsm::Event,
    pub new_master_reason: MasterReason,
    pub up_time: Option<DateTime<Utc>>,
    pub timer: VrrpTimer,
    pub last_adv_src: Option<IpAddr>,
    pub statistics: Statistics,
}

#[derive(Debug)]
pub struct InstanceMacvlan {
    // Interface name.
    pub name: String,
    // Interface system data.
    pub system: InterfaceSys,
}

#[derive(Debug)]
pub struct InstanceNet {
    // Raw sockets.
    pub socket_vrrp_tx: Arc<AsyncFd<Socket>>,
    pub socket_vrrp_rx: Arc<AsyncFd<Socket>>,
    pub socket_arp: Arc<AsyncFd<Socket>>,
    // Network Tx/Rx tasks.
    _net_tx_task: Task<()>,
    _vrrp_net_rx_task: Task<()>,
    // Network Tx output channel.
    pub net_tx_packetp: UnboundedSender<NetTxPacketMsg>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum Version {
    V2,
    V3(AddressFamily),
}

// Protocol state machine.
pub mod fsm {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub enum State {
        #[default]
        Initialize,
        Backup,
        Master,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub enum Event {
        #[default]
        None,
        Startup,
        Shutdown,
        HigherPriorityBackup,
        MasterTimeout,
        InterfaceUp,
        InterfaceDown,
        NoPrimaryIpAddress,
        PrimaryIpAddress,
        NoVirtualIpAddresses,
        VirtualIpAddresses,
        PreemptHoldTimeout,
        LowerPriorityMaster,
        OwnerPreempt,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MasterReason {
    #[default]
    NotMaster,
    Priority,
    Preempted,
    NoResponse,
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum VrrpTimer {
    #[default]
    Null,
    AdvTimer(IntervalTask),
    MasterDownTimer(TimeoutTask),
}

#[derive(Debug)]
pub struct Statistics {
    pub discontinuity_time: DateTime<Utc>,
    pub master_transitions: u32,
    pub adv_rcvd: u64,
    pub adv_sent: Arc<AtomicU64>,
    pub interval_errors: u64,
    pub priority_zero_pkts_rcvd: u64,
    pub priority_zero_pkts_sent: u64,
    pub invalid_type_pkts_rcvd: u64,
    pub pkt_length_errors: u64,
}

// ===== impl Instance =====

impl Instance {
    pub(crate) fn new(vrid: u8, af: AddressFamily) -> Self {
        Debug::InstanceCreate(vrid).log();
        let mvlan = InstanceMacvlan::new(vrid, af);

        Instance {
            vrid,
            config: InstanceCfg::default(af),
            state: InstanceState::default(),
            mvlan,
            net: None,
        }
    }

    pub(crate) fn update(&mut self, interface: &InterfaceView<'_>) {
        let is_ready =
            interface.system.flags.contains(InterfaceFlags::OPERATIVE)
                && self.mvlan.system.flags.contains(InterfaceFlags::OPERATIVE)
                && interface.system.addresses.iter().any(|addr| {
                    addr.address_family()
                        == self.config.version.address_family()
                });
        if is_ready && self.state.state == fsm::State::Initialize {
            self.startup(interface);
        } else if !is_ready && self.state.state != fsm::State::Initialize {
            self.shutdown(interface);
        }
    }

    fn startup(&mut self, interface: &InterfaceView<'_>) {
        match InstanceNet::new(
            interface,
            &self.mvlan,
            self.config.version.address_family(),
        ) {
            Ok(net) => {
                self.net = Some(net);
                if self.config.priority == 255 {
                    let src_ip =
                        interface.system.addresses.first().unwrap().ip();
                    self.send_vrrp_advertisement(src_ip);
                    self.send_gratuitous_arp();
                    self.change_state(
                        interface,
                        fsm::State::Master,
                        fsm::Event::Startup,
                        MasterReason::Priority,
                    );
                } else {
                    self.change_state(
                        interface,
                        fsm::State::Backup,
                        fsm::Event::Startup,
                        MasterReason::NotMaster,
                    );
                }
            }
            Err(error) => {
                Error::InstanceStartError(self.vrid, error).log();
            }
        }
    }

    pub(crate) fn shutdown(&mut self, interface: &InterfaceView<'_>) {
        if self.state.state == fsm::State::Master {
            // Send an advertisement with Priority = 0.
            match self.config.version.address_family() {
                AddressFamily::Ipv4 => {
                    if let Some(addr) = interface
                        .system
                        .addresses
                        .iter()
                        .find_map(|addr| Ipv4Addr::get(addr.ip()))
                    {
                        let net = self.net.as_ref().unwrap();
                        let mut pkt = self.generate_vrrp_packet();
                        pkt.priority = 0;
                        let packet = Vrrp4Packet {
                            ip: self.generate_ipv4_packet(addr),
                            vrrp: pkt,
                        };
                        let msg = NetTxPacketMsg::Vrrp { packet };
                        let _ = net.net_tx_packetp.send(msg);
                    }
                }
                AddressFamily::Ipv6 => {
                    if let Some(src_ip) = self.link_local_address() {
                        let net = self.net.as_ref().unwrap();
                        let ifindex = interface.system.ifindex.unwrap();
                        let mut packet = self.generate_vrrp_packet();
                        packet.priority = 0;
                        let msg = NetTxPacketMsg::Vrrp6 {
                            packet,
                            src_ip: src_ip.into(),
                            ifindex,
                        };
                        let _ = net.net_tx_packetp.send(msg);
                    }
                }
            }
        }

        // Transition to the Initialize state.
        self.change_state(
            interface,
            fsm::State::Initialize,
            fsm::Event::Shutdown,
            MasterReason::NotMaster,
        );

        // Close network sockets and tasks.
        self.net = None;
    }

    pub(crate) fn change_state(
        &mut self,
        interface: &InterfaceView<'_>,
        state: fsm::State,
        event: fsm::Event,
        new_master_reason: MasterReason,
    ) {
        if self.state.state == state {
            return;
        }

        // Log the state transition.
        if self.config.log_state_change || interface.config.trace_opts.events {
            Debug::InstanceStateChange(
                self.vrid,
                event,
                self.state.state,
                state,
            )
            .log();
        }

        match (self.state.state, state) {
            (fsm::State::Initialize, _) => {
                // Set the up-time to the current time.
                self.state.up_time = Some(Utc::now());
            }
            (_, fsm::State::Initialize) => {
                // Reset state attributes.
                self.state.up_time = None;
                self.state.last_adv_src = None;
            }
            (_, fsm::State::Backup) => {
                // Remove virtual IPs from the macvlan interface.
                for addr in &self.config.virtual_addresses {
                    ibus::tx::ip_addr_del(
                        &interface.tx.ibus,
                        &self.mvlan.name,
                        *addr,
                    );
                }
            }
            (_, fsm::State::Master) => {
                // Add virtual IPs to the macvlan interface.
                for addr in &self.config.virtual_addresses {
                    ibus::tx::ip_addr_add(
                        &interface.tx.ibus,
                        &self.mvlan.name,
                        *addr,
                    );
                }

                // Send YANG notification.
                let addr = interface.system.addresses.first().unwrap().ip();
                notification::new_master_event(
                    &interface.tx.nb,
                    addr,
                    new_master_reason,
                );
            }
        }

        // Update state and initialize the corresponding timer.
        self.state.state = state;
        self.state.last_event = event;
        self.state.new_master_reason = new_master_reason;
        self.timer_set(interface);
    }

    pub(crate) fn timer_set(&mut self, interface: &InterfaceView<'_>) {
        match self.state.state {
            fsm::State::Initialize => {
                self.state.timer = VrrpTimer::Null;
            }
            fsm::State::Backup => {
                let duration = Duration::from_secs(
                    self.config.master_down_interval() as u64,
                );
                let task = tasks::master_down_timer(
                    self,
                    duration,
                    &interface.tx.protocol_input.master_down_timer_tx,
                );
                self.state.timer = VrrpTimer::MasterDownTimer(task);
            }
            fsm::State::Master => match self.config.version.address_family() {
                AddressFamily::Ipv4 => {
                    let src_addr = interface
                        .system
                        .addresses
                        .iter()
                        .find_map(|addr| Ipv4Addr::get(addr.ip()));
                    if let Some(src_addr) = src_addr {
                        let net = self.net.as_ref().unwrap();
                        let task = tasks::advertisement_interval4(
                            self,
                            src_addr,
                            &net.net_tx_packetp,
                        );
                        self.state.timer = VrrpTimer::AdvTimer(task);
                    }
                }
                AddressFamily::Ipv6 => {
                    let net = self.net.as_ref().unwrap();
                    let task = tasks::advertisement_interval6(
                        self,
                        &net.net_tx_packetp,
                    );
                    self.state.timer = VrrpTimer::AdvTimer(task);
                }
            },
        }
    }

    pub(crate) fn timer_reset(&mut self) {
        match &mut self.state.timer {
            VrrpTimer::AdvTimer(t) => {
                t.reset(Some(Duration::from_secs(
                    self.config.advertise_interval as u64,
                )));
            }
            VrrpTimer::MasterDownTimer(t) => {
                t.reset(Some(Duration::from_secs(
                    self.config.master_down_interval() as u64,
                )));
            }
            _ => {}
        }
    }

    // Generates VRRP packet.
    pub(crate) fn generate_vrrp_packet(&self) -> VrrpHdr {
        let ip_addresses: Vec<IpAddr> = self
            .config
            .virtual_addresses
            .iter()
            .filter(|addr| {
                addr.address_family() == self.config.version.address_family()
            })
            .map(|addr| addr.ip())
            .collect();

        VrrpHdr {
            version: self.config.version,
            hdr_type: 1,
            vrid: self.vrid,
            priority: self.config.priority,
            count_ip: ip_addresses.len() as u8,
            adver_int: self.config.advertise_interval,
            checksum: 0,
            ip_addresses,
        }
    }

    // A Neighbor Advertisement packet, usually unsolicitated in VRRP.
    fn neighbor_solicitation_packet(
        &self,
        addr: Ipv6Addr,
    ) -> NeighborAdvertisement {
        NeighborAdvertisement {
            target_address: addr,
        }
    }

    pub(crate) fn generate_ipv4_packet(
        &self,
        src_address: Ipv4Addr,
    ) -> Ipv4Hdr {
        let addr_count = self
            .config
            .virtual_addresses
            .iter()
            .filter(|addr| addr.ip().is_ipv4())
            .count();

        // 36 bytes (20 IP + 16 vrrp)
        // we add 36 to:
        // 4 * (no of virtual IPs) -> since the number of
        //      virtual IPs makes the length of the header variable
        let total_length = (36 + (4 * addr_count)) as u16;

        Ipv4Hdr {
            total_length,
            src_address,
        }
    }

    // RFC 5798-5.1.2 specifies using the link local
    // address as the source address when sending out
    // ipv6 packets. We will use the mvlans link local address
    pub(crate) fn link_local_address(&self) -> Option<Ipv6Addr> {
        self.mvlan
            .system
            .addresses
            .iter()
            .find_map(|addr| match Ipv6Addr::get(addr.ip()) {
                None => None,
                Some(addr) => addr.is_unicast_link_local().then_some(addr),
            })
    }

    pub(crate) fn send_vrrp_advertisement(&mut self, src_ip: IpAddr) {
        match self.config.version {
            Version::V2 => {
                if let IpAddr::V4(addr) = src_ip {
                    let packet = Vrrp4Packet {
                        ip: self.generate_ipv4_packet(addr),
                        vrrp: self.generate_vrrp_packet(),
                    };

                    let msg = NetTxPacketMsg::Vrrp { packet };
                    let net = self.net.as_ref().unwrap();
                    let _ = net.net_tx_packetp.send(msg);
                }
            }
            Version::V3(_addr_fam) => match src_ip {
                IpAddr::V4(addr) => {
                    let packet = Vrrp4Packet {
                        ip: self.generate_ipv4_packet(addr),
                        vrrp: self.generate_vrrp_packet(),
                    };

                    let msg = NetTxPacketMsg::Vrrp { packet };
                    let net = self.net.as_ref().unwrap();
                    let _ = net.net_tx_packetp.send(msg);
                }
                IpAddr::V6(_) => {
                    let packet = self.generate_vrrp_packet();
                    let ifindex = self.mvlan.system.ifindex.unwrap();
                    if let Some(src_ip) = self.link_local_address() {
                        let msg = NetTxPacketMsg::Vrrp6 {
                            packet,
                            src_ip: src_ip.into(),
                            ifindex,
                        };
                        let net = self.net.as_ref().unwrap();
                        let _ = net.net_tx_packetp.send(msg);
                    }
                }
            },
        };
    }

    pub(crate) fn send_gratuitous_arp(&self) {
        // Send a gratuitous for each of the virtual IP addresses.
        let eth_hdr = EthernetHdr {
            ethertype: libc::ETH_P_ARP as _,
            dst_mac: MacAddr::BROADCAST,
            src_mac: self.mvlan.system.mac_address,
        };
        for addr in &self.config.virtual_addresses {
            match addr {
                IpNetwork::V4(addr) => {
                    let arp_hdr = ArpHdr {
                        // Sender HW address is virtual MAC
                        // https://datatracker.ietf.org/doc/html/rfc3768#section-7.3
                        sender_hw_address: self.mvlan.system.mac_address,
                        sender_proto_address: addr.ip(),
                        target_proto_address: addr.ip(),
                    };

                    let msg = NetTxPacketMsg::Arp {
                        vrid: self.vrid,
                        ifindex: self.mvlan.system.ifindex.unwrap(),
                        eth_hdr,
                        arp_hdr,
                    };
                    let net = self.net.as_ref().unwrap();
                    let _ = net.net_tx_packetp.send(msg);
                }
                IpNetwork::V6(addr) => {
                    let nadv_hdr = self.neighbor_solicitation_packet(addr.ip());

                    let msg = NetTxPacketMsg::NAdv {
                        vrid: self.vrid,
                        ifindex: self.mvlan.system.ifindex.unwrap(),
                        nadv_hdr,
                    };
                    let net = self.net.as_ref().unwrap();
                    let _ = net.net_tx_packetp.send(msg);
                }
            }
        }
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        Debug::InstanceDelete(self.vrid).log();
    }
}

// ==== impl InstanceMacvlan ====

impl InstanceMacvlan {
    pub(crate) fn new(vrid: u8, af: AddressFamily) -> Self {
        let ver = match af {
            AddressFamily::Ipv4 => 4,
            AddressFamily::Ipv6 => 6,
        };
        let name = format!("mvlan{ver}-vrrp-{vrid}");
        Self {
            name,
            system: InterfaceSys::default(),
        }
    }
}

// ==== impl InstanceNet ====

impl InstanceNet {
    pub(crate) fn new(
        parent_iface: &InterfaceView<'_>,
        mvlan: &InstanceMacvlan,
        af: AddressFamily,
    ) -> Result<Self, IoError> {
        let instance_channels_tx = &parent_iface.tx;

        // Create raw sockets.
        let socket_vrrp_rx = match af {
            AddressFamily::Ipv4 => network::socket_vrrp_rx4(parent_iface),
            AddressFamily::Ipv6 => network::socket_vrrp_rx6(parent_iface),
        }
        .map_err(IoError::SocketError)
        .and_then(|socket| AsyncFd::new(socket).map_err(IoError::SocketError))
        .map(Arc::new)?;

        let socket_vrrp_tx = match af {
            AddressFamily::Ipv4 => network::socket_vrrp_tx4(mvlan),
            AddressFamily::Ipv6 => network::socket_vrrp_tx6(mvlan),
        }
        .map_err(IoError::SocketError)
        .and_then(|socket| AsyncFd::new(socket).map_err(IoError::SocketError))
        .map(Arc::new)?;

        let socket_arp = match af {
            AddressFamily::Ipv4 => network::socket_arp(&mvlan.name),
            AddressFamily::Ipv6 => network::socket_nadv(mvlan),
        }
        .map_err(IoError::SocketError)
        .and_then(|socket| AsyncFd::new(socket).map_err(IoError::SocketError))
        .map(Arc::new)?;

        // Start network Tx/Rx tasks.
        let (net_tx_packetp, net_tx_packetc) = mpsc::unbounded_channel();
        let net_tx_task = tasks::net_tx(
            socket_vrrp_tx.clone(),
            socket_arp.clone(),
            parent_iface.config.trace_opts.packets.clone(),
            net_tx_packetc,
            #[cfg(feature = "testing")]
            &instance_channels_tx.protocol_output,
        );
        let vrrp_net_rx_task = tasks::vrrp_net_rx(
            socket_vrrp_rx.clone(),
            &instance_channels_tx.protocol_input.vrrp_net_packet_tx,
            af,
        );

        Ok(Self {
            socket_vrrp_tx,
            socket_vrrp_rx,
            socket_arp,
            _net_tx_task: net_tx_task,
            _vrrp_net_rx_task: vrrp_net_rx_task,
            net_tx_packetp,
        })
    }
}

// ===== impl Version =====

impl Version {
    pub fn address_family(&self) -> AddressFamily {
        match self {
            Self::V2 => AddressFamily::Ipv4,
            Self::V3(af) => *af,
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::V2 => 2,
            Self::V3(_) => 3,
        }
    }
}

// ===== impl Statistics =====

impl Default for Statistics {
    fn default() -> Self {
        Statistics {
            discontinuity_time: Utc::now(),
            master_transitions: 0,
            adv_rcvd: 0,
            adv_sent: Arc::new(AtomicU64::new(0)),
            interval_errors: 0,
            priority_zero_pkts_rcvd: 0,
            priority_zero_pkts_sent: 0,
            invalid_type_pkts_rcvd: 0,
            pkt_length_errors: 0,
        }
    }
}
