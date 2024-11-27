//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use enum_as_inner::EnumAsInner;
use holo_utils::task::{IntervalTask, TimeoutTask};

use crate::consts::{VRRP_MULTICAST_ADDRESS, VRRP_PROTO_NUMBER};
use crate::debug::Debug;
use crate::interface::InterfaceView;
use crate::macvlan::{MacvlanInterface, MacvlanNet};
use crate::northbound::configuration::InstanceCfg;
use crate::packet::{ArpHdr, EthernetHdr, Ipv4Hdr, VrrpHdr, VrrpPacket};
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::{southbound, tasks};

#[derive(Debug)]
pub struct Instance {
    // Virtual Router ID.
    pub vrid: u8,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: InstanceState,
    // Macvlan interface.
    pub mvlan: MacvlanInterface,
}

#[derive(Debug, Default)]
pub struct InstanceState {
    pub state: fsm::State,
    pub last_event: fsm::Event,
    pub new_master_reason: MasterReason,
    pub up_time: Option<DateTime<Utc>>,
    pub timer: VrrpTimer,
    pub last_adv_src: Option<Ipv4Addr>,
    pub statistics: Statistics,
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
    pub(crate) fn new(vrid: u8) -> Self {
        Debug::InstanceCreate(vrid).log();

        Instance {
            vrid,
            config: InstanceCfg::default(),
            state: InstanceState::default(),
            mvlan: MacvlanInterface::new(vrid),
        }
    }

    pub(crate) fn update(&mut self, interface: &InterfaceView) {
        if interface.system.is_ready() && self.mvlan.system.is_ready() {
            if let Ok(net) = MacvlanNet::new(interface, &self.mvlan) {
                self.mvlan.net = Some(net);
                self.timer_set(interface);
            }
        } else {
            self.mvlan.net = None;
        }
    }

    pub(crate) fn change_state(
        &mut self,
        interface: &InterfaceView,
        state: fsm::State,
        new_master_reason: MasterReason,
    ) {
        if self.state.state == state {
            return;
        }

        // Log the state transition.
        Debug::InstanceStateChange(self.vrid, self.state.state, state).log();

        if state == fsm::State::Backup {
            for addr in &self.config.virtual_addresses {
                southbound::tx::ip_addr_del(
                    &interface.tx.ibus,
                    &self.mvlan.name,
                    *addr,
                );
            }
        } else if state == fsm::State::Master {
            for addr in &self.config.virtual_addresses {
                southbound::tx::ip_addr_add(
                    &interface.tx.ibus,
                    &self.mvlan.name,
                    *addr,
                );
            }
        }

        self.state.state = state;
        self.state.new_master_reason = new_master_reason;
        self.timer_set(interface);
    }

    pub(crate) fn timer_set(&mut self, interface: &InterfaceView) {
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
            fsm::State::Master => {
                let Some(net) = &self.mvlan.net else {
                    return;
                };
                let src_ip = interface.system.addresses.first().unwrap().ip();
                let task = tasks::advertisement_interval(
                    self,
                    src_ip,
                    &net.net_tx_packetp,
                );
                self.state.timer = VrrpTimer::AdvTimer(task);
            }
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

    pub(crate) fn generate_vrrp_packet(&self) -> VrrpHdr {
        let mut ip_addresses: Vec<Ipv4Addr> = vec![];
        for addr in self.config.virtual_addresses.clone() {
            ip_addresses.push(addr.ip());
        }

        let mut packet = VrrpHdr {
            version: 2,
            hdr_type: 1,
            vrid: self.vrid,
            priority: self.config.priority,
            count_ip: self.config.virtual_addresses.len() as u8,
            auth_type: 0,
            adver_int: self.config.advertise_interval,
            checksum: 0,
            ip_addresses,
            auth_data: 0,
            auth_data2: 0,
        };
        packet.generate_checksum();
        packet
    }

    pub(crate) fn generate_ipv4_packet(
        &self,
        src_address: Ipv4Addr,
    ) -> Ipv4Hdr {
        // 36 bytes (20 IP + 16 vrrp)
        // we add 36 to:
        // 4 * (no of virtual IPs) -> since the number of
        //      virtual IPs makes the length of the header variable
        let total_length =
            (36 + (4 * self.config.virtual_addresses.len())) as u16;

        Ipv4Hdr {
            version: 4,
            ihl: 5,
            tos: 0xc0,
            total_length,
            identification: 0x0007,
            flags: 0x00,
            offset: 0x00,
            ttl: 255,
            protocol: VRRP_PROTO_NUMBER as u8,
            checksum: 0x00,
            src_address,
            dst_address: VRRP_MULTICAST_ADDRESS,
            options: None,
            padding: None,
        }
    }

    pub(crate) fn send_vrrp_advertisement(&mut self, src_ip: Ipv4Addr) {
        let Some(net) = &self.mvlan.net else {
            return;
        };

        let packet = VrrpPacket {
            ip: self.generate_ipv4_packet(src_ip),
            vrrp: self.generate_vrrp_packet(),
        };
        let msg = NetTxPacketMsg::Vrrp { packet };
        let _ = net.net_tx_packetp.send(msg);
    }

    pub(crate) fn send_gratuitous_arp(&self) {
        let Some(net) = &self.mvlan.net else {
            return;
        };

        // Send a gratuitous for each of the virtual IP addresses.
        let eth_hdr = EthernetHdr {
            ethertype: 0x806,
            dst_mac: [0xff; 6],
            src_mac: self.mvlan.system.mac_address,
        };
        for addr in &self.config.virtual_addresses {
            let arp_hdr = ArpHdr {
                hw_type: 1,
                // IPv4
                proto_type: 0x0800,
                // MAC address length
                hw_length: 6,
                proto_length: 4,
                operation: 1,
                // Sender HW address is virtual mac.
                // https://datatracker.ietf.org/doc/html/rfc3768#section-7.3
                sender_hw_address: self.mvlan.system.mac_address,
                sender_proto_address: addr.ip(),
                target_hw_address: [0xff; 6],
                target_proto_address: addr.ip(),
            };

            let msg = NetTxPacketMsg::Arp {
                ifindex: self.mvlan.system.ifindex.unwrap(),
                eth_hdr,
                arp_hdr,
            };
            let _ = net.net_tx_packetp.send(msg);
        }
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        Debug::InstanceDelete(self.vrid).log();
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
