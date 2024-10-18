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
use holo_utils::task::{IntervalTask, TimeoutTask};

use crate::interface::{MacVlanInterface, VRRP_PROTO_NUMBER};
use crate::northbound::configuration::InstanceCfg;
use crate::packet::{ArpPacket, EthernetHdr, Ipv4Hdr, VrrpHdr};
use crate::tasks::messages::output::NetTxPacketMsg;

#[derive(Debug)]
pub struct Instance {
    // vrid
    pub vrid: u8,

    // Instance configuration data.
    pub config: InstanceCfg,

    // Instance state data.
    pub state: InstanceState,

    // timers
    pub timer: VrrpTimer,

    // mvlan
    pub mac_vlan: MacVlanInterface,
}

#[derive(Debug)]
pub enum VrrpTimer {
    Null,
    AdverTimer(IntervalTask),
    MasterDownTimer(TimeoutTask),
}

#[derive(Debug)]
pub struct InstanceState {
    pub state: State,
    pub last_adv_src: Option<Ipv4Addr>,
    pub up_time: Option<DateTime<Utc>>,
    pub last_event: Event,
    pub new_master_reason: MasterReason,
    pub skew_time: f32,
    pub master_down_interval: u32,
    pub is_owner: bool,

    // TODO: interval/timer tasks
    pub statistics: Statistics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Initialize,
    Backup,
    Master,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MasterReason {
    NotMaster,
    Priority,
    Preempted,
    NoResponse,
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
    pub checksum_errors: u64,
    pub version_errors: u64,
    pub vrid_errors: u64,
    pub ip_ttl_errors: u64,
}

// ===== impl Instance =====

impl Instance {
    pub(crate) fn new(vrid: u8) -> Self {
        let mut inst = Instance {
            vrid,
            config: InstanceCfg::default(),
            state: InstanceState::new(),
            timer: VrrpTimer::Null,
            mac_vlan: MacVlanInterface::new(vrid),
        };
        inst.set_advert_interval(inst.config.advertise_interval);
        inst
    }

    pub(crate) fn reset_timer(&mut self) {
        match self.timer {
            VrrpTimer::AdverTimer(ref mut t) => {
                t.reset(Some(Duration::from_secs(
                    self.config.advertise_interval as u64,
                )));
            }
            VrrpTimer::MasterDownTimer(ref mut t) => {
                t.reset(Some(Duration::from_secs(
                    self.state.master_down_interval as u64,
                )));
            }
            _ => {}
        }
    }

    // advert interval directly affects other state parameters
    // thus separated in its own function during modification of it.
    pub(crate) fn set_advert_interval(&mut self, advertisement_interval: u8) {
        self.config.advertise_interval = advertisement_interval;
        let skew_time: f32 = (256_f32 - self.config.priority as f32) / 256_f32;
        let master_down: u32 =
            (3_u32 * self.config.advertise_interval as u32) + skew_time as u32;
        self.state.skew_time = skew_time;
        self.state.master_down_interval = master_down;
    }

    pub(crate) fn adver_vrrp_pkt(&self) -> VrrpHdr {
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

    pub(crate) fn adver_ipv4_pkt(&self, src_address: Ipv4Addr) -> Ipv4Hdr {
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
            dst_address: Ipv4Addr::new(224, 0, 0, 18),
            options: None,
            padding: None,
        }
    }

    pub(crate) fn send_gratuitous_arp(&self) {
        // send a gratuitous for each of the
        // virutal IP addresses
        for addr in self.config.virtual_addresses.clone() {
            let arp_packet = ArpPacket {
                hw_type: 1,
                // for Ipv4
                proto_type: 0x0800,
                // mac address length
                hw_length: 6,
                proto_length: 4,
                operation: 1,
                // sender hw address is virtual mac.
                // https://datatracker.ietf.org/doc/html/rfc3768#section-7.3
                sender_hw_address: self.mac_vlan.system.mac_address,
                sender_proto_address: addr.ip().octets(),
                target_hw_address: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // broadcast
                target_proto_address: addr.ip().octets(),
            };

            let eth_hdr = EthernetHdr {
                ethertype: 0x806,
                dst_mac: [0xff; 6],
                src_mac: self.mac_vlan.system.mac_address,
            };

            let msg = NetTxPacketMsg::Arp {
                name: self.mac_vlan.name.clone(),
                eth_frame: eth_hdr,
                arp_packet,
            };

            if let Some(net) = &self.mac_vlan.net {
                let _ = net.net_tx_packetp.send(msg);
            }
        }
    }
}

// ===== impl InstanceState =====

impl InstanceState {
    pub(crate) fn new() -> Self {
        InstanceState {
            state: State::Initialize,
            last_adv_src: None,
            up_time: None,
            last_event: Event::None,
            new_master_reason: MasterReason::NotMaster,
            statistics: Default::default(),
            skew_time: 0.0,
            master_down_interval: 0,
            is_owner: false,
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
            checksum_errors: 0,
            version_errors: 0,
            vrid_errors: 0,
            ip_ttl_errors: 0,
        }
    }
}
