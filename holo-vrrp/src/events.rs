//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::error::{Error, IoError};
use crate::instance::{Instance, State};
use crate::interface::Interface;
use crate::packet::{ArpPacket, DecodeResult, EthernetFrame, VrrpPacket};
use crate::tasks;
use crate::tasks::messages::output::NetTxPacketMsg;

// To collect actions to be executed later
enum VrrpAction {
    Initialize(Ipv4Addr, VrrpPacket),
    Backup(Ipv4Addr, VrrpPacket),
    Master(Ipv4Addr, VrrpPacket),
}

// ===== Network packet receipt =====
pub(crate) fn process_vrrp_packet(
    interface: &mut Interface,
    src_ip: Ipv4Addr,
    packet: DecodeResult<VrrpPacket>,
) -> Result<(), Error> {
    // Handle packet decoding errors
    let pkt = match packet {
        Ok(pkt) => pkt,
        Err(_e) => {
            return Err(Error::IoError(IoError::RecvError(
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "problem receiving VRRP packet",
                ),
            )))
        }
    };

    // collect the actions that are required
    let action = match get_vrrp_action(interface, src_ip, pkt) {
        Ok(a) => a,
        Err(e) => return Err(e),
    };

    // execute all collected actions
    handle_vrrp_actions(interface, action);
    Ok(())
}

#[allow(unused)]
pub(crate) fn process_arp_packet(
    interface: &mut Interface,
    packet: DecodeResult<ArpPacket>,
) -> Result<(), Error> {
    // Handle packet decoding errors
    let pkt = match packet {
        Ok(pkt) => pkt,
        Err(_e) => {
            return Err(Error::IoError(IoError::RecvError(
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "problem receiving ARP packet",
                ),
            )))
        }
    };

    let mut instance: Option<&mut Instance> = None;

    'outer: for (_vr, inst) in interface.instances.iter_mut() {
        for addr in inst.config.virtual_addresses.clone() {
            let addr_arr = addr.ip().octets();
            if addr_arr == pkt.target_proto_address {
                instance = Some(inst);
                break 'outer;
            }
        }
    }

    let instance = match instance {
        Some(i) => i,
        // the target ip address in the ARP request is for none of the instances
        None => return Ok(()),
    };

    match instance.state.state {
        State::Initialize => {}
        State::Backup => {
            // ========================================================
            // RFC 3768 Section 6.4.2. Backup
            // While in this state, a VRRP router MUST do the following
            // ========================================================

            // MUST NOT respond to ARP requests for the IP address(es) associated with the virutal
            // router
        }
        State::Master => {
            // ========================================================
            // RFC 3768 Section 6.4.3. Master
            // While in the {Maste} state the router functions as the forwarding router for the IP
            // address(es) associated with the virtual router.
            // While in this state, a VRRP router MUST do the following:
            // ========================================================

            // MUST respond to ARP requests for the IP address(es) associated with the virtual
            // router

            if pkt.operation == 1 {
                // if is ARP request
                // build ARP response packet.
                let mut arp_response_pkt = pkt.clone();
                arp_response_pkt.operation = 2; // reply operation
                arp_response_pkt.sender_hw_address = pkt.target_hw_address;
                arp_response_pkt.target_hw_address = pkt.sender_hw_address;
                arp_response_pkt.sender_proto_address =
                    pkt.target_proto_address;
                arp_response_pkt.target_proto_address =
                    pkt.sender_proto_address;

                // build ethernet packet
                let eth_frame = EthernetFrame {
                    ethertype: 0x806,
                    src_mac: interface.system.mac_address,
                    dst_mac: pkt.sender_hw_address,
                };
                let msg = NetTxPacketMsg::Arp {
                    name: interface.name.clone(),
                    eth_frame,
                    arp_packet: arp_response_pkt,
                };
                interface.net.net_tx_packetp.send(msg);
            }
        }
    }

    Ok(())
}

// gets all the actions that are required to be done bacsed on the interface
// configs and incoming packet
fn get_vrrp_action(
    interface: &mut Interface,
    src_ip: Ipv4Addr,
    packet: VrrpPacket,
) -> Result<VrrpAction, Error> {
    // Handle missing instance
    let instance = match interface.instances.get_mut(&packet.vrid) {
        Some(instance) => instance,
        None => {
            return Err(Error::InterfaceError(String::from(
                "unable to fetch VRRP instance from interface",
            )))
        }
    };

    // Update statistics
    instance.state.statistics.adv_rcvd += 1;

    // Handle the current state
    match instance.state.state {
        State::Initialize => Ok(VrrpAction::Initialize(src_ip, packet)),
        State::Backup => Ok(VrrpAction::Backup(src_ip, packet)),
        State::Master => Ok(VrrpAction::Master(src_ip, packet)),
    }
}

fn handle_vrrp_actions(interface: &mut Interface, action: VrrpAction) {
    match action {
        VrrpAction::Initialize(_src, pkt) => {
            let vrid = pkt.vrid;
            if vrid == 255 {
                interface.send_vrrp_advert(vrid);
                interface.send_gratuitous_arp(vrid);
                interface.change_state(vrid, State::Master);
            } else {
                interface.change_state(vrid, State::Backup);
            }
        }
        VrrpAction::Backup(_src, pkt) => {
            let vrid = pkt.vrid;

            if let Some(instance) = interface.instances.get_mut(&vrid) {
                if pkt.priority == 0 {
                    let duration =
                        Duration::from_secs_f32(instance.state.skew_time);
                    tasks::set_master_down_timer(interface, vrid, duration);
                } else {
                    // RFC 3768 Section 6.4.2
                    // If Preempt Mode if False, or if the priority in the ADVERTISEMENT is
                    // greater than or equal to local priority then:
                    if !instance.config.preempt
                        || (pkt.priority > instance.config.priority)
                    {
                        instance.reset_timer();
                    }
                    // drop the packet
                }
            }
        }

        VrrpAction::Master(src, pkt) => {
            let vrid = pkt.vrid;
            let mut send_ad = false;
            if let Some(instance) = interface.instances.get_mut(&vrid) {
                if pkt.priority == 0 {
                    send_ad = true;

                    instance.reset_timer();
                }
                //If the Priority in the ADVERTISEMENT is greater than the
                // local Priority,
                // or
                // If the Priority in the ADVERTISEMENT is equal to the local
                // Priority and the primary IP Address of the sender is greater
                // than the local primary IP Address
                else if pkt.priority > instance.config.priority
                    || ((pkt.priority == instance.config.priority)
                        && src
                            > interface
                                .system
                                .addresses
                                .first()
                                .unwrap()
                                .network())
                {
                    interface.change_state(vrid, State::Backup);
                } else {
                    return;
                }
            }

            if send_ad {
                interface.send_vrrp_advert(vrid);
            }
        }
    }
}

// ====== Handle Master Down Timer =====
// RFC 3768 : Section 6.4.2
// 'If the Master_Down_timer fires'
pub(crate) fn handle_master_down_timer(
    interface: &mut Interface,
    vrid: u8,
) -> Result<(), Error> {
    interface.send_vrrp_advert(vrid);
    interface.send_gratuitous_arp(vrid);
    interface.change_state(vrid, State::Master);

    Ok(())
}
