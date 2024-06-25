//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::error::{Error, IoError};
use crate::instance::State;
use crate::interface::Interface;
use crate::packet::{DecodeResult, VrrpHdr};
use crate::tasks;

// To collect actions to be executed later
enum VrrpAction {
    Initialize(Ipv4Addr, VrrpHdr),
    Backup(Ipv4Addr, VrrpHdr),
    Master(Ipv4Addr, VrrpHdr),
}

// ===== Vrrp Network packet receipt =====
pub(crate) fn process_vrrp_packet(
    interface: &mut Interface,
    src_ip: Ipv4Addr,
    packet: DecodeResult<VrrpHdr>,
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

// gets all the actions that are required to be done bacsed on the interface
// configs and incoming packet
fn get_vrrp_action(
    interface: &mut Interface,
    src_ip: Ipv4Addr,
    packet: VrrpHdr,
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
                interface.change_state(vrid, State::Master);
                if let Some(instance) =
                    interface.instances.get_mut(&vrid).take()
                {
                    instance.send_gratuitous_arp();
                }
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
                    tasks::set_master_down_timer(
                        instance,
                        duration,
                        interface
                            .tx
                            .protocol_input
                            .master_down_timer_tx
                            .clone(),
                    );
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
            if let Some(instance) = interface.instances.get_mut(&vrid).take() {
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
    if let Some(instance) = interface.instances.get_mut(&vrid) {
        instance.send_gratuitous_arp();
    }

    interface.change_state(vrid, State::Master);

    Ok(())
}
