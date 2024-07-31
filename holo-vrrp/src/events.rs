//
// SPDX-License-Identifier: MIT
//

use core::task;
use std::borrow::{Borrow, BorrowMut};
use std::net::IpAddr;
use std::time::Duration;

use crate::error::Error;
use crate::instance::{self, Instance, InstanceState, State};
use crate::interface::Interface;
use crate::packet::{DecodeResult, VrrpPacket};
use crate::tasks;

// To collect actions to be executed later
enum Action {
    // described in 6.4.1 part 1. Is when the instance owns the
    // IP addresses associated with the virtual router
    Initialize(VrrpPacket),
    Backup(VrrpPacket),
    Master(VrrpPacket),
}

// ===== Network packet receipt =====
pub(crate) fn process_vrrp_packet(
    interface: &mut Interface,
    packet: DecodeResult<VrrpPacket>,
) -> Result<(), Error> {
    // Handle packet decoding errors
    let pkt = packet.unwrap();

    // collect the actions that are required
    let mut action = match get_action(interface, pkt) {
        Ok(a) => a,
        Err(e) => return Err(e),
    };

    // execute all collected actions
    handle_actions(interface, action);
    Ok(())
}

// gets all the actions that are required to be done bacsed on the interface
// configs and incoming packet
fn get_action(
    interface: &mut Interface,
    packet: VrrpPacket,
) -> Result<Action, Error> {
    // Handle missing instance
    let instance = match interface.instances.get_mut(&packet.vrid) {
        Some(inst) => inst,
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
        State::Initialize => return Ok(Action::Initialize(packet)),
        State::Backup => return Ok(Action::Backup(packet)),
        State::Master => return Ok(Action::Master(packet)),
    }
}

fn handle_actions(interface: &mut Interface, action: Action) {
    match action {
        Action::Initialize(pkt) => {
            let vrid = pkt.vrid;
            if vrid == 255 {
                interface.send_vrrp_advert(vrid);
                interface.send_gratuitous_arp(vrid);
                interface.change_state(vrid, State::Master);
            } else {
                interface.change_state(vrid, State::Backup);
            }
        }
        Action::Backup(pkt) => {
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
                    if (instance.config.preempt == false)
                        || (pkt.priority > instance.config.priority)
                    {
                        instance.reset_timer();
                    }
                    // drop the packet
                    else {
                        return;
                    }
                }
            }
        }

        Action::Master(pkt) => {
            let vrid = pkt.vrid;
            let mut send_ad = false;
            if let Some(instance) = interface.instances.get_mut(&vrid) {
                if pkt.priority == 0 {
                    send_ad = true;

                    instance.reset_timer();
                } else if (pkt.priority > instance.config.priority)
                // TODO: in RFC 3768 page 18, we have a requirement, where If the priority
                // in the ADVERTISEMENT is equal to the local Priority and the primary IP
                // Address of the sender is greater than the local primary IP Address, then we
                // proceed.
                //
                // We can get our primary IP address, but purely from the VRRP packet we cannot
                // get our senders primary.
                //
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
// This is called when the master down timer fires.
// Basically When the Instance master down timer
// ticks down.
//
// RFC 3768 : Section 6.4.2
// 'If the Master_Down_timer fires'
pub(crate) fn handle_master_down_timer(
    interface: &mut Interface,
    vrid: u8,
) -> Result<(), Error> {
    interface.send_vrrp_advert(vrid);
    interface.send_gratuitous_arp(vrid);

    let instance: &mut Instance = match interface.instances.get_mut(&vrid) {
        Some(i) => i,
        None => {
            return Err(Error::InterfaceError(String::from(
                "unable to get VRRP instance from interface",
            )));
        }
    };
    interface.change_state(vrid, State::Master);

    Ok(())
}
