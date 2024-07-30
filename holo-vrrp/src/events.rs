//
// SPDX-License-Identifier: MIT
//

use std::borrow::{Borrow, BorrowMut};
use std::net::IpAddr;

use libc::wait;

use crate::error::Error;
use crate::instance::{Instance, InstanceState, State};
use crate::interface::Interface;
use crate::packet::{DecodeResult, VrrpPacket};
use crate::tasks;

// To collect actions to be executed later
enum Action {
    SendVrrpAdvert(u8),
    SendGratuitousArp(u8),
    ChangeState(u8, State),
    SetMasterDownTimer(u8, u64),
    ResetTimer(u8),
}

// ===== Network packet receipt =====
pub(crate) fn process_packet(
    interface: &mut Interface,
    packet: DecodeResult<VrrpPacket>,
) -> Result<(), Error> {
    // Handle packet decoding errors
    let pkt = packet.unwrap(); 

    // collect the actions that are required
    let mut actions = match get_actions(interface, pkt) {
        Ok(a) => a,
        Err(e) => return Err(e)
    };
    
    // execute all collected actions
    handle_actions(interface, actions);
    Ok(())
}


// gets all the actions that are required to be done bacsed on the interface
// configs and incoming packet
fn get_actions(interface: &mut Interface, packet: VrrpPacket) -> Result<Vec<Action>, Error> {
    let mut actions = Vec::new();

    // Handle missing instance
    let instance = match interface.instances.get_mut(&packet.vrid) {
        Some(inst) => inst,
        None => return Err(
            Error::InterfaceError(String::from("unable to fetch VRRP instance from interface"))
        ),  
    };

    // Update statistics
    instance.state.statistics.adv_rcvd += 1;

    // Handle the current state
    match instance.state.state {
        State::Initialize => {
            if instance.config.priority == 255 {
                actions.push(Action::SendVrrpAdvert(packet.vrid));
                actions.push(Action::SendGratuitousArp(packet.vrid));
                actions.push(Action::ChangeState(packet.vrid, State::Master));
            }
        }
        State::Backup => {
            if packet.priority == 0 {
                actions.push(Action::SetMasterDownTimer(packet.vrid, instance.state.skew_time as u64));
            } else if !instance.config.preempt
            || packet.priority >= instance.config.priority
            {
                actions.push(Action::ResetTimer(packet.vrid));
            }
        }
        State::Master => {
            if packet.priority == 0 {
                actions.push(Action::ResetTimer(packet.vrid));
            } else if packet.priority > instance.config.priority
            || (packet.priority == instance.config.priority
            // && check if primary IP of sender is greater than the local primary IP
        ) {
                actions.push(Action::ChangeState(packet.vrid, State::Backup));
            }
        }
    }
    return Ok(actions)
} 


fn handle_actions(interface: &mut Interface, actions: Vec<Action>) {
    for action in actions {
        match action {
            Action::SendVrrpAdvert(vrid) => interface.send_vrrp_advert(vrid),
            Action::SendGratuitousArp(vrid) => {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap()
                    .block_on(interface.send_gratuitous_arp(vrid));
            },
            Action::ChangeState(vrid, state) => {
                if let Some(instance) = interface.instances.get_mut(&vrid) {
                    instance.change_state(state);
                }
            }
            Action::SetMasterDownTimer(vrid, time) => {
                if let Some(instance) = interface.instances.get_mut(&vrid) {
                    tasks::set_master_down_timer(instance, time);
                }
            }
            Action::ResetTimer(vrid) => {
                if let Some(instance) = interface.instances.get_mut(&vrid) {
                    instance.reset_timer();
                }
            }
        }
    }
}
