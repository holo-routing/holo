//
// SPDX-License-Identifier: MIT
//

use std::borrow::{Borrow, BorrowMut};
use std::net::IpAddr;

use crate::error::Error;
use crate::instance::{Instance, InstanceState, State};
use crate::interface::Interface;
use crate::packet::{DecodeResult, VrrpPacket};
use crate::tasks;

// ===== Network packet receipt =====
//
pub(crate) fn process_packet(
    interface: &mut Interface,
    packet: DecodeResult<VrrpPacket>,
) -> Result<(), Error> {
    // Handle packet decoding errors
    let pkt = match packet {
        Ok(p) => p,
        Err(e) => return Ok(()), // or handle the error appropriately
    };

    // To collect actions to be executed later
    enum Action {
        SendVrrpAdvert(u8),
        SendGratuitousArp(u8),
        ChangeState(u8, State),
        SetMasterDownTimer(u8, u64),
        ResetTimer(u8),
    }

    let mut actions = Vec::new();

    {
        // Handle missing instance
        let instance = match interface.instances.get_mut(&pkt.vrid) {
            Some(inst) => inst,
            None => return Ok(()), // or handle the error appropriately
        };

        // Update statistics
        instance.state.statistics.adv_rcvd += 1;

        // Handle the current state
        match instance.state.state {
            State::Initialize => {
                if instance.config.priority == 255 {
                    actions.push(Action::SendVrrpAdvert(pkt.vrid));
                    actions.push(Action::SendGratuitousArp(pkt.vrid));
                    actions.push(Action::ChangeState(pkt.vrid, State::Master));
                }
            }
            State::Backup => {
                if pkt.priority == 0 {
                    actions.push(Action::SetMasterDownTimer(pkt.vrid, instance.state.skew_time as u64));
                } else if !instance.config.preempt
                    || pkt.priority >= instance.config.priority
                {
                    actions.push(Action::ResetTimer(pkt.vrid));
                }
            }
            State::Master => {
                if pkt.priority == 0 {
                    actions.push(Action::ResetTimer(pkt.vrid));
                } else if pkt.priority > instance.config.priority
                    || (pkt.priority == instance.config.priority
                        // && check if primary IP of sender is greater than the local primary IP
                        ) {
                    actions.push(Action::ChangeState(pkt.vrid, State::Backup));
                }
            }
        }
    }

    // Execute collected actions
    for action in actions {
        match action {
            Action::SendVrrpAdvert(vrid) => interface.send_vrrp_advert(vrid),
            Action::SendGratuitousArp(vrid) => {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap()
                    .block_on(interface.send_gratuitous_arp(vrid));
                //interface.send_gratuitous_arp(vrid).await
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

    Ok(())
}
