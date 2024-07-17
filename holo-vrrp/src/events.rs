//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use crate::error::Error;
use crate::instance::{Instance, State};
use crate::interface::Interface;
use crate::packet::{DecodeResult, VrrpPacket};
use crate::tasks;

// ===== Network packet receipt =====

pub(crate) fn process_packet(
    _interface: &mut Interface,
    _src: IpAddr,
    _packet: DecodeResult<VrrpPacket>,
) -> Result<(), Error> {
    // TODO

    Ok(())
}

pub(crate) fn process_vrrp_packet(
    interface: &mut Interface,
    packet: DecodeResult<VrrpPacket>,
) -> Result<(), Error> {
    let pkt = packet.unwrap();
    let mut instance = interface.instances.get_mut(&pkt.vrid).unwrap();

    // errors will be modified to occupy the other statistics
    instance.state.statistics.adv_rcvd += 1;

    match instance.state.state {
        State::Initialize => {}
        State::Backup => {
            if pkt.priority == 0 {
                tasks::set_master_down_timer(
                    instance,
                    instance.state.skew_time as u64,
                );
            } else if !instance.config.preempt
                || pkt.priority >= instance.config.priority
            {
                instance.reset_timer();
            }
        }
        State::Master => {
            if pkt.priority == 0 {
                instance.reset_timer();
            } else if (pkt.priority > instance.config.priority)
                || (
                    pkt.priority == instance.config.priority
                    // && check if primary IP of sender is greater than the local primary IP
                )
            {
                instance.transition_state(State::Backup);
            }
        }
    }

    Ok(())
}
