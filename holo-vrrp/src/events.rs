//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::IpAddr;
use std::time::Duration;

use chrono::Utc;
use holo_utils::ip::{IpAddrKind, IpNetworkKind};

use crate::consts::VALID_VRRP_VERSIONS;
use crate::debug::Debug;
use crate::error::{Error, GlobalError, VirtualRouterError};
use crate::instance::{MasterReason, VrrpTimer, fsm};
use crate::interface::Interface;
use crate::packet::{DecodeError, DecodeResult, VrrpHdr};
use crate::tasks;
use crate::version::Version;

// ===== VRRP network packet receipt =====

pub(crate) fn process_vrrp_packet(
    interface: &mut Interface,
    src: IpAddr,
    packet: DecodeResult<VrrpHdr>,
) -> Result<(), Error> {
    // Check if the packet was decoded successfully.
    let packet = match packet {
        Ok(packet) => packet,
        Err(error) => {
            match error {
                DecodeError::ChecksumError => {
                    interface.statistics.checksum_errors += 1;
                    interface.statistics.discontinuity_time = Utc::now();
                }
                DecodeError::PacketLengthError { vrid, version } => {
                    if let Some((_, instance)) =
                        interface.get_instance(vrid, &version)
                    {
                        instance.state.statistics.pkt_length_errors += 1;
                        instance.state.statistics.discontinuity_time =
                            Utc::now();
                    }
                }
                DecodeError::IpTtlError { .. } => {}
                DecodeError::VersionError { .. } => {}
                DecodeError::IncompletePacket => {}
            }
            return Err(Error::from((src, error)));
        }
    };

    // Log received packet.
    Debug::PacketRx(&src, &packet).log();

    let Some((interface, instance)) =
        interface.get_instance(packet.vrid, &packet.version)
    else {
        interface.statistics.vrid_errors += 1;
        interface.statistics.discontinuity_time = Utc::now();
        return Err(Error::GlobalError(src, GlobalError::VridError));
    };

    // Update last advertised source address.
    instance.state.last_adv_src = Some(src);

    // Sanity checks.
    if !VALID_VRRP_VERSIONS.contains(&packet.version.version()) {
        interface.statistics.version_errors += 1;
        interface.statistics.discontinuity_time = Utc::now();
        let error = GlobalError::VersionError;
        return Err(Error::GlobalError(src, error));
    }
    if packet.adver_int != instance.config.advertise_interval {
        instance.state.statistics.interval_errors += 1;
        instance.state.statistics.discontinuity_time = Utc::now();
        let error = VirtualRouterError::IntervalError;
        return Err(Error::VirtualRouterError(src, error));
    }

    // Update statistics.
    instance.state.statistics.adv_rcvd += 1;
    if packet.priority == 0 {
        instance.state.statistics.priority_zero_pkts_rcvd += 1;
    }
    instance.state.statistics.discontinuity_time = Utc::now();

    // RFC 3768: Section 6.4.2 ("If an ADVERTISEMENT is received")
    match instance.state.state {
        fsm::State::Initialize => {
            unreachable!()
        }
        fsm::State::Backup => {
            if packet.priority == 0 {
                let duration =
                    Duration::from_secs_f32(instance.config.skew_time());
                let task = tasks::master_down_timer(
                    instance,
                    duration,
                    &interface.tx.protocol_input.master_down_timer_tx,
                );
                instance.state.timer = VrrpTimer::MasterDownTimer(task);
            } else if !instance.config.preempt
                || packet.priority >= instance.config.priority
            {
                instance.timer_reset();
            }
        }
        fsm::State::Master => {
            let primary_addr = interface
                .system
                .addresses
                .iter()
                .find(|addr| addr.address_family() == src.address_family())
                .map(|addr| addr.ip())
                .unwrap();
            if packet.priority == 0 {
                instance.send_vrrp_advertisement(primary_addr);
                instance.timer_reset();
            } else if packet.priority > instance.config.priority
                || (packet.priority == instance.config.priority
                    && src > primary_addr)
            {
                instance.change_state(
                    &interface,
                    fsm::State::Backup,
                    fsm::Event::HigherPriorityBackup,
                    MasterReason::NotMaster,
                );
            }
        }
    }

    Ok(())
}

// ====== Master down timer =====

pub(crate) fn handle_master_down_timer(
    interface: &mut Interface,
    vrid: u8,
    version: &Version,
) -> Result<(), Error> {
    // Lookup instance.
    let Some((interface, instance)) =
        interface.get_instance(vrid, version)
    else {
        return Ok(());
    };
    let Some(src_ip) = interface.system.addresses.first().map(|addr| addr.ip())
    else {
        return Ok(());
    };

    // RFC 3768: Section 6.4.2 ("If the Master_Down_timer fires")
    instance.send_vrrp_advertisement(src_ip);
    instance.send_gratuitous_arp();
    instance.change_state(
        &interface,
        fsm::State::Master,
        fsm::Event::MasterTimeout,
        MasterReason::NoResponse,
    );

    Ok(())
}
