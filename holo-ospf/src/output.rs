//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use smallvec::smallvec;

use crate::area::{Area, OptionsLocation};
use crate::collections::{Arena, NeighborIndex};
use crate::instance::InstanceUpView;
use crate::interface::{ism, Interface, InterfaceType};
use crate::lsdb;
use crate::neighbor::{nsm, Neighbor};
use crate::network::{MulticastAddr, SendDestination};
use crate::packet::lsa::LsaHdrVersion;
use crate::packet::{
    DbDescFlags, DbDescVersion, LsAckVersion, LsRequestVersion,
    LsUpdateVersion, PacketHdrVersion, PacketType,
};
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::version::Version;

// ===== Database Description Packets =====

pub(crate) fn send_dbdesc<V>(
    nbr: &mut Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
) where
    V: Version,
{
    // Initialize source and destination address.
    let src = iface.state.src_addr.unwrap();
    let dst = send_dest_nbr(nbr, iface);

    // Calculate maximum packet size.
    let max_size = V::max_packet_size(iface)
        - V::PacketHdr::LENGTH
        - V::PacketDbDesc::BASE_LENGTH;

    // Append as many LSA headers as possible while on the Exchange state.
    let mut total = 0;
    let mut lsa_hdrs = vec![];
    while total + V::LsaHdr::LENGTH <= max_size {
        match nbr.lists.db_summary.pop_first() {
            Some((_, lsa)) => {
                total += V::LsaHdr::LENGTH;

                // Update LSA age.
                let mut lsa_hdr = lsa.hdr;
                lsa_hdr.set_age(lsa.age());
                lsa_hdrs.push(lsa_hdr);
            }
            None => break,
        }
    }

    // Clear the M-bit if there's no more data to send.
    if !nbr.dd_flags.contains(DbDescFlags::I) && nbr.lists.db_summary.is_empty()
    {
        nbr.dd_flags.remove(DbDescFlags::M);
    }

    // Generate Database Description packet.
    let pkt_hdr = V::PacketHdr::generate(
        PacketType::DbDesc,
        instance.state.router_id,
        area.area_id,
        iface.config.instance_id.resolved,
    );
    let packet = V::PacketDbDesc::generate(
        pkt_hdr,
        V::area_options(
            area,
            OptionsLocation::new_packet(
                PacketType::DbDesc,
                iface.state.auth.is_some(),
            ),
        ),
        iface.system.mtu.unwrap(),
        nbr.dd_flags,
        nbr.dd_seq_no,
        lsa_hdrs,
    );

    // Enqueue packet for network transmission.
    let msg = NetTxPacketMsg { packet, src, dst };
    nbr.last_sent_dbdesc = Some(msg.clone());
    iface.send_packet(msg);

    // Start retransmission interval in two cases:
    // * The router is master
    // * When sending the initial database description packet
    if nbr.dd_flags.intersects(DbDescFlags::MS | DbDescFlags::I) {
        nbr.rxmt_dbdesc_start(iface, area, instance);
    }
}

pub(crate) fn rxmt_dbdesc<V>(nbr: &Neighbor<V>, iface: &Interface<V>)
where
    V: Version,
{
    if let Some(msg) = &nbr.last_sent_dbdesc {
        // Enqueue packet for network transmission.
        iface.send_packet(msg.clone());
    }
}

// ===== LS Request Packets =====

pub(crate) fn send_lsreq<V>(
    nbr: &mut Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
) where
    V: Version,
{
    // Initialize source and destination address.
    let src = iface.state.src_addr.unwrap();
    let dst = send_dest_nbr(nbr, iface);

    // Calculate maximum packet size.
    let max_size = V::max_packet_size(iface) - V::PacketHdr::LENGTH;

    // Append as many LS Request Entries as possible in a single packet.
    let mut total = 0;
    while total + V::PacketLsRequest::ENTRY_LENGTH < max_size {
        match nbr.lists.ls_request.pop_first() {
            Some((lsa_key, lsa_hdr)) => {
                nbr.lists.ls_request_pending.insert(lsa_key, lsa_hdr);
                total += V::PacketLsRequest::ENTRY_LENGTH;
            }
            None => break,
        }
    }

    // Generate Link State Request packet.
    let pkt_hdr = V::PacketHdr::generate(
        PacketType::LsRequest,
        instance.state.router_id,
        area.area_id,
        iface.config.instance_id.resolved,
    );
    let entries = nbr.lists.ls_request_pending.keys().copied().collect();
    let packet = V::PacketLsRequest::generate(pkt_hdr, entries);

    // Enqueue packet for network transmission.
    let msg = NetTxPacketMsg { packet, src, dst };
    iface.send_packet(msg);

    // Start retransmission interval.
    nbr.rxmt_lsreq_start(iface, area, instance);
}

pub(crate) fn rxmt_lsreq<V>(
    nbr: &Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
) where
    V: Version,
{
    // Initialize source and destination address.
    let src = iface.state.src_addr.unwrap();
    let dst = send_dest_nbr(nbr, iface);

    // Generate Link State Request packet.
    let pkt_hdr = V::PacketHdr::generate(
        PacketType::LsRequest,
        instance.state.router_id,
        area.area_id,
        iface.config.instance_id.resolved,
    );
    let entries = nbr.lists.ls_request_pending.keys().copied().collect();
    let packet = V::PacketLsRequest::generate(pkt_hdr, entries);

    // Enqueue packet for network transmission.
    let msg = NetTxPacketMsg { packet, src, dst };
    iface.send_packet(msg);
}

// ===== LS Update Packets =====

pub(crate) fn send_lsupd<V>(
    nbr_idx: Option<NeighborIndex>,
    iface: &mut Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    neighbors: &mut Arena<Neighbor<V>>,
) where
    V: Version,
{
    // Initialize source and destination address(es).
    let src = iface.state.src_addr.unwrap();
    let dst = send_dest_iface(iface, neighbors);

    // Calculate maximum packet size.
    let max_size = V::max_packet_size(iface)
        - V::PacketHdr::LENGTH
        - V::PacketLsUpdate::BASE_LENGTH;

    // Get list of LSAs enqueued for transmission.
    let ls_update_list = match nbr_idx {
        Some(nbr_idx) => {
            let nbr = &mut neighbors[nbr_idx];
            &mut nbr.lists.ls_update
        }
        None => &mut iface.state.ls_update_list,
    };
    let mut ls_update_list = std::mem::take(ls_update_list);

    // Send as many LS Updates as necessary.
    while !ls_update_list.is_empty() {
        // Append as many LSAs as possible in a single packet.
        let mut total = 0;
        let mut lsas = vec![];
        while let Some(mut o) = ls_update_list.first_entry() {
            let lsa = o.get_mut();
            // If a single LSA is bigger than the maximum packet size, there's
            // nothing we can do other than relying on IP-level fragmentation.
            if lsa.hdr.length() <= max_size
                && total + lsa.hdr.length() > max_size
            {
                break;
            }
            total += lsa.hdr.length();

            // Update LSA age before transmission.
            let lsa = o.remove();
            let mut lsa = (*lsa).clone();
            let age = std::cmp::min(
                lsa.age() + iface.config.transmit_delay,
                lsdb::LSA_MAX_AGE,
            );
            lsa.set_age(age);
            lsas.push(lsa);
        }

        // Generate Link State Update packet.
        let pkt_hdr = V::PacketHdr::generate(
            PacketType::LsUpdate,
            instance.state.router_id,
            area.area_id,
            iface.config.instance_id.resolved,
        );
        let packet = V::PacketLsUpdate::generate(pkt_hdr, lsas);

        // Enqueue packet for network transmission.
        let msg = NetTxPacketMsg {
            packet,
            src,
            dst: dst.clone(),
        };
        iface.send_packet(msg);
    }
}

pub(crate) fn rxmt_lsupd<V>(
    nbr: &Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
) where
    V: Version,
{
    // Initialize source and destination address.
    let src = iface.state.src_addr.unwrap();
    let dst = send_dest_nbr(nbr, iface);

    // Calculate maximum packet size.
    let max_size = V::max_packet_size(iface)
        - V::PacketHdr::LENGTH
        - V::PacketLsUpdate::BASE_LENGTH;

    // Append as many LSAs as possible in a single packet.
    let mut total = 0;
    let mut lsas = vec![];
    for lsa in nbr.lists.ls_rxmt.values() {
        // If a single LSA is bigger than the maximum packet size, there's
        // nothing we can do other than relying on IP-level fragmentation.
        if lsa.hdr.length() <= max_size && total + lsa.hdr.length() > max_size {
            break;
        }
        total += lsa.hdr.length();

        // Update LSA age before transmission.
        let mut lsa = (**lsa).clone();
        let age = std::cmp::min(
            lsa.age() + iface.config.transmit_delay,
            lsdb::LSA_MAX_AGE,
        );
        lsa.set_age(age);
        lsas.push(lsa);
    }

    // Generate Link State Update packet.
    let pkt_hdr = V::PacketHdr::generate(
        PacketType::LsUpdate,
        instance.state.router_id,
        area.area_id,
        iface.config.instance_id.resolved,
    );
    let packet = V::PacketLsUpdate::generate(pkt_hdr, lsas);

    // Enqueue packet for network transmission.
    let msg = NetTxPacketMsg { packet, src, dst };
    iface.send_packet(msg);
}

// ===== LS Ack Packets =====

pub(crate) fn send_lsack_direct<V>(
    nbr: &Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    lsa_hdr: &V::LsaHdr,
) where
    V: Version,
{
    // Initialize source and destination address.
    let src = iface.state.src_addr.unwrap();
    let dst = send_dest_nbr(nbr, iface);

    // Generate Link State Ack packet.
    let pkt_hdr = V::PacketHdr::generate(
        PacketType::LsAck,
        instance.state.router_id,
        area.area_id,
        iface.config.instance_id.resolved,
    );
    let lsa_hdrs = vec![*lsa_hdr];
    let packet = V::PacketLsAck::generate(pkt_hdr, lsa_hdrs);

    // Enqueue packet for network transmission.
    let msg = NetTxPacketMsg { packet, src, dst };
    iface.send_packet(msg);
}

pub(crate) fn send_lsack_delayed<V>(
    iface: &mut Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    neighbors: &Arena<Neighbor<V>>,
) where
    V: Version,
{
    // Initialize source and destination address(es).
    let src = iface.state.src_addr.unwrap();
    let dst = send_dest_iface(iface, neighbors);

    // Calculate maximum packet size.
    let max_size = V::max_packet_size(iface) - V::PacketHdr::LENGTH;

    // Send as many LS Acks as necessary.
    while !iface.state.ls_ack_list.is_empty() {
        // Append as many LSA headers as possible in a single packet.
        let mut total = 0;
        let mut lsa_hdrs = vec![];
        while total + V::LsaHdr::LENGTH <= max_size {
            match iface.state.ls_ack_list.pop_first() {
                Some((_, lsa_hdr)) => {
                    total += V::LsaHdr::LENGTH;
                    lsa_hdrs.push(lsa_hdr);
                }
                None => break,
            }
        }

        // Generate Link State Ack packet.
        let pkt_hdr = V::PacketHdr::generate(
            PacketType::LsAck,
            instance.state.router_id,
            area.area_id,
            iface.config.instance_id.resolved,
        );
        let packet = V::PacketLsAck::generate(pkt_hdr, lsa_hdrs);

        // Enqueue packet for network transmission.
        let msg = NetTxPacketMsg {
            packet,
            src,
            dst: dst.clone(),
        };
        iface.send_packet(msg);
    }
}

// ===== helper functions =====

// Returns destination used to send a packet directly to the given neighbor.
fn send_dest_nbr<V>(
    nbr: &Neighbor<V>,
    iface: &Interface<V>,
) -> SendDestination<V::NetIpAddr>
where
    V: Version,
{
    let ifindex = iface.system.ifindex.unwrap();
    let addr = if iface.config.if_type == InterfaceType::PointToPoint {
        *V::multicast_addr(MulticastAddr::AllSpfRtrs)
    } else {
        nbr.src
    };
    SendDestination::new(ifindex, smallvec![addr])
}

// Returns a destination used to send a packet to all adjacent neighbors
// associated with the given interface.
fn send_dest_iface<V>(
    iface: &Interface<V>,
    neighbors: &Arena<Neighbor<V>>,
) -> SendDestination<V::NetIpAddr>
where
    V: Version,
{
    let ifindex = iface.system.ifindex.unwrap();
    let addrs = match iface.config.if_type {
        InterfaceType::Broadcast => {
            let addr = if matches!(
                iface.state.ism_state,
                ism::State::Dr | ism::State::Backup
            ) {
                MulticastAddr::AllSpfRtrs
            } else {
                MulticastAddr::AllDrRtrs
            };
            smallvec![*V::multicast_addr(addr)]
        }
        InterfaceType::NonBroadcast | InterfaceType::PointToMultipoint => {
            // On non-broadcast networks, separate LS Update and delayed LS Ack
            // packets must be sent, as unicasts, to each adjacent neighbor.
            iface
                .state
                .neighbors
                .iter(neighbors)
                .filter(|nbr| nbr.state >= nsm::State::Exchange)
                .map(|nbr| nbr.src)
                .collect()
        }
        InterfaceType::PointToPoint => {
            let addr = MulticastAddr::AllSpfRtrs;
            smallvec![*V::multicast_addr(addr)]
        }
    };
    SendDestination::new(ifindex, addrs)
}
