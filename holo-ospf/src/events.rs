//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::cmp::Ordering;
use std::collections::btree_map;
use std::net::Ipv4Addr;
use std::sync::Arc;

use chrono::Utc;
use holo_utils::bfd;
use holo_utils::ibus::{BierCfgEvent, SrCfgEvent};

use crate::area::{Area, AreaType};
use crate::collections::{
    lsdb_get, lsdb_get_mut, lsdb_index, lsdb_index_mut, AreaIndex, AreaKey,
    Arena, InterfaceIndex, InterfaceKey, LsaEntryKey, LsdbIndex, LsdbKey,
    NeighborIndex, NeighborKey,
};
use crate::debug::{Debug, LsaFlushReason, SeqNoMismatchReason};
use crate::error::{Error, InterfaceCfgError};
use crate::flood::flood;
use crate::gr::GrExitReason;
use crate::instance::{Instance, InstanceArenas, InstanceUpView};
use crate::interface::{ism, Interface};
use crate::lsdb::{
    self, lsa_compare, LsaEntry, LsaEntryFlags, LsaOriginateEvent,
};
use crate::neighbor::{nsm, LastDbDesc, Neighbor, RxmtPacketType};
use crate::northbound::notification;
use crate::packet::error::DecodeResult;
use crate::packet::lsa::{
    Lsa, LsaBodyVersion, LsaHdrVersion, LsaKey, LsaScope, LsaTypeVersion,
};
use crate::packet::{
    DbDescFlags, DbDescVersion, HelloVersion, LsAckVersion, LsRequestVersion,
    LsUpdateVersion, OptionsVersion, Packet, PacketBase, PacketHdrVersion,
    PacketType,
};
use crate::version::Version;
use crate::{gr, output, spf, tasks};

// ===== Interface FSM event =====

pub(crate) fn process_ism_event<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    event: ism::Event,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area and interface.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;

    // Invoke FSM event.
    iface.fsm(
        area,
        instance,
        &mut arenas.neighbors,
        &arenas.lsa_entries,
        event,
    );

    Ok(())
}

// ===== Neighbor FSM event =====

pub(crate) fn process_nsm_event<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: NeighborKey,
    event: nsm::Event,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let (nbr_idx, nbr) = iface
        .state
        .neighbors
        .get_mut_by_key(&mut arenas.neighbors, &nbr_key)?;

    // Invoke FSM event.
    nbr.fsm(iface, area, instance, &arenas.lsa_entries, event);
    if nbr.state == nsm::State::Down {
        // Effectively delete the neighbor.
        iface.state.neighbors.delete(&mut arenas.neighbors, nbr_idx);

        // Synchronize interface's Hello Tx task (updated list of neighbors).
        iface.sync_hello_tx(area, instance);
    }

    Ok(())
}

// ===== Network packet receipt =====

pub(crate) fn process_packet<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    src: V::NetIpAddr,
    dst: V::NetIpAddr,
    packet: DecodeResult<Packet<V>>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area and interface.
    let (area_idx, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;

    // Check if the packet was decoded successfully.
    let packet = match packet {
        Ok(packet) => packet,
        Err(error) => {
            notification::if_rx_bad_packet(instance, iface, src);
            return Err(Error::PacketDecodeError(error));
        }
    };

    // Ignore packets received on inoperational or passive interfaces.
    if iface.is_down() || iface.is_passive() {
        return Ok(());
    }

    // Validate IP destination address.
    V::validate_packet_dst(iface, dst)?;

    // Validate IP source address.
    V::validate_packet_src(iface, src)?;

    // Check for Area ID mismatch.
    let pkt_type = packet.hdr().pkt_type();
    if packet.hdr().area_id() != area.area_id {
        return Err(Error::InterfaceCfgError(
            iface.name.clone(),
            src,
            pkt_type,
            InterfaceCfgError::AreaIdMismatch(
                packet.hdr().area_id(),
                area.area_id,
            ),
        ));
    }

    // OSPFv3: check for Instance ID mismatch.
    if !V::packet_instance_id_match(iface, packet.hdr()) {
        // Instance ID mismatches are expected in normal operation and do not
        // constitute an error.
        return Ok(());
    }

    // Perform authentication sequence number validation.
    let router_id = packet.hdr().router_id();
    if let Some(auth_seqno) = packet.hdr().auth_seqno()
        && let Some((_, nbr)) =
            V::get_neighbor(iface, &src, router_id, &mut arenas.neighbors)
    {
        // Discard the packet if its sequence number is lower than the recorded
        // sequence number in the sender's neighbor data structure.
        //
        // Sequence number checking is dependent on OSPF packet type in order to
        // account for packet prioritization as specified in RFC 4222.
        let nbr_auth_seqno = nbr.auth_seqno.entry(pkt_type).or_default();
        match auth_seqno.cmp(nbr_auth_seqno) {
            Ordering::Less => {
                return Err(Error::PacketAuthInvalidSeqno(src, auth_seqno));
            }
            Ordering::Equal if V::STRICT_AUTH_SEQNO_CHECK => {
                return Err(Error::PacketAuthInvalidSeqno(src, auth_seqno));
            }
            _ => {
                // Packet sequence number is valid.
            }
        }

        // Update neighbor's last received sequence number.
        *nbr_auth_seqno = auth_seqno;
    }

    // Log received packet.
    Debug::<V>::PacketRx(iface, &src, &dst, &packet).log();

    if let Packet::Hello(pkt) = packet {
        process_packet_hello(
            iface,
            area,
            instance,
            &mut arenas.neighbors,
            &arenas.lsa_entries,
            src,
            pkt,
        )
    } else {
        // Non-Hello packets not matching any active neighbor are discarded.
        let (nbr_idx, nbr) =
            V::get_neighbor(iface, &src, router_id, &mut arenas.neighbors)
                .ok_or(Error::UnknownNeighbor(src, router_id))?;

        match packet {
            Packet::Hello(_) => unreachable!(),
            Packet::DbDesc(pkt) => process_packet_dbdesc(
                nbr,
                iface,
                area,
                instance,
                &arenas.lsa_entries,
                src,
                pkt,
            ),
            Packet::LsRequest(pkt) => process_packet_lsreq(
                nbr,
                iface,
                area,
                instance,
                &arenas.lsa_entries,
                pkt,
            ),
            Packet::LsUpdate(pkt) => process_packet_lsupd(
                nbr_idx, iface_idx, area_idx, instance, arenas, src, pkt,
            ),
            Packet::LsAck(pkt) => process_packet_lsack(nbr, pkt),
        }
    }
}

fn process_packet_hello<V>(
    iface: &mut Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsa_entries: &Arena<LsaEntry<V>>,
    src: V::NetIpAddr,
    hello: V::PacketHello,
) -> Result<(), Error<V>>
where
    V: Version,
{
    let protocol_input = &instance.tx.protocol_input;

    // Perform all the required sanity checks.
    process_packet_hello_sanity_checks(iface, area, instance, &hello).map_err(
        |error| {
            Error::InterfaceCfgError(
                iface.name.clone(),
                src,
                PacketType::Hello,
                error,
            )
        },
    )?;

    // Find or create new neighbor.
    let (_, nbr) =
        match V::get_neighbor(iface, &src, hello.router_id(), neighbors) {
            Some(value) => value,
            None => {
                // Create new neighbor.
                let (nbr_idx, nbr) = iface.state.neighbors.insert(
                    neighbors,
                    hello.router_id(),
                    src,
                );

                // Initialize neighbor values.
                nbr.iface_id = hello.iface_id();
                nbr.priority = hello.priority();
                if iface.is_broadcast_or_nbma() {
                    nbr.dr = hello.dr();
                    nbr.bdr = hello.bdr();
                }

                // Synchronize interface's Hello Tx task (updated list of
                // neighbors).
                iface.sync_hello_tx(area, instance);

                (nbr_idx, nbr)
            }
        };

    // Update neighbor's source address.
    //
    // For OSPFv2, this can only happen for point-to-point interfaces (for the
    // other interface types, an address change would prompt the creation of
    // a different neighbor entity).
    //
    // Once an address change occurs, the corresponding neighbor should
    // reoriginate its Router-LSA, so there's no need to reschedule SPF
    // manually in order to update the routing table.
    nbr.src = src;

    // Trigger the HelloReceived event.
    nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::HelloRcvd);

    // Trigger the 1-WayReceived or the 2-WayReceived event.
    if hello
        .neighbors()
        .iter()
        .any(|id| *id == instance.state.router_id)
    {
        nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::TwoWayRcvd);
    } else {
        nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::OneWayRcvd);

        // Update neighbor values.
        nbr.iface_id = hello.iface_id();
        if iface.is_broadcast_or_nbma() {
            nbr.priority = hello.priority();
            nbr.dr = hello.dr();
            nbr.bdr = hello.bdr();
        }

        return Ok(());
    }

    // Check for Interface ID change.
    if hello.iface_id() != nbr.iface_id {
        nbr.iface_id = hello.iface_id();

        // (Re)originate LSAs that might have been affected.
        instance.tx.protocol_input.lsa_orig_event(
            LsaOriginateEvent::NeighborInterfaceIdChange {
                area_id: area.id,
                iface_id: iface.id,
            },
        );
    }

    // Examine rest of the Hello Packet (ignore Point-to-MultiPoint interfaces
    // as per errata 4022 of RFC 2328).
    if iface.is_broadcast_or_nbma() {
        // Check for Router Priority change.
        if hello.priority() != nbr.priority {
            nbr.priority = hello.priority();
            protocol_input.ism_event(area.id, iface.id, ism::Event::NbrChange);
        }

        // Check for DR/BDR changes.
        let nbr_net_id = nbr.network_id();
        if iface.state.ism_state == ism::State::Waiting
            && ((hello.dr() == Some(nbr_net_id) && hello.bdr().is_none())
                || hello.bdr() == Some(nbr_net_id))
        {
            protocol_input.ism_event(area.id, iface.id, ism::Event::BackupSeen);
        }
        if (hello.dr() == Some(nbr_net_id) && nbr.dr != Some(nbr_net_id))
            || (hello.dr() != Some(nbr_net_id) && nbr.dr == Some(nbr_net_id))
            || (hello.bdr() == Some(nbr_net_id) && nbr.bdr != Some(nbr_net_id))
            || (hello.bdr() != Some(nbr_net_id) && nbr.bdr == Some(nbr_net_id))
        {
            protocol_input.ism_event(area.id, iface.id, ism::Event::NbrChange);
        }

        // Update neighbor's DR/BDR.
        nbr.dr = hello.dr();
        nbr.bdr = hello.bdr();
    }

    Ok(())
}

fn process_packet_hello_sanity_checks<V>(
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    hello: &V::PacketHello,
) -> Result<(), InterfaceCfgError>
where
    V: Version,
{
    // OSPF version-specific hello validation.
    V::validate_hello(iface, hello)?;

    // Check for HelloInterval mismatch.
    if hello.hello_interval() != iface.config.hello_interval {
        return Err(InterfaceCfgError::HelloIntervalMismatch(
            hello.hello_interval(),
            iface.config.hello_interval,
        ));
    }

    // Check for RouterDeadInterval mismatch.
    if hello.dead_interval() != iface.config.dead_interval as u32 {
        return Err(InterfaceCfgError::DeadIntervalMismatch(
            hello.dead_interval(),
            iface.config.dead_interval as u32,
        ));
    }

    // Check for ExternalRoutingCapability mismatch.
    if hello.options().e_bit() && area.config.area_type != AreaType::Normal
        || !hello.options().e_bit() && area.config.area_type == AreaType::Normal
    {
        return Err(InterfaceCfgError::ExternalRoutingCapabilityMismatch(
            hello.options().e_bit(),
        ));
    }

    // Check for duplicate Router ID.
    if hello.router_id() == instance.state.router_id {
        return Err(InterfaceCfgError::DuplicateRouterId(hello.router_id()));
    }

    Ok(())
}

fn process_packet_dbdesc<V>(
    nbr: &mut Neighbor<V>,
    iface: &mut Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    lsa_entries: &Arena<LsaEntry<V>>,
    src: V::NetIpAddr,
    dbdesc: V::PacketDbDesc,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // MTU mismatch check.
    if !iface.config.mtu_ignore && dbdesc.mtu() > iface.system.mtu.unwrap() {
        return Err(Error::InterfaceCfgError(
            iface.name.clone(),
            src,
            PacketType::DbDesc,
            InterfaceCfgError::MtuMismatch(dbdesc.mtu()),
        ));
    }

    // Further processing depends on the neighbor's state.
    match nbr.state {
        nsm::State::Down | nsm::State::Attempt | nsm::State::TwoWay => {
            return Err(Error::DbDescReject(nbr.router_id, nbr.state));
        }
        nsm::State::Init | nsm::State::ExStart => {
            if nbr.state == nsm::State::Init {
                let event = nsm::Event::TwoWayRcvd;
                nbr.fsm(iface, area, instance, lsa_entries, event);
                if nbr.state != nsm::State::ExStart {
                    return Ok(());
                }
                // Fall through to the ExStart case.
            }

            if dbdesc
                .dd_flags()
                .contains(DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS)
                && dbdesc.lsa_hdrs().is_empty()
                && dbdesc.router_id() > instance.state.router_id
            {
                // Set the master/slave bit to slave, and set the neighbor data
                // structure's DD sequence number to that specified by the
                // master.
                nbr.dd_flags.remove(DbDescFlags::MS);
                nbr.dd_seq_no = dbdesc.dd_seq_no();
            } else if !dbdesc
                .dd_flags()
                .contains(DbDescFlags::I | DbDescFlags::MS)
                && dbdesc.dd_seq_no() == nbr.dd_seq_no
                && dbdesc.router_id() < instance.state.router_id
            {
                // In this case the router is Master.
            } else {
                // Ignore the packet.
                return Ok(());
            }

            nbr.options = Some(dbdesc.options());
            let event = nsm::Event::NegotiationDone;
            nbr.fsm(iface, area, instance, lsa_entries, event);
        }
        nsm::State::Exchange => {
            // Check for duplicate packet.
            if nbr.dbdesc_is_dup(&dbdesc) {
                // The slave needs to retransmit the last Database Description
                // packet that it had sent.
                if !nbr.dd_flags.contains(DbDescFlags::MS) {
                    output::rxmt_dbdesc(nbr, iface);
                }

                return Ok(());
            }

            // Sanity checks.
            let last_rcvd_dbdesc = nbr.last_rcvd_dbdesc.as_ref().unwrap();
            if dbdesc.dd_flags().contains(DbDescFlags::I)
                || dbdesc.dd_flags().contains(DbDescFlags::MS)
                    != last_rcvd_dbdesc.dd_flags.contains(DbDescFlags::MS)
            {
                let reason = SeqNoMismatchReason::InconsistentFlags;
                let event = nsm::Event::SeqNoMismatch(reason);
                nbr.fsm(iface, area, instance, lsa_entries, event);
                return Ok(());
            }
            if dbdesc.options() != last_rcvd_dbdesc.options {
                let reason = SeqNoMismatchReason::InconsistentOptions;
                let event = nsm::Event::SeqNoMismatch(reason);
                nbr.fsm(iface, area, instance, lsa_entries, event);
                return Ok(());
            }
            if (nbr.dd_flags.contains(DbDescFlags::MS)
                && dbdesc.dd_seq_no() != nbr.dd_seq_no)
                || (!nbr.dd_flags.contains(DbDescFlags::MS)
                    && dbdesc.dd_seq_no() != nbr.dd_seq_no + 1)
            {
                let reason = SeqNoMismatchReason::InconsistentSeqNo;
                let event = nsm::Event::SeqNoMismatch(reason);
                nbr.fsm(iface, area, instance, lsa_entries, event);
                return Ok(());
            }
        }
        nsm::State::Loading | nsm::State::Full => {
            // Check for duplicate packet.
            if nbr.dbdesc_is_dup(&dbdesc) {
                // The slave must respond to duplicates by repeating the last
                // Database Description packet that it had sent.
                if !nbr.dd_flags.contains(DbDescFlags::MS) {
                    output::rxmt_dbdesc(nbr, iface);
                }

                return Ok(());
            }

            let reason = SeqNoMismatchReason::UnexpectedDbDesc;
            let event = nsm::Event::SeqNoMismatch(reason);
            nbr.fsm(iface, area, instance, lsa_entries, event);
            return Ok(());
        }
    }

    // If we got this far it means the packet was accepted. Stop the
    // retransmission interval in case it's active.
    nbr.rxmt_dbdesc_stop();

    // Now iterate over all LSA headers.
    for lsa_hdr in dbdesc.lsa_hdrs() {
        // Check if the LSA is valid for this area and neighbor.
        if !V::lsa_type_is_valid(
            Some(area.config.area_type),
            nbr.options,
            lsa_hdr.lsa_type(),
        ) {
            let reason = SeqNoMismatchReason::InvalidLsaType;
            let event = nsm::Event::SeqNoMismatch(reason);
            nbr.fsm(iface, area, instance, lsa_entries, event);
            return Ok(());
        }

        // RFC 5243 says:
        // "If the Database summary list contains an instance of the LSA that is
        // the same as or less recent than the listed LSA, the LSA is removed
        // from the Database summary list".
        let lsa_key = lsa_hdr.key();
        if let btree_map::Entry::Occupied(o) =
            nbr.lists.db_summary.entry(lsa_key)
        {
            let db_summ_lsa = o.get();
            if lsa_compare::<V>(&db_summ_lsa.hdr, lsa_hdr) != Ordering::Greater
            {
                o.remove();
            }
        }

        // Put the LSA on the Link state request list if it's not present on the
        // LSDB, or if the local copy is less recent than the received one.
        let lsdb = match lsa_hdr.lsa_type().scope() {
            LsaScope::Link => &iface.state.lsdb,
            LsaScope::Area => &area.state.lsdb,
            LsaScope::As => &instance.state.lsdb,
            LsaScope::Unknown => unreachable!(),
        };
        if let Some((_, lse)) = lsdb.get(lsa_entries, &lsa_key) {
            if lsa_compare::<V>(&lse.data.hdr, lsa_hdr) != Ordering::Less {
                continue;
            }
        }
        nbr.lists.ls_request.insert(lsa_key, *lsa_hdr);
    }

    // Start sending Link State Request packets.
    if !nbr.lists.ls_request.is_empty()
        && nbr.lists.ls_request_pending.is_empty()
    {
        output::send_lsreq(nbr, iface, area, instance);
    }

    // Further processing depends on whether the router is master or slave.
    let mut exchange_done = false;
    if nbr.dd_flags.contains(DbDescFlags::MS) {
        nbr.dd_seq_no += 1;

        if !nbr.dd_flags.contains(DbDescFlags::M)
            && !dbdesc.dd_flags().contains(DbDescFlags::M)
        {
            exchange_done = true;
        } else {
            output::send_dbdesc(nbr, iface, area, instance);
        }
    } else {
        nbr.dd_seq_no = dbdesc.dd_seq_no();

        output::send_dbdesc(nbr, iface, area, instance);

        if !nbr.dd_flags.contains(DbDescFlags::M)
            && !dbdesc.dd_flags().contains(DbDescFlags::M)
        {
            exchange_done = true;
        }
    }
    if exchange_done {
        nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::ExchangeDone);

        // The slave must wait RouterDeadInterval seconds before freeing the
        // last Database Description packet. Reception of a Database Description
        // packet from the master after this interval will generate a
        // SeqNumberMismatch neighbor event.
        if !nbr.dd_flags.contains(DbDescFlags::MS) {
            let dbdesc_free_timer =
                tasks::dbdesc_free_timer(nbr, iface, area, instance);
            nbr.tasks.dbdesc_free_timer = Some(dbdesc_free_timer);
        }
    }

    // Save last received Database Description packet.
    nbr.last_rcvd_dbdesc = Some(LastDbDesc {
        options: dbdesc.options(),
        dd_flags: dbdesc.dd_flags(),
        dd_seq_no: dbdesc.dd_seq_no(),
    });

    Ok(())
}

fn process_packet_lsreq<V>(
    nbr: &mut Neighbor<V>,
    iface: &mut Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    lsa_entries: &Arena<LsaEntry<V>>,
    ls_req: V::PacketLsRequest,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if nbr.state < nsm::State::Exchange {
        Debug::<V>::PacketRxIgnore(nbr.router_id, &nbr.state).log();
        return Ok(());
    }

    // Iterate over all request entries.
    for lsa_key in ls_req.entries() {
        // Locate LSA in the LSDB.
        let lsdb = match lsa_key.lsa_type.scope() {
            LsaScope::Link => &iface.state.lsdb,
            LsaScope::Area => &area.state.lsdb,
            LsaScope::As => &instance.state.lsdb,
            LsaScope::Unknown => {
                // OSPFv3: ignore requests for LSAs of unknown scope.
                continue;
            }
        };

        if let Some((_, lse)) = lsdb.get(lsa_entries, lsa_key) {
            // Copy LSA for transmission to the neighbor.
            let lsa = lse.data.clone();
            nbr.lists.ls_update.insert(*lsa_key, lsa);
        } else {
            // Something has gone wrong with the Database Exchange process.
            nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::BadLsReq);
            return Ok(());
        }
    }

    // Schedule transmission of new LS Update.
    if !nbr.lists.ls_update.is_empty() {
        instance
            .tx
            .protocol_input
            .send_lsupd(area.id, iface.id, Some(nbr.id));
    }

    Ok(())
}

fn process_packet_lsupd<V>(
    nbr_idx: NeighborIndex,
    iface_idx: InterfaceIndex,
    area_idx: AreaIndex,
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    src: V::NetIpAddr,
    ls_upd: V::PacketLsUpdate,
) -> Result<(), Error<V>>
where
    V: Version,
{
    let nbr = &arenas.neighbors[nbr_idx];
    if nbr.state < nsm::State::Exchange {
        Debug::<V>::PacketRxIgnore(nbr.router_id, &nbr.state).log();
        return Ok(());
    }

    // Process all LSAs contained in the packet.
    for lsa in ls_upd.into_lsas() {
        let stop = process_packet_lsupd_lsa(
            nbr_idx, iface_idx, area_idx, instance, arenas, src, lsa,
        );
        if stop {
            break;
        }
    }

    Ok(())
}

fn process_packet_lsupd_lsa<V>(
    nbr_idx: NeighborIndex,
    iface_idx: InterfaceIndex,
    area_idx: AreaIndex,
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    src: V::NetIpAddr,
    #[allow(unused_mut)] mut lsa: Lsa<V>,
) -> bool
where
    V: Version,
{
    let nbr = &arenas.neighbors[nbr_idx];
    let iface = &mut arenas.interfaces[iface_idx];
    let area = &arenas.areas[area_idx];

    // Generate raw data that might be missing for LSAs received in testing
    // mode.
    #[cfg(feature = "testing")]
    if lsa.raw.is_empty() {
        lsa.encode();
    }

    // (1) Validate the LSA (not only the checksum as specified by the RFC).
    if let Err(error) = lsa.validate() {
        // Send error notification.
        notification::if_rx_bad_lsa(instance, src, error);

        // Log why the LSA is being discarded.
        Debug::<V>::LsaDiscard(nbr.router_id, &lsa.hdr, &error).log();

        // Examine the next LSA.
        return false;
    }

    // (2-3) Check if the LSA type is valid for this area and neighbor.
    if !V::lsa_type_is_valid(
        Some(area.config.area_type),
        nbr.options,
        lsa.hdr.lsa_type(),
    ) {
        // Examine the next LSA.
        return false;
    }

    // (5) Find the instance of this LSA that is currently contained in the
    // router's link state database.
    let lsdb_idx =
        V::lsdb_get_by_lsa_type(iface_idx, area_idx, lsa.hdr.lsa_type());
    let lsdb = match lsdb_idx {
        LsdbIndex::Link(_, _) => &iface.state.lsdb,
        LsdbIndex::Area(_) => &area.state.lsdb,
        LsdbIndex::As => &instance.state.lsdb,
    };
    let lsa_key = lsa.hdr.key();
    let lse = lsdb.get(&arenas.lsa_entries, &lsa_key).map(|(_, lse)| lse);

    // (4) If the LSA's LS age is equal to MaxAge, and there is currently no
    // instance of the LSA in the router's link state database, and none of
    // router's neighbors are in states Exchange or Loading.
    if lsa.hdr.is_maxage()
        && lse.is_none()
        && !arenas.neighbors.iter().any(|(_, nbr)| {
            matches!(nbr.state, nsm::State::Exchange | nsm::State::Loading)
        })
    {
        // Acknowledge the receipt of the LSA.
        output::send_lsack_direct(nbr, iface, area, instance, &lsa.hdr);

        // Examine the next LSA.
        return false;
    }

    // (5 cont.) There is no database copy, or the received LSA is more
    // recent than the database copy.
    let lsa_cmp = lse.map(|lse| lsa_compare::<V>(&lse.data.hdr, &lsa.hdr));
    if matches!(lsa_cmp, None | Some(Ordering::Less)) {
        // (5.a) MinLSArrival check.
        if let Some(lse) = lse {
            if lsdb::lsa_min_arrival_check(lse) {
                // Log why the LSA is being discarded.
                Debug::<V>::LsaMinArrivalDiscard(nbr.router_id, &lsa.hdr).log();

                // Examine the next LSA.
                return false;
            }
        }

        // Move LSA into a reference-counting pointer.
        let lsa = Arc::new(lsa);

        // (5.b) Immediately flood the new LSA out some subset of the
        // router's interfaces.
        let src = Some((iface_idx, nbr_idx));
        let flooded_back = flood(
            instance,
            &arenas.areas,
            &mut arenas.interfaces,
            &mut arenas.neighbors,
            lsdb_idx,
            &lsa,
            src,
        );

        // (5.c) This step can be skipped since the LSA installation process
        // already takes care of removing the old copy from all Link state
        // retransmission lists.

        // (5.d) Install the new LSA in the link state database (replacing
        // the current database copy).
        let lse_idx = lsdb::install(instance, arenas, lsdb_idx, lsa);
        let lse = &mut arenas.lsa_entries[lse_idx];
        lse.flags.insert(LsaEntryFlags::RECEIVED);

        // Update statistics.
        instance.state.rx_lsa_count += 1;
        instance.state.discontinuity_time = Utc::now();

        // (5.e) Possibly acknowledge the receipt of the LSA by sending a
        // Link State Acknowledgment packet.
        let nbr = &mut arenas.neighbors[nbr_idx];
        let iface = &mut arenas.interfaces[iface_idx];
        let area = &arenas.areas[area_idx];
        let nbr_net_id = nbr.network_id();
        let nbr_router_id = nbr.router_id;
        if !flooded_back
            && (iface.state.ism_state != ism::State::Backup
                || iface.state.dr == Some(nbr_net_id))
        {
            // Enqueue delayed ack.
            iface.enqueue_delayed_ack(area, instance, &lse.data.hdr);
        }

        // Grace-LSA processing.
        if let Some((grace_period, reason, addr)) = lse.data.body.as_grace() {
            // For OSPFv2, on broadcast, NBMA and P2MP segments, the restarting
            // neighbor is identified by the IP interface address in the body of
            // the Grace-LSA.
            let nbr = match addr {
                Some(addr) => V::get_neighbor(
                    iface,
                    &addr,
                    nbr_router_id,
                    &mut arenas.neighbors,
                )
                .map(|(_, nbr)| nbr),
                None => Some(nbr),
            };

            if let Some(nbr) = nbr {
                gr::helper_process_grace_lsa(
                    nbr,
                    iface,
                    area,
                    &lse.data.hdr,
                    grace_period,
                    reason,
                    instance,
                );
            }
        }

        // (5.f) Check if this is a self-originated LSA.
        if lse.flags.contains(LsaEntryFlags::SELF_ORIGINATED) {
            Debug::<V>::LsaSelfOriginated(nbr_router_id, &lse.data.hdr).log();

            // (Re)originate or flush self-originated LSA.
            let (lsdb_id, _) = lsdb_index(
                &instance.state.lsdb,
                &arenas.areas,
                &arenas.interfaces,
                lsdb_idx,
            );
            instance.tx.protocol_input.lsa_orig_event(
                LsaOriginateEvent::SelfOriginatedLsaRcvd {
                    lsdb_id,
                    lse_id: lse.id,
                },
            );
        }

        // Examine the next LSA.
        return false;
    }

    // (6 - errata 3974) Check if the received LSA is the same instance as
    // the database copy (i.e., neither one is more recent).
    let nbr = &mut arenas.neighbors[nbr_idx];
    let lse = lse.unwrap();
    if lsa_cmp == Some(Ordering::Equal) {
        // Check if this LSA can be handled as an implied acknowledgment.
        if let btree_map::Entry::Occupied(o) = nbr.lists.ls_rxmt.entry(lsa_key)
        {
            o.remove();
            nbr.rxmt_lsupd_stop_check();

            let nbr_net_id = nbr.network_id();
            if iface.state.ism_state == ism::State::Backup
                && iface.state.dr == Some(nbr_net_id)
            {
                // Enqueue delayed ack.
                iface.enqueue_delayed_ack(area, instance, &lsa.hdr);
            }
        } else {
            // Send direct ack.
            output::send_lsack_direct(nbr, iface, area, instance, &lsa.hdr);
        }

        // Examine the next LSA.
        return false;
    }

    // (7 - errata 3974) If there is an instance of the LSA on the sending
    // neighbor's Link state request list, an error has occurred in the
    // Database Exchange process.
    if nbr.lists.ls_request.contains_key(&lsa_key)
        || nbr.lists.ls_request_pending.contains_key(&lsa_key)
    {
        // Restart the Database Exchange process.
        nbr.fsm(
            iface,
            area,
            instance,
            &arenas.lsa_entries,
            nsm::Event::BadLsReq,
        );

        // Stop processing the Link State Update packet.
        return true;
    }

    // (8) The database copy is more recent.
    //
    // If the database copy has LS age equal to MaxAge and LS sequence
    // number equal to MaxSequenceNumber, simply discard the received LSA
    // without acknowledging it.
    if lse.data.hdr.is_maxage() && lse.data.hdr.seq_no() == lsdb::LSA_MAX_SEQ_NO
    {
        // Examine the next LSA.
        return false;
    }
    if !lsdb::lsa_min_arrival_check(lse) {
        // Send the database copy back to the sending neighbor, encapsulated
        // within a Link State Update Packet.
        nbr.lists.ls_update.insert(lsa_key, lse.data.clone());
        instance
            .tx
            .protocol_input
            .send_lsupd(area.id, iface.id, Some(nbr.id));
    } else {
        // Log why the LSA is being discarded.
        Debug::<V>::LsaMinArrivalDiscard(nbr.router_id, &lsa.hdr).log();
    }

    // Examine the next LSA.
    false
}

fn process_packet_lsack<V>(
    nbr: &mut Neighbor<V>,
    ls_ack: V::PacketLsAck,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if nbr.state < nsm::State::Exchange {
        Debug::<V>::PacketRxIgnore(nbr.router_id, &nbr.state).log();
        return Ok(());
    }

    // Iterate over all LSA headers.
    for lsa_hdr in ls_ack.lsa_hdrs() {
        let lsa_key = lsa_hdr.key();
        if let btree_map::Entry::Occupied(o) = nbr.lists.ls_rxmt.entry(lsa_key)
        {
            let lsa = o.get();
            if lsa_compare::<V>(&lsa.hdr, lsa_hdr) == Ordering::Equal {
                o.remove();
                nbr.rxmt_lsupd_stop_check();
            } else {
                Debug::<V>::QuestionableAck(nbr.router_id, lsa_hdr).log();
            }
        }
    }

    Ok(())
}

// ===== Free last sent/received Database Description packets =====

pub(crate) fn process_dbdesc_free<V>(
    _instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: NeighborKey,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let (_, nbr) = iface
        .state
        .neighbors
        .get_mut_by_key(&mut arenas.neighbors, &nbr_key)?;

    // Free last sent/received Database Description packets.
    nbr.tasks.dbdesc_free_timer = None;
    nbr.last_rcvd_dbdesc = None;
    nbr.last_sent_dbdesc = None;

    Ok(())
}

// ===== Request to send LS Update =====

pub(crate) fn process_send_lsupd<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: Option<NeighborKey>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and optional neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let nbr_idx = match &nbr_key {
        Some(nbr_key) => {
            let (nbr_idx, _) = iface
                .state
                .neighbors
                .get_mut_by_key(&mut arenas.neighbors, nbr_key)?;
            Some(nbr_idx)
        }
        None => None,
    };

    // Send LS Update.
    iface.state.tasks.ls_update_timer = None;
    output::send_lsupd(nbr_idx, iface, area, instance, &mut arenas.neighbors);

    Ok(())
}

// ===== Packet retransmission =====

pub(crate) fn process_packet_rxmt<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: NeighborKey,
    packet_type: RxmtPacketType,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and optional neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let (_, nbr) = iface
        .state
        .neighbors
        .get_mut_by_key(&mut arenas.neighbors, &nbr_key)?;

    // Retransmit packet.
    match packet_type {
        RxmtPacketType::DbDesc => {
            output::rxmt_dbdesc(nbr, iface);
        }
        RxmtPacketType::LsRequest => {
            output::rxmt_lsreq(nbr, iface, area, instance);
        }
        RxmtPacketType::LsUpdate => {
            output::rxmt_lsupd(nbr, iface, area, instance);
        }
    }

    Ok(())
}

// ===== Delayed Ack timeout =====

pub(crate) fn process_delayed_ack_timeout<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area and interface.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;

    // Send delayed LS Ack.
    iface.state.tasks.ls_delayed_ack = None;
    output::send_lsack_delayed(iface, area, instance, &arenas.neighbors);

    Ok(())
}

// ===== LSA origination event =====

pub(crate) fn process_lsa_orig_event<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &InstanceArenas<V>,
    event: LsaOriginateEvent,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Check which LSAs need to be reoriginated or flushed.
    V::lsa_orig_event(instance, arenas, event)
}

// ===== LSA origination check =====

pub(crate) fn process_lsa_orig_check<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
    options: Option<V::PacketOptions>,
    lsa_id: Ipv4Addr,
    lsa_body: V::LsaBody,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSDB.
    let (lsdb_idx, _) = lsdb_get(
        &instance.state.lsdb,
        &arenas.areas,
        &arenas.interfaces,
        &lsdb_key,
    )?;

    // Attempt to originate LSA.
    lsdb::originate_check(
        instance, arenas, lsdb_idx, options, lsa_id, lsa_body,
    );

    Ok(())
}

// ===== LSA delayed origination timer =====

pub(crate) fn process_lsa_orig_delayed_timer<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
    lsa_key: LsaKey<V::LsaType>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSDB.
    let (lsdb_idx, lsdb) = lsdb_get_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        &lsdb_key,
    )?;

    // Originate LSA.
    if let Some(ldo) = lsdb.delayed_orig.remove(&lsa_key) {
        lsdb::originate(instance, arenas, lsdb_idx, ldo.data);
    }

    Ok(())
}

// ===== LSA flush event =====

pub(crate) fn process_lsa_flush<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
    lse_key: LsaEntryKey<V::LsaType>,
    reason: LsaFlushReason,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSA entry and its corresponding LSDB.
    let (lsdb_idx, lsdb) = lsdb_get_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        &lsdb_key,
    )?;
    let (lse_idx, _) =
        lsdb.get_mut_by_key(&mut arenas.lsa_entries, &lse_key)?;

    // Flush LSA.
    lsdb::flush(instance, arenas, lsdb_idx, lse_idx, reason);

    Ok(())
}

// ===== LSA refresh event =====

pub(crate) fn process_lsa_refresh<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
    lse_key: LsaEntryKey<V::LsaType>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSA entry and its corresponding LSDB.
    let (lsdb_idx, lsdb) = lsdb_get_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        &lsdb_key,
    )?;
    let (_, lse) = lsdb.get_by_key(&arenas.lsa_entries, &lse_key)?;

    assert!(lse.flags.contains(LsaEntryFlags::SELF_ORIGINATED));

    Debug::<V>::LsaRefresh(&lse.data.hdr).log();

    // Originate new instance of the LSA.
    let lsa = Lsa::new(
        0,
        lse.data.hdr.options(),
        lse.data.hdr.lsa_id(),
        lse.data.hdr.adv_rtr(),
        lse.data.hdr.seq_no() + 1,
        lse.data.body.clone(),
    );
    lsdb::originate(instance, arenas, lsdb_idx, lsa);

    Ok(())
}

// ===== LSDB MaxAge sweep timer =====

pub(crate) fn process_lsdb_maxage_sweep_interval<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSDB.
    let (lsdb_idx, lsdb) = lsdb_get_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        &lsdb_key,
    )?;

    // Skip discarding MaxAge LSAs if any of the router's neighbors are in
    // states Exchange or Loading.
    if arenas.neighbors.iter().any(|(_, nbr)| {
        matches!(nbr.state, nsm::State::Exchange | nsm::State::Loading)
    }) {
        return Ok(());
    }

    // Get list of MaxAge LSAs that are no longer contained on any neighbor LS
    // retransmission lists.
    for lse_idx in lsdb
        .maxage_lsas
        .extract_if(|lse_idx| {
            let lse = &arenas.lsa_entries[*lse_idx];
            !arenas.neighbors.iter().any(|(_, nbr)| {
                nbr.lists
                    .ls_rxmt
                    .get(&lse.data.hdr.key())
                    .filter(|rxmt_lsa| Arc::ptr_eq(&lse.data, rxmt_lsa))
                    .is_some()
            })
        })
        .collect::<Vec<_>>()
    {
        let (_, lsdb) = lsdb_index_mut(
            &mut instance.state.lsdb,
            &mut arenas.areas,
            &mut arenas.interfaces,
            lsdb_idx,
        );
        let lse = &arenas.lsa_entries[lse_idx];

        // Delete or originate new instance of the LSA depending whether it's
        // wrapping its sequence number.
        if let Some(lsa) = lsdb.seqno_wrapping.remove(&lse.data.hdr.key()) {
            let lsa = Lsa::new(
                0,
                lsa.hdr.options(),
                lsa.hdr.lsa_id(),
                lsa.hdr.adv_rtr(),
                lsdb::LSA_INIT_SEQ_NO,
                lsa.body.clone(),
            );
            lsdb::originate(instance, arenas, lsdb_idx, lsa);
        } else {
            lsdb.delete(&mut arenas.lsa_entries, lse_idx);
        }
    }

    Ok(())
}

// ===== SPF run event =====

pub(crate) fn process_spf_delay_event<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    event: spf::fsm::Event,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Trigger SPF Delay FSM event.
    spf::fsm(event, instance, arenas)
}

// ===== Grace period timeout =====

pub(crate) fn process_grace_period_timeout<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: NeighborKey,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let (_, nbr) = iface
        .state
        .neighbors
        .get_mut_by_key(&mut arenas.neighbors, &nbr_key)?;

    if nbr.gr.is_some() {
        // Exit from the helper mode.
        gr::helper_exit(nbr, iface, area, GrExitReason::TimedOut, instance);

        // Delete the neighbor.
        instance.tx.protocol_input.nsm_event(
            area.id,
            iface.id,
            nbr.id,
            nsm::Event::InactivityTimer,
        );
    }

    Ok(())
}

// ===== SR configuration change event =====

pub(crate) fn process_sr_cfg_change<V>(
    instance: &mut Instance<V>,
    change: SrCfgEvent,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if let Some((instance, arenas)) = instance.as_up() {
        if instance.config.sr_enabled {
            // Check which LSAs need to be reoriginated or flushed.
            V::lsa_orig_event(
                &instance,
                arenas,
                LsaOriginateEvent::SrCfgChange { change },
            )?;
        }
    }

    Ok(())
}

// ===== BIER configuration change event =====

pub(crate) fn process_bier_cfg_change<V>(
    instance: &mut Instance<V>,
    change: BierCfgEvent,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if let Some((instance, arenas)) = instance.as_up()
        && instance.config.bier.enabled
    {
        V::lsa_orig_event(
            &instance,
            arenas,
            LsaOriginateEvent::BierCfgChange { change },
        )?;
    }
    Ok(())
}

// ===== BFD state update event =====

pub(crate) fn process_bfd_state_update<V>(
    instance: &mut Instance<V>,
    sess_key: bfd::SessionKey,
    state: bfd::State,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // We're only interested on peer down notifications.
    if state != bfd::State::Down {
        return Ok(());
    }

    // Ignore notification if the OSPF instance isn't active anymore.
    let Some((instance, arenas)) = instance.as_up() else {
        return Ok(());
    };

    if let bfd::SessionKey::IpSingleHop { ifname, dst } = sess_key {
        // Lookup area and interface.
        let (iface, area) = match arenas.areas.iter().find_map(|area| {
            area.interfaces
                .get_by_name(&arenas.interfaces, &ifname)
                .map(|(_, iface)| (iface, area))
        }) {
            Some(value) => value,
            None => return Ok(()),
        };

        // Lookup neighbor.
        if let Some(nbr) = iface
            .state
            .neighbors
            .iter(&arenas.neighbors)
            .find(|nbr| nbr.src.into() == dst)
        {
            instance.tx.protocol_input.nsm_event(
                area.id,
                iface.id,
                nbr.id,
                nsm::Event::InactivityTimer,
            );
        }
    }

    Ok(())
}

// ===== Keychain update event =====

pub(crate) fn process_keychain_update<V>(
    instance: &mut Instance<V>,
    keychain_name: &str,
) -> Result<(), Error<V>>
where
    V: Version,
{
    let Some((instance, arenas)) = instance.as_up() else {
        return Ok(());
    };

    for area in arenas.areas.iter_mut() {
        for iface_idx in area.interfaces.indexes() {
            let iface = &mut arenas.interfaces[iface_idx];
            if iface.config.auth_keychain.as_deref() != Some(keychain_name) {
                continue;
            }

            // Update interface authentication keys.
            iface.auth_update(area, &instance);
        }
    }

    Ok(())
}

// ===== Hostname update event =====

pub(crate) fn process_hostname_update<V>(
    instance: &mut Instance<V>,
    hostname: Option<String>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    instance.shared.hostname = hostname;

    if let Some((instance, arenas)) = instance.as_up() {
        V::lsa_orig_event(
            &instance,
            arenas,
            LsaOriginateEvent::HostnameChange,
        )?;
    }

    Ok(())
}
