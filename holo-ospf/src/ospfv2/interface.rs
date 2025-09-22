//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use holo_utils::ip::{AddressFamily, Ipv4AddrExt};

use crate::area::{Area, AreaVersion, OptionsLocation};
use crate::collections::{Arena, NeighborIndex};
use crate::debug::InterfaceInactiveReason;
use crate::error::{Error, InterfaceCfgError};
use crate::instance::InstanceUpView;
use crate::interface::{
    self, Interface, InterfaceSys, InterfaceType, InterfaceVersion,
};
use crate::neighbor::{Neighbor, NeighborVersion};
use crate::network::{MulticastAddr, NetworkVersion};
use crate::ospfv2;
use crate::ospfv2::packet::{Hello, PacketHdr};
use crate::packet::auth::AuthMethod;
use crate::packet::{Packet, PacketType};
use crate::version::Ospfv2;

// ===== impl Ospfv2 =====

impl InterfaceVersion<Self> for Ospfv2 {
    fn is_ready(
        _af: AddressFamily,
        iface: &Interface<Self>,
    ) -> Result<(), InterfaceInactiveReason> {
        interface::is_ready_common(iface)?;

        if iface.system.primary_addr.is_none() {
            return Err(InterfaceInactiveReason::MissingIpv4Address);
        }

        Ok(())
    }

    fn src_addr(iface_sys: &InterfaceSys<Self>) -> Ipv4Addr {
        iface_sys.primary_addr.unwrap().ip()
    }

    fn generate_hello(
        iface: &Interface<Self>,
        area: &Area<Self>,
        instance: &InstanceUpView<'_, Self>,
    ) -> Packet<Self> {
        let hdr = PacketHdr {
            pkt_type: PacketType::Hello,
            router_id: instance.state.router_id,
            area_id: area.area_id,
            auth_seqno: None,
        };

        let network_mask = if iface.is_virtual_link() {
            Ipv4Addr::UNSPECIFIED
        } else {
            iface.system.primary_addr.unwrap().mask()
        };

        let lls = if iface.config.lls_enabled {
            // TODO: Get LLS configuration
            None
        } else {
            None
        };

        Packet::Hello(Hello {
            hdr,
            network_mask,
            hello_interval: iface.config.hello_interval,
            options: Self::area_options(
                area,
                OptionsLocation::new_packet(
                    PacketType::Hello,
                    iface.state.auth.is_some(),
                    lls.is_some(),
                ),
            ),
            priority: iface.config.priority,
            dead_interval: iface.config.dead_interval as u32,
            dr: iface.state.dr,
            bdr: iface.state.bdr,
            neighbors: iface.state.neighbors.router_ids().collect(),
            lls,
        })
    }

    fn validate_packet_dst(
        iface: &Interface<Self>,
        dst: Ipv4Addr,
    ) -> Result<(), Error<Self>> {
        // Accept only unicast packets on virtual links.
        if iface.is_virtual_link() {
            if dst.is_multicast() {
                return Err(Error::InvalidDstAddr(dst));
            } else {
                return Ok(());
            }
        }

        // Check if the destination matches the interface primary address.
        if dst == iface.system.primary_addr.unwrap().ip() {
            return Ok(());
        }

        // Check if the destination matches AllSPFRouters.
        if dst == *Self::multicast_addr(MulticastAddr::AllSpfRtrs) {
            return Ok(());
        }

        // Packets whose IP destination is AllDRouters should only be accepted
        // if the state of the receiving interface is DR or Backup.
        if dst == *Self::multicast_addr(MulticastAddr::AllDrRtrs)
            && iface.is_dr_or_backup()
        {
            return Ok(());
        }

        Err(Error::InvalidDstAddr(dst))
    }

    fn validate_packet_src(
        iface: &Interface<Self>,
        src: Ipv4Addr,
    ) -> Result<(), Error<Self>> {
        if !src.is_usable() {
            return Err(Error::InvalidSrcAddr(src));
        }

        // The packet's IP source address is required to be on the same
        // network as the receiving interface.
        if iface.config.if_type != InterfaceType::PointToPoint
            && iface.config.if_type != InterfaceType::VirtualLink
            && !iface.system.primary_addr.unwrap().contains(src)
        {
            return Err(Error::InvalidSrcAddr(src));
        }

        Ok(())
    }

    fn packet_instance_id_match(
        _iface: &Interface<Self>,
        _packet_hdr: &ospfv2::packet::PacketHdr,
    ) -> bool {
        // The Instance ID field is not present in OSPFv2's packet header.
        true
    }

    fn validate_hello(
        iface: &Interface<Self>,
        hello: &ospfv2::packet::Hello,
    ) -> Result<(), InterfaceCfgError> {
        match iface.config.if_type {
            InterfaceType::PointToPoint | InterfaceType::VirtualLink => {
                // Nothing to validate.
            }
            InterfaceType::PointToMultipoint
            | InterfaceType::Broadcast
            | InterfaceType::NonBroadcast => {
                // Validate the Hello Network mask field.
                let iface_addrmask = iface.system.primary_addr.unwrap().mask();
                if hello.network_mask != iface_addrmask {
                    return Err(InterfaceCfgError::HelloMaskMismatch(
                        hello.network_mask,
                        iface_addrmask,
                    ));
                }
            }
        }

        Ok(())
    }

    fn max_packet_size(iface: &Interface<Self>) -> u16 {
        const VIRTUAL_LINK_MTU: u16 = 576;
        const IPV4_HDR_SIZE: u16 = 20;

        let mtu = if iface.is_virtual_link() {
            VIRTUAL_LINK_MTU
        } else {
            iface.system.mtu.unwrap()
        };

        let mut max = mtu - IPV4_HDR_SIZE;

        // Reserve space for the message digest when authentication is enabled.
        if let Some(auth) = &iface.state.auth {
            match auth {
                AuthMethod::ManualKey(key) => {
                    max -= key.algo.digest_size() as u16
                }
                AuthMethod::Keychain(keychain) => {
                    max -= keychain.max_digest_size as u16
                }
            }
        }

        max
    }

    fn get_neighbor<'a>(
        iface: &mut Interface<Self>,
        src: &Ipv4Addr,
        router_id: Ipv4Addr,
        neighbors: &'a mut Arena<Neighbor<Self>>,
    ) -> Option<(NeighborIndex, &'a mut Neighbor<Self>)> {
        match iface.config.if_type {
            InterfaceType::PointToPoint | InterfaceType::VirtualLink => {
                // If the receiving interface connects to a point-to-point
                // network or a virtual link, the sender is identified by the
                // Router ID (source router) found in the packet's OSPF header.
                iface
                    .state
                    .neighbors
                    .get_mut_by_router_id(neighbors, router_id)
            }
            InterfaceType::Broadcast
            | InterfaceType::NonBroadcast
            | InterfaceType::PointToMultipoint => {
                // If the receiving interface connects to a broadcast network,
                // Point-to-MultiPoint network or NBMA network the sender is
                // identified by the IP source address found in the packet's IP
                // header.
                let net_id =
                    <Self as NeighborVersion<Self>>::network_id(src, router_id);
                if let Some((nbr_idx, nbr)) =
                    iface.state.neighbors.get_mut_by_net_id(neighbors, net_id)
                {
                    // Update the neighbor's Router ID before returning it.
                    iface
                        .state
                        .neighbors
                        .update_router_id(nbr_idx, nbr, router_id);
                    Some((nbr_idx, nbr))
                } else {
                    None
                }
            }
        }
    }
}
