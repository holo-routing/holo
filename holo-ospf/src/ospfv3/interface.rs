//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::{Ipv4Addr, Ipv6Addr};

use holo_utils::ip::AddressFamily;

use crate::area::{Area, AreaVersion};
use crate::collections::{Arena, NeighborIndex};
use crate::debug::InterfaceInactiveReason;
use crate::error::{Error, InterfaceCfgError};
use crate::instance::InstanceUpView;
use crate::interface::{self, Interface, InterfaceSys, InterfaceVersion};
use crate::neighbor::Neighbor;
use crate::ospfv3;
use crate::ospfv3::packet::{Hello, Options, PacketHdr};
use crate::packet::{Packet, PacketType};
use crate::version::Ospfv3;

// ===== impl Ospfv3 =====

impl InterfaceVersion<Self> for Ospfv3 {
    fn is_ready(
        af: AddressFamily,
        iface: &Interface<Self>,
    ) -> Result<(), InterfaceInactiveReason> {
        interface::is_ready_common(iface)?;

        if !iface.system.loopback && iface.system.linklocal_addr.is_none() {
            return Err(InterfaceInactiveReason::MissingLinkLocalAddress);
        }

        if af == AddressFamily::Ipv4
            && !iface.system.addr_list.iter().any(|addr| addr.is_ipv4())
        {
            return Err(InterfaceInactiveReason::MissingIpv4Address);
        }

        Ok(())
    }

    fn src_addr(iface_sys: &InterfaceSys<Self>) -> Option<Ipv6Addr> {
        Some(iface_sys.linklocal_addr.unwrap().ip())
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
            instance_id: PacketHdr::instance_id(
                instance.state.af,
                iface.config.instance_id,
            ),
        };

        Packet::Hello(Hello {
            hdr,
            iface_id: iface.system.ifindex.unwrap(),
            priority: iface.config.priority,
            options: Self::area_options(area, false),
            hello_interval: iface.config.hello_interval,
            dead_interval: iface.config.dead_interval,
            dr: iface.state.dr,
            bdr: iface.state.bdr,
            neighbors: iface.state.neighbors.router_ids().collect(),
        })
    }

    fn validate_packet_dst(
        iface: &Interface<Self>,
        dst: Ipv6Addr,
    ) -> Result<(), Error<Self>> {
        // Check if the destination matches one of the interface unicast
        // addresses.
        if iface.system.addr_list.iter().any(|addr| addr.ip() == dst) {
            return Ok(());
        }

        interface::validate_packet_dst_common(iface, dst)
    }

    fn validate_packet_src(
        iface: &Interface<Self>,
        src: Ipv6Addr,
    ) -> Result<(), Error<Self>> {
        // No OSPFv3-specific validation required.
        interface::validate_packet_src_common(iface, src)
    }

    fn validate_packet_instance_id(
        af: AddressFamily,
        iface: &Interface<Self>,
        packet_hdr: &ospfv3::packet::PacketHdr,
    ) -> Result<(), Error<Self>> {
        let iface_instance_id =
            PacketHdr::instance_id(af, iface.config.instance_id);

        if packet_hdr.instance_id != iface_instance_id {
            return Err(Error::InstanceIdMismatch(
                packet_hdr.instance_id,
                iface_instance_id,
            ));
        }

        Ok(())
    }

    fn validate_hello_netmask(
        _iface: &Interface<Self>,
        _hello: &ospfv3::packet::Hello,
    ) -> Result<(), InterfaceCfgError> {
        // Nothing to do.
        Ok(())
    }

    fn validate_hello_af_bit(
        _iface: &Interface<Self>,
        hello: &ospfv3::packet::Hello,
    ) -> Result<(), InterfaceCfgError> {
        if hello.hdr.instance_id >= 32 && !hello.options.contains(Options::AF) {
            return Err(InterfaceCfgError::AfBitClear);
        }

        Ok(())
    }

    fn max_packet_size(iface: &Interface<Self>) -> u16 {
        const IPV6_HDR_SIZE: u16 = 40;

        iface.system.mtu.unwrap() - IPV6_HDR_SIZE
    }

    fn get_neighbor<'a>(
        iface: &mut Interface<Self>,
        _src: &Ipv6Addr,
        router_id: Ipv4Addr,
        neighbors: &'a mut Arena<Neighbor<Self>>,
    ) -> Option<(NeighborIndex, &'a mut Neighbor<Self>)> {
        // In OSPF for IPv6, neighboring routers on a given link are always
        // identified by their OSPF Router ID.
        iface
            .state
            .neighbors
            .get_mut_by_router_id(neighbors, router_id)
    }
}
