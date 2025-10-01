//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{Ipv4Addr, Ipv6Addr};

use holo_utils::ip::{AddressFamily, Ipv6AddrExt};
use holo_utils::southbound::InterfaceFlags;

use crate::area::{Area, AreaVersion, OptionsLocation};
use crate::collections::{Arena, NeighborIndex};
use crate::debug::InterfaceInactiveReason;
use crate::error::{Error, InterfaceCfgError};
use crate::instance::InstanceUpView;
use crate::interface::{self, Interface, InterfaceSys, InterfaceVersion};
use crate::neighbor::Neighbor;
use crate::network::{MulticastAddr, NetworkVersion};
use crate::ospfv3;
use crate::ospfv3::packet::{Hello, Options, PacketHdr};
use crate::packet::auth::AuthMethod;
use crate::packet::lls::{LlsHelloData, ReverseMetricFlags};
use crate::packet::{Packet, PacketType};
use crate::version::Ospfv3;

// ===== impl Ospfv3 =====

impl InterfaceVersion<Self> for Ospfv3 {
    fn is_ready(
        af: AddressFamily,
        iface: &Interface<Self>,
    ) -> Result<(), InterfaceInactiveReason> {
        interface::is_ready_common(iface)?;

        if !iface.system.flags.contains(InterfaceFlags::LOOPBACK)
            && iface.system.linklocal_addr.is_none()
        {
            return Err(InterfaceInactiveReason::MissingLinkLocalAddress);
        }

        if af == AddressFamily::Ipv4
            && !iface.system.addr_list.iter().any(|addr| addr.is_ipv4())
        {
            return Err(InterfaceInactiveReason::MissingIpv4Address);
        }

        Ok(())
    }

    fn src_addr(iface_sys: &InterfaceSys<Self>) -> Ipv6Addr {
        iface_sys.linklocal_addr.unwrap().ip()
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
            instance_id: iface.config.instance_id.resolved,
            auth_seqno: None,
        };

        let lls = (iface.config.lls_enabled
            & iface.config.reverse_metric.advertise)
            .then(|| {
                let mut lls_data: LlsHelloData = Default::default();

                // Handle Reverse Metric (RFC 9339).
                if iface.config.reverse_metric.advertise {
                    for (mtid, cfg) in iface.config.reverse_metric.rm_tx.iter()
                    {
                        let mut flags = ReverseMetricFlags::empty();
                        if cfg.higher {
                            flags |= ReverseMetricFlags::H;
                        }
                        if cfg.offset {
                            flags |= ReverseMetricFlags::O;
                        }
                        lls_data
                            .reverse_metric
                            .insert(*mtid, (flags, cfg.metric));
                    }
                }

                lls_data
            });

        Packet::Hello(Hello {
            hdr,
            iface_id: iface.system.ifindex.unwrap(),
            priority: iface.config.priority,
            options: Self::area_options(
                area,
                OptionsLocation::new_packet(
                    PacketType::Hello,
                    iface.state.auth.is_some(),
                    lls.is_some(),
                ),
            ),
            hello_interval: iface.config.hello_interval,
            dead_interval: iface.config.dead_interval,
            dr: iface.state.dr,
            bdr: iface.state.bdr,
            neighbors: iface.state.neighbors.router_ids().collect(),
            lls,
        })
    }

    fn validate_packet_dst(
        iface: &Interface<Self>,
        dst: Ipv6Addr,
    ) -> Result<(), Error<Self>> {
        // Accept only unicast packets on virtual links.
        if iface.is_virtual_link() {
            if dst.is_multicast() {
                return Err(Error::InvalidDstAddr(dst));
            } else {
                return Ok(());
            }
        }

        // Check if the destination matches one of the interface unicast
        // addresses.
        if iface.system.addr_list.iter().any(|addr| addr.ip() == dst) {
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
        _iface: &Interface<Self>,
        src: Ipv6Addr,
    ) -> Result<(), Error<Self>> {
        if !src.is_usable() {
            return Err(Error::InvalidSrcAddr(src));
        }

        Ok(())
    }

    fn packet_instance_id_match(
        iface: &Interface<Self>,
        packet_hdr: &ospfv3::packet::PacketHdr,
    ) -> bool {
        let iface_instance_id = iface.config.instance_id.resolved;
        packet_hdr.instance_id == iface_instance_id
    }

    fn validate_hello(
        _iface: &Interface<Self>,
        hello: &ospfv3::packet::Hello,
    ) -> Result<(), InterfaceCfgError> {
        // Validate the setting of the AF-bit.
        if hello.hdr.instance_id >= 32 && !hello.options.contains(Options::AF) {
            return Err(InterfaceCfgError::AfBitClear);
        }

        Ok(())
    }

    fn max_packet_size(iface: &Interface<Self>) -> u16 {
        const VIRTUAL_LINK_MTU: u16 = 1280;
        const IPV6_HDR_SIZE: u16 = 40;

        let mtu = if iface.is_virtual_link() {
            VIRTUAL_LINK_MTU
        } else {
            iface.system.mtu.unwrap()
        };

        let mut max = mtu - IPV6_HDR_SIZE;

        // Reserve space for the authentication trailer when authentication is
        // enabled.
        if let Some(auth) = &iface.state.auth {
            max -= ospfv3::packet::AUTH_TRAILER_HDR_SIZE;
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
