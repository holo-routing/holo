//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, LazyLock as Lazy};

use holo_utils::ip::{AddressFamily, IpAddrExt};
use holo_utils::socket::{SocketExt, UdpSocket, UdpSocketExt};
use holo_utils::{Sender, capabilities};
use tokio::sync::mpsc::error::SendError;

use crate::error::{Error, IoError};
use crate::interface::Interface;
use crate::network;
use crate::packet::error::DecodeError;
use crate::packet::{DecodeCxt, PacketInfo, Pdu};
use crate::tasks::messages::input::UdpRxPduMsg;

// All routers on this subnet multicast addresses.
pub static LDP_MCAST_ADDR_V4: Lazy<Ipv4Addr> =
    Lazy::new(|| Ipv4Addr::from_str("224.0.0.2").unwrap());
pub static LDP_MCAST_ADDR_V6: Lazy<Ipv6Addr> =
    Lazy::new(|| Ipv6Addr::from_str("ff02::2").unwrap());
pub static LDP_MCAST_SOCKADDR_V4: Lazy<SocketAddr> = Lazy::new(|| {
    SocketAddr::new(IpAddr::V4(*LDP_MCAST_ADDR_V4), network::LDP_PORT)
});
pub static LDP_MCAST_SOCKADDR_V6: Lazy<SocketAddr> = Lazy::new(|| {
    SocketAddr::new(IpAddr::V6(*LDP_MCAST_ADDR_V6), network::LDP_PORT)
});

// ===== global functions =====

pub(crate) fn discovery_socket(
    addr: IpAddr,
) -> Result<UdpSocket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Create and bind socket.
        let sockaddr = SocketAddr::from((addr, network::LDP_PORT));
        let socket =
            capabilities::raise(|| UdpSocket::bind_reuseaddr(sockaddr))?;

        // Set socket options.
        socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(UdpSocket {})
    }
}

pub(crate) fn interface_discovery_socket(
    iface: &Interface,
) -> Result<UdpSocket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Create and bind socket.
        let socket = UdpSocket::new(AddressFamily::Ipv4)?;
        capabilities::raise(|| {
            socket.bind_device(Some(iface.name.as_bytes()))
        })?;

        // Set socket options.
        socket.set_multicast_loop_v4(false)?;
        socket.set_multicast_ttl_v4(1)?;
        socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(UdpSocket {})
    }
}

pub(crate) async fn send_packet_multicast(
    socket: &UdpSocket,
    pdu: Pdu,
) -> Result<(), std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Encode Hello message.
        let buf = pdu.encode(Pdu::DFLT_MAX_LEN);

        // Send packet.
        socket.send_to(&buf, &*LDP_MCAST_SOCKADDR_V4).await?;
    }

    Ok(())
}

pub(crate) async fn send_packet_unicast(
    socket: &UdpSocket,
    pdu: Pdu,
    addr: &IpAddr,
) -> Result<(), std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Encode Hello message.
        let buf = pdu.encode(Pdu::DFLT_MAX_LEN);

        // Send packet.
        socket
            .send_to(&buf, SocketAddr::new(*addr, network::LDP_PORT))
            .await?;
    }

    Ok(())
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop(
    socket: Arc<UdpSocket>,
    multicast: bool,
    udp_pdu_rxp: Sender<UdpRxPduMsg>,
) -> Result<(), SendError<UdpRxPduMsg>> {
    let mut buf = [0; 4096];

    // PDU header validation closure.
    let validate_pdu_hdr = |_lsr_id, label_space| {
        if label_space != 0 {
            return Err(DecodeError::InvalidLabelSpace(label_space));
        }
        Ok(())
    };

    // Decode context.
    let mut cxt = DecodeCxt {
        pkt_info: PacketInfo {
            // The source address will be overwritten later.
            src_addr: IpAddr::from([0, 0, 0, 0]),
            multicast: None,
        },
        pdu_max_len: Pdu::DFLT_MAX_LEN,
        validate_pdu_hdr: Some(Box::new(validate_pdu_hdr)),
        validate_msg_hdr: None,
    };

    loop {
        // Receive data from the network.
        let (_, src) = match socket.recv_from(&mut buf).await {
            Ok((num_bytes, src)) => (num_bytes, src),
            Err(error) => {
                IoError::UdpRecvError(error).log();
                continue;
            }
        };

        // Validate packet source address.
        let src_addr = src.ip();
        if !src_addr.is_usable() {
            Error::UdpInvalidSourceAddr(src_addr).log();
            continue;
        }

        // Decode packet.
        cxt.pkt_info.src_addr = src_addr;
        let pdu = Pdu::get_pdu_size(&buf, &cxt)
            .and_then(|pdu_size| Pdu::decode(&buf[0..pdu_size], &cxt));
        let msg = UdpRxPduMsg {
            src_addr,
            multicast,
            pdu,
        };
        udp_pdu_rxp.send(msg).await?;
    }
}
