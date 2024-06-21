//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use libc::ETH_P_ALL;
use socket2::{Socket, Domain, Type, Protocol};
use capctl::caps;
use holo_utils::capabilities;

fn socket() -> Result<Socket, std::io::Error> {
    let socket = capabilities::raise(|| {
        Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(112))
        )
    })?;

    socket.set_broadcast(true);
    Ok(socket)
}
