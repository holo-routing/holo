//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_bgp::instance::Instance;
use holo_protocol::test::stub::run_test;

mod topologies;

// Test BGP as a BFD client:
//
//  * Northbound: enable BFD on a directly connected eBGP neighbor
//  * Ibus: subscribe to interface updates
//  * Ibus: learn the connected interface address
//  * Ibus: register a single-hop BFD session to the neighbor
//  * Ibus: BFD session goes down
//  * Protocol: reset the BGP session with Cease/BFD-down
//  * Northbound: disable BFD on the neighbor
//  * Ibus: unregister the BFD session
#[tokio::test]
async fn bfd_bgp_1() {
    run_test::<Instance>("bfd-bgp-1", "topo2-1", "rt1").await;
}
