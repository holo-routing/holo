//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_protocol::test::stub::run_test_topology;
use holo_vrrp::interface::Interface;

#[tokio::test]
async fn topology1_1() {
    for rt_num in 1..=3 {
        let rt_name = format!("rt{}", rt_num);
        run_test_topology::<Interface>("topo1-1", &rt_name).await;
        //run_test_topology::<Interface>("topo1-1", "eth-sw1", &rt_name).await;
    }
}
