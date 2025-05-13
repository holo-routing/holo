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
async fn topology_v2_1_1() {
    for rt_num in 1..=3 {
        let rt_name = format!("rt{}", rt_num);
        run_test_topology::<Interface>("v2-topo1-1", &rt_name).await;
    }
}

#[tokio::test]
async fn topology_v3_1_1() {
    for rt_num in 1..=3 {
        let rt_name = format!("rt{}", rt_num);
        run_test_topology::<Interface>("v3-topo1-1", &rt_name).await;
    }
}

#[tokio::test]
async fn topology_v3_1_2() {
    for rt_num in 1..=3 {
        let rt_name = format!("rt{}", rt_num);
        run_test_topology::<Interface>("v3-topo1-2", &rt_name).await;
    }
}
