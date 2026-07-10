//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_bgp::instance::Instance;
use holo_protocol::test::stub::{run_test, run_test_topology};

#[tokio::test]
async fn topology1_1() {
    for rt_num in 1..=4 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance>("topo1-1", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_1() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance>("topo2-1", &rt_name).await;
    }
}

#[tokio::test]
async fn policy_core_1() {
    run_test_topology::<Instance>("policy-core-1", "rt1").await;
}

#[tokio::test]
async fn policy_community_1() {
    run_test_topology::<Instance>("policy-community-1", "rt1").await;
}

#[tokio::test]
async fn soft_reconfig_in_1() {
    run_test::<Instance>("soft-reconfig-in-1", "soft-reconfig-in-1", "rt1")
        .await;
}
