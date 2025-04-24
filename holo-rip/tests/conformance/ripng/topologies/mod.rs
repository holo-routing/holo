//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_protocol::test::stub::run_test_topology;
use holo_rip::instance::Instance;
use holo_rip::version::Ripng;

#[tokio::test]
async fn topology1_1() {
    for rt_num in 1..=4 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ripng>>("topo1-1", &rt_name).await;
    }
}

#[tokio::test]
async fn topology1_2() {
    for rt_num in 1..=4 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ripng>>("topo1-2", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_1() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ripng>>("topo2-1", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_2() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ripng>>("topo2-2", &rt_name).await;
    }
}
