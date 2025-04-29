//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_ospf::instance::Instance;
use holo_ospf::version::Ospfv2;
use holo_protocol::test::stub::run_test_topology;

#[tokio::test]
async fn topology1_1() {
    for rt_num in 1..=7 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ospfv2>>("topo1-1", &rt_name).await;
    }
}

#[tokio::test]
async fn topology1_2() {
    for rt_num in 1..=7 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ospfv2>>("topo1-2", &rt_name).await;
    }
}

#[ignore]
#[tokio::test]
async fn topology1_3() {
    for rt_num in 1..=7 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ospfv2>>("topo1-3", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_1() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ospfv2>>("topo2-1", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_2() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ospfv2>>("topo2-2", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_3() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ospfv2>>("topo2-3", &rt_name).await;
    }
}

#[ignore]
#[tokio::test]
async fn topology2_4() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance<Ospfv2>>("topo2-4", &rt_name).await;
    }
}
