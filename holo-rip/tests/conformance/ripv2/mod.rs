//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod topologies;

use holo_protocol::test::stub::run_test;
use holo_rip::instance::Instance;
use holo_rip::version::Ripv2;

#[tokio::test]
async fn message_errors1() {
    // TODO: check if error counters increased as expected.
    run_test::<Instance<Ripv2>>("message-errors1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_request1() {
    run_test::<Instance<Ripv2>>("message-request1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_request2() {
    run_test::<Instance<Ripv2>>("message-request2", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_response1() {
    run_test::<Instance<Ripv2>>("message-response1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_response2() {
    run_test::<Instance<Ripv2>>("message-response2", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_response3() {
    run_test::<Instance<Ripv2>>("message-response3", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_response4() {
    run_test::<Instance<Ripv2>>("message-response4", "topo1-2", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_response5() {
    run_test::<Instance<Ripv2>>("message-response5", "topo1-2", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_response6() {
    run_test::<Instance<Ripv2>>("message-response6", "topo1-2", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_response7() {
    run_test::<Instance<Ripv2>>("message-response7", "topo1-2", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_response8() {
    run_test::<Instance<Ripv2>>("message-response8", "topo1-2", "rt2").await;
}

// Test description:
#[tokio::test]
async fn message_response9() {
    run_test::<Instance<Ripv2>>("message-response9", "topo2-1", "rt1").await;
}

// Test description:
#[tokio::test]
async fn nb_config_distance1() {
    run_test::<Instance<Ripv2>>("nb-config-distance1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn nb_config_iface1() {
    run_test::<Instance<Ripv2>>("nb-config-iface1", "topo1-2", "rt2").await;
}

// Test description:
#[tokio::test]
async fn nb_config_iface2() {
    run_test::<Instance<Ripv2>>("nb-config-iface2", "topo1-2", "rt2").await;
}

// Test description:
#[tokio::test]
async fn nb_config_iface_cost1() {
    run_test::<Instance<Ripv2>>("nb-config-iface-cost1", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_neighbor1() {
    run_test::<Instance<Ripv2>>("nb-config-neighbor1", "topo2-1", "rt1").await;
}

// Test description:
#[tokio::test]
async fn nb_config_neighbor2() {
    run_test::<Instance<Ripv2>>("nb-config-neighbor2", "topo2-1", "rt1").await;
}

// Test description:
#[tokio::test]
async fn nb_config_passive1() {
    run_test::<Instance<Ripv2>>("nb-config-passive1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn nb_config_passive2() {
    run_test::<Instance<Ripv2>>("nb-config-passive2", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn nb_config_split_horizon1() {
    run_test::<Instance<Ripv2>>("nb-config-split-horizon1", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_split_horizon2() {
    run_test::<Instance<Ripv2>>("nb-config-split-horizon2", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_split_horizon3() {
    run_test::<Instance<Ripv2>>("nb-config-split-horizon3", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_rpc_clear_route1() {
    run_test::<Instance<Ripv2>>("nb-rpc-clear-route1", "topo1-2", "rt2").await;
}

// Test description:
#[tokio::test]
async fn ibus_addr_add1() {
    run_test::<Instance<Ripv2>>("ibus-addr-add1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn ibus_addr_add2() {
    run_test::<Instance<Ripv2>>("ibus-addr-add2", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn ibus_addr_del1() {
    run_test::<Instance<Ripv2>>("ibus-addr-del1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn ibus_addr_del2() {
    run_test::<Instance<Ripv2>>("ibus-addr-del2", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn ibus_iface_update1() {
    run_test::<Instance<Ripv2>>("ibus-iface-update1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn ibus_iface_update2() {
    run_test::<Instance<Ripv2>>("ibus-iface-update2", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn timeout_initial_update1() {
    run_test::<Instance<Ripv2>>("timeout-initial-update1", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn timeout_neighbor1() {
    run_test::<Instance<Ripv2>>("timeout-neighbor1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn timeout_route1() {
    run_test::<Instance<Ripv2>>("timeout-route1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn timeout_route_gc1() {
    run_test::<Instance<Ripv2>>("timeout-route-gc1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn timeout_triggered_update1() {
    run_test::<Instance<Ripv2>>("timeout-triggered-update1", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn timeout_update_interval1() {
    run_test::<Instance<Ripv2>>("timeout-update-interval1", "topo1-1", "rt2")
        .await;
}
