//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

mod topologies;

use holo_ospf::instance::Instance;
use holo_ospf::version::Ospfv2;
use holo_protocol::test::stub::run_test;

// Test description:
#[tokio::test]
async fn lsa_expiry1() {
    run_test::<Instance<Ospfv2>>("lsa-expiry1", "topo2-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn lsa_expiry2() {
    run_test::<Instance<Ospfv2>>("lsa-expiry2", "topo2-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn lsa_refresh1() {
    run_test::<Instance<Ospfv2>>("lsa-refresh1", "topo2-1", "rt2").await;
}

// Test description:
#[tokio::test]
#[should_panic]
async fn lsa_refresh2() {
    run_test::<Instance<Ospfv2>>("lsa-refresh2", "topo2-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn nb_config_area1() {
    run_test::<Instance<Ospfv2>>("nb-config-area1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn nb_config_area_dflt_cost1() {
    run_test::<Instance<Ospfv2>>("nb-config-area-dflt-cost1", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_area_range1() {
    run_test::<Instance<Ospfv2>>("nb-config-area-range1", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_area_range2() {
    run_test::<Instance<Ospfv2>>("nb-config-area-range2", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_area_range3() {
    run_test::<Instance<Ospfv2>>("nb-config-area-range3", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_area_range4() {
    run_test::<Instance<Ospfv2>>("nb-config-area-range4", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_area_summary1() {
    run_test::<Instance<Ospfv2>>("nb-config-area-summary1", "topo1-1", "rt4")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_area_summary2() {
    run_test::<Instance<Ospfv2>>("nb-config-area-summary2", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_enable1() {
    run_test::<Instance<Ospfv2>>("nb-config-enable1", "topo1-1", "rt3").await;
}

// Test description:
#[tokio::test]
async fn nb_config_enable2() {
    run_test::<Instance<Ospfv2>>("nb-config-enable2", "topo1-1", "rt3").await;
}

// Test description:
#[tokio::test]
async fn nb_config_iface1() {
    run_test::<Instance<Ospfv2>>("nb-config-iface1", "topo1-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn nb_config_iface_cost1() {
    run_test::<Instance<Ospfv2>>("nb-config-iface-cost1", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_preference1() {
    run_test::<Instance<Ospfv2>>("nb-config-preference1", "topo1-1", "rt1")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_preference2() {
    run_test::<Instance<Ospfv2>>("nb-config-preference2", "topo1-1", "rt1")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_preference3() {
    run_test::<Instance<Ospfv2>>("nb-config-preference3", "topo1-1", "rt1")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_preference4() {
    run_test::<Instance<Ospfv2>>("nb-config-preference4", "topo1-1", "rt1")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_router_id1() {
    run_test::<Instance<Ospfv2>>("nb-config-router-id1", "topo1-1", "rt3")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_config_router_id2() {
    run_test::<Instance<Ospfv2>>("nb-config-router-id2", "topo1-1", "rt3")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_rpc_clear_database1() {
    run_test::<Instance<Ospfv2>>("nb-rpc-clear-database1", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_rpc_clear_neighbor1() {
    run_test::<Instance<Ospfv2>>("nb-rpc-clear-neighbor1", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn nb_rpc_clear_neighbor2() {
    run_test::<Instance<Ospfv2>>("nb-rpc-clear-neighbor2", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_area_mismatch1() {
    run_test::<Instance<Ospfv2>>("packet-area-mismatch1", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_decode_error1() {
    run_test::<Instance<Ospfv2>>("packet-decode-error1", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_dst1() {
    run_test::<Instance<Ospfv2>>("packet-dst1", "topo2-1", "rt1").await;
}

// Test description:
#[tokio::test]
async fn packet_dst2() {
    run_test::<Instance<Ospfv2>>("packet-dst2", "topo2-1", "rt1").await;
}

// Test description:
#[tokio::test]
async fn packet_dst3() {
    run_test::<Instance<Ospfv2>>("packet-dst3", "topo2-1", "rt6").await;
}

// Test description:
#[tokio::test]
async fn packet_hello_validation1() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation1", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_hello_validation2() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation2", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_hello_validation3() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation3", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_hello_validation4() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation4", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_hello_validation5() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation5", "topo1-2", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_self_orig1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig1", "topo2-1", "rt3")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_self_orig2() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig2", "topo2-1", "rt3")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_self_orig3() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig3", "topo2-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_self_orig4() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig4", "topo2-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_self_orig5() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig5", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_self_orig6() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig6", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_self_orig7() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig7", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_self_orig8() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig8", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step1_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step1-1", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step1_2() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step1-2", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step1_3() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step1-3", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step1_4() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step1-4", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step2and3_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step2and3-1", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step2and3_2() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step2and3-2", "topo1-1", "rt7")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step2and3_3() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step2and3-3", "topo1-1", "rt7")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step4_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step4-1", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step5_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-1", "topo2-1", "rt1")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step5_2() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-2", "topo2-1", "rt3")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step5_3() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-3", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step5_4() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-4", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step5_5() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-5", "topo1-1", "rt2")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_lsupd_step8_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step8-1", "topo1-1", "rt6")
        .await;
}

// Test description:
#[tokio::test]
async fn packet_src1() {
    run_test::<Instance<Ospfv2>>("packet-src1", "topo2-1", "rt1").await;
}

// Test description:
#[tokio::test]
async fn packet_src2() {
    run_test::<Instance<Ospfv2>>("packet-src2", "topo2-1", "rt1").await;
}

// Test description:
#[tokio::test]
async fn packet_src3() {
    run_test::<Instance<Ospfv2>>("packet-src3", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn rxmt_lsupd1() {
    run_test::<Instance<Ospfv2>>("rxmt-lsupd1", "topo2-1", "rt2").await;
}

// Test description:
#[tokio::test]
async fn sb_addr_add1() {
    run_test::<Instance<Ospfv2>>("sb-addr-add1", "topo2-1", "rt6").await;
}

/// Test description:
#[tokio::test]
async fn sb_addr_add2() {
    run_test::<Instance<Ospfv2>>("sb-addr-add2", "topo2-1", "rt6").await;
}

/// Test description:
#[tokio::test]
async fn sb_addr_add3() {
    run_test::<Instance<Ospfv2>>("sb-addr-add3", "topo2-1", "rt6").await;
}

/// Test description:
#[tokio::test]
async fn sb_addr_del1() {
    run_test::<Instance<Ospfv2>>("sb-addr-del1", "topo2-1", "rt2").await;
}

/// Test description:
#[tokio::test]
async fn sb_addr_del2() {
    run_test::<Instance<Ospfv2>>("sb-addr-del2", "topo2-1", "rt2").await;
}

/// Test description:
#[tokio::test]
async fn sb_addr_del3() {
    run_test::<Instance<Ospfv2>>("sb-addr-del3", "topo2-1", "rt2").await;
}

/// Test description:
#[tokio::test]
async fn sb_iface_update1() {
    run_test::<Instance<Ospfv2>>("sb-iface-update1", "topo2-1", "rt2").await;
}

/// Test description:
#[tokio::test]
async fn sb_iface_update2() {
    run_test::<Instance<Ospfv2>>("sb-iface-update2", "topo2-1", "rt2").await;
}

/// Test description:
#[tokio::test]
async fn sb_iface_update3() {
    run_test::<Instance<Ospfv2>>("sb-iface-update3", "topo2-1", "rt3").await;
}

/// Test description:
#[tokio::test]
async fn sb_iface_update4() {
    run_test::<Instance<Ospfv2>>("sb-iface-update4", "topo2-1", "rt2").await;
}

/// Test description:
#[tokio::test]
async fn sb_iface_update5() {
    run_test::<Instance<Ospfv2>>("sb-iface-update5", "topo2-1", "rt2").await;
}

/// Test description:
#[tokio::test]
async fn sb_iface_update6() {
    run_test::<Instance<Ospfv2>>("sb-iface-update6", "topo2-1", "rt2").await;
}

/// Test description:
#[tokio::test]
async fn sb_iface_update7() {
    run_test::<Instance<Ospfv2>>("sb-iface-update7", "topo2-1", "rt2").await;
}

/// Test description:
#[tokio::test]
async fn sb_router_id_update1() {
    run_test::<Instance<Ospfv2>>("sb-router-id-update1", "topo1-1", "rt2")
        .await;
}

// Test description:
//
// XXX
//
// Input:
//  * Protocol: adjacency 2.2.2.2@eth-rt2 timed out
// Output:
//  * Northbound:
//    - update self-originated Router-LSA
//    - update self-originated Network-LSA XXX
//    - schedule SPF
//    - remove neighbor 2.2.2.2 from eth-rt2
//    - unset BDR from eth-rt2
//    - update rxmt queues for the remaining neighbors
#[tokio::test]
async fn timeout_nbr1() {
    run_test::<Instance<Ospfv2>>("timeout-nbr1", "topo1-2", "rt3").await;
}

// Test description:
//
// XXX
//
// Input:
//  * Protocol: adjacency 4.4.4.4@eth-rt4 timed out
// Output:
//  * Northbound:
//    - update self-originated Router-LSA
//    - schedule SPF
//    - remove neighbor 4.4.4.4 from eth-rt4
//    - become the DR in eth-rt4 and unset the BDR
//    - update rxmt queues for the remaining neighbors
#[tokio::test]
async fn timeout_nbr2() {
    run_test::<Instance<Ospfv2>>("timeout-nbr2", "topo1-2", "rt3").await;
}
