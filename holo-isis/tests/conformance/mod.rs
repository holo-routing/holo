//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_isis::instance::Instance;
use holo_protocol::test::stub::run_test;

mod topologies;

#[tokio::test]
async fn csnp_interval1() {
    run_test::<Instance>("csnp-interval1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_csnp1() {
    run_test::<Instance>("pdu-csnp1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_csnp2() {
    run_test::<Instance>("pdu-csnp2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_csnp_error1() {
    run_test::<Instance>("pdu-csnp-error1", "topo2-2", "rt6").await;
}

#[tokio::test]
async fn pdu_csnp_error2() {
    run_test::<Instance>("pdu-csnp-error2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_csnp_error3() {
    run_test::<Instance>("pdu-csnp-error3", "topo2-1", "rt3").await;
}

#[tokio::test]
async fn pdu_psnp1() {
    run_test::<Instance>("pdu-psnp1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_psnp2() {
    run_test::<Instance>("pdu-psnp2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_psnp3() {
    run_test::<Instance>("pdu-psnp3", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_psnp4() {
    run_test::<Instance>("pdu-psnp4", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_psnp5() {
    run_test::<Instance>("pdu-psnp5", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_psnp6() {
    run_test::<Instance>("pdu-psnp6", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_psnp_error1() {
    run_test::<Instance>("pdu-psnp-error1", "topo2-2", "rt6").await;
}

#[tokio::test]
async fn pdu_psnp_error2() {
    run_test::<Instance>("pdu-psnp-error2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn pdu_psnp_error3() {
    run_test::<Instance>("pdu-psnp-error3", "topo2-1", "rt3").await;
}

#[tokio::test]
async fn pdu_decode_error1() {
    run_test::<Instance>("pdu-decode-error1", "topo2-1", "rt2").await;
}

#[tokio::test]
async fn pdu_decode_error2() {
    run_test::<Instance>("pdu-decode-error2", "topo2-1", "rt2").await;
}

#[tokio::test]
async fn pdu_decode_error3() {
    run_test::<Instance>("pdu-decode-error3", "topo2-1", "rt2").await;
}

#[tokio::test]
async fn pdu_decode_error4() {
    run_test::<Instance>("pdu-decode-error4", "topo2-1", "rt2").await;
}

#[tokio::test]
async fn pdu_decode_error5() {
    run_test::<Instance>("pdu-decode-error5", "topo2-1", "rt2").await;
}

#[tokio::test]
async fn nb_config_af1() {
    run_test::<Instance>("nb-config-af1", "topo2-1", "rt1").await;
}

#[tokio::test]
async fn nb_config_af2() {
    run_test::<Instance>("nb-config-af2", "topo2-1", "rt1").await;
}

#[tokio::test]
async fn nb_config_enabled1() {
    run_test::<Instance>("nb-config-enabled1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_enabled2() {
    run_test::<Instance>("nb-config-enabled2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_iface_af1() {
    run_test::<Instance>("nb-config-iface-af1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_iface_af2() {
    run_test::<Instance>("nb-config-iface-af2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_iface_delete1() {
    run_test::<Instance>("nb-config-iface-delete1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_iface_enabled1() {
    run_test::<Instance>("nb-config-iface-enabled1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_iface_enabled2() {
    run_test::<Instance>("nb-config-iface-enabled2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_iface_metric1() {
    run_test::<Instance>("nb-config-iface-metric1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_iface_passive1() {
    run_test::<Instance>("nb-config-iface-passive1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_metric_type1() {
    run_test::<Instance>("nb-config-metric-type1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_metric_type2() {
    run_test::<Instance>("nb-config-metric-type2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_overload1() {
    run_test::<Instance>("nb-config-overload1", "topo2-1", "rt2").await;
}

#[tokio::test]
async fn nb_config_preference1() {
    run_test::<Instance>("nb-config-preference1", "topo2-1", "rt1").await;
}

#[tokio::test]
async fn nb_config_spf_paths1() {
    run_test::<Instance>("nb-config-spf-paths1", "topo2-1", "rt1").await;
}

#[tokio::test]
async fn nb_config_te_router_id1() {
    run_test::<Instance>("nb-config-te-router-id1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn nb_config_te_router_id2() {
    run_test::<Instance>("nb-config-te-router-id2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn sb_addr_add1() {
    run_test::<Instance>("sb-addr-add1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn sb_addr_add2() {
    run_test::<Instance>("sb-addr-add2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn sb_addr_del1() {
    run_test::<Instance>("sb-addr-del1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn sb_addr_del2() {
    run_test::<Instance>("sb-addr-del2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn sb_iface_update1() {
    run_test::<Instance>("sb-iface-update1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn sb_iface_update2() {
    run_test::<Instance>("sb-iface-update2", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn sb_iface_update3() {
    run_test::<Instance>("sb-iface-update3", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn sb_hostname_update1() {
    run_test::<Instance>("sb-hostname-update1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn timeout_adj1() {
    run_test::<Instance>("timeout-adj1", "topo2-1", "rt6").await;
}

#[tokio::test]
async fn timeout_adj2() {
    run_test::<Instance>("timeout-adj2", "topo2-1", "rt2").await;
}
