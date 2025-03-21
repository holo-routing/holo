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

// Input:
//  * Protocol: the interval for sending L2 CSNP PDUs has expired on eth-rt4
// Output:
//  * Protocol: send an L2 CSNP containing an LSP entry for each L2 LSP in the
//    database
#[tokio::test]
async fn csnp_interval1() {
    run_test::<Instance>("csnp-interval1", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received an L2 CSNP with zero LSP entries on eth-rt4
// Output:
//  * Protocol: send all L2 LSPs from the database on eth-rt4
//  * Northbound: add all L2 LSPs from the database to the SRM list of eth-rt4
#[tokio::test]
async fn pdu_csnp1() {
    run_test::<Instance>("pdu-csnp1", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received an L2 CSNP with one LSP entry (0000.0000.0004.00-00)
//    that is more recent than the one in the database
// Output:
//  * Protocol: send all L2 LSPs from the database on eth-rt4, except for LSP
//    0000.0000.0004.00-00
//  * Northbound:
//    - add all L2 LSPs from the database to the SRM list of eth-rt4, except for
//      LSP 0000.0000.0004.00-00
//    - add 0000.0000.0004.00-00 to the SSN list of eth-rt4
#[tokio::test]
async fn pdu_csnp2() {
    run_test::<Instance>("pdu-csnp2", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received a CSNP with an invalid maximum area addresses value (4)
// Output: no changes
#[tokio::test]
async fn pdu_csnp_error1() {
    run_test::<Instance>("pdu-csnp-error1", "topo2-2", "rt6").await;
}

// Input:
//  * Protocol: received a CSNP with an incompatible PDU type (L1-CSNP-PDU on an
//    L2-only interface)
// Output: no changes
#[tokio::test]
async fn pdu_csnp_error2() {
    run_test::<Instance>("pdu-csnp-error2", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received a CSNP from an unknown source
// Output: no changes
#[tokio::test]
async fn pdu_csnp_error3() {
    run_test::<Instance>("pdu-csnp-error3", "topo2-1", "rt3").await;
}

// Input:
//  * Protocol: received a PSNP on eth-rt4 with one LSP entry
//    (0000.0000.0009.00-00) that doesn't exist in the database
// Output:
//  * Northbound:
//    - add an empty LSP 0000.0000.0009.00-00 to the database with a sequence
//      number of zero
//    - add 0000.0000.0009.00-00 to the SSN list of eth-rt4
#[tokio::test]
async fn pdu_psnp1() {
    run_test::<Instance>("pdu-psnp1", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol:
//    - received a PSNP with one LSP entry (0000.0000.0009.00-00) that doesn't
//      exist in the database, but with a remaining lifetime of zero
//    - received a PSNP with one LSP entry (0000.0000.0009.00-00) that doesn't
//      exist in the database, but with a sequence number of zero
//    - received a PSNP with one LSP entry (0000.0000.0009.00-00) that doesn't
//      exist in the database, but with a checksum of zero
// Output: no changes
#[tokio::test]
async fn pdu_psnp2() {
    run_test::<Instance>("pdu-psnp2", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received a PSNP on eth-rt4 with one LSP entry
//    (0000.0000.0004.00-00) that is more recent than the one in the database
// Output:
//  * Northbound: add 0000.0000.0004.00-00 to the SSN list of eth-rt4
#[tokio::test]
async fn pdu_psnp3() {
    run_test::<Instance>("pdu-psnp3", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received a PSNP on eth-rt4 with one LSP entry
//    (0000.0000.0004.00-00) that is older than the one in the database
// Output:
//  * Protocol: send LSP 0000.0000.0004.00-00 from the database on eth-rt4
//  * Northbound: add 0000.0000.0004.00-00 to the SRM list of eth-rt4
#[tokio::test]
async fn pdu_psnp4() {
    run_test::<Instance>("pdu-psnp4", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0009.00-00) from eth-rt4 that doesn't
//    exist in the database
// Output:
//  * Protocol: send LSP 0000.0000.0009.00-00 to eth-rt5
//  * Northbound:
//    - add 0000.0000.0009.00-00 to the database
//    - add 0000.0000.0009.00-00 to the SSN list of eth-rt4
//    - add 0000.0000.0009.00-00 to the SRM list of eth-rt5
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
//
// Input:
//  * Protocol: received a PSNP with one LSP entry (0000.0000.0009.00-00) that
//    exists in the database with the same sequence number and checksum
// Output: no changes
#[tokio::test]
async fn pdu_psnp5() {
    run_test::<Instance>("pdu-psnp5", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0009.00-00) from eth-rt4 that
//    doesn't exist in the database
// Output:
//  * Protocol: send LSP 0000.0000.0009.00-00 to eth-rt5
//  * Northbound:
//    - add 0000.0000.0009.00-00 to the database
//    - add 0000.0000.0009.00-00 to the SSN list of eth-rt4
//    - add 0000.0000.0009.00-00 to the SRM list of eth-rt5
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
//
// Input:
//  * Protocol: the interval for sending PSNP PDUs has expired on eth-rt4
// Output:
//  * Protocol: send a PSNP containing a single LSP entry (0000.0000.0009.00-00)
//  * Northbound: remove 0000.0000.0009.00-00 from the SSN list of eth-rt4
//
// Input:
//  * Protocol: received a PSNP with one LSP entry (0000.0000.0009.00-00) that
//    exists in the database with the same sequence number but a different
//    checksum (LSP confusion)
// Output:
//  * Protocol: send a purged LSP 0000.0000.0009.00-00 to all adjacencies
//  * Northbound:
//    - set the remaining lifetime of 0000.0000.0009.00-00 to zero
//    - add 0000.0000.0009.00-00 to the SRM list of eth-rt4
#[tokio::test]
async fn pdu_psnp6() {
    run_test::<Instance>("pdu-psnp6", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received a PSNP with invalid maximum area addresses (4)
// Output: no changes
#[tokio::test]
async fn pdu_psnp_error1() {
    run_test::<Instance>("pdu-psnp-error1", "topo2-2", "rt6").await;
}

// Input:
//  * Protocol: received a PSNP with an incompatible PDU type (L1-PSNP-PDU on an
//    L2-only interface)
// Output: no changes
#[tokio::test]
async fn pdu_psnp_error2() {
    run_test::<Instance>("pdu-psnp-error2", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received a PSNP from an unknown source
// Output: no changes
#[tokio::test]
async fn pdu_psnp_error3() {
    run_test::<Instance>("pdu-psnp-error3", "topo2-1", "rt3").await;
}

// Input:
//  * Protocol: received a PDU with an invalid version (2)
// Output:
//  * Northbound: send a "version-skew" YANG notification
#[tokio::test]
async fn pdu_decode_error1() {
    run_test::<Instance>("pdu-decode-error1", "topo2-1", "rt2").await;
}

// Input:
//  * Protocol: received a PDU with an invalid ID length (8)
// Output:
//  * Northbound: send an "id-len-mismatch" YANG notification
#[tokio::test]
async fn pdu_decode_error2() {
    run_test::<Instance>("pdu-decode-error2", "topo2-1", "rt2").await;
}

// Input:
//  * Protocol: received a PDU with an authentication type mismatch
// Output:
//  * Northbound: send an "authentication-type-failure" YANG notification
#[tokio::test]
async fn pdu_decode_error3() {
    run_test::<Instance>("pdu-decode-error3", "topo2-1", "rt2").await;
}

// Input:
//  * Protocol: received a PDU with an authentication error
// Output:
//  * Northbound: send an "authentication-failure" YANG notification
#[tokio::test]
async fn pdu_decode_error4() {
    run_test::<Instance>("pdu-decode-error4", "topo2-1", "rt2").await;
}

// Input:
//  * Protocol: received PDUs with other decoding errors
// Output: no changes
#[tokio::test]
async fn pdu_decode_error5() {
    run_test::<Instance>("pdu-decode-error5", "topo2-1", "rt2").await;
}

// Input:
//  * Northbound: disable the IPv4 address family for the instance
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - remove all IPv4 data from the local LSP
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: remove all IPv4 routes from the local RIB
//  * Southbound: uninstall all IPv4 routes
#[tokio::test]
async fn nb_config_af1() {
    run_test::<Instance>("nb-config-af1", "topo2-1", "rt1").await;
}

// Input:
//  * Northbound: disable the IPv6 address family for the instance
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - remove all IPv6 data from the local LSP
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: remove all IPv6 routes from the local RIB
//  * Southbound: uninstall all IPv6 routes
#[tokio::test]
async fn nb_config_af2() {
    run_test::<Instance>("nb-config-af2", "topo2-1", "rt1").await;
}

// Input:
//  * Northbound: disable the IS-IS instance
// Output:
//  * Northbound:
//    - remove all adjacencies
//    - transition all interfaces to the "down" state
//    - clear the local RIB and LSDBs
//    - send "if-state-change" YANG notifications
//    - send "adjacency-state-change" YANG notifications
//  * Southbound: uninstall all routes
#[tokio::test]
async fn nb_config_enabled1() {
    run_test::<Instance>("nb-config-enabled1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: disable the IS-IS instance
// Output:
//  * Northbound:
//    - remove all adjacencies
//    - transition all interfaces to the "down" state
//    - clear the local RIB and LSDBs
//    - send "if-state-change" YANG notifications
//    - send "adjacency-state-change" YANG notifications
//  * Southbound: uninstall all routes
//
// Input:
//  * Northbound: enable the IS-IS instance
// Output:
//  * Northbound:
//    - transition all interfaces to the "up" state
//    - add the local LSP to the LSDB
//    - send "if-state-change" YANG notifications
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_enabled2() {
    run_test::<Instance>("nb-config-enabled2", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: disable the IPv4 address family for the "lo" interface
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - remove IPv4 data from the "lo" interface in the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_iface_af1() {
    run_test::<Instance>("nb-config-iface-af1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: disable the IPv6 address family for the "lo" interface
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - remove IPv6 data from the "lo" interface in the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_iface_af2() {
    run_test::<Instance>("nb-config-iface-af2", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: delete the eth-rt5 interface
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0004 adjacency
//  * Northbound:
//    - remove all data associated with the eth-rt5 interface
//    - add the local LSP to the SRM list of the 0000.0000.0004 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "if-state-change" YANG notification
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
//  * Southbound: unsubscribe from receiving notifications about the eth-rt5
//    interface
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt4 instead of
//    eth-rt5
//  * Southbound: reinstall all routes using eth-rt4 instead of eth-rt5
#[tokio::test]
async fn nb_config_iface_delete1() {
    run_test::<Instance>("nb-config-iface-delete1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: disable the eth-rt4 interface
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - transition the eth-rt4 interface to the "down" state
//    - remove the 0000.0000.0004 adjacency from eth-rt4
//    - remove data from the eth-rt4 interface in the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0005 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "if-state-change" YANG notification
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt5 instead of
//    eth-rt4
//  * Southbound: reinstall all routes using eth-rt5 instead of eth-rt4
#[tokio::test]
async fn nb_config_iface_enabled1() {
    run_test::<Instance>("nb-config-iface-enabled1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: disable the eth-rt4 interface
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - transition the eth-rt4 interface to the "down" state
//    - remove the 0000.0000.0004 adjacency from eth-rt4
//    - remove data from the eth-rt4 interface in the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0005 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "if-state-change" YANG notification
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt5 instead of
//    eth-rt4
//  * Southbound: reinstall all routes using eth-rt5 instead of eth-rt4
//
// Input:
//  * Northbound: enable the eth-rt4 interface
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - transition the eth-rt4 interface to the "up" state
//    - add data from the eth-rt4 interface to the local LSP
//    - send an "if-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_iface_enabled2() {
    run_test::<Instance>("nb-config-iface-enabled2", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: change the eth-rt4 metric from 10 to 50
// Output:
//  * Northbound:
//    - update the local LSP with the new metric for the eth-rt4 interface
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//  * Protocol: send an updated local LSP to all adjacencies
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt5 instead of
//    eth-rt4
//  * Southbound: reinstall all routes using eth-rt5 instead of eth-rt4
#[tokio::test]
async fn nb_config_iface_metric1() {
    run_test::<Instance>("nb-config-iface-metric1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: configure eth-rt5 as passive
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0004 adjacency
//  * Northbound:
//    - remove the 0000.0000.0005 adjacency from eth-rt5
//    - remove 0000.0000.0005 IS reachability from the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0004 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send "if-state-change" YANG notifications
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt4 instead of
//    eth-rt5
//  * Southbound: reinstall all routes using eth-rt4 instead of eth-rt5
#[tokio::test]
async fn nb_config_iface_passive1() {
    run_test::<Instance>("nb-config-iface-passive1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: change the metric type from old-only to wide-only
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - update IS/IP reachability TLVs in the local LSP to use the configured
//      metric style
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_metric_type1() {
    run_test::<Instance>("nb-config-metric-type1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: change the metric type from old-only to both
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - update IS/IP reachability TLVs in the local LSP to use the configured
//      metric style
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_metric_type2() {
    run_test::<Instance>("nb-config-metric-type2", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: change the overload status from false to true
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - set the "lsp-overload-flag" flag in the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send a "database-overload" YANG notification
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_overload1() {
    run_test::<Instance>("nb-config-overload1", "topo2-1", "rt2").await;
}

// Input:
//  * Northbound: change the route preference from 115 to 50
// Output:
//  * Southbound: reinstall all routes using the updated preference
#[tokio::test]
async fn nb_config_preference1() {
    run_test::<Instance>("nb-config-preference1", "topo2-1", "rt1").await;
}

// Input:
//  * Northbound: change the SPF maximum-paths from 16 to 1
// Output:
//  * Northbound: update all routes in the local RIB to use a single nexthop
//  * Southbound: reinstall all ECMP routes using a single nexthop
#[tokio::test]
async fn nb_config_spf_paths1() {
    run_test::<Instance>("nb-config-spf-paths1", "topo2-1", "rt1").await;
}

// Input:
//  * Northbound: configure a TE IPv4 Router ID of 6.6.6.6
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - add the "ipv4-te-routerid" TLV to the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_te_router_id1() {
    run_test::<Instance>("nb-config-te-router-id1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: configure a TE IPv6 Router ID of 2001:db8:1000::6
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - add the "ipv6-te-routerid" TLV to the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_te_router_id2() {
    run_test::<Instance>("nb-config-te-router-id2", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: "ietf-isis:clear-adjacency" RPC
// Output:
//  * Northbound:
//    - remove all adjacencies
//    - remove IS reachability TLVs from the local LSP
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send "adjacency-state-change" YANG notifications
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: remove all routes from the local RIB
//  * Southbound: uninstall all routes
#[tokio::test]
async fn nb_rpc_clear_adjacency1() {
    run_test::<Instance>("nb-rpc-clear-adjacency1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: "ietf-isis:clear-adjacency" RPC with the "interface" input
//    option set to eth-rt4
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - remove the 0000.0000.0004 adjacency from eth-rt4
//    - remove 0000.0000.0004 IS reachability from the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0005 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt5 instead of
//    eth-rt4
//  * Southbound: reinstall all routes using eth-rt5 instead of eth-rt4
#[tokio::test]
async fn nb_rpc_clear_adjacency2() {
    run_test::<Instance>("nb-rpc-clear-adjacency2", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: "ietf-isis:clear-database" RPC
// Output:
//  * Northbound:
//    - remove all adjacencies
//    - remove all LSPs from the database and add a new local LSP
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - clear the LSDBs
//    - send "adjacency-state-change" YANG notifications
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: remove all routes from the local RIB
//  * Southbound: uninstall all routes
#[tokio::test]
async fn nb_rpc_clear_database1() {
    run_test::<Instance>("nb-rpc-clear-database1", "topo2-1", "rt6").await;
}

// Input:
//  * Southbound: new addresses (172.16.1.1/24 and fc00::1/64) added to eth-rt4
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - add the addresses to the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn sb_addr_add1() {
    run_test::<Instance>("sb-addr-add1", "topo2-1", "rt6").await;
}

// Input:
//  * Southbound: duplicate addresses (10.0.7.6/24 and fc00:0:0:7::6/64) added
//    to eth-rt4
// Output: no changes
#[tokio::test]
async fn sb_addr_add2() {
    run_test::<Instance>("sb-addr-add2", "topo2-1", "rt6").await;
}

// Input:
//  * Southbound: existing addresses (10.0.7.6/24 and fc00:0:0:7::6/64) removed
//    from eth-rt4
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - remove the addresses from the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn sb_addr_del1() {
    run_test::<Instance>("sb-addr-del1", "topo2-1", "rt6").await;
}

// Input:
//  * Southbound: non-existing addresses (172.16.1.1/24 and fc00::1/64) removed
//    from eth-rt4
// Output: no changes
#[tokio::test]
async fn sb_addr_del2() {
    run_test::<Instance>("sb-addr-del2", "topo2-1", "rt6").await;
}

// Input:
//  * Southbound: eth-rt4 operational status is down
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - transition the eth-rt4 interface to the "down" state
//    - remove the 0000.0000.0004 adjacency from eth-rt4
//    - remove data from the eth-rt4 interface in the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0005 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "if-state-change" YANG notification
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt5 instead of
//    eth-rt4
//  * Southbound: reinstall all routes using eth-rt5 instead of eth-rt4
#[tokio::test]
async fn sb_iface_update1() {
    run_test::<Instance>("sb-iface-update1", "topo2-1", "rt6").await;
}

// Input:
//  * Southbound: eth-rt4 operational status is down
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - transition the eth-rt4 interface to the "down" state
//    - remove the 0000.0000.0004 adjacency from eth-rt4
//    - remove data from the eth-rt4 interface in the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0005 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "if-state-change" YANG notification
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt5 instead of
//    eth-rt4
//  * Southbound: reinstall all routes using eth-rt5 instead of eth-rt4
//
// Input:
//  * Southbound: eth-rt4 operational status is up
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - transition the eth-rt4 interface to the "up" state
//    - add data from the eth-rt4 interface to the local LSP
//    - send an "if-state-change" YANG notification
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn sb_iface_update2() {
    run_test::<Instance>("sb-iface-update2", "topo2-1", "rt6").await;
}

// Input:
//  * Southbound: eth-rt4 operational status is up (was already up)
// Output: no changes
#[tokio::test]
async fn sb_iface_update3() {
    run_test::<Instance>("sb-iface-update3", "topo2-1", "rt6").await;
}

// Input:
//  * Southbound: hostname update ("earth")
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - update the dynamic-hostname TLV in the local LSP
//    - update the hostname mapping for 0000.0000.0006
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Southbound: hostname update ("mars")
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - update the dynamic-hostname TLV in the local LSP
//    - update the hostname mapping for 0000.0000.0006
//    - add the local LSP to the SRM list of all adjacencies
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Southbound: hostname update (none)
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - update the dynamic-hostname TLV in the local LSP
//    - update the hostname mapping for 0000.0000.0006
//    - add the local LSP to the SRM list of all adjacencies
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn sb_hostname_update1() {
    run_test::<Instance>("sb-hostname-update1", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: point-to-point adjacency on eth-rt4 timed out
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - remove the 0000.0000.0004 adjacency from eth-rt4
//    - remove 0000.0000.0004 IS reachability from the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0005 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt5 instead of
//    eth-rt4
//  * Southbound: reinstall all routes using eth-rt5 instead of eth-rt4
#[tokio::test]
async fn timeout_adj1() {
    run_test::<Instance>("timeout-adj1", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: LAN adjacency (0000.0000.0001) on eth-sw1 timed out
// Output:
//  * Northbound:
//    - remove the 0000.0000.0001 adjacency from eth-rt4
//    - send an "adjacency-state-change" YANG notification
#[tokio::test]
async fn timeout_adj2() {
    run_test::<Instance>("timeout-adj2", "topo2-1", "rt2").await;
}
