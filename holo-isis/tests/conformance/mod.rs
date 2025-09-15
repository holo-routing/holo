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
//  * Protocol: the refresh timer for L2 LSP 0000.0000.0004.00-00 has expired
// Output:
//  * Protocol: send LSP 0000.0000.0004.00-00 to all L2 adjacencies
//  * Northbound: add 0000.0000.0004.00-00 to the SRM list of all L2 adjacencies
#[tokio::test]
async fn lsp_refresh1() {
    run_test::<Instance>("lsp-refresh1", "topo2-2", "rt4").await;
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
//  * Protocol: received an L1 CSNP with an invalid maximum area addresses
//    value (4)
// Output:
//  * Northbound: send a "max-area-addresses-mismatch" YANG notification
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
//  * Protocol: received an LSP (0000.0000.0009.00-00) from eth-rt6 that doesn't
//    exist in the database
// Output:
//  * Protocol: send LSP 0000.0000.0009.00-00 to all other adjacencies
//  * Northbound:
//    - add 0000.0000.0009.00-00 to the database
//    - add 0000.0000.0009.00-00 to the SSN list of eth-rt6
//    - add 0000.0000.0009.00-00 to the SRM list of all other adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
#[tokio::test]
async fn pdu_lsp1() {
    run_test::<Instance>("pdu-lsp1", "topo2-1", "rt4").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0009.00-00) from eth-rt6 that doesn't
//    exist in the database
// Output:
//  * Protocol: send LSP 0000.0000.0009.00-00 to all other adjacencies
//  * Northbound:
//    - add 0000.0000.0009.00-00 to the database
//    - add 0000.0000.0009.00-00 to the SSN list of eth-rt6
//    - add 0000.0000.0009.00-00 to the SRM list of all other adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
//
// Input:
//  * Protocol: received three PSNPs with one LSP entry (0000.0000.0009.00-00)
//    that exists in the database with the same sequence number and checksum
// Output:
//  * Northbound: remove 0000.0000.0009.00-00 from the SRM list of eth-rt2-1,
//    eth-rt2-2, and eth-rt5
//
// Input:
//  * Protocol: received an LSP (0000.0000.0009.00-00) from eth-rt6 that is more
//    recent than the one in the database
// Output:
//  * Northbound:
//    - add 0000.0000.0009.00-00 to the SRM list of eth-rt2-1, eth-rt2-2, and
//      eth-rt5
//    - send an "lsp-received" YANG notification
#[tokio::test]
async fn pdu_lsp2() {
    run_test::<Instance>("pdu-lsp2", "topo2-1", "rt4").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0009.00-00) from eth-rt6 that doesn't
//    exist in the database
// Output:
//  * Protocol: send LSP 0000.0000.0009.00-00 to all other adjacencies
//  * Northbound:
//    - add 0000.0000.0009.00-00 to the database
//    - add 0000.0000.0009.00-00 to the SSN list of eth-rt6
//    - add 0000.0000.0009.00-00 to the SRM list of all other adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
//
// Input:
//  * Protocol: received an LSP (0000.0000.0009.00-00) from eth-rt6 that is
//    older than the one in the database
// Output:
//  * Northbound:
//    - add 0000.0000.0009.00-00 to the SRM list of eth-rt6
//    - remove 0000.0000.0009.00-00 from the SSN list of eth-rt6
//    - send an "lsp-received" YANG notification
#[tokio::test]
async fn pdu_lsp3() {
    run_test::<Instance>("pdu-lsp3", "topo2-1", "rt4").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0009.00-00) from eth-rt6 that doesn't
//    exist in the database
// Output:
//  * Protocol: send LSP 0000.0000.0009.00-00 to all other adjacencies
//  * Northbound:
//    - add 0000.0000.0009.00-00 to the database
//    - add 0000.0000.0009.00-00 to the SSN list of eth-rt6
//    - add 0000.0000.0009.00-00 to the SRM list of all other adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
//
// Input:
//  * Protocol: received three PSNPs with one LSP entry (0000.0000.0009.00-00)
//    that exists in the database with the same sequence number and checksum
// Output:
//  * Northbound: remove 0000.0000.0009.00-00 from the SRM list of eth-rt2-1,
//    eth-rt2-2, and eth-rt5
//
// Input:
//  * Protocol: received an LSP (0000.0000.0009.00-00) from eth-rt6 that is
//    equal to the one in the database
// Output:
//  * Northbound: send an "lsp-received" YANG notification
#[tokio::test]
async fn pdu_lsp4() {
    run_test::<Instance>("pdu-lsp4", "topo2-1", "rt4").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0009.00-00) with zero remaining
//    lifetime from eth-rt6 that doesn't exist in the database
// Output:
//  * Protocol: send an acknowledgement back
//  * Northbound: send an "lsp-received" YANG notification
#[tokio::test]
async fn pdu_lsp5() {
    run_test::<Instance>("pdu-lsp5", "topo2-1", "rt4").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0006.00-00) from eth-rt6
//    without the ATT bit set
// Output:
//  * Northbound:
//    - update 0000.0000.0006.00-00 without the ATT bit set
//    - add 0000.0000.0006.00-00 to the SSN list of eth-rt6
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: remove IPv4 and IPv6 default routes from the RIB
//  * Ibus: uninstall the IPv4 and IPv6 default routes
#[tokio::test]
async fn pdu_lsp_att_bit1() {
    run_test::<Instance>("pdu-lsp-att-bit1", "topo1-2", "rt7").await;
}

// Input:
//  * Protocol: received an L1 LSP with an invalid maximum area addresses
//    value (4)
// Output:
//  * Northbound: send a "max-area-addresses-mismatch" YANG notification
#[tokio::test]
async fn pdu_lsp_error1() {
    run_test::<Instance>("pdu-lsp-error1", "topo2-2", "rt6").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0005.00-00) from eth-rt5
//    with zero remaining lifetime
// Output:
//  * Protocol: send LSP 0000.0000.0005.00-00 to eth-rt4
//  * Northbound:
//    - update 0000.0000.0005.00-00 with zero remaining lifetime
//    - add 0000.0000.0005.00-00 to the SSN list of eth-rt5
//    - add 0000.0000.0005.00-00 to the SRM list of eth-rt4
//    - remove the hostname mapping for 0000.0000.0005
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound:
//    - remove rt5's local networks from the local RIB
//    - update all routes in the local RIB to use eth-rt4 instead of eth-rt5
//  * Ibus:
//    - uninstall rt5's local networks
//    - reinstall all routes using eth-rt4 instead of eth-rt5
#[tokio::test]
async fn pdu_lsp_expiration1() {
    run_test::<Instance>("pdu-lsp-expiration1", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0005.00-00) from eth-rt5
//    containing a new value ("rt-500") for the hostname TLV
// Output:
//  * Protocol: send LSP 0000.0000.0005.00-00 to eth-rt5
//  * Northbound:
//    - update the dynamic-hostname TLV in 0000.0000.0005.00-00 with the new
//      value
//    - update the hostname mapping for 0000.0000.0005 with the new value
//    - add 0000.0000.0005.00-00 to the SSN list of eth-rt5
//    - add 0000.0000.0005.00-00 to the SRM list of eth-rt4
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
//
// Input:
//  * Protocol: received an LSP (0000.0000.0005.00-00) from eth-rt5
//    removing the hostname TLV
// Output:
//  * Protocol: send LSP 0000.0000.0005.00-00 to eth-rt5
//  * Northbound:
//    - remove the dynamic-hostname TLV in 0000.0000.0005.00-00
//    - remove the hostname mapping for 0000.0000.0005
//    - send an "lsp-received" YANG notification
#[tokio::test]
async fn pdu_lsp_hostname1() {
    run_test::<Instance>("pdu-lsp-hostname1", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received an LSP (0000.0000.0005.00-00) from eth-rt5
//    with the Overload bit set
// Output:
//  * Protocol: send LSP 0000.0000.0005.00-00 to eth-rt4
//  * Northbound:
//    - update 0000.0000.0005.00-00 with the Overload bit set
//    - add 0000.0000.0005.00-00 to the SSN list of eth-rt5
//    - add 0000.0000.0005.00-00 to the SRM list of eth-rt4
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt5 instead of
//    eth-rt4
//  * Ibus: reinstall all routes using eth-rt5 instead of eth-rt4
#[tokio::test]
async fn pdu_lsp_overload1() {
    run_test::<Instance>("pdu-lsp-overload1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: enable purge originator for the instance
// Output: no changes
//
// Input:
//  * Protocol: LSP 0000.0000.0007.00-00 has expired in the database
// Output:
//  * Protocol: send the expired LSP to the 0000.0000.0002 adjacency
//  * Northbound:
//    - set the remaining lifetime of the expired LSP to zero
//    - remove all TLVs from the expired LSP, then add POI and Hostname TLVs
//    - add the expired LSP to the SRM list of the 0000.0000.0002 adjacency
//    - remove the hostname mapping for 0000.0000.0007
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
#[tokio::test]
async fn pdu_lsp_purge_originator1() {
    run_test::<Instance>("pdu-lsp-purge-originator1", "topo1-1", "rt1").await;
}

// Input:
//  * Northbound: enable purge originator for the instance
// Output: no changes
//
// Input:
//  * Protocol: receive an LSP (0000.0000.0007.00-00) with zero remaining
//    lifetime from eth-rt1, containing no TLVs
// Output:
//  * Protocol: send the expired LSP to the 0000.0000.0003 adjacency
//  * Northbound:
//    - add POI (with two system IDs) and Hostname TLVs to the expired LSP
//    - add the expired LSP to the SSN list of the 0000.0000.0001 adjacency
//    - add the expired LSP to the SRM list of the 0000.0000.0003 adjacency
//    - remove the hostname mapping for 0000.0000.0007
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-received" YANG notification
#[tokio::test]
async fn pdu_lsp_purge_originator2() {
    run_test::<Instance>("pdu-lsp-purge-originator2", "topo1-1", "rt2").await;
}

// Input:
//  * Protocol: received a self-originated LSP (0000.0000.0006.00-01) from
//    eth-rt4 that doesn't exist in the database
// Output:
//  * Protocol: send LSP 0000.0000.0006.00-01 with zero remaining lifetime to
//    all adjacencies
//  * Northbound:
//    - add 0000.0000.0006.00-01 to the SRM list of all adjacencies
//    - send an "lsp-received" YANG notification
//    - send an "own-lsp-purge" YANG notification
#[tokio::test]
async fn pdu_lsp_self_orig1() {
    run_test::<Instance>("pdu-lsp-self-orig1", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: received a self-originated LSP (0000.0000.0006.00-00) from
//    eth-rt4 that exists in the database
// Output:
//  * Protocol: send LSP 0000.0000.0006.00-00 to all adjacencies
//  * Northbound:
//    - add 0000.0000.0006.00-00 to the SRM list of all adjacencies
//    - send an "lsp-received" YANG notification
#[tokio::test]
async fn pdu_lsp_self_orig2() {
    run_test::<Instance>("pdu-lsp-self-orig2", "topo2-1", "rt6").await;
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
//  * Protocol: received an L1 PSNP with invalid maximum area addresses
//    value (4)
// Output:
//  * Northbound: send a "max-area-addresses-mismatch" YANG notification
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
//  * Northbound: enable the extended-sequence-number feature in
//    "send-and-verify" mode on the "eth-rt2" interface
// Output: no changes
//
// Input:
//  * Protocol: received an L2 CSNP with zero LSP entries on eth-rt2
//    (seqnum = 100)
// Output:
//  * Protocol: send all L2 LSPs from the database on eth-rt2
//  * Northbound: add all L2 LSPs from the database to the SRM list of eth-rt2
//
// Input:
//  * Protocol: received an L2 CSNP with zero LSP entries on eth-rt2
//    (seqnum = missing)
// Output: no changes (PDU is discarded)
//
// Input:
//  * Protocol: received an L2 CSNP with zero LSP entries on eth-rt2
//    (seqnum = 100, replayed packet)
// Output: no changes (PDU is discarded)
//
// Input:
//  * Protocol: received an L2 CSNP with zero LSP entries on eth-rt2
//    (seqnum = 101, newer)
// Output:
//  * Protocol: send all L2 LSPs from the database on eth-rt2
#[tokio::test]
async fn pdu_ext_seqnum1() {
    run_test::<Instance>("pdu-ext-seqnum1", "topo1-1", "rt1").await;
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
//  * Ibus: uninstall all IPv4 routes
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
//  * Ibus: uninstall all IPv6 routes
#[tokio::test]
async fn nb_config_af2() {
    run_test::<Instance>("nb-config-af2", "topo2-1", "rt1").await;
}

// Input:
//  * Northbound: configure to ignore the attached bit in L1 LSPs
// Output:
//  * Northbound: remove IPv4 and IPv6 default routes from the RIB
//  * Ibus: uninstall the IPv4 and IPv6 default routes
#[tokio::test]
async fn nb_config_att_ignore1() {
    run_test::<Instance>("nb-config-att-ignore1", "topo1-2", "rt7").await;
}

// Input:
//  * Northbound: configure to suppress the ATT bit in L1 LSPs
// Output:
//  * Protocol: send an updated local LSP to 0000.0000.0007
//  * Northbound:
//    - unset the "lsp-attached-default-metric-flag" flag in the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0007 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_att_suppress1() {
    run_test::<Instance>("nb-config-att-suppress1", "topo1-2", "rt6").await;
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
//  * Ibus: uninstall all routes
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
//  * Ibus: uninstall all routes
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
//  * Northbound: enable BFD on the eth-rt4 interface
// Output:
//  * Ibus: register IPv4 and IPv6 BFD sessions on eth-rt4
//
// Input:
//  * Northbound: configure a custom BFD min-interval (500000 us) on the
//    eth-rt4 interface
// Output:
//  * Ibus: register IPv4 and IPv6 BFD sessions on eth-rt4 using the
//    new interval
//
// Input:
//  * Northbound: disable BFD on the eth-rt4 interface
// Output:
//  * Ibus: unregister IPv4 and IPv6 BFD sessions on eth-rt4
#[tokio::test]
async fn nb_config_iface_bfd1() {
    run_test::<Instance>("nb-config-iface-bfd1", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: enable BFD on the eth-rt4 interface
// Output:
//  * Ibus: register IPv4 and IPv6 BFD sessions on eth-rt4
//
// Input:
//  * Ibus: BFD sessions to rt4 on eth-rt4 are down
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - remove the 0000.0000.0004 adjacency from eth-rt4
//    - remove 0000.0000.0004 IS reachability from the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0005 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
//  * Ibus: unregister IPv4 and IPv6 BFD sessions on eth-rt4
#[tokio::test]
async fn nb_config_iface_bfd2() {
    run_test::<Instance>("nb-config-iface-bfd2", "topo2-1", "rt6").await;
}

// Input:
//  * Northbound: enable BFD on the eth-sw1 interface
// Output:
//  * Ibus: register IPv4 and IPv6 BFD sessions on eth-sw1
//
// Input:
//  * Protocol: receive an L2 LAN Hello on eth-sw1 from a new adjacency
//    (0000.0000.0009) containing the 10.0.1.9 IPv4 address
// Output:
//  * Northbound:
//    - add 0000.0000.0009 adjacency in the "init" state
//    - send an "adjacency-state-change" YANG notification
//  * Ibus: register BFD session to 10.0.1.9
//
// Input:
//  * Protocol: receive an L2 LAN Hello on eth-sw1 from the 0000.0000.0009
//    adjacency containing no IPv4 addresses
// Output:
//  * Ibus: unregister BFD session to 10.0.1.9
#[tokio::test]
async fn nb_config_iface_bfd3() {
    run_test::<Instance>("nb-config-iface-bfd3", "topo2-1", "rt1").await;
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
//  * Ibus: unsubscribe from receiving notifications about the eth-rt5
//    interface
//
// Input:
//  * Protocol: SPF_TIMER expiration for L2
// Output:
//  * Northbound: update all routes in the local RIB to use eth-rt4 instead of
//    eth-rt5
//  * Ibus: reinstall all routes using eth-rt4 instead of eth-rt5
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
//  * Ibus: reinstall all routes using eth-rt5 instead of eth-rt4
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
//  * Ibus: reinstall all routes using eth-rt5 instead of eth-rt4
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
//  * Ibus: reinstall all routes using eth-rt5 instead of eth-rt4
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
//  * Ibus: reinstall all routes using eth-rt4 instead of eth-rt5
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
//  * Northbound: configure node tag 1
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0002 adjacency
//  * Northbound:
//    - add a Router Capability TLV to the local LSP with node tag 1
//    - add the local LSP to the SRM list of the 0000.0000.0002 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Northbound: configure node tag 2
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0002 adjacency
//  * Northbound:
//    - add node tag 2 to the Router Capability TLV in the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0002 adjacency
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Northbound: remove all configured node tags (1 and 2)
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0002 adjacency
//  * Northbound:
//    - remove the Router Capability TLV from the local LSP
//    - add the local LSP to the SRM list of the 0000.0000.0002 adjacency
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_node_tags1() {
    run_test::<Instance>("nb-config-node-tags1", "topo1-1", "rt1").await;
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
//  * Ibus: reinstall all routes using the updated preference
#[tokio::test]
async fn nb_config_preference1() {
    run_test::<Instance>("nb-config-preference1", "topo2-1", "rt1").await;
}

// Input:
//  * Northbound: change the SPF maximum-paths from 16 to 1
// Output:
//  * Northbound: update all routes in the local RIB to use a single nexthop
//  * Ibus: reinstall all ECMP routes using a single nexthop
#[tokio::test]
async fn nb_config_spf_paths1() {
    run_test::<Instance>("nb-config-spf-paths1", "topo2-1", "rt1").await;
}

// Input:
//  * Northbound: enable segment routing
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - add IPv4 and IPv6 Adj-SIDs for all adjacencies to the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
//  * Ibus: install IPv4 and IPv6 Adj-SIDs for all adjacencies
//
// Input:
//  * Ibus: SR configuration update  (SRGB, SRLB and Prefix-SIDs)
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - add a Router Capability TLV including the configured SRGB and SRLB to
//      the local LSP
//    - add Prefix-SID sub-TLVs as per the configuration update
//    - add the local LSP to the SRM list of all adjacencies
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn nb_config_sr_enabled1() {
    run_test::<Instance>("nb-config-sr-enabled1", "topo1-1", "rt3").await;
}

// Input:
//  * Northbound: add a summary route (1.0.0.0/8)
// Output:
//  * Protocol: send an updated L2 local LSP to rt3
//  * Northbound:
//    - remove the 1.1.1.1/32 reachability entry from the local L2 LSP
//    - add the 1.0.0.0/8 reachability entry to the local L2 LSP
//    - add the 1.0.0.0/8 summary to the local RIB
//    - add the L2 local LSP to the SRM list for the 0000.0000.0003 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
//  * Ibus: install a blackhole route for 1.0.0.0/8 with a metric of 20
//
// Input:
//  * Northbound: set the metric for the 1.0.0.0/8 summary route to 100
// Output:
//  * Protocol: send an updated L2 local LSP to rt3
//  * Northbound:
//    - update the metric of the 1.0.0.0/8 reachability entry in the local L2
//      LSP from 20 to 100
//    - update the metric of the 1.0.0.0/8 route in the local RIB from 20 to 100
//    - send an "lsp-generation" YANG notification
//  * Ibus: install a blackhole route for 1.0.0.0/8 with a metric of 100
//
// Input:
//  * Northbound: remove the 1.0.0.0/8 summary route
// Output:
//  * Protocol: send an updated L2 local LSP to rt3
//  * Northbound:
//    - remove the 1.0.0.0/8 reachability entry from the local L2 LSP
//    - add the 1.1.1.1/32 reachability entry to the local L2 LSP
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol: L2 SPF_TIMER expiration
// Output:
//  * Northbound: remove the 1.0.0.0/8 summary from the local RIB
//  * Ibus: uninstall the blackhole route for 1.0.0.0/8
#[tokio::test]
async fn nb_config_summary1() {
    run_test::<Instance>("nb-config-summary1", "topo1-2", "rt2").await;
}

// Input:
//  * Northbound: add a summary route (1.0.0.0/8)
// Output:
//  * Protocol: send an updated L2 local LSP to rt3
//  * Northbound:
//    - remove the 1.1.1.1/32 reachability entry from the local L2 LSP
//    - add the 1.0.0.0/8 reachability entry to the local L2 LSP
//    - add the 1.0.0.0/8 summary to the local RIB
//    - add the L2 local LSP to the SRM list for the 0000.0000.0003 adjacency
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
//  * Ibus: install a blackhole route for 1.0.0.0/8 with a metric of 20
//
// Input:
//  * Protocol: receive an L1 LSP (0000.0000.0001.00-00) from eth-rt1
//    with the 1.1.1.1/32 IPv4 reachability removed
// Output:
//  * Northbound:
//    - remove the 1.1.1.1/32 reachability entry from the 0000.0000.0001.00-00
//      L1 LSP
//    - add 0000.0000.0001.00-00 to the SSN list for eth-rt1
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Protocol:
//    - L1 SPF_TIMER expiration
//    - LSP_ORIGINATE_TIMER expiration
//    - L2 SPF_TIMER expiration
// Output:
//  * Protocol: send an updated L2 local LSP to rt3
//  * Northbound:
//    - remove the 1.0.0.0/8 reachability entry from the local L2 LSP
//    - remove the 1.0.0.0/8 summary from the local RIB
//    - remove the 1.1.1.1/32 route from the local RIB
//    - send an "lsp-generation" YANG notification
//  * Ibus: uninstall the blackhole route for 1.0.0.0/8
#[tokio::test]
async fn nb_config_summary2() {
    run_test::<Instance>("nb-config-summary2", "topo1-2", "rt2").await;
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
//  * Ibus: uninstall all routes
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
//  * Ibus: reinstall all routes using eth-rt5 instead of eth-rt4
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
//  * Ibus: uninstall all routes
#[tokio::test]
async fn nb_rpc_clear_database1() {
    run_test::<Instance>("nb-rpc-clear-database1", "topo2-1", "rt6").await;
}

// Input:
//  * Ibus: new addresses (172.16.1.1/24 and fc00::1/64) added to eth-rt4
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - add the addresses to the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn ibus_addr_add1() {
    run_test::<Instance>("ibus-addr-add1", "topo2-1", "rt6").await;
}

// Input:
//  * Ibus: duplicate addresses (10.0.7.6/24 and fc00:0:0:7::6/64) added
//    to eth-rt4
// Output: no changes
#[tokio::test]
async fn ibus_addr_add2() {
    run_test::<Instance>("ibus-addr-add2", "topo2-1", "rt6").await;
}

// Input:
//  * Ibus: existing addresses (10.0.7.6/24 and fc00:0:0:7::6/64) removed
//    from eth-rt4
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - remove the addresses from the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn ibus_addr_del1() {
    run_test::<Instance>("ibus-addr-del1", "topo2-1", "rt6").await;
}

// Input:
//  * Ibus: non-existing addresses (172.16.1.1/24 and fc00::1/64) removed
//    from eth-rt4
// Output: no changes
#[tokio::test]
async fn ibus_addr_del2() {
    run_test::<Instance>("ibus-addr-del2", "topo2-1", "rt6").await;
}

// Input:
//  * Ibus: eth-rt4 operational status is down
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
//  * Ibus: reinstall all routes using eth-rt5 instead of eth-rt4
#[tokio::test]
async fn ibus_iface_update1() {
    run_test::<Instance>("ibus-iface-update1", "topo2-1", "rt6").await;
}

// Input:
//  * Ibus: eth-rt4 operational status is down
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
//  * Ibus: reinstall all routes using eth-rt5 instead of eth-rt4
//
// Input:
//  * Ibus: eth-rt4 operational status is up
// Output:
//  * Protocol: send an updated local LSP to the 0000.0000.0005 adjacency
//  * Northbound:
//    - transition the eth-rt4 interface to the "up" state
//    - add data from the eth-rt4 interface to the local LSP
//    - send an "if-state-change" YANG notification
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn ibus_iface_update2() {
    run_test::<Instance>("ibus-iface-update2", "topo2-1", "rt6").await;
}

// Input:
//  * Ibus: eth-rt4 operational status is up (was already up)
// Output: no changes
#[tokio::test]
async fn ibus_iface_update3() {
    run_test::<Instance>("ibus-iface-update3", "topo2-1", "rt6").await;
}

// Input:
//  * Ibus: hostname update ("earth")
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
//  * Ibus: hostname update ("mars")
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - update the dynamic-hostname TLV in the local LSP
//    - update the hostname mapping for 0000.0000.0006
//    - add the local LSP to the SRM list of all adjacencies
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Ibus: hostname update (none)
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - update the dynamic-hostname TLV in the local LSP
//    - update the hostname mapping for 0000.0000.0006
//    - add the local LSP to the SRM list of all adjacencies
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn ibus_hostname_update1() {
    run_test::<Instance>("ibus-hostname-update1", "topo2-1", "rt6").await;
}

// Input:
//  * Ibus:
//    - Interface eth-rt4 MSD update (16)
//    - Node MSD update (16)
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - add Node MSD (16) to the local LSP
//    - add Link MSD (16) for the eth-rt4 interface to the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn ibus_msd_update1() {
    run_test::<Instance>("ibus-msd-update1", "topo2-3", "rt6").await;
}

// Input:
//  * Northbound: configure route redistribution for directly connected routes
//    (IPv4 and IPv6)
// Output:
//  * Ibus: subscribe to route redistribution for directly connected
//    routes (IPv4 and IPv6)
//
// Input:
//  * Ibus: new redistributed routes (10.0.255.6/32 and
//    2001:db8:255::6/128)
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - add redistributed routes to the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - transition the SPF Delay FSM state from "quiet" to "short-wait"
//    - send an "lsp-generation" YANG notification
//
// Input:
//  * Ibus: redistributed routes removed (10.0.255.6/32 and
//    2001:db8:255::6/128)
// Output:
//  * Protocol: send an updated local LSP to all adjacencies
//  * Northbound:
//    - remove redistributed routes from the local LSP
//    - add the local LSP to the SRM list of all adjacencies
//    - send an "lsp-generation" YANG notification
#[tokio::test]
async fn ibus_route_redist1() {
    run_test::<Instance>("ibus-route-redist1", "topo2-1", "rt6").await;
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
//  * Ibus: reinstall all routes using eth-rt5 instead of eth-rt4
#[tokio::test]
async fn timeout_adj1() {
    run_test::<Instance>("timeout-adj1", "topo2-1", "rt6").await;
}

// Input:
//  * Protocol: LAN adjacency (0000.0000.0001) on eth-sw1 timed out
// Output:
//  * Protocol: send an updated local LSP to all other adjacencies
//  * Northbound:
//    - remove the 0000.0000.0001 adjacency from eth-sw1
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification (lsp-id = 0000.0000.0003.01-00)
#[tokio::test]
async fn timeout_adj2() {
    run_test::<Instance>("timeout-adj2", "topo2-1", "rt2").await;
}

// Input:
//  * Protocol: LAN adjacency (0000.0000.0001) on eth-sw1 timed out
// Output:
//  * Protocol: send an updated local LSP to all other adjacencies
//  * Northbound:
//    - remove the 0000.0000.0001 adjacency from eth-sw1
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification (lsp-id = 0000.0000.0003.01-00)
//
// Input:
//  * Protocol: LAN adjacency (0000.0000.0002) on eth-sw1 timed out
// Output:
//  * Protocol:
//    - send an updated local LSP to all other adjacencies
//    - send the flushed LSP 0000.0000.0003.01-00 to all other adjacencies
//  * Northbound:
//    - remove the 0000.0000.0002 adjacency from eth-sw1
//    - flush the 0000.0000.0003.01-00 pseudonode LSP
//    - remove 0000.0000.0003.01 IS reachability from the local LSP
//    - send an "adjacency-state-change" YANG notification
//    - send an "lsp-generation" YANG notification (lsp-id = 0000.0000.0003.00-00)
#[tokio::test]
async fn timeout_adj3() {
    run_test::<Instance>("timeout-adj3", "topo2-1", "rt3").await;
}
