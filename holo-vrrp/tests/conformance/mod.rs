//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

mod topologies;

use holo_protocol::test::stub::run_test;
use holo_vrrp::interface::Interface;

// Test description:
//
// The interface in "backup" state should transition to the "master" mode once
// the Master_Down_Timer has expired.
//
// Input:
//  * Protocol: Master_Down_Timer has expired
// Output:
//  * Protocol:
//    - Send VRRP advertisement
//    - Send gratuitous ARP
//  * Northbound: interface state transitioned to the "master" state
//  * Southbound: install the 10.0.1.5/32 address to the mvlan-vrrp-1 interface
#[tokio::test]
async fn master_down_timer1() {
    run_test::<Interface>("master-down-timer1", "vrrpv2-topo-1-1", "rt1").await;
}

#[tokio::test]
async fn master_down_timer2() {
    run_test::<Interface>("master-down-timer1", "vrrpv3-topo-1-1", "rt1").await;
}

#[tokio::test]
async fn master_down_timer3() {
    run_test::<Interface>("master-down-timer1", "vrrpv3-topo-1-2", "rt1").await;
}
