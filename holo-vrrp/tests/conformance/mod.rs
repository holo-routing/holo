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

// Input:
//  * Protocol: Master_Down_Timer expires (instance is in "backup" state)
// Output:
//  * Protocol:
//    - Send VRRP advertisement
//    - Send gratuitous ARP
//  * Northbound:
//    - Transition instance state to "master" with "new-master-reason" set to
//      "no-response"
//    - Send "vrrp-new-master-event" YANG notification
//  * Ibus: Install 10.0.1.5/32 address on the mvlan4-vrrp-1 interface
#[tokio::test]
async fn master_down_timer1() {
    run_test::<Interface>("master-down-timer1", "v2-topo1-1", "rt1").await;
}

// Input:
//  * Northbound: Add new VRRP instance with VRID 2
// Output:
//  * Northbound: New VRRP instance in "initialize" state
//  * Ibus: Create "mvlan4-vrrp-2" interface using "eth-sw1" as parent
#[tokio::test]
async fn nb_config_instance1() {
    run_test::<Interface>("nb-config-instance1", "v2-topo1-1", "rt3").await;
}

// Input:
//  * Northbound: Delete existing VRRP instance with VRID 1
// Output:
//  * Northbound: Remove VRRP instance with VRID 1
//  * Ibus: Delete "mvlan4-vrrp-1" interface
#[tokio::test]
async fn nb_config_instance2() {
    run_test::<Interface>("nb-config-instance2", "v2-topo1-1", "rt3").await;
}

// Input:
//  * Northbound: Add virtual address (10.0.1.6) to VRRP instance in "master"
//    state
// Output:
//  * Ibus: Install 10.0.1.6/32 address on mvlan4-vrrp-1 interface
#[tokio::test]
async fn nb_config_virtual_addr1() {
    run_test::<Interface>("nb-config-virtual-addr1", "v2-topo1-1", "rt3").await;
}

// Input:
//  * Northbound: Remove virtual address (10.0.1.5) from VRRP instance in
//    "master" state
// Output:
//  * Ibus: Uninstall 10.0.1.5/32 address from mvlan4-vrrp-1 interface
#[tokio::test]
async fn nb_config_virtual_addr2() {
    run_test::<Interface>("nb-config-virtual-addr2", "v2-topo1-1", "rt3").await;
}

// Input:
//  * Northbound: Add virtual address (10.0.1.6) to VRRP instance in "backup"
//    state
// Output: No changes
#[tokio::test]
async fn nb_config_virtual_addr3() {
    run_test::<Interface>("nb-config-virtual-addr3", "v2-topo1-1", "rt1").await;
}

// Input:
//  * Northbound: Remove virtual address (10.0.1.5) from VRRP instance in
//    "backup" state
// Output: No changes
#[tokio::test]
async fn nb_config_virtual_addr4() {
    run_test::<Interface>("nb-config-virtual-addr4", "v2-topo1-1", "rt1").await;
}

// Input:
//  * Protocol: Received VRRP advertisement with invalid VRRP version field
// Output:
//  * Northbound: Send "vrrp-protocol-error-event" YANG notification with
//    "protocol-error-reason" set to "version-error"
#[tokio::test]
async fn packet_error1() {
    run_test::<Interface>("packet-error1", "v2-topo1-1", "rt2").await;
}

// Input:
//  * Protocol: Received VRRP advertisement with invalid advertisement
//    interval
// Output:
//  * Northbound: Send "vrrp-virtual-router-error-event" YANG notification with
//    "virtual-router-error-reason" set to "interval-error"
#[tokio::test]
async fn packet_error2() {
    run_test::<Interface>("packet-error2", "v2-topo1-1", "rt2").await;
}

// Input:
//  * Protocol: Received VRRP advertisement for unknown VRID
// Output:
//  * Northbound: Send "vrrp-protocol-error-event" YANG notification with
//    "protocol-error-reason" set to "vrid-error"
#[tokio::test]
async fn packet_error3() {
    run_test::<Interface>("packet-error3", "v2-topo1-1", "rt2").await;
}

// Input:
//  * Protocol: Received VRRP advertisement with priority 0
// Output:
//  * Protocol: Send VRRP advertisement
#[tokio::test]
async fn packet1() {
    run_test::<Interface>("packet1", "v2-topo1-1", "rt3").await;
}

// Input:
//  * Protocol: Received VRRP advertisement from 10.0.1.2 with priority 1
//    (lower than configured priority)
// Output: No changes
#[tokio::test]
async fn packet2() {
    run_test::<Interface>("packet2", "v2-topo1-1", "rt3").await;
}

// Input:
//  * Protocol: Received VRRP advertisement from 10.0.1.2 with priority 100
//    (higher than configured priority)
// Output:
//  * Northbound: Transition instance state to "backup"
//  * Ibus: Uninstall 10.0.1.5/32 address from mvlan4-vrrp-1 interface
#[tokio::test]
async fn packet3() {
    run_test::<Interface>("packet3", "v2-topo1-1", "rt3").await;
}

// Input:
//  * Ibus: "eth-sw1" operational status is down
// Output:
//  * Northbound: Transition instance state to "initialize"
#[tokio::test]
async fn ibus_iface_update1() {
    run_test::<Interface>("ibus-iface-update1", "v2-topo1-1", "rt3").await;
}

// Input:
//  * Ibus: "mvlan4-vrrp-1" operational status is down
// Output:
//  * Northbound: Transition instance state to "initialize"
#[tokio::test]
async fn ibus_iface_update2() {
    run_test::<Interface>("ibus-iface-update2", "v2-topo1-1", "rt3").await;
}
