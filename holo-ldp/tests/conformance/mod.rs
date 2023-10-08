//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod topologies;

use holo_ldp::instance::Instance;
use holo_protocol::test::stub::run_test;

// Test description:
//
// Received LDP Address messages should be rejected if the neighbor's state
// isn't OPERATIONAL.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.10 (new neighbor)
//  * Protocol: Accepted TCP connection from 10.0.1.10
//  * Protocol: LDP Address message from 10.0.1.10
// Output:
//  * Protocol: LDP Notification message (Shutdown) to 10.10.10.10
//  * Northbound:
//    - new adjacency
//    - new neighbor in the NON EXISTENT state
#[tokio::test]
async fn message_addr1() {
    run_test::<Instance>("message-addr1", "topo2-1", "rt2").await;
}

// Test description:
//
// Received LDP Address messages should prompt the activation of previously
// received label mappings from the same peer.
//
// Input:
//  * Protocol: LDP Address Withdraw message from 4.4.4.4 (address list:
//    [10.0.3.4])
// Output:
//  * Northbound:
//    - removed address binding received from 4.4.4.4
//    - updated statistics
//  * Southbound: uninstall all labels learned from 4.4.4.4 and mapped to the
//    10.0.3.4 nexthop
//
// Input:
//  * Protocol: LDP Address message from 4.4.4.4 (address list: [10.0.3.4])
// Output:
//  * Northbound:
//    - new address binding received from 4.4.4.4
//    - updated statistics
//  * Southbound: install all labels learned from 4.4.4.4 and mapped to the
//    10.0.3.4 nexthop
#[tokio::test]
async fn message_addr2() {
    run_test::<Instance>("message-addr2", "topo2-1", "rt2").await;
}

// Test description:
//
// Received LDP Address Withdraw messages should be rejected if the neighbor's
// state isn't OPERATIONAL.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.10 (new neighbor)
//  * Protocol: Accepted TCP connection from 10.0.1.10
//  * Protocol: LDP Address Withdraw message from 10.0.1.10
// Output:
//  * Protocol: LDP Notification message (Shutdown) to 10.10.10.10
//  * Northbound:
//    - new adjacency
//    - new neighbor in the NON EXISTENT state
#[tokio::test]
async fn message_addr_withdraw1() {
    run_test::<Instance>("message-addr-withdraw1", "topo2-1", "rt2").await;
}

// Test description:
//
// Received LDP Address Withdraw messages should prompt the deactivation of
// previously received label mappings from the same peer.
//
// Input:
//  * Protocol: LDP Address Withdraw message from 4.4.4.4 (address list:
//    [10.0.3.4])
// Output:
//  * Northbound:
//    - removed address binding received from 4.4.4.4
//    - updated statistics
//  * Southbound: uninstall all labels learned from 4.4.4.4 and mapped to the
//    10.0.3.4 nexthop
#[tokio::test]
async fn message_addr_withdraw2() {
    run_test::<Instance>("message-addr-withdraw2", "topo2-1", "rt2").await;
}

// Test description:
//
// Fatal errors corresponding to the receipt of malformed PDUs or messages
// should cause the corresponding session to be torn down.
//
// Input:
//  * Protocol: LDP message with invalid LDP version (2) from 3.3.3.3
// Output:
//  * Protocol: LDP Notification message (Bad Protocol Version) to 3.3.3.3
//  * Northbound:
//    - neighbor 3.3.3.3 transitioned from OPERATIONAL to NON EXISTENT
//    - removed all address and label bindings learned from 3.3.3.3
//    - updated statistics
//  * Southbound: uninstall all labels learned from 3.3.3.3
#[tokio::test]
async fn message_decode_error1() {
    run_test::<Instance>("message-decode-error1", "topo2-1", "rt2").await;
}

// Test description:
//
// Non-fatal errors corresponding to the receipt of malformed PDUs or messages
// should prompt the transmission of an advisory notification to the peer.
//
// Input:
//  * Protocol: Unknown LDP message from 3.3.3.3
// Output:
//  * Protocol: LDP Notification message (Unknown Message Type) to 3.3.3.3
#[tokio::test]
async fn message_decode_error2() {
    run_test::<Instance>("message-decode-error2", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a LDP Link Hello message should cause the creation of a new LDP
// link adjacency.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.10 (new neighbor)
// Output:
//  * Northbound:
//    - new adjacency
//    - new neighbor in the NON EXISTENT state
#[tokio::test]
async fn message_hello1() {
    run_test::<Instance>("message-hello1", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a LDP Targeted Hello message should cause the creation of a new
// LDP targeted adjacency.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.4 (rt4)
// Output:
//  * Northbound: new adjacency to existing neighbor (rt4)
#[tokio::test]
async fn message_hello2() {
    run_test::<Instance>("message-hello2", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a LDP Hello message indicating an LSR-ID change should cause the
// corresponding session to be torn down.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.1 (rt1) containing a different
//    LSR-ID
// Output:
//  * Protocol: LDP Notification message (Shutdown) to 1.1.1.1
//  * Northbound:
//    - neighbor 1.1.1.1 transitioned from OPERATIONAL to NON EXISTENT
//    - removed all address and label bindings learned from 1.1.1.1
//    - updated statistics
//  * Southbound: uninstall all labels learned from 1.1.1.1
#[tokio::test]
async fn message_hello3() {
    run_test::<Instance>("message-hello3", "topo2-1", "rt2").await;
}

// Test description:
//
// Receiving LDP Initialization messages while in the OPERATIONAL state should
// cause the neighborship to be torned down.
//
// Input:
//  * Protocol: Initialization message from rt1
// Output:
//  * Protocol: LDP Notification message (Shutdown) to rt1
//  * Northbound:
//    - neighbor rt1 transitioned from OPERATIONAL to NON EXISTENT
//    - removed all address and label bindings learned from rt1
//    - updated statistics
//  * Southbound: uninstall all labels learned from rt1
#[tokio::test]
async fn message_init1() {
    run_test::<Instance>("message-init1", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of an invalid Initialization message should be rejected.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.10 (new neighbor)
//  * Protocol: Established TCP connection to 1.1.1.10
//  * Protocol: Initialization message from 1.1.1.10 w/ invalid LSR-ID
// Output:
//  * Protocol: LDP Notification message (Session Rejected/No Hello) to 1.1.1.10
//  * Northbound: new adjacency
#[tokio::test]
async fn message_init2() {
    run_test::<Instance>("message-init2", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a valid Initialization message should prompt the creation of a new
// neighbor.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.10 (new neighbor)
//  * Protocol: Established TCP connection to 1.1.1.10
//  * Protocol: Initialization message from 1.1.1.10 w/ valid LSR-ID
// Output:
//  * Protocol: LDP Initialization and LDP KeepAlive to 1.1.1.10
//  * Northbound:
//    - new adjacency
//    - new neighbor in the OPENREC state
#[tokio::test]
async fn message_init3() {
    run_test::<Instance>("message-init3", "topo2-1", "rt2").await;
}

// Test description:
//
// Received LDP Label Mapping messages should be rejected if the neighbor's
// state isn't OPERATIONAL.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.10 (new neighbor)
//  * Protocol: Accepted TCP connection from 10.0.1.10
//  * Protocol: LDP Label Mapping message from 10.0.1.10
// Output:
//  * Protocol: LDP Notification message (Shutdown) to 10.10.10.10
//  * Northbound:
//    - new adjacency
//    - new neighbor in the NON EXISTENT state
#[tokio::test]
async fn message_label_mapping1() {
    run_test::<Instance>("message-label-mapping1", "topo2-1", "rt2").await;
}

// Test description:
//
// Received LDP Label Mapping for an unknown route should be recorded in the
// LIB.
//
// Input:
//  * Protocol: LDP Label Mapping message from rt4 for 192.168.1.0/24
// Output:
//  * Northbound: new received label mapping from rt4
#[tokio::test]
async fn message_label_mapping2() {
    run_test::<Instance>("message-label-mapping2", "topo2-1", "rt2").await;
}

// Test description:
//
// Received LDP Label Mapping for a known route should prompt the installation
// of the advertised label.
//
// Input:
//  * Southbound: new route (192.168.1.0/24 nexthops [10.0.1.1])
// Output:
//  * Protocol: Label Mapping Message to all peers advertising a non-null label
//  * Northbound: new advertised label mappings
//
// Input:
//  * Protocol: LDP Label Mapping message from rt1 for 192.168.1.0/24
// Output:
//  * Northbound:
//    - new received label mapping from rt1
//    - updated statistics
//  * Southbound: install label for 192.168.1.0/24
//
#[tokio::test]
async fn message_label_mapping3() {
    run_test::<Instance>("message-label-mapping3", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a duplicate LDP Label Mapping should be ignored.
//
// Input:
//  * Protocol: LDP Label Mapping message from rt4 for 6.6.6.6/32 (label 24)
// Output: no changes
#[tokio::test]
async fn message_label_mapping4() {
    run_test::<Instance>("message-label-mapping4", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of an LDP Label Mapping containing a different label than previously
// advertised should cause the label mapping to be updated in the LIB.
//
// Input:
//  * Protocol: LDP Label Mapping message from rt4 for 6.6.6.6/32 (label 100)
// Output:
//  * Northbound: updated received label mapping from rt4 for 6.6.6.6/32
#[tokio::test]
async fn message_label_mapping5() {
    run_test::<Instance>("message-label-mapping5", "topo2-1", "rt2").await;
}

// Test description:
//
// Received LDP Label Release messages should be rejected if the neighbor's
// state isn't OPERATIONAL.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.10 (new neighbor)
//  * Protocol: Accepted TCP connection from 10.0.1.10
//  * Protocol: LDP Label Release message from 10.0.1.10
// Output:
//  * Protocol: LDP Notification message (Shutdown) to 10.10.10.10
//  * Northbound:
//    - new adjacency
//    - new neighbor in the NON EXISTENT state
#[tokio::test]
async fn message_label_release1() {
    run_test::<Instance>("message-label-release1", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of an LDP Label Release for an unknown route should be ignored.
//
// Input:
//  * Protocol: LDP Label Release message from rt4 for 10.10.10.10/32
// Output: no changes
#[tokio::test]
async fn message_label_release2() {
    run_test::<Instance>("message-label-release2", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of an LDP Label Release whose label doesn't match the corresponding
// label mapping should be ignored.
//
// Input:
//  * Protocol: LDP Label Release message from rt4 for 1.1.1.1/32 (label 100)
// Output: no changes
#[tokio::test]
async fn message_label_release3() {
    run_test::<Instance>("message-label-release3", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of an LDP Label Release message that matches the corresponding label
// mapping should cause that label mapping to be deleted.
//
// Input:
//  * Protocol: LDP Label Release message from rt4 for 1.1.1.1/32 (no label)
// Output:
//  * Northbound: removed label binding advertised to rt4 for 1.1.1.1/32
#[tokio::test]
async fn message_label_release4() {
    run_test::<Instance>("message-label-release4", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a wildcard LDP Label Release message should cause all label
// mappings advertised to the corresponding peer to be deleted.
//
// Input:
//  * Protocol: LDP Label Release message from rt4 containing a wildcard FEC (no
//    label)
// Output:
//  * Northbound: removed all label bindings advertised to rt4
#[tokio::test]
async fn message_label_release5() {
    run_test::<Instance>("message-label-release5", "topo2-1", "rt2").await;
}

// Test description:
//
// Received LDP Label Request messages should be rejected if the neighbor's
// state isn't OPERATIONAL.
//
// Input:
//  * LDP Hello message from 10.0.1.10 (new neighbor)
//  * Accepted TCP connection from 10.0.1.10
//  * LDP Label Request message from 10.0.1.10
// Output:
//  * Protocol: LDP Notification message (Shutdown) to 10.10.10.10
//  * Northbound:
//    - new adjacency
//    - new neighbor in the NON EXISTENT state
#[tokio::test]
async fn message_label_request1() {
    run_test::<Instance>("message-label-request1", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of an LDP Label Request message for an unknown route should prompt
// the transmission of an advisory notification to the peer.
//
// Input:
//  * Protocol: LDP Label Request message from rt4 for 10.10.10.10/32
// Output:
//  * Protocol: LDP Notification message (No Route) to rt4
#[tokio::test]
async fn message_label_request2() {
    run_test::<Instance>("message-label-request2", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of an LDP Label Request message for a route whose nexthop is the peer
// itself should prompt the transmission of an advisory notification to the
// peer.
//
// Input:
//  * Protocol: LDP Label Request message from rt4 for 4.4.4.4/32
// Output:
//  * Protocol: LDP Notification message (Loop Detected) to rt4
#[tokio::test]
async fn message_label_request3() {
    run_test::<Instance>("message-label-request3", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a valid LDP Label Request message should prompt the transmission
// of a Label Mapping message to the peer.
//
// Input:
//  * Protocol: LDP Label Request message from rt4 for 1.1.1.1/32
// Output:
//  * Protocol: Label Mapping Message to rt4 for 1.1.1.1/32
#[tokio::test]
async fn message_label_request4() {
    run_test::<Instance>("message-label-request4", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a wildcard LDP Label Request message should prompt the
// transmission of all local label bindings.
//
// Input:
//  * Protocol: LDP Label Request message from rt4 containing a wildcard FEC
// Output:
//  * Protocol: Label Mapping message to rt4 containing all local label bindings
#[tokio::test]
async fn message_label_request5() {
    run_test::<Instance>("message-label-request5", "topo2-1", "rt2").await;
}

// Test description:
//
// Received LDP Label Withdraw messages should be rejected if the neighbor's
// state isn't OPERATIONAL.
//
// Input:
//  * LDP Hello message from 10.0.1.10 (new neighbor)
//  * Accepted TCP connection from 10.0.1.10
//  * LDP Label Withdraw message from 10.0.1.10
// Output:
//  * Protocol: LDP Notification message (Shutdown) to 10.10.10.10
//  * Northbound:
//    - new adjacency
//    - new neighbor in the NON EXISTENT state
#[tokio::test]
async fn message_label_withdraw1() {
    run_test::<Instance>("message-label-withdraw1", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a Label Withdraw of an unused label.
//
// Input:
//  * Protocol: Label Withdraw message from rt4 for 1.1.1.1/32
// Output:
//  * Protocol: Label Release message to rt4 for 1.1.1.1/32
//  * Northbound: remove label mapping from rt4 for 1.1.1.1/32
#[tokio::test]
async fn message_label_withdraw2() {
    run_test::<Instance>("message-label-withdraw2", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a Label Withdraw containing a label that doesn't match the
// previously received value.
//
// Input:
//  * Protocol: Label Withdraw message from rt4 for 4.4.4.4/32 (label 100)
// Output:
//  * Protocol: Label Release message to rt4 for 4.4.4.4/32
#[tokio::test]
async fn message_label_withdraw3() {
    run_test::<Instance>("message-label-withdraw3", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a valid Label Withdraw should cause the corresponding label to be
// uninstalled from the system.
//
// Input:
//  * Protocol: Label Withdraw message from rt4 for 4.4.4.4/32 (no label)
// Output:
//  * Protocol: Label Release message to rt4 for 4.4.4.4/32
//  * Northbound:
//    - remove label mapping from rt4 for 1.1.1.1/32
//    - updated statistics
//  * Southbound: uninstall labels received from rt4 for 4.4.4.4/32
#[tokio::test]
async fn message_label_withdraw4() {
    run_test::<Instance>("message-label-withdraw4", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of a wildcard LDP Label Withdraw message should cause all previously
// received label mappings to be uninstalled.
//
// Input:
//  * Protocol: Label Withdraw message from rt4 containing a wildcard FEC
// Output:
//  * Protocol: Label Release to rt4 for all previously received labels
//  * Northbound:
//    - remove all label bindings learned from rt4
//    - updated statistics
//  * Southbound: uninstall all labels learned from rt4
#[tokio::test]
async fn message_label_withdraw5() {
    run_test::<Instance>("message-label-withdraw5", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of fatal Notification message should torn down the session.
//
// Input:
//  * Protocol: fatal Notification message (Shutdown) from rt1
// Output:
//  * Northbound:
//    - neighbor rt1 transitioned from OPERATIONAL to NON EXISTENT
//    - remove all address and label bindings learned from rt1
//    - update statistics
//  * Southbound: uninstall all labels learned from rt1
#[tokio::test]
async fn message_notification1() {
    run_test::<Instance>("message-notification1", "topo2-1", "rt2").await;
}

// Test description:
//
// Receipt of advisory Notification message should be ignored.
//
// Input:
//  * Protocol: advisory Notification message (Unknown TLV) from rt1
// Output: no changes
#[tokio::test]
async fn message_notification2() {
    run_test::<Instance>("message-notification2", "topo2-1", "rt2").await;
}

// Test description:
//
// Targeted hellos from unknown neighbors should be accepted or not depending on
// the "hello-accept" setting.
//
// Input:
//  * Protocol: targeted Hello message from rt6
// Output: no changes
//
// Input:
//  * Northbound: enable "hello-accept"
// Output: no changes
//
// Input:
//  * Protocol: targeted Hello message from rt6
// Output:
//  * Northbound: new targeted adjacency for rt6
#[tokio::test]
async fn nb_config_hello_accept1() {
    run_test::<Instance>("nb-config-hello-accept1", "topo2-1", "rt2").await;
}

// Test description:
//
// Dynamic targeted neighbors should be deleted when "hello-accept" is disabled.
//
// Input:
//  * Northbound: enable "hello-accept"
// Output: no changes
//
// Input:
//  * Protocol: targeted Hello message from rt6
// Output:
//  * Northbound: new targeted adjacency for rt6
//
// Input:
//  * Northbound: disable "hello-accept"
// Output:
//  * Northbound: deleted targeted adjacency for rt6
#[tokio::test]
async fn nb_config_hello_accept2() {
    run_test::<Instance>("nb-config-hello-accept2", "topo2-1", "rt2").await;
}

// Test description:
//
// Deleting an interface causes the associated adjacencies to be deleted as
// well.
//
// Input:
//  * Northbound: delete the eth-sw1 interface
// Output:
//  * Protocol: Notification (Shutdown) to rt1 and rt3
//  * Northbound:
//    - deleted rt1 and rt3 neighbors
//    - removed all address and label bindings learned from rt1 and rt3
//  * Southbound: uninstall all labels learned from rt1 and rt3
#[tokio::test]
async fn nb_config_iface1() {
    run_test::<Instance>("nb-config-iface1", "topo2-1", "rt2").await;
}

// Test description:
//
// Adding a new interface should prompt the request of interface information to
// the southbound layer.
//
// Input:
//  * Northbound: delete the eth-sw1 interface
// Output:
//  * Protocol: Notification (Shutdown) to rt1 and rt3
//  * Northbound:
//    - deleted rt1 and rt3 neighbors
//    - removed all address and label bindings learned from rt1 and rt3
//  * Southbound: uninstall all labels learned from rt1 and rt3
//
// Input:
//  * Northbound: re-add the eth-sw1 interface
// Output:
//  * Southbound: request interface information
#[tokio::test]
async fn nb_config_iface2() {
    run_test::<Instance>("nb-config-iface2", "topo2-1", "rt2").await;
}

// Test description:
//
// Disabling LDP-IPv4 on an interface should cause its adjacencies to be
// deleted.
//
// Input:
//  * Northbound: disable LDP-IPv4 operation in the eth-sw1 interface
// Output:
//  * Protocol: Notification (Shutdown) to rt1 and rt3
//  * Northbound:
//    - deleted rt1 and rt3 adjacencies and neighbors
//    - removed all address and label bindings learned from rt1 and rt3
//  * Southbound: uninstall all labels learned from rt1 and rt3
#[tokio::test]
async fn nb_config_iface_ipv4_enabled1() {
    run_test::<Instance>("nb-config-iface-ipv4-enabled1", "topo2-1", "rt2")
        .await;
}

// Test description:
//
// Enabling LDP-IPv4 on an interface should activate the interface.
//
// Input:
//  * Northbound: disable LDP-IPv4 operation in the eth-sw1 interface
// Output:
//  * Protocol: Notification (Shutdown) to rt1 and rt3
//  * Northbound:
//    - deleted rt1 and rt3 neighbors
//    - removed all address and label bindings learned from rt1 and rt3
//  * Southbound: uninstall all labels learned from rt1 and rt3
//
// Input:
//  * Northbound: enable LDP-IPv4 operation in the eth-sw1 interface
// Output:
//  * Northbound: eth-rt1 is active again
#[tokio::test]
async fn nb_config_iface_ipv4_enabled2() {
    run_test::<Instance>("nb-config-iface-ipv4-enabled2", "topo2-1", "rt2")
        .await;
}

// Test description:
//
// Disabling LDP globally should cause all adjacencies and neighbors to be
// deleted.
//
// Input:
//  * Northbound: disable LDP IPv4 operation
// Output:
//  * Protocol: Notification message (Shutdown) to all peers
//  * Northbound:
//    - remove all adjacencies
//    - remove all neighbors
//    - remove all address and label bindings
//  * Southbound: uninstall all learned labels
#[tokio::test]
async fn nb_config_ipv4_enabled1() {
    run_test::<Instance>("nb-config-ipv4-enabled1", "topo2-1", "rt2").await;
}

// Test description:
//
// Enabling LDP globally should prompt the activation of all eligible
// interfaces.
//
// Input:
//  * Northbound: disable LDP IPv4 operation
// Output:
//  * Protocol: Notification message (Shutdown) to all peers
//  * Northbound:
//    - remove all adjacencies
//    - remove all neighbors
//    - remove all address and label bindings
//  * Southbound: uninstall all learned labels
//
// Input:
//  * Northbound: enable LDP IPv4 operation
// Output:
//  * Northbound: all interfaces are active again
//  * Southbound: request to receive route information
#[tokio::test]
async fn nb_config_ipv4_enabled2() {
    run_test::<Instance>("nb-config-ipv4-enabled2", "topo2-1", "rt2").await;
}

// Test description:
//
// Targeted hellos should be accepted only for configured sources.
//
// Input:
//  * Protocol: targeted Hello message from rt6
// Output: no changes
//
// Input:
//  * Northbound: add targeted neighbor to rt6
// Output: no changes
//
// Input:
//  * Protocol: targeted Hello message from rt6
// Output:
//  * Northbound: new targeted adjacency for rt6
#[tokio::test]
async fn nb_config_tnbr1() {
    run_test::<Instance>("nb-config-tnbr1", "topo2-1", "rt2").await;
}

// Test description:
//
// Removing a static targeted neighbor should cause the corresponding adjacency
// to be deleted.
//
// Input:
//  * Northbound: add targeted neighbor to rt6
// Output: no changes
//
// Input:
//  * Protocol: targeted Hello message from rt6
// Output:
//  * Northbound: new targeted adjacency for rt6
//
// Input:
//  * Northbound: remove targeted neighbor to rt6
// Output:
//  * Northbound: deleted targeted adjacency for rt6
#[tokio::test]
async fn nb_config_tnbr2() {
    run_test::<Instance>("nb-config-tnbr2", "topo2-1", "rt2").await;
}

// Test description:
//
// Disabling a static targeted neighbor should cause the corresponding adjacency
// to be deleted.
//
// Input:
//  * Northbound: add targeted neighbor to rt6
// Output: no changes
//
// Input:
//  * Protocol: targeted Hello message from rt6
// Output:
//  * Northbound: new targeted adjacency for rt6
//
// Input:
//  * Northbound: disable the targeted neighbor to rt6
// Output:
//  * Northbound: deleted targeted adjacency for rt6
#[tokio::test]
async fn nb_config_tnbr_ipv4_enabled1() {
    run_test::<Instance>("nb-config-tnbr-ipv4-enabled1", "topo2-1", "rt2")
        .await;
}

// Test description:
//
// The "mpls-ldp-clear-hello-adjacency" RPC without any input parameter should
// delete all link and targeted adjacencies.
//
// Input:
//  * Northbound: "mpls-ldp-clear-hello-adjacency" RPC without any input
//    parameter
// Output:
//  * Protocol: LDP Notification message (Shutdown) to all peers
//  * Northbound:
//    - delete all adjacencies
//    - delete all neighbors
//    - remove all address and label bindings
//  * Southbound: uninstall all learned labels
#[tokio::test]
async fn nb_rpc_clear_hello_adj1() {
    run_test::<Instance>("nb-rpc-clear-hello-adj1", "topo2-1", "rt2").await;
}

// Test description:
//
// The "mpls-ldp-clear-hello-adjacency" RPC should delete only the specified
// adjacencies when one or more input parameters are present.
//
// Input:
//  * Northbound: "mpls-ldp-clear-hello-adjacency" RPC specifying the only
//    adjacency to rt1
// Output:
//  * Protocol: LDP Notification message (Shutdown) to rt1
//  * Northbound:
//    - remove eth-rt1 adjacency
//    - remove rt1 neighbor
//    - remove all address and label bindings learned from rt1
//  * Southbound: uninstall all labels learned from rt1
#[tokio::test]
async fn nb_rpc_clear_hello_adj2() {
    run_test::<Instance>("nb-rpc-clear-hello-adj2", "topo2-1", "rt2").await;
}

// Test description:
//
// The "mpls-ldp-clear-peer" RPC without any input parameter should torn down
// all neighbors.
//
// Input:
//  * Northbound: "mpls-ldp-clear-peer" RPC without any input parameter
// Output:
//  * Protocol: LDP Notification message (Shutdown) to all peers
//  * Northbound:
//    - all neighbors transitioned from OPERATIONAL to NON EXISTENT
//    - remove all address and label bindings
//  * Southbound: uninstall all learned labels
#[tokio::test]
async fn nb_rpc_clear_peer1() {
    run_test::<Instance>("nb-rpc-clear-peer1", "topo2-1", "rt2").await;
}

// Test description:
//
// The "mpls-ldp-clear-peer" RPC should torn down only the specified neighbors
// when one or more input parameters are present.
//
// Input:
//  * Northbound: "mpls-ldp-clear-peer" RPC specifying the rt1 neighbor
// Output:
//  * Protocol: LDP Notification message (Shutdown) to rt1
//  * Northbound:
//    - neighbor rt1 transitioned from OPERATIONAL to NON EXISTENT
//    - remove all address and label bindings learned from rt1
//  * Southbound: uninstall all labels learned from rt1
#[tokio::test]
async fn nb_rpc_clear_peer2() {
    run_test::<Instance>("nb-rpc-clear-peer2", "topo2-1", "rt2").await;
}

// Test description:
//
// New interface address should prompt the transmission of an Address message to
// all peers.
//
// Input:
//  * Southbound: address 172.16.1.2/24 added to eth-rt1
// Output:
//  * Protocol: Address Message to all peers (address list: [172.16.1.2/24])
//  * Northbound: new advertised address binding
#[tokio::test]
async fn sb_addr_add1() {
    run_test::<Instance>("sb-addr-add1", "topo1-1", "rt2").await;
}

// Test description:
//
// New interface address should activate interface that was previously missing
// an address.
//
// Input:
//  * Southbound: address 10.0.1.2 removed from eth-rt1
// Output:
//  * Protocol:
//    - Address Withdraw message to all peers (address list: [10.0.1.2])
//    - Notification (Shutdown) to rt1
//  * Northbound:
//    - neighbor rt1 deleted
//    - removed all address and label bindings learned from rt1
//  * Southbound: uninstall all labels learned from rt1
//
// Input:
//  * Southbound: address 10.0.1.2 added to eth-rt1
// Output:
//  * Protocol:
//    - Address message to all peers (address list: [10.0.1.2])
//    - Notification (Shutdown) to rt1
//  * Northbound:
//    - new advertised address binding
//    - eth-rt1 is active again
#[tokio::test]
async fn sb_addr_add2() {
    run_test::<Instance>("sb-addr-add2", "topo1-1", "rt2").await;
}

// Test description:
//
// Removed interface address should prompt the transmission of an Address
// Withdraw message to all peers.
//
// Input:
//  * Southbound: address 172.16.1.2/24 added to eth-rt1
// Output:
//  * Protocol: Address Message to all peers (address list: [172.16.1.2/24])
//  * Northbound: new advertised address binding
//
// Input:
//  * Southbound: address 172.16.1.2/24 removed from eth-rt1
// Output:
//  * Protocol: Address Withdraw Message to all peers (address list:
//    [172.16.1.2/24])
//  * Northbound: removed advertised address binding
#[tokio::test]
async fn sb_addr_del1() {
    run_test::<Instance>("sb-addr-del1", "topo1-1", "rt2").await;
}

// Test description:
//
// When the last interface address is removed, the interface should be
// deactivated.
//
// Input:
//  * Southbound: address 10.0.1.2 removed from eth-rt1
// Output:
//  * Protocol:
//    - Address Withdraw to all peers (address list: [10.0.1.2])
//    - Notification (Shutdown) to rt1
//  * Northbound:
//    - neighbor rt1 deleted
//    - removed all address and label bindings learned from rt1
//  * Southbound: uninstall all labels learned from rt1
#[tokio::test]
async fn sb_addr_del2() {
    run_test::<Instance>("sb-addr-del2", "topo1-1", "rt2").await;
}

// Test description:
//
// Neighbors that are reachable only through one interface are torned down as
// soon as that interface is disabled.
//
// Input:
//  * Southbound: disable the eth-sw1 interface
// Output:
//  * Protocol: Notification (Shutdown) to rt1 and rt3
//  * Northbound:
//    - deleted rt1 and rt3 neighbors
//    - removed all address and label bindings learned from rt1 and rt3
//  * Southbound: uninstall all labels learned from rt1 and rt3
#[tokio::test]
async fn sb_iface_update1() {
    run_test::<Instance>("sb-iface-update1", "topo2-1", "rt2").await;
}

// Test description:
//
// Neighbors that ae reachable through more than one interface are preserved
// when one of those interfaces is disabled.
//
// Input:
//  * Southbound: disable the eth-rt4-1 interface
// Output:
//  * Northbound: removed the eth-rt4-1 link adjacency
#[tokio::test]
async fn sb_iface_update2() {
    run_test::<Instance>("sb-iface-update2", "topo2-1", "rt2").await;
}

// Test description:
//
// LDP operation on the interface should be reactivated as soon as its
// operational status is up again.
//
// Input:
//  * Southbound: disable the eth-sw1 interface
// Output:
//  * Protocol: Notification (Shutdown) to rt1 and rt3
//  * Northbound:
//    - deleted rt1 and rt3 neighbors
//    - removed all address and label bindings learned from rt1 and rt3
//  * Southbound: uninstall all labels learned from rt1 and rt3
//
// Input:
//  * Southbound: enable the eth-sw1 interface
// Output:
//  * Northbound: eth-sw1 is active again
#[tokio::test]
async fn sb_iface_update3() {
    run_test::<Instance>("sb-iface-update3", "topo2-1", "rt2").await;
}

// Test description:
//
// Route added without any available label binding.
//
// Input:
//  * Southbound: new route (192.168.1.0/24 nexthops [10.0.1.1])
// Output:
//  * Protocol: Label Mapping message to all peers advertising a non-null label
//  * Northbound: new advertised label bindings
#[tokio::test]
async fn sb_route_add1() {
    run_test::<Instance>("sb-route-add1", "topo2-1", "rt2").await;
}

// Test description:
//
// Route added with a previously learned label binding.
//
// Input:
//  * Protocol: LDP Label Mapping message from rt1 for 192.168.1.0/24
// Output:
//  * Northbound:
//    - new received label mapping from rt1
//    - updated statistics
//
// Input:
//  * Southbound: new route (192.168.1.0/24 nexthops [10.0.1.1])
// Output:
//  * Protocol: Label Mapping message to all peers advertising a non-null label
//  * Northbound:
//    - new advertised label bindings
//    - received label binding from rt1 for 192.168.1.0/24 is marked as used in
//      forwarding
//    - updated statistics
//  * Southbound: install label for 192.168.1.0/24
#[tokio::test]
async fn sb_route_add2() {
    run_test::<Instance>("sb-route-add2", "topo2-1", "rt2").await;
}

// Test description:
//
// Route updates should trigger labels to be installed or uninstalled.
//
// Input:
//  * Southbound: updated route (6.6.6.6/32 nexthops [10.0.2.4])
// Output:
//  * Protocol: Label Mapping Message to all peers advertising a non-null label
//  * Southbound: uninstall label for 192.168.1.0/24 via 10.0.3.4
//
// Input:
//  * Southbound: updated route (6.6.6.6/32 nexthops [10.0.2.4, 10.0.3.4])
// Output:
//  * Protocol: Label Mapping Message to all peers advertising a non-null label
//  * Southbound: reinstall label for 192.168.1.0/24 via 10.0.3.4
#[tokio::test]
async fn sb_route_add3() {
    run_test::<Instance>("sb-route-add3", "topo2-1", "rt2").await;
}

// Test description:
//
// Route removal should prompt the corresponding labels to be uninstalled.
//
// Input:
//  * Southbound: deleted route (6.6.6.6/32)
// Output:
//  * Protocol: Label Withdraw message to all peers
//  * Northbound:
//    - received label binding from rt4 for 6.6.6.6/32 is marked as not used in
//      forwarding
//    - updated statistics
//  * Southbound: uninstall labels for 6.6.6.6/32
#[tokio::test]
async fn sb_route_del1() {
    run_test::<Instance>("sb-route-del1", "topo2-1", "rt2").await;
}

// Test description:
//
// Removal of route that doesn't have any remote label binding.
//
// Input:
//  * Southbound: new route (192.168.1.0/24 nexthops [10.0.1.1])
// Output:
//  * Protocol: Label Mapping message to all peers advertising a non-null label
//  * Northbound: new advertised label bindings
//
// Input:
//  * Southbound: deleted route (192.168.1.0/24)
// Output:
//  * Protocol: Label Withdraw message to all peers
#[tokio::test]
async fn sb_route_del2() {
    run_test::<Instance>("sb-route-del2", "topo2-1", "rt2").await;
}

// Test description:
//
// Accepted TCP connection that doesn't match any adjacency should be closed.
//
// Input:
//  * Protocol: Accepted TCP connection from 10.0.1.10
// Output: no changes
#[tokio::test]
async fn tcp_accept1() {
    run_test::<Instance>("tcp-accept1", "topo2-1", "rt2").await;
}

// Test description:
//
// Accepted TCP connection that matches an adjacency should prompt the creation
// of a new neighor in the NON EXISTENT state.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.10 (new neighbor)
//  * Protocol: Accepted TCP connection from 1.1.1.10
// Output:
//  * Northbound:
//    - new adjacency
//    - new neighbor in the NON EXISTENT state
#[tokio::test]
async fn tcp_accept2() {
    run_test::<Instance>("tcp-accept2", "topo2-1", "rt2").await;
}

// Test description:
//
// Duplicate connection requests should be rejected.
//
// Input:
//  * Protocol: Accepted TCP connection from 4.4.4.4
// Output: no changes
#[tokio::test]
async fn tcp_accept3() {
    run_test::<Instance>("tcp-accept3", "topo2-1", "rt2").await;
}

// Test description:
//
// TCP connection teardown should torn down the corresponding LDP session.
//
// Input:
//  * Protocol: TCP connection to rt4 was closed
// Output:
//  * Northbound:
//    - neighbor rt4 transitioned from OPERATIONAL to NON EXISTENT
//    - remove all address and label bindings learned from rt4
//    - update statistics
//  * Southbound: uninstall all labels learned from rt4
#[tokio::test]
async fn tcp_close1() {
    run_test::<Instance>("tcp-close1", "topo2-1", "rt2").await;
}

// Test description:
//
// TCP connection established with new adjacency should prompt the creation of a
// new neighbor.
//
// Input:
//  * Protocol: LDP Hello message from 10.0.1.10 (new neighbor)
//  * Protocol: Established TCP connection to 1.1.1.10
// Output:
//  * Protocol: LDP Initialization message to 1.1.1.10
//  * Northbound:
//    - new adjacency
//    - new neighbor in the OPENSENT state
#[tokio::test]
async fn tcp_connect1() {
    run_test::<Instance>("tcp-connect1", "topo2-1", "rt2").await;
}

// Test description:
//
// Timed out adjacency shouldn't cause the corresponding neighborship to be torn
// down if there's at least one other adjacency.
//
// Input:
//  * Protocol: eth-rt4-1 adjacency to rt4 timed out
// Output:
//  * Northbound: removed eth-rt4-1 adjacency
#[tokio::test]
async fn timeout_adj1() {
    run_test::<Instance>("timeout-adj1", "topo2-1", "rt2").await;
}

// Test description:
//
// The removal of the last adjacency associated to a neighbor should prompt the
// session to be torned down.
//
// Input:
//  * Protocol: eth-rt4-1 adjacency to rt4 timed out
// Output:
//  * Northbound: remove eth-rt4-1 adjacency
//
// Input:
//  * Protocol: eth-rt4-2 adjacency to rt4 timed out
// Output:
//  * Protocol: LDP Notification message (Hold Timer Expired) to rt4
//  * Northbound:
//    - remove eth-rt4-1 adjacency
//    - remove rt4 neighbor
//    - remove all address and label bindings learned from rt4
//  * Southbound: uninstall all labels learned from rt4
#[tokio::test]
async fn timeout_adj2() {
    run_test::<Instance>("timeout-adj2", "topo2-1", "rt2").await;
}

// Test description:
//
// Timed out keepalive timer should cause the neighborship to be torned down.
//
// Input:
//  * Protocol: neighbor rt4 timed out
// Output:
//  * Protocol: LDP Notification message (KeepAlive Timer Expired) to rt4
//  * Northbound:
//    - neighbor rt4 transitioned from OPERATIONAL to NON EXISTENT
//    - remove all address and label bindings learned from rt4
//    - update statistics
//  * Southbound: uninstall all labels learned from rt4
#[tokio::test]
async fn timeout_nbr1() {
    run_test::<Instance>("timeout-nbr1", "topo1-1", "rt2").await;
}

// Test description:
//
// Timed out keepalive timer should cause the neighborship to be torned down.
// Once no active neighborship remains, the LIB should be empty.
//
// Input:
//  * Protocol: neighbor rt4 timed out
// Output:
//  * Protocol: LDP Notification message (KeepAlive Timer Expired) to rt4
//  * Northbound:
//    - neighbor rt4 transitioned from OPERATIONAL to NON EXISTENT
//    - remove all address and label bindings learned from rt4
//    - update statistics
//  * Southbound: uninstall all labels learned from rt4
//
// Input:
//  * Protocol: neighbor rt1 timed out
// Output:
//  * Protocol: LDP Notification message (KeepAlive Timer Expired) to rt1
//  * Northbound:
//    - neighbor rt1 transitioned from OPERATIONAL to NON EXISTENT
//    - remove all address and label bindings learned from rt1
//    - update statistics
//  * Southbound: uninstall all labels learned from rt1
#[tokio::test]
async fn timeout_nbr2() {
    run_test::<Instance>("timeout-nbr2", "topo1-1", "rt2").await;
}
