//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

mod topologies;

use holo_ospf::instance::Instance;
use holo_ospf::version::Ospfv3;
use holo_protocol::test::stub::run_test;

// Test description:
//
// Input:
//  * Protocol: received a self-originated Router-LSA (lsa-id 0.0.0.0) that is
//    newer than the database copy
// Output:
//  * Protocol:
//    - send an LS Update to all adjacencies containing the received
//      self-originated Router-LSA
//    - send another LS Update to all adjacencies containing the updated
//      self-originated Router-LSA
//  * Northbound: the retransmission queue length of all adjacencies increases
//    to 1
#[tokio::test]
async fn packet_lsupd_self_orig1() {
    run_test::<Instance<Ospfv3>>("packet-lsupd-self-orig1", "topo2-1", "rt3")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a self-originated Router-LSA (lsa-id 0.0.0.1) that
//    isn't present in the LSDB
// Output:
//  * Protocol:
//    - send an LS Update to all adjacencies containing the received
//      self-originated Router-LSA
//    - send another LS Update to all adjacencies containing the same
//      self-originated Router-LSA, now with MaxAge
//  * Northbound:
//    - Router-LSA (lsa-id 0.0.0.1) is present in the LSDB with MaxAge
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
#[tokio::test]
async fn packet_lsupd_self_orig2() {
    run_test::<Instance<Ospfv3>>("packet-lsupd-self-orig2", "topo2-1", "rt3")
        .await;
}
