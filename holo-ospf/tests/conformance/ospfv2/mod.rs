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
//
// Input:
//  * Protocol: received Grace-LSA from rt6
// Output:
//  * Protocol: send an LS Ack to rt6 containing the Grace-LSA
//  * Northbound:
//    - The Grace-LSA is present in the interface LSDB
//    - neighbor rt6 is in graceful restart mode
//
// Input:
//  * Northbound: disable the graceful restart helper mode
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    self-originated Router Information LSA
//  * Northbound:
//    - the self-originated Router Information LSA no longer has the
//      "ietf-ospf:graceful-restart-helper" informational capability
//    - neighbor rt6 is no longer in graceful restart mode
//      ("exit-reason":"topology-changed")
#[tokio::test]
async fn gr_helper_disable1() {
    run_test::<Instance<Ospfv2>>("gr-helper-disable1", "topo2-1", "rt4").await;
}

// Test description:
//
// Input:
//  * Protocol: received Grace-LSA from rt6
// Output:
//  * Protocol: send an LS Ack to rt6 containing the Grace-LSA
//  * Northbound:
//    - The Grace-LSA is present in the interface LSDB
//    - neighbor rt6 is in graceful restart mode
#[tokio::test]
async fn gr_helper_enter1() {
    run_test::<Instance<Ospfv2>>("gr-helper-enter1", "topo2-1", "rt4").await;
}

// Test description:
//
// Input:
//  * Protocol: received Grace-LSA from rt1 (reachable over a broadcast network)
//    containing rt1's eth-sw1 interface address
// Output:
//  * Northbound:
//    - The Grace-LSA is present in the interface LSDB
//    - neighbor rt1 is in graceful restart mode
#[tokio::test]
async fn gr_helper_enter2() {
    run_test::<Instance<Ospfv2>>("gr-helper-enter2", "topo2-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Protocol: received Grace-LSA from rt6
// Output:
//  * Protocol: send an LS Ack to rt6 containing the Grace-LSA
//  * Northbound:
//    - the Grace-LSA is present in the interface LSDB
//    - neighbor rt6 is in graceful restart mode
//
// Input:
//  * Protocol: received MaxAge Grace-LSA from rt6
// Output:
//  * Protocol: send an LS Ack to rt6 containing the MaxAge Grace-LSA
//  * Northbound:
//    - The Grace-LSA is present in the interface LSDB with MaxAge
//    - neighbor rt6 is no longer in graceful restart mode
//      ("exit-reason":"completed")
#[tokio::test]
async fn gr_helper_exit1() {
    run_test::<Instance<Ospfv2>>("gr-helper-exit1", "topo2-1", "rt4").await;
}

// Test description:
//
// Input:
//  * Protocol: received Grace-LSA from rt6
// Output:
//  * Protocol: send an LS Ack to rt6 containing the Grace-LSA
//  * Northbound:
//    - the Grace-LSA is present in the interface LSDB
//    - neighbor rt6 is in graceful restart mode
//
// Input:
//  * Protocol: the grace period for rt6 has timed out
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    self-originated Router-LSA, which no longer has a link to rt6
//  * Northbound:
//    - neighbor rt6 is no longer in graceful restart mode
//      ("exit-reason":"timed-out")
//    - neighbor rt6 is deleted
//    - the self-originated Router-LSA no longer includes a link to rt6
#[tokio::test]
async fn gr_helper_exit2() {
    run_test::<Instance<Ospfv2>>("gr-helper-exit2", "topo2-1", "rt4").await;
}

// Test description:
//
// Input:
//  * Protocol: received Grace-LSA from rt6
// Output:
//  * Protocol: send an LS Ack to rt6 containing the Grace-LSA
//  * Northbound:
//    - the Grace-LSA is present in the interface LSDB
//    - neighbor rt6 is in graceful restart mode
//
// Input:
//  * Protocol: received updated Router-LSA (adv-rtr 3.3.3.3) from rt5
// Output:
//    - send an LS Ack to rt6 containing the received Router-LSA
//    - send an LS Update to all adjacencies containing the received Router-LSA,
//      except to rt5
//  * Northbound:
//    - neighbor rt6 is no longer in graceful restart mode
//      ("exit-reason":"topology-changed")
//    - Router-LSA (adv-rtr 3.3.3.3) is updated
#[tokio::test]
async fn gr_helper_exit3() {
    run_test::<Instance<Ospfv2>>("gr-helper-exit3", "topo2-1", "rt4").await;
}

// Test description:
//
// Input:
//  * Protocol: Router-LSA (adv-rtr 1.1.1.1, lsa-id 1.1.1.1) has expired
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the expired LSA
//    (age = 3600)
//  * Northbound:
//    - the age of the expired LSA is set to 3600
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: remove the route to 1.1.1.1/32 from the local RIB
//  * Southbound: uninstall the route to 1.1.1.1/32
#[tokio::test]
async fn lsa_expiry1() {
    run_test::<Instance<Ospfv2>>("lsa-expiry1", "topo2-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Protocol: Router-LSA (adv-rtr 3.3.3.3, lsa-id 3.3.3.3) has expired
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the expired LSA
//    (age = 3600)
//  * Northbound:
//    - the age of the expired LSA is set to 3600
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound:
//    - remove the route to 3.3.3.3/32 from the local RIB
//    - update the routes to 5.5.5.5/32, 10.0.4.0/24, 10.0.5.0/24 and
//      10.0.8.0/24 (nexthop through rt3 no longer exists)
//  * Southbound:
//    - uninstall the route to 3.3.3.3/32
//    - reinstall the routes to 5.5.5.5/32, 10.0.4.0/24, 10.0.5.0/24 and
//      10.0.8.0/24 using a different set of nexthops
#[tokio::test]
async fn lsa_expiry2() {
    run_test::<Instance<Ospfv2>>("lsa-expiry2", "topo2-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Protocol: the refresh timer for Router-LSA (adv-rtr 2.2.2.2, lsa-id
//    2.2.2.2) has expired
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the refreshed
//    LSA (age = 0)
//  * Northbound: the retransmission queue length of all adjacencies increases
//    to 1
#[tokio::test]
async fn lsa_refresh1() {
    run_test::<Instance<Ospfv2>>("lsa-refresh1", "topo2-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Protocol: the refresh timer for Router-LSA (adv-rtr 3.3.3.3, lsa-id
//    3.3.3.3) has expired
//
// The OSPF instance should panic since the LSA being refreshed isn't
// self-originated (hence, only a grave internal inconsistency could cause this)
#[tokio::test]
#[should_panic]
async fn lsa_refresh2() {
    run_test::<Instance<Ospfv2>>("lsa-refresh2", "topo2-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Northbound: delete area 0.0.0.1
// Output:
//  * Protocol: send an LS Update to rt3 containing the updated self-originated
//    Router-LSA (the ABR bit no longer set) and flushed summary LSAs
//  * Northbound:
//    - the routes to 1.1.1.1/32, 2.2.2.2/32 and 10.0.1.0/24 were removed from
//      the local RIB
//    - the self-originated LSA from the backbone area no longer has the ABR bit
//      set
//    - the self-originated summary LSAs to the 1.1.1.1/32, 2.2.2.2/32 and
//      10.0.1.0/24 destinations were flushed
//    - everything under area 0.0.0.1 was removed
//    - the retransmission queue length of the 3.3.3.3 adjacency increases to 4
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//  * Southbound: uninstall the route to 1.1.1.1/32
#[tokio::test]
async fn nb_config_area1() {
    run_test::<Instance<Ospfv2>>("nb-config-area1", "topo1-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Northbound: change the cost of default routes advertised into stub areas
//    to 50
// Output:
//  * Protocol: send an LS Update containing the updated Type-3 Summary LSA
//    (adv-rtr 6.6.6.6, lsa-id 0.0.0.0) out the eth-rt7 interface, destined to
//    224.0.0.5
//  * Northbound:
//    - The cost of the updated Type-3 Summary LSA (adv-rtr 6.6.6.6, lsa-id
//      0.0.0.0) changes to 50
//    - the retransmission queue length of adjacency 7.7.7.7 increases to 1
#[tokio::test]
async fn nb_config_area_dflt_cost1() {
    run_test::<Instance<Ospfv2>>("nb-config-area-dflt-cost1", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: create the 10.0.0.0/8 range for area 0.0.0.1
// Output:
//  * Northbound:
//    - a new Type-3 Summary LSA (adv-rtr 2.2.2.2, lsa-id 10.0.0.0) is now
//      present in the LSDB, with a metric of 10
//    - Type-3 Summary LSA (adv-rtr 2.2.2.2, lsa-id 10.0.1.0) was summarized and
//      prematurely aged
//    - the retransmission queue length of adjacency 5.5.5.5 increases to 2
//  * Protocol: send an LS Update containing two Type-3 Summary LSAs out the
//    eth-rt5 interface, destined to 224.0.0.5
#[tokio::test]
async fn nb_config_area_range1() {
    run_test::<Instance<Ospfv2>>("nb-config-area-range1", "topo1-1", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: create the 10.0.0.0/8 range for area 0.0.0.1
// Output:
//  * Northbound:
//    - a new Type-3 Summary LSA (adv-rtr 2.2.2.2, lsa-id 10.0.0.0) is now
//      present in the LSDB, with a metric of 10
//    - Type-3 Summary LSA (adv-rtr 2.2.2.2, lsa-id 10.0.1.0) was summarized and
//      prematurely aged
//    - the retransmission queue length of adjacency 5.5.5.5 increases to 2
//  * Protocol: send an LS Update containing two Type-3 Summary LSAs out the
//    eth-rt5 interface, destined to 224.0.0.5
//
// Input:
//  * Northbound: delete the 10.0.0.0/8 range from area 0.0.0.1
// Output:
//  * Northbound:
//    - Type-3 Summary LSA (adv-rtr 2.2.2.2, lsa-id 10.0.0.0) was prematurely
//      aged
//    - Type-3 Summary LSA (adv-rtr 2.2.2.2, lsa-id 10.0.1.0) was reoriginated
//  * Protocol: send an LS Update containing two Type-3 Summary LSAs out the
//    eth-rt5 interface, destined to 224.0.0.5
//
// It's important to note that retransmission queue length of adjacency 5.5.5.5
// wasn't increased in the second step since the LSAs were updated before their
// older instances were acknowledged, so the retransmission queue length remains
// the same, albeit with updated LSAs.
#[tokio::test]
async fn nb_config_area_range2() {
    run_test::<Instance<Ospfv2>>("nb-config-area-range2", "topo1-1", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: create the 10.0.0.0/8 range for area 0.0.0.1, with the
//    "advertise" option disabled
// Output:
//  * Northbound:
//    - Type-3 Summary LSA (adv-rtr 2.2.2.2, lsa-id 10.0.1.0) was summarized and
//      prematurely aged
//    - the retransmission queue length of adjacency 5.5.5.5 increases to 1
//  * Protocol: send an LS Update containing two Type-3 Summary LSAs out the
//    eth-rt5 interface, destined to 224.0.0.5
#[tokio::test]
async fn nb_config_area_range3() {
    run_test::<Instance<Ospfv2>>("nb-config-area-range3", "topo1-1", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: create the 10.0.0.0/8 range for area 0.0.0.1, with a static
//    cost of 1000
// Output:
//  * Northbound:
//    - a new Type-3 Summary LSA (adv-rtr 2.2.2.2, lsa-id 10.0.0.0) is now
//      present in the LSDB, with a metric of 1000
//    - Type-3 Summary LSA (adv-rtr 2.2.2.2, lsa-id 10.0.1.0) was summarized and
//      prematurely aged
//    - the retransmission queue length of adjacency 5.5.5.5 increases to 2
//  * Protocol: send an LS Update containing two Type-3 Summary LSAs out the
//    eth-rt5 interface, destined to 224.0.0.5
#[tokio::test]
async fn nb_config_area_range4() {
    run_test::<Instance<Ospfv2>>("nb-config-area-range4", "topo1-1", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: disable summary advertisement into the 0.0.0.2 stub area
// Output:
//  * Protocol: send an LS Update containing ten MaxAge Type-3 Summary LSAs out
//    the eth-rt5 interface, destined to 224.0.0.5
//  * Northbound:
//    - ten self-originated Type-3 Summary LSAs were prematurely aged
//    - the retransmission queue length of adjacency 5.5.5.5 increases to 10
#[tokio::test]
async fn nb_config_area_summary1() {
    run_test::<Instance<Ospfv2>>("nb-config-area-summary1", "topo1-1", "rt4")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: enable summary advertisement into the 0.0.0.3 stub area
// Output:
//  * Protocol: send an LS Update containing ten Type-3 Summary LSAs out the
//    eth-rt7 interface, destined to 224.0.0.5
//  * Northbound:
//    - ten new self-originated Type-3 Summary LSAs are now present in the LSDB
//    - the retransmission queue length of adjacency 7.7.7.7 increases to 10
#[tokio::test]
async fn nb_config_area_summary2() {
    run_test::<Instance<Ospfv2>>("nb-config-area-summary2", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: disable the OSPF instance
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the flushed
//    self-originated LSAs (age = 3600)
//  * Northbound:
//    - all neighbors were killed
//    - all non-loopback interfaces transitioned to the "down" state
//    - everything else is cleared, including LSDBs, local RIB and statistics
//  * Southbound: uninstall all non-connected routes
#[tokio::test]
async fn nb_config_enable1() {
    run_test::<Instance<Ospfv2>>("nb-config-enable1", "topo1-1", "rt3").await;
}

// Test description:
//
// Input:
//  * Northbound: disable the OSPF instance
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the flushed
//    self-originated LSAs (age = 3600)
//  * Northbound:
//    - all neighbors were killed
//    - all non-loopback interfaces transitioned to the "down" state
//    - everything else is cleared, including LSDBs, local RIB and statistics
//
// Input:
//  * Northbound: enable the OSPF instance
// Output:
//  * Northbound:
//    - all non-loopback interfaces transitioned to the "point-to-point" state
//    - the LSDB is initialized with a Router-LSA and a Routing Information LSA
#[tokio::test]
async fn nb_config_enable2() {
    run_test::<Instance<Ospfv2>>("nb-config-enable2", "topo1-1", "rt3").await;
}

// Test description:
//
// Input:
//  * Northbound: delete the eth-rt1 interface
// Output:
//  * Northbound:
//    - the 1.1.1.1 neighbor was killed
//    - the self-originated Router-LSA for area 0.0.0.1 is updated, with a
//      point-to-point link and a stub network removed
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound:
//    - the routes to 1.1.1.1/32 and 10.0.1.0/24 were removed
//    - the summary routes to 1.1.1.1/32 and 10.0.1.0/24 were flushed from the
//      backbone area
//    - the retransmission queue length of the 3.3.3.3 adjacency increases to 2
//  * Southbound: uninstall the route to 1.1.1.1/32
#[tokio::test]
async fn nb_config_iface1() {
    run_test::<Instance<Ospfv2>>("nb-config-iface1", "topo1-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Northbound: change the cost of the eth-rt1 interface to 50
// Output:
//  * Protocol: send an LS Update to rt3 containing the updated self-originated
//    Router-LSA
//  * Northbound:
//    - the self-originated Router-LSA for area 0.0.0.1 is updated with the new
//      link cost
//    - the retransmission queue length of the 1.1.1.1 adjacency increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound:
//    - all routes going through eth-rt1 have their metric increased
//    - the summary routes to 1.1.1.1/32 and 10.0.1.0/24 are updated to account
//      for the metric change
//    - the retransmission queue length of the 3.3.3.3 adjacency increases to 2
//  * Southbound: reinstall the route to 1.1.1.1/32 with the new metric
#[tokio::test]
async fn nb_config_iface_cost1() {
    run_test::<Instance<Ospfv2>>("nb-config-iface-cost1", "topo1-1", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: change the preference of all route types to 50
// Output:
//  * Southbound: reinstall all routes using the new preference
#[tokio::test]
async fn nb_config_preference1() {
    run_test::<Instance<Ospfv2>>("nb-config-preference1", "topo1-1", "rt1")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: change the preference of intra-area routes to 50
// Output:
//  * Southbound: reinstall all intra-area routes using the new preference
#[tokio::test]
async fn nb_config_preference2() {
    run_test::<Instance<Ospfv2>>("nb-config-preference2", "topo1-1", "rt1")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: change the preference of inter-area routes to 50
// Output:
//  * Southbound: reinstall all inter-area routes using the new preference
#[tokio::test]
async fn nb_config_preference3() {
    run_test::<Instance<Ospfv2>>("nb-config-preference3", "topo1-1", "rt1")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: change the preference of internal routes to 50
// Output:
//  * Southbound: reinstall all internal routes using the new preference
#[tokio::test]
async fn nb_config_preference4() {
    run_test::<Instance<Ospfv2>>("nb-config-preference4", "topo1-1", "rt1")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: change the configured Router ID to 10.0.255.3
// Output:
//  * Northbound:
//    - all neighbors were killed
//    - the LSDB is now empty (except for the self-originated Router-LSA, which
//      was updated to use the new Router ID)
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//  * Protocol: send an LS Update to all adjacencies flushing all
//    self-originated LSAs
//  * Southbound: uninstall all routes
//
// Once the instance is reset, it should reconverge using the new Router-ID.
#[tokio::test]
async fn nb_config_router_id1() {
    run_test::<Instance<Ospfv2>>("nb-config-router-id1", "topo1-1", "rt3")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: delete the configured Router ID
// Output: no changes (the system Router ID is the same as the previously
// configured Router ID)
#[tokio::test]
async fn nb_config_router_id2() {
    run_test::<Instance<Ospfv2>>("nb-config-router-id2", "topo1-1", "rt3")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: "ietf-ospf:clear-database" RPC
// Output:
//  * Northbound:
//    - all neighbors were killed
//    - the LSDB is now empty (except for the self-originated Router-LSA)
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
#[tokio::test]
async fn nb_rpc_clear_database1() {
    run_test::<Instance<Ospfv2>>("nb-rpc-clear-database1", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: "ietf-ospf:clear-neighbor" RPC
// Output:
//  * Northbound:
//    - all neighbors were killed
//    - all point-to-point links were removed from the self-originated
//      Router-LSAs
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound:
//    - all non-connected routes were removed from the local RIB
//    - Type-3 Summary LSA (adv-rtr 6.6.6.6, lsa-id 7.7.7.7) was prematurely
//      aged
//  * Southbound: uninstall all routes
#[tokio::test]
async fn nb_rpc_clear_neighbor1() {
    run_test::<Instance<Ospfv2>>("nb-rpc-clear-neighbor1", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Northbound: "ietf-ospf:clear-neighbor" RPC with the "interface" input
//    option set to "eth-rt3"
// Output:
//  * Northbound:
//    - the 3.3.3.3 neighbor was killed
//    - the point-to-point link to 3.3.3.3 was removed from the self-originated
//      backbone Router-LSA
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: all routes reachable over the eth-rt3 interface were removed
//    from the local RIB
//  * Southbound: uninstall all routes reachable over the eth-rt3 interface
#[tokio::test]
async fn nb_rpc_clear_neighbor2() {
    run_test::<Instance<Ospfv2>>("nb-rpc-clear-neighbor2", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Protocol:
//    - Received Hello packet with the Area ID field set to 0.0.0.99
//    - Received Database Description packet with the Area ID field set to
//      0.0.0.99
//    - Received LS Request packet with the Area ID field set to 0.0.0.99
//    - Received LS Update packet with the Area ID field set to 0.0.0.99
//    - Received LS Ack packet with the Area ID field set to 0.0.0.99
// Output:
//  * Northbound: for each received packet, send an "if-config-error" YANG
//    notifications with the error field set to "area-mismatch"
#[tokio::test]
async fn packet_area_mismatch1() {
    run_test::<Instance<Ospfv2>>("packet-area-mismatch1", "topo1-2", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received an unknown OSPF packet (packet type = 6)
// Output:
//  * Northbound: send an "if-rx-bad-packet" YANG notification
#[tokio::test]
async fn packet_decode_error1() {
    run_test::<Instance<Ospfv2>>("packet-decode-error1", "topo1-2", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the eth-sw1 interface from an unknown
//    neighbor (src = 10.0.1.10, dst = 224.0.0.6)
//
// Output: no changes (eth-sw1 isn't a DR or BDR, so the Hello packet is
// dropped)
#[tokio::test]
async fn packet_dst1() {
    run_test::<Instance<Ospfv2>>("packet-dst1", "topo2-1", "rt1").await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the eth-sw1 broadcast interface from
//    an unknown neighbor (src = 10.0.1.10, dst = 10.0.1.99)
//
// Output: no changes (eth-sw1 doesn't have the 10.0.1.99 address, so the Hello
// packet is dropped)
#[tokio::test]
async fn packet_dst2() {
    run_test::<Instance<Ospfv2>>("packet-dst2", "topo2-1", "rt1").await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the eth-rt4 point-to-point interface
//    from an unknown neighbor (src = 10.0.7.4, dst = 10.0.7.99)
//
// Output: no changes (eth-rt4 doesn't have the 10.0.7.99 address, so the Hello
// packet is dropped)
#[tokio::test]
async fn packet_dst3() {
    run_test::<Instance<Ospfv2>>("packet-dst3", "topo2-1", "rt6").await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the eth-sw1 interface with the
//    Network Mask field set to 255.255.0.0
//  * Northbound: send an "if-config-error" YANG notification with the error
//    field set to "net-mask-mismatch"
#[tokio::test]
async fn packet_hello_validation1() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation1", "topo1-2", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the eth-sw1 interface with the
//    HelloInterval field set to 1
//  * Northbound: send an "if-config-error" YANG notification with the error
//    field set to "hello-interval-mismatch"
#[tokio::test]
async fn packet_hello_validation2() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation2", "topo1-2", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the eth-sw1 interface with the
//    RouterDeadInterval field set to 100
//  * Northbound: send an "if-config-error" YANG notification with the error
//    field set to "dead-interval-mismatch"
#[tokio::test]
async fn packet_hello_validation3() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation3", "topo1-2", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the eth-sw1 interface with the
//    Options field set to 0 (empty options)
//  * Northbound: send an "if-config-error" YANG notification with the error
//    field set to "option-mismatch"
#[tokio::test]
async fn packet_hello_validation4() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation4", "topo1-2", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the eth-sw1 interface with the Router
//    ID field set to 2.2.2.2
//  * Northbound: send an "if-config-error" YANG notification with the error
//    field set to "duplicate-router-id"
#[tokio::test]
async fn packet_hello_validation5() {
    run_test::<Instance<Ospfv2>>("packet-hello-validation5", "topo1-2", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a self-originated Router-LSA that is newer than the
//    database copy
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
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig1", "topo2-1", "rt3")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a self-originated Network-LSA (adv-rtr 3.3.3.3, lsa-id
//    10.0.1.3) that is newer than the database copy
// Output:
//  * Protocol:
//    - send an LS Update to all adjacencies containing the received
//      self-originated Network-LSA
//    - send another LS Update to all adjacencies containing the updated
//      self-originated Network-LSA
//  * Northbound: the retransmission queue length of all adjacencies increases
//    to 1
#[tokio::test]
async fn packet_lsupd_self_orig2() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig2", "topo2-1", "rt3")
        .await;
}

// Test description:
//
// A received Network-LSA should be flushed if the router is no longer the DR
// for the network.
//
// In this test, the Network-LSA should be identified as self-originated based
// on the LSA-ID, and not based on the LSA advertising router.
//
// Input:
//  * Protocol: received a self-originated Network-LSA (adv-rtr 10.0.255.2,
//    lsa-id 10.0.1.2) that is newer than the database copy
// Output:
//  * Protocol:
//    - send an LS Update to the 4.4.4.4 adjacencies containing the received
//      self-originated Network-LSA
//    - send another LS Update to all adjacencies containing the same
//      self-originated Network-LSA, now with MaxAge
//  * Northbound:
//    - Network-LSA (adv-rtr 10.0.255.2, lsa-id 10.0.1.2) is present in the LSDB
//      with MaxAge
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
#[tokio::test]
async fn packet_lsupd_self_orig3() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-self-orig3", "topo2-1", "rt2")
        .await;
}

// Test description:
//
// A received Network-LSA should be flushed if the router is no longer the DR
// for the network.
//
// Input:
//  * Protocol: received a self-originated Network-LSA (adv-rtr 2.2.2.2, lsa-id
//    10.0.1.2) that is newer than the database copy
// Output:
//  * Protocol:
//    - send an LS Update to the 4.4.4.4 adjacencies containing the received
//      self-originated Network-LSA
//    - send another LS Update to all adjacencies containing the same
//      self-originated Network-LSA, now with MaxAge
//  * Northbound:
//    - Network-LSA (adv-rtr 2.2.2.2, lsa-id 10.0.1.2) is present in the LSDB
//      with MaxAge
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
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
//
// Input:
//  * Protocol: received an LSA containing an invalid checksum
// Output:
//  * Northbound: send an "if-rx-bad-lsa" YANG notification with the error field
//    set to "invalid-checksum"
#[tokio::test]
async fn packet_lsupd_step1_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step1-1", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received an LSA containing an invalid age (3700)
// Output:
//  * Northbound: send an "if-rx-bad-lsa" YANG notification with the error field
//    set to "invalid-age"
#[tokio::test]
async fn packet_lsupd_step1_2() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step1-2", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received an LSA containing an invalid sequence number
//    (0x80000000)
// Output:
//  * Northbound: send an "if-rx-bad-lsa" YANG notification with the error field
//    set to "invalid-seq-num"
#[tokio::test]
async fn packet_lsupd_step1_3() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step1-3", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a Router-LSA where the Link State ID and Advertising
//    Router fields are different
// Output:
//  * Northbound: send an "if-rx-bad-lsa" YANG notification with the error field
//    set to "ospfv2-router-lsa-id-mismatch"
#[tokio::test]
async fn packet_lsupd_step1_4() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step1-4", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received an LSA containing an unknown LSA type (6)
// Output: no changes (the LSA is discarded)
#[tokio::test]
async fn packet_lsupd_step2and3_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step2and3-1", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a Type-4 Summary LSA in an interface associated to a
//    stub area
// Output: no changes (the LSA is discarded)
#[tokio::test]
async fn packet_lsupd_step2and3_2() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step2and3-2", "topo1-1", "rt7")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received an AS-External LSA in an interface associated to a stub
//    area
// Output: no changes (the LSA is discarded)
#[tokio::test]
async fn packet_lsupd_step2and3_3() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step2and3-3", "topo1-1", "rt7")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a MaxAge LSA, and there's no instance of that LSA in
//    the LSDB
// Output:
//  * Protocol: send an LS Ack containing the MaxAge LSA back to the sending
//    neighbor
#[tokio::test]
async fn packet_lsupd_step4_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step4-1", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received an LSA in eth-sw1 (DROther) from 2.2.2.2 (BDR), and
//    there's an instance of that LSA in the LSDB that is less recent
// Output:
//  * Protocol: send an LS Ack out the same interface, destined to 224.0.0.6
//  * Northbound: the retransmission queue length of adjacency 3.3.3.3 increases
//    to 1
#[tokio::test]
async fn packet_lsupd_step5_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-1", "topo2-1", "rt1")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received an LSA in eth-sw1 (DR) from 1.1.1.1 (DROther), and
//    there's an instance of that LSA in the LSDB that is less recent
// Output:
//  * Protocol: send an LS Update containing the received LSA out all
//    interfaces, destined to 224.0.0.5
//  * Northbound: the retransmission queue length of all adjacencies, except
//    1.1.1.1, increases to 1
#[tokio::test]
async fn packet_lsupd_step5_2() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-2", "topo2-1", "rt3")
        .await;
}

// Test description:
//
// Type-3 Summary LSAs shouldn't be flooded to other areas.
//
// Input:
//  * Protocol: received a Type-3 Summary LSA in eth-rt3 from 3.3.3.3, and
//    there's no instance of that LSA in the LSDB
// Output:
//  * Protocol: send an LS Ack out the same interface, destined to 224.0.0.5
//  * Northbound:
//    - the received LSA is present in the LSDB
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
#[tokio::test]
async fn packet_lsupd_step5_3() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-3", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// AS-External LSAs shouldn't be flooded to stub areas.
//
// Input:
//  * Protocol: received an AS-External LSA in eth-rt3 from 3.3.3.3, and there's
//    no instance of that LSA in the LSDB
// Output:
//  * Protocol: send an LS Ack out the same interface, destined to 224.0.0.5
//  * Northbound:
//    - the received LSA is present in the LSDB
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
#[tokio::test]
async fn packet_lsupd_step5_4() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-4", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// AS-External LSAs should be flooded to normal areas.
//
// Input:
//  * Protocol: received an AS-External LSA in eth-rt3 from 3.3.3.3, and there's
//    no instance of that LSA in the LSDB
// Output:
//  * Protocol:
//    - send an LS Ack out the same interface, destined to 224.0.0.5
//    - send an LS Update containing the received LSA out the eth-rt1 interface,
//      destined to 224.0.0.5
//  * Northbound:
//    - the received LSA is present in the LSDB
//    - the retransmission queue length of adjacency 1.1.1.1 increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
#[tokio::test]
async fn packet_lsupd_step5_5() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step5-5", "topo1-1", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received an LSA, and there's an instance of that LSA in the LSDB
//    that is more recent
// Output:
//  * Protocol: send the database copy back to the sending neighbor
#[tokio::test]
async fn packet_lsupd_step8_1() {
    run_test::<Instance<Ospfv2>>("packet-lsupd-step8-1", "topo1-1", "rt6")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the eth-sw1 interface from an unknown
//    neighbor (src = 0.0.0.0, dst = 10.0.1.1, router-id = 10.10.10.10)
//
// Output: no changes (0.0.0.0 isn't a valid source address, so the Hello packet
// is dropped)
#[tokio::test]
async fn packet_src1() {
    run_test::<Instance<Ospfv2>>("packet-src1", "topo2-1", "rt1").await;
}

// Test description:
//
// Input:
//  * Protocol: received a Hello packet in the broadcast eth-sw1 interface from
//    an unknown neighbor (src = 172.16.1.10, dst = 10.0.1.1, router-id =
//    10.10.10.10)
//
// Output: no changes (the packet's source address isn't on the same network as
// the receiving interface, so the Hello packet is dropped)
#[tokio::test]
async fn packet_src2() {
    run_test::<Instance<Ospfv2>>("packet-src2", "topo2-1", "rt1").await;
}

// Test description:
//
// This is the same test as packet-src2, except that the Hello packet is
// accepted since the source address network check isn't performed on
// point-to-point interfaces.
//
// Input:
//  * Protocol: received a Hello packet in the point-to-point eth-rt4 interface
//    (src = 172.16.1.10, dst = 10.0.1.1, router-id = 4.4.4.4)
//
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    self-originated Router-LSA
//  * Northbound:
//    - the 4.4.4.4 neighbor transitions from the full state to the init state
//    - the source address from the 4.4.4.4 neighbor changes to 172.16.1.10
//    - the self-originated Router-LSA is updated since the adjacency to 4.4.4.4
//      was reset
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
#[tokio::test]
async fn packet_src3() {
    run_test::<Instance<Ospfv2>>("packet-src3", "topo2-1", "rt6").await;
}

// Test description:
//
// Input:
//  * Protocol: the refresh timer for Router-LSA (adv-rtr 2.2.2.2, lsa-id
//    2.2.2.2) has expired
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the refreshed
//    LSA (age = 0)
//  * Northbound: the retransmission queue length of all adjacencies increases
//    to 1
//
// Input:
//  * Protocol: the retransmission interval has expired for all adjacencies
// Output:
//  * Protocol: send an LS Update to all adjacencies containing all LSAs that
//    that have been flooded but not acknowledged on
#[tokio::test]
async fn rxmt_lsupd1() {
    run_test::<Instance<Ospfv2>>("rxmt-lsupd1", "topo2-1", "rt2").await;
}

// Test description:
//
// New interface address should prompt the local Router-LSA to be reoriginated.
//
// Input:
//  * Southbound: address 172.16.1.1/24 added to eth-rt4
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    Router-LSA, which has a new stub network
//  * Northbound:
//    - the self-originated Router-LSA now contains a new stub network
//      (172.16.1.0/24)
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
#[tokio::test]
async fn sb_addr_add1() {
    run_test::<Instance<Ospfv2>>("sb-addr-add1", "topo2-1", "rt6").await;
}

// Test description:
//
// Southbound messages about interface addresses that already exist should be
// ignored.
//
// Input:
//  * Southbound: address 10.0.7.6/24 added to eth-rt4
// Output: no changes
#[tokio::test]
async fn sb_addr_add2() {
    run_test::<Instance<Ospfv2>>("sb-addr-add2", "topo2-1", "rt6").await;
}

// Test description:
//
// Input:
//  * Southbound: address 10.0.7.6/24 was removed from eth-rt4
// Output:
//  * Protocol: send an LS Update to rt5 containing the updated Router-LSA (the
//    link to rt4 and the 10.0.7.0/24 stub network were removed)
//  * Northbound:
//    - the eth-rt4 interface transitioned to the "down" state
//    - the 4.4.4.4 neighbor was killed
//    - the self-originated Router-LSA was updated
//    - the retransmission queue length of the 5.5.5.5 adjacency increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: all routes affected by the address removal reconverged going
//    through rt5
//  * Southbound: all routes affected by the address removal were reinstalled
//    going through rt5
//
// Input:
//  * Southbound: address 10.0.7.6/24 added to eth-rt4
// Output:
//  * Protocol: send an LS Update to rt5 containing the updated Router-LSA (the
//    10.0.7.0/24 stub network was added)
//  * Northbound:
//    - the eth-rt4 interface transitioned to the "point-to-point" state
//    - the self-originated Router-LSA was updated
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: the route to 10.0.7.0/24 is now marked as connected with a
//    metric of 10
#[tokio::test]
async fn sb_addr_add3() {
    run_test::<Instance<Ospfv2>>("sb-addr-add3", "topo2-1", "rt6").await;
}

// Test description:
//
// Input:
//  * Southbound: address 10.0.2.2/24 was removed from eth-rt4-1
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    Router-LSA (one link to rt4 and the 10.0.2.0/24 stub network were removed)
//  * Northbound:
//    - the eth-rt4-1 interface transitioned to the "down" state
//    - the 4.4.4.4@eth-rt4-1 neighbor was killed
//    - the self-originated Router-LSA was updated
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: the 10.0.2.4 nexthop was removed from all affected routes in
//    the local RIB
//  * Southbound: all routes affected by the address removal were reinstalled
#[tokio::test]
async fn sb_addr_del1() {
    run_test::<Instance<Ospfv2>>("sb-addr-del1", "topo2-1", "rt2").await;
}

// Test description:
//
// Removal of interface address that doesn't exist should be ignored.
//
// Input:
//  * Southbound: address 10.0.2.10/24 was removed from eth-rt4-1
// Output: no changes
#[tokio::test]
async fn sb_addr_del2() {
    run_test::<Instance<Ospfv2>>("sb-addr-del2", "topo2-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Southbound: address 172.16.1.1/24 added to eth-rt4
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    Router-LSA, which has a new stub network
//  * Northbound:
//    - the self-originated Router-LSA now contains a new stub network
//      (172.16.1.0/24)
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Southbound: address 172.16.1.1/24 was removed from eth-rt4
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    Router-LSA (the new stub network was removed)
//  * Northbound:
//    - the self-originated Router-LSA was updated
#[tokio::test]
async fn sb_addr_del3() {
    run_test::<Instance<Ospfv2>>("sb-addr-del3", "topo2-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Southbound: eth-rt4-1 operational status is down
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    Router-LSA (one link to rt4 and the 10.0.2.0/24 stub network were removed)
//  * Northbound:
//    - the eth-rt4-1 interface transitioned to the "down" state
//    - the 4.4.4.4@eth-rt4-1 neighbor was killed
//    - the self-originated Router-LSA was updated
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: the 10.0.2.4 nexthop was removed from all affected routes in
//    the local RIB
//  * Southbound: all routes affected by the interface shutdown were reinstalled
#[tokio::test]
async fn sb_iface_update1() {
    run_test::<Instance<Ospfv2>>("sb-iface-update1", "topo2-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Southbound: eth-sw1 operational status is down
// Output:
//  * Protocol: send an LS Update to all remaining adjacencies containing the
//    updated Router-LSA (transit network link 10.0.1.0/24 was removed)
//  * Northbound:
//    - the eth-sw1 interface transitioned to the "down" state
//    - the 1.1.1.1 and 3.3.3.3 neighbors were killed
//    - the self-originated Router-LSA was updated
//    - the retransmission queue length of all remaining adjacencies increases
//      to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: all routes going through eth-sw1 reconverged through eth-rt4-1
//    and eth-rt4-2
//  * Southbound: all routes affected by the interface shutdown were reinstalled
#[tokio::test]
async fn sb_iface_update2() {
    run_test::<Instance<Ospfv2>>("sb-iface-update2", "topo2-1", "rt2").await;
}

// Test description:
//
// Input:
//  * Southbound: eth-sw1 operational status is down
// Output:
//  * Protocol: send an LS Update to all remaining adjacencies containing the
//    updated Router-LSA (transit network link 10.0.1.0/24 was removed) and
//    flushed Network-LSA (age = 3600)
//  * Northbound:
//    - the eth-sw1 interface transitioned to the "down" state
//    - the 1.1.1.1 and 2.2.2.2 neighbors were killed
//    - the self-originated Router-LSA was updated
//    - the self-originated Network-LSA for 10.0.1.0/24 was flushed
//    - the retransmission queue length of all remaining adjacencies increases
//      to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: all routes going through eth-sw1 reconverged through eth-rt5-1
//    and eth-rt5-2
//  * Southbound: all routes affected by the interface shutdown were reinstalled
#[tokio::test]
async fn sb_iface_update3() {
    run_test::<Instance<Ospfv2>>("sb-iface-update3", "topo2-1", "rt3").await;
}

// Test description:
//
// Input:
//  * Southbound: eth-rt4-1 operational status is down
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    Router-LSA (one link to rt4 and the 10.0.2.0/24 stub network were removed)
//  * Northbound:
//    - the eth-rt4-1 interface transitioned to the "down" state
//    - the 4.4.4.4@eth-rt4-1 neighbor was killed
//    - the self-originated Router-LSA was updated
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: the 10.0.2.4 nexthop was removed from all affected routes in
//    the local RIB
//  * Southbound: all routes affected by the interface shutdown were reinstalled
//
// Input:
//  * Southbound: eth-rt4-1 operational status is up
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    Router-LSA (the 10.0.2.0/24 stub network was added back)
//  * Northbound:
//    - the eth-rt4-1 interface transitioned to the "point-to-point" state
//    - the self-originated Router-LSA was updated
#[tokio::test]
async fn sb_iface_update4() {
    run_test::<Instance<Ospfv2>>("sb-iface-update4", "topo2-1", "rt2").await;
}

// Test description:
//
// Southbound messages about interface status updates where nothing has changed
// should be ignored.
//
// Input:
//  * Southbound: eth-rt4-1 operational status is up
// Output: no changes
#[tokio::test]
async fn sb_iface_update5() {
    run_test::<Instance<Ospfv2>>("sb-iface-update5", "topo2-1", "rt2").await;
}

// Test description:
//
// Southbound messages about interface status updates where nothing has changed
// should be ignored.
//
// Input:
//  * Southbound: eth-rt4-1 operational status is down
// Output:
//  * Protocol: send an LS Update to all adjacencies containing the updated
//    Router-LSA (one link to rt4 and the 10.0.2.0/24 stub network were removed)
//  * Northbound:
//    - the eth-rt4-1 interface transitioned to the "down" state
//    - the 4.4.4.4@eth-rt4-1 neighbor was killed
//    - the self-originated Router-LSA was updated
//    - the retransmission queue length of all adjacencies increases to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound: the 10.0.2.4 nexthop was removed from all affected routes in
//    the local RIB
//  * Southbound: all routes affected by the interface shutdown were reinstalled
//
// Input:
//  * Southbound: eth-rt4-1 operational status is down
// Output: no changes
#[tokio::test]
async fn sb_iface_update6() {
    run_test::<Instance<Ospfv2>>("sb-iface-update6", "topo2-1", "rt2").await;
}

// Test description:
//
// Status messages about interfaces that are not configured for OSPF operation
// should be ignored.
//
// Input:
//  * Southbound: status message about the eth-rt999 interface
// Output: no changes
#[tokio::test]
async fn sb_iface_update7() {
    run_test::<Instance<Ospfv2>>("sb-iface-update7", "topo2-1", "rt2").await;
}

// Test description:
//
// The system Router ID should be ignored if the OSPF instance has an explicit
// Router ID configured.
//
// Input:
//  * Southbound: system Router ID initialize to 10.0.255.1
// Output: no changes
#[tokio::test]
async fn sb_router_id_update1() {
    run_test::<Instance<Ospfv2>>("sb-router-id-update1", "topo1-1", "rt2")
        .await;
}

// Test description:
//
// Input:
//  * Protocol: adjacency 2.2.2.2@eth-rt2 timed out
// Output:
//  * Protocol: send an LS Update to all remaining adjacencies containing the
//    updated Router-LSA and flushed Network-LSA
//  * Northbound:
//    - the self-originated Router-LSA was updated (link to transit network
//      became a stub network)
//    - the self-originated Network-LSA was flushed
//    - the 2.2.2.2 neighbor no longer exists
//    - the BDR is no longer known for interface eth-rt2
//    - the retransmission queue length of all remaining adjacencies increases
//      to 2
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound:
//    - the routes to 1.1.1.1/32, 2.2.2.2/32 and 10.0.1.0/24 were removed
//    - the ABR count is now 2
//  * Southbound: uninstall the routes to 1.1.1.1/32, 2.2.2.2/32 and 10.0.1.0/24
#[tokio::test]
async fn timeout_nbr1() {
    run_test::<Instance<Ospfv2>>("timeout-nbr1", "topo1-2", "rt3").await;
}

// Test description:
//
// Input:
//  * Protocol: adjacency 4.4.4.4@eth-rt4 timed out
// Output:
//  * Protocol: send an LS Update to all remaining adjacencies containing the
//    updated Router-LSA
//  * Northbound:
//    - the self-originated Router-LSA was updated (link to transit network
//      became a stub network)
//    - the 4.4.4.4 neighbor no longer exists
//    - the BDR is no longer known for interface eth-rt4
//    - the retransmission queue length of all remaining adjacencies increases
//      to 1
//    - the SPF Delay FSM state transitions from "quiet" to "short-wait"
//
// Input:
//  * Protocol: SPF_TIMER expiration
// Output:
//  * Northbound:
//    - the routes to 4.4.4.4/32, 5.5.5.5/32 and 10.0.5.0/24 were removed
//    - the ABR count is now 2
//  * Southbound: uninstall the routes to 4.4.4.4/32, 5.5.5.5/32 and 10.0.5.0/24
#[tokio::test]
async fn timeout_nbr2() {
    run_test::<Instance<Ospfv2>>("timeout-nbr2", "topo1-2", "rt3").await;
}
