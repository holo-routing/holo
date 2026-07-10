//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};

use holo_bgp::instance::Instance;
use holo_bgp::packet::attribute::{
    AsPath, AsPathSegment, AsPathSegmentType, Attrs, BaseAttrs,
};
use holo_bgp::packet::iana::{Afi, Safi};
use holo_bgp::packet::message::{
    AddPathMode, AddPathTuple, Capability, KeepaliveMsg, Message, OpenMsg,
    ReachNlri, UnreachNlri, UpdateMsg,
};
use holo_bgp::policy::RoutePolicyInfo;
use holo_bgp::rib::RouteOrigin;
use holo_bgp::tasks::messages::input::{
    NbrRxMsg, NbrTimerMsg, PolicyResultMsg, ProtocolMsg, TcpAcceptMsg,
};
use holo_protocol::InstanceMsg;
use holo_protocol::test::setup;
use holo_protocol::test::stub::{Stub, start_test_instance};
use holo_utils::bgp::{AfiSafi, Origin, RouteType};
use holo_utils::policy::{PolicyResult, PolicyType};
use holo_utils::socket::TcpConnInfo;
use ipnetwork::{IpNetwork, Ipv4Network};
use serde_json::Value;

const PREFIX: &str = "203.0.113.0/24";

#[tokio::test]
async fn rx_multiple_paths_are_keyed_by_path_id() {
    setup();

    let mut stub = start_test_instance::<Instance>("test").await;
    stub.commit_replace(&config(&[neighbor("192.0.2.1", 65001, true, false)]))
        .await;
    stub.reset_output();

    establish_session(
        &stub,
        "192.0.2.254",
        "192.0.2.1",
        65001,
        "192.0.2.1",
        AddPathMode::Send,
    )
    .await;
    drain(&stub).await;

    inject_path(&stub, "192.0.2.1", 1, &[65001, 65002]).await;
    accept_import(&stub, "192.0.2.1", 1, &[65001, 65002]).await;
    inject_path(&stub, "192.0.2.1", 2, &[65001]).await;
    accept_import(&stub, "192.0.2.1", 2, &[65001]).await;
    nexthop_update(&stub, "192.0.2.1").await;
    trigger_decision(&stub).await;

    let state_json = state(&stub).await;
    assert_path_id_present(&state_json, 1);
    assert_path_id_present(&state_json, 2);
    assert_local_rib_as_path(&state_json, &[65001]);

    withdraw_path(&stub, "192.0.2.1", 2).await;
    trigger_decision(&stub).await;

    let state_json = state(&stub).await;
    assert_path_id_present(&state_json, 1);
    assert_path_id_absent(&state_json, 2);
    assert_local_rib_as_path(&state_json, &[65001, 65002]);

    stub.close().await;
}

#[tokio::test]
async fn tx_all_paths_and_non_add_path_peer_behavior() {
    setup();

    let mut stub = start_test_instance::<Instance>("test").await;
    stub.commit_replace(&config(&[
        neighbor("192.0.2.1", 65001, true, false),
        neighbor("192.0.2.2", 65002, false, true),
        neighbor("192.0.2.3", 65003, false, false),
    ]))
    .await;
    stub.reset_output();

    establish_session(
        &stub,
        "192.0.2.254",
        "192.0.2.1",
        65001,
        "192.0.2.1",
        AddPathMode::Send,
    )
    .await;
    establish_session(
        &stub,
        "192.0.2.254",
        "192.0.2.2",
        65002,
        "192.0.2.2",
        AddPathMode::Receive,
    )
    .await;
    establish_session_without_add_path(
        &stub,
        "192.0.2.254",
        "192.0.2.3",
        65003,
        "192.0.2.3",
    )
    .await;
    drain(&stub).await;

    inject_path(&stub, "192.0.2.1", 1, &[65001, 65011]).await;
    accept_import(&stub, "192.0.2.1", 1, &[65001, 65011]).await;
    inject_path(&stub, "192.0.2.1", 2, &[65001]).await;
    accept_import(&stub, "192.0.2.1", 2, &[65001]).await;
    nexthop_update(&stub, "192.0.2.1").await;
    trigger_decision(&stub).await;

    let add_path_ids = [
        advertised_path_id("192.0.2.1", 1),
        advertised_path_id("192.0.2.1", 2),
    ];
    accept_export(&stub, "192.0.2.2", add_path_ids[0], &[65001, 65011]).await;
    accept_export(&stub, "192.0.2.2", add_path_ids[1], &[65001]).await;
    accept_export(&stub, "192.0.2.3", 0, &[65001]).await;

    let output = drain(&stub).await;
    let add_path_reach = reach_path_ids(&output, "192.0.2.2");
    assert_eq!(add_path_reach.len(), 2);
    assert!(add_path_reach.contains(&add_path_ids[0]));
    assert!(add_path_reach.contains(&add_path_ids[1]));
    assert_ne!(add_path_ids[0], add_path_ids[1]);

    let non_add_path_reach = reach_path_ids(&output, "192.0.2.3");
    assert_eq!(non_add_path_reach, vec![0]);

    send_route_refresh(&stub, "192.0.2.2").await;
    let refresh_output = drain(&stub).await;
    let mut refresh_path_ids = reach_path_ids(&refresh_output, "192.0.2.2");
    let mut add_path_reach_sorted = add_path_reach;
    refresh_path_ids.sort();
    add_path_reach_sorted.sort();
    assert_eq!(refresh_path_ids, add_path_reach_sorted);

    stub.close().await;
}

#[tokio::test]
async fn negotiation_direction_controls_rx_and_tx() {
    setup();

    let mut stub = start_test_instance::<Instance>("test").await;
    stub.commit_replace(&config(&[
        neighbor("192.0.2.1", 65001, true, false),
        neighbor("192.0.2.2", 65002, false, true),
    ]))
    .await;
    stub.reset_output();

    establish_session(
        &stub,
        "192.0.2.254",
        "192.0.2.1",
        65001,
        "192.0.2.1",
        AddPathMode::Send,
    )
    .await;
    establish_session(
        &stub,
        "192.0.2.254",
        "192.0.2.2",
        65002,
        "192.0.2.2",
        AddPathMode::Receive,
    )
    .await;
    drain(&stub).await;

    inject_path(&stub, "192.0.2.1", 7, &[65001]).await;
    accept_import(&stub, "192.0.2.1", 7, &[65001]).await;
    inject_path(&stub, "192.0.2.2", 0, &[65002]).await;
    accept_import(&stub, "192.0.2.2", 0, &[65002]).await;
    nexthop_update(&stub, "192.0.2.1").await;
    nexthop_update(&stub, "192.0.2.2").await;
    trigger_decision(&stub).await;

    let state = state(&stub).await;
    assert_path_id_present(&state, 7);
    assert_path_id_present(&state, 0);

    accept_export(&stub, "192.0.2.1", 0, &[65001]).await;
    let advertised_id = advertised_path_id("192.0.2.1", 7);
    accept_export(&stub, "192.0.2.2", advertised_id, &[65001]).await;

    let output = drain(&stub).await;
    assert_eq!(reach_path_ids(&output, "192.0.2.1"), vec![0]);
    assert_eq!(reach_path_ids(&output, "192.0.2.2"), vec![advertised_id]);

    stub.close().await;
}

fn config(neighbors: &[String]) -> String {
    format!(
        r#"{{
  "ietf-routing:routing": {{
    "control-plane-protocols": {{
      "control-plane-protocol": [
        {{
          "type": "ietf-bgp:bgp",
          "name": "test",
          "ietf-bgp:bgp": {{
            "global": {{
              "as": 65000,
              "identifier": "192.0.2.254",
              "afi-safis": {{
                "afi-safi": [
                  {{
                    "name": "iana-bgp-types:ipv4-unicast"
                  }}
                ]
              }}
            }},
            "neighbors": {{
              "neighbor": [
                {}
              ]
            }}
          }}
        }}
      ]
    }}
  }}
}}"#,
        neighbors.join(",\n                ")
    )
}

fn neighbor(
    remote_addr: &str,
    peer_as: u32,
    add_path_receive: bool,
    add_path_send_all: bool,
) -> String {
    let add_paths = match (add_path_receive, add_path_send_all) {
        (false, false) => String::new(),
        (receive, false) => {
            format!(r#","add-paths":{{"receive":{receive}}}"#)
        }
        (receive, true) => {
            format!(r#","add-paths":{{"receive":{receive},"all":[null]}}"#)
        }
    };

    format!(
        r#"{{
                  "remote-address": "{remote_addr}",
                  "peer-as": {peer_as},
                  "afi-safis": {{
                    "afi-safi": [
                      {{
                        "name": "iana-bgp-types:ipv4-unicast",
                        "enabled": true,
                        "apply-policy": {{
                          "default-import-policy": "accept-route",
                          "default-export-policy": "accept-route"
                        }}
                      }}
                    ]
                  }}{add_paths}
                }}"#
    )
}

async fn establish_session(
    stub: &Stub<Instance>,
    local_addr: &str,
    remote_addr: &str,
    peer_as: u32,
    identifier: &str,
    peer_add_path: AddPathMode,
) {
    accept_tcp(stub, local_addr, remote_addr).await;
    recv(
        stub,
        remote_addr,
        Message::Open(open(peer_as, identifier, Some(peer_add_path))),
    )
    .await;
    recv(stub, remote_addr, Message::Keepalive(KeepaliveMsg {})).await;
}

async fn establish_session_without_add_path(
    stub: &Stub<Instance>,
    local_addr: &str,
    remote_addr: &str,
    peer_as: u32,
    identifier: &str,
) {
    accept_tcp(stub, local_addr, remote_addr).await;
    recv(
        stub,
        remote_addr,
        Message::Open(open(peer_as, identifier, None)),
    )
    .await;
    recv(stub, remote_addr, Message::Keepalive(KeepaliveMsg {})).await;
}

async fn accept_tcp(
    stub: &Stub<Instance>,
    local_addr: &str,
    remote_addr: &str,
) {
    stub.send(InstanceMsg::Protocol(ProtocolMsg::NbrTimer(NbrTimerMsg {
        nbr_addr: ip(remote_addr),
        timer: holo_bgp::neighbor::fsm::Timer::AutoStart,
    })))
    .await;
    stub.send(InstanceMsg::Protocol(ProtocolMsg::TcpAccept(
        TcpAcceptMsg {
            stream: None,
            conn_info: TcpConnInfo {
                local_addr: ip(local_addr),
                local_port: 179,
                remote_addr: ip(remote_addr),
                remote_port: 1179,
            },
        },
    )))
    .await;
}

fn open(
    peer_as: u32,
    identifier: &str,
    add_path: Option<AddPathMode>,
) -> OpenMsg {
    let mut capabilities: BTreeSet<Capability> = [
        Capability::MultiProtocol {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        },
        Capability::FourOctetAsNumber { asn: peer_as },
        Capability::RouteRefresh,
    ]
    .into();

    if let Some(mode) = add_path {
        capabilities.insert(Capability::AddPath(
            [AddPathTuple {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                mode,
            }]
            .into(),
        ));
    }

    OpenMsg {
        version: OpenMsg::VERSION,
        my_as: peer_as.try_into().unwrap(),
        holdtime: 90,
        identifier: identifier.parse().unwrap(),
        capabilities,
    }
}

async fn inject_path(
    stub: &Stub<Instance>,
    nbr_addr: &str,
    path_id: u32,
    as_path: &[u32],
) {
    let attrs = attrs(nbr_addr, as_path);
    recv(
        stub,
        nbr_addr,
        Message::Update(UpdateMsg {
            unreach: None,
            attrs: Some(attrs),
            reach: Some(ReachNlri {
                prefixes: vec![prefix()],
                path_ids: vec![path_id],
                nexthop: nbr_addr.parse().unwrap(),
            }),
            mp_reach: None,
            mp_unreach: None,
        }),
    )
    .await;
}

async fn withdraw_path(stub: &Stub<Instance>, nbr_addr: &str, path_id: u32) {
    recv(
        stub,
        nbr_addr,
        Message::Update(UpdateMsg {
            unreach: Some(UnreachNlri {
                prefixes: vec![prefix()],
                path_ids: vec![path_id],
            }),
            attrs: None,
            reach: None,
            mp_reach: None,
            mp_unreach: None,
        }),
    )
    .await;
}

async fn send_route_refresh(stub: &Stub<Instance>, nbr_addr: &str) {
    recv(
        stub,
        nbr_addr,
        Message::RouteRefresh(holo_bgp::packet::message::RouteRefreshMsg {
            afi: Afi::Ipv4 as u16,
            safi: Safi::Unicast as u8,
        }),
    )
    .await;
}

async fn recv(stub: &Stub<Instance>, nbr_addr: &str, msg: Message) {
    stub.send(InstanceMsg::Protocol(ProtocolMsg::NbrRx(NbrRxMsg {
        nbr_addr: ip(nbr_addr),
        msg: Ok(msg),
    })))
    .await;
}

async fn accept_import(
    stub: &Stub<Instance>,
    nbr_addr: &str,
    path_id: u32,
    as_path: &[u32],
) {
    policy_result(
        stub,
        PolicyType::Import,
        nbr_addr,
        path_id,
        nbr_addr,
        nbr_addr,
        as_path,
    )
    .await;
}

async fn accept_export(
    stub: &Stub<Instance>,
    nbr_addr: &str,
    path_id: u32,
    as_path: &[u32],
) {
    policy_result(
        stub,
        PolicyType::Export,
        nbr_addr,
        path_id,
        "192.0.2.1",
        "192.0.2.1",
        as_path,
    )
    .await;
}

async fn policy_result(
    stub: &Stub<Instance>,
    policy_type: PolicyType,
    nbr_addr: &str,
    path_id: u32,
    origin_remote_addr: &str,
    nexthop: &str,
    as_path: &[u32],
) {
    stub.send(InstanceMsg::Protocol(ProtocolMsg::PolicyResult(
        PolicyResultMsg::Neighbor {
            policy_type,
            nbr_addr: ip(nbr_addr),
            afi_safi: AfiSafi::Ipv4Unicast,
            routes: vec![(
                IpNetwork::V4(prefix()),
                PolicyResult::Accept(RoutePolicyInfo {
                    origin: RouteOrigin::Neighbor {
                        identifier: Ipv4Addr::new(192, 0, 2, 1),
                        remote_addr: ip(origin_remote_addr),
                    },
                    route_type: RouteType::External,
                    tag: None,
                    opaque_attrs: None,
                    attrs: attrs(nexthop, as_path),
                }),
            )],
            path_ids: vec![path_id],
        },
    )))
    .await;
}

async fn nexthop_update(stub: &Stub<Instance>, addr: &str) {
    let msg = format!(
        r#"{{"Ibus":{{"NexthopUpd":{{"addr":"{addr}","metric":0}}}}}}"#
    );
    stub.send(serde_json::from_str(&msg).unwrap()).await;
}

async fn trigger_decision(stub: &Stub<Instance>) {
    stub.send(InstanceMsg::Protocol(ProtocolMsg::TriggerDecisionProcess(
        (),
    )))
    .await;
    stub.sync().await;
}

async fn drain(stub: &Stub<Instance>) -> Vec<Value> {
    stub.sync().await;
    tokio::task::yield_now().await;
    stub.take_protocol_output()
        .into_iter()
        .map(|line| serde_json::from_str(&line).unwrap())
        .collect()
}

async fn state(stub: &Stub<Instance>) -> Value {
    serde_json::from_str(&stub.state_json().await).unwrap()
}

fn attrs(nexthop: &str, as_path: &[u32]) -> Attrs {
    Attrs {
        base: BaseAttrs {
            origin: Origin::Incomplete,
            as_path: AsPath {
                segments: vec![AsPathSegment {
                    seg_type: AsPathSegmentType::Sequence,
                    members: as_path.iter().copied().collect::<VecDeque<_>>(),
                }]
                .into(),
            },
            nexthop: Some(ip(nexthop)),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn reach_path_ids(output: &[Value], nbr_addr: &str) -> Vec<u32> {
    let mut path_ids = vec![];
    for msg in output {
        let Some(send_msg_list) =
            msg.get("NbrTx").and_then(|msg| msg.get("SendMessageList"))
        else {
            continue;
        };
        if send_msg_list.get("nbr_addr").and_then(Value::as_str)
            != Some(nbr_addr)
        {
            continue;
        }
        let Some(msg_list) =
            send_msg_list.get("msg_list").and_then(Value::as_array)
        else {
            continue;
        };
        for msg in msg_list {
            let Some(reach) =
                msg.get("Update").and_then(|update| update.get("reach"))
            else {
                continue;
            };
            let Some(prefixes) =
                reach.get("prefixes").and_then(Value::as_array)
            else {
                continue;
            };
            if !prefixes
                .iter()
                .any(|prefix| prefix.as_str() == Some(PREFIX))
            {
                continue;
            }
            if let Some(ids) = reach.get("path_ids").and_then(Value::as_array) {
                path_ids.extend(
                    ids.iter().map(|path_id| path_id.as_u64().unwrap() as u32),
                );
            } else {
                path_ids.push(0);
            }
        }
    }
    path_ids
}

fn assert_path_id_present(state: &Value, path_id: u32) {
    assert!(
        has_path_id(state, path_id),
        "path-id {path_id} missing from state: {state}"
    );
}

fn assert_path_id_absent(state: &Value, path_id: u32) {
    assert!(
        !has_path_id(state, path_id),
        "path-id {path_id} unexpectedly present in state: {state}"
    );
}

fn has_path_id(value: &Value, path_id: u32) -> bool {
    match value {
        Value::Object(map) => {
            if map.get("path-id").and_then(Value::as_u64)
                == Some(path_id as u64)
                && object_contains_prefix(value)
            {
                return true;
            }
            map.values().any(|value| has_path_id(value, path_id))
        }
        Value::Array(values) => {
            values.iter().any(|value| has_path_id(value, path_id))
        }
        _ => false,
    }
}

fn object_contains_prefix(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.get("prefix").and_then(Value::as_str) == Some(PREFIX)
                || map.values().any(object_contains_prefix)
        }
        Value::Array(values) => values.iter().any(object_contains_prefix),
        _ => false,
    }
}

fn assert_local_rib_as_path(state: &Value, expected: &[u32]) {
    let Some(loc_rib) = find_key(state, "loc-rib") else {
        panic!("loc-rib not found in state: {state}");
    };
    let Some(attr_index) = loc_rib_attr_index(loc_rib) else {
        panic!("{PREFIX} not found in loc-rib: {loc_rib}");
    };
    let Some(attr_sets) = find_key(state, "attr-sets") else {
        panic!("attr-sets not found in state: {state}");
    };
    assert!(
        attr_set_contains_as_path(attr_sets, attr_index, expected),
        "attr-set {attr_index} did not contain AS path {expected:?}: {attr_sets}"
    );
}

fn loc_rib_attr_index(value: &Value) -> Option<&str> {
    match value {
        Value::Object(map) => {
            if map.get("prefix").and_then(Value::as_str) == Some(PREFIX) {
                return map.get("attr-index").and_then(Value::as_str);
            }
            map.values().find_map(loc_rib_attr_index)
        }
        Value::Array(values) => values.iter().find_map(loc_rib_attr_index),
        _ => None,
    }
}

fn attr_set_contains_as_path(
    value: &Value,
    attr_index: &str,
    expected: &[u32],
) -> bool {
    match value {
        Value::Object(map) => {
            if map.get("index").and_then(Value::as_str) == Some(attr_index)
                && find_key(value, "member")
                    .and_then(Value::as_array)
                    .is_some_and(|members| {
                        members
                            .iter()
                            .map(|member| member.as_u64().unwrap() as u32)
                            .eq(expected.iter().copied())
                    })
            {
                return true;
            }
            map.values().any(|value| {
                attr_set_contains_as_path(value, attr_index, expected)
            })
        }
        Value::Array(values) => values.iter().any(|value| {
            attr_set_contains_as_path(value, attr_index, expected)
        }),
        _ => false,
    }
}

fn find_key<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map
            .get(key)
            .or_else(|| map.values().find_map(|value| find_key(value, key))),
        Value::Array(values) => {
            values.iter().find_map(|value| find_key(value, key))
        }
        _ => None,
    }
}

fn advertised_path_id(remote_addr: &str, path_id: u32) -> u32 {
    let mut hasher = DefaultHasher::new();
    ip(remote_addr).hash(&mut hasher);
    path_id.hash(&mut hasher);
    let path_id = hasher.finish() as u32;
    if path_id == 0 { 1 } else { path_id }
}

fn prefix() -> Ipv4Network {
    PREFIX.parse().unwrap()
}

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}
