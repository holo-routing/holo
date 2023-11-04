//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::str::FromStr;

use clap::{App, Arg};
use holo_ospf::version::{Ospfv2, Ospfv3};
use holo_protocol::test::setup;
use holo_protocol::test::stub::start_test_instance;
use holo_protocol::ProtocolInstance;
use holo_rip::version::{Ripng, Ripv2};
use holo_utils::protocol::Protocol;

async fn replay<P: ProtocolInstance>(filename: &str) {
    // Spawn protocol instance.
    let stub = start_test_instance::<P>("replay").await;

    // Push events from the record file.
    for msg in std::fs::read_to_string(filename)
        .expect("Unable to read record file")
        .lines()
    {
        let msg = serde_json::from_str(msg)
            .expect("Failed to parse instance message");
        stub.send(msg).await;
    }

    // Close protocol instance.
    stub.close().await;
}

#[tokio::main]
async fn main() {
    // Parse command-line parameters.
    let matches = App::new("Replay events")
        .about("Replay events from a record file")
        .arg(
            Arg::with_name("PROTOCOL")
                .long("protocol")
                .help("Protocol name (e.g. BGP, OSPFv2)")
                .value_name("PROTOCOL")
                .required(true),
        )
        .arg(
            Arg::with_name("FILENAME")
                .help("Events file path")
                .required(true)
                .index(1),
        )
        .get_matches();
    let protocol = matches.value_of("PROTOCOL").unwrap();
    let protocol = Protocol::from_str(protocol).expect("Unknown protocol");
    let filename = matches.value_of("FILENAME").unwrap();

    // Setup test environment.
    setup();

    // Replay events.
    match protocol {
        Protocol::BFD => replay::<holo_bfd::master::Master>(filename).await,
        Protocol::LDP => replay::<holo_ldp::instance::Instance>(filename).await,
        Protocol::OSPFV2 => {
            replay::<holo_ospf::instance::Instance<Ospfv2>>(filename).await
        }
        Protocol::OSPFV3 => {
            replay::<holo_ospf::instance::Instance<Ospfv3>>(filename).await
        }
        Protocol::RIPV2 => {
            replay::<holo_rip::instance::Instance<Ripv2>>(filename).await
        }
        Protocol::RIPNG => {
            replay::<holo_rip::instance::Instance<Ripng>>(filename).await
        }
        Protocol::DIRECT | Protocol::STATIC => {
            eprintln!("Unsupported protocol type");
            std::process::exit(1);
        }
    }
}
