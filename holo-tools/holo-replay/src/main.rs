//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::str::FromStr;

use holo_ospf::version::{Ospfv2, Ospfv3};
use holo_protocol::ProtocolInstance;
use holo_protocol::test::setup;
use holo_protocol::test::stub::start_test_instance;
use holo_rip::version::{Ripng, Ripv2};
use holo_utils::protocol::Protocol;

#[derive(Debug)]
struct Args {
    protocol: String,
    filename: String,
}

// Usage summary printed by --help and on command-line errors.
const USAGE: &str = "\
Usage: replay --protocol <PROTOCOL> <FILENAME>

Replay events from a record file.

Arguments:
  <FILENAME>  Events file path

Options:
      --protocol <PROTOCOL>  Protocol name (e.g. BGP, OSPFv2)
  -h, --help                 Print this help message and exit";

fn parse_args() -> Result<Args, lexopt::Error> {
    let mut protocol = None;
    let mut filename = None;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("protocol") => {
                protocol = Some(parser.value()?.into_string()?);
            }
            lexopt::Arg::Value(value) if filename.is_none() => {
                filename = Some(value.into_string()?);
            }
            lexopt::Arg::Short('h') | lexopt::Arg::Long("help") => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(Args {
        protocol: protocol.ok_or("missing option '--protocol'")?,
        filename: filename.ok_or("missing argument <FILENAME>")?,
    })
}

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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Parse command-line parameters.
    let args = parse_args().unwrap_or_else(|error| {
        eprintln!("{error}\n\n{USAGE}");
        std::process::exit(1);
    });
    let protocol =
        Protocol::from_str(&args.protocol).expect("Unknown protocol");
    let filename = args.filename.as_str();

    // Setup test environment.
    setup();

    // Replay events.
    match protocol {
        Protocol::BFD => replay::<holo_bfd::master::Master>(filename).await,
        Protocol::BGP => replay::<holo_bgp::instance::Instance>(filename).await,
        Protocol::LDP => replay::<holo_ldp::instance::Instance>(filename).await,
        Protocol::IGMP => {
            replay::<holo_igmp::instance::Instance>(filename).await
        }
        Protocol::ISIS => {
            replay::<holo_isis::instance::Instance>(filename).await
        }
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
        Protocol::DIRECT | Protocol::KERNEL | Protocol::STATIC => {
            eprintln!("Unsupported protocol type");
            std::process::exit(1);
        }
        Protocol::VRRP => {
            replay::<holo_vrrp::interface::Interface>(filename).await
        }
    }
}
