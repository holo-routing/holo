//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! Build time platform selection.
//!
//! Every function here emits Cargo directives and is only meaningful when
//! called from a build script. The platform backends themselves live in the
//! crates that need them, selected by the cfg symbols emitted here.

use std::env;

/// Network backend a build can use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetworkBackend {
    /// Real sockets.
    Linux,
    /// A network that goes nowhere.
    Null,
}

/// Emits the cfg naming the network backend this build should use.
///
/// `network_backend = "linux"` selects the real sockets, and
/// `network_backend = "null"` a network that goes nowhere. Every platform
/// other than Linux takes the latter, and so do test builds, since their
/// packets are collected by the test framework rather than put on a wire.
pub fn network_backend() {
    println!(
        "cargo::rustc-check-cfg=cfg(network_backend, values(\"linux\", \"null\"))"
    );

    let testing = env::var_os("CARGO_FEATURE_TESTING").is_some();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    match select_network_backend(testing, &target_os) {
        NetworkBackend::Linux => {
            println!("cargo::rustc-cfg=network_backend=\"linux\"");
        }
        NetworkBackend::Null => {
            println!("cargo::rustc-cfg=network_backend=\"null\"");
            if !testing {
                println!(
                    "cargo::warning=no network backend for \"{target_os}\", \
                     network I/O disabled"
                );
            }
        }
    }
}

// ===== helper functions =====

fn select_network_backend(testing: bool, target_os: &str) -> NetworkBackend {
    if !testing && target_os == "linux" {
        return NetworkBackend::Linux;
    }

    NetworkBackend::Null
}
