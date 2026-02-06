//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

fn main() {
    let modules = holo_yang::implemented_modules::SYSTEM;
    holo_northbound::yang_codegen::build(modules);
}
