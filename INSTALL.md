## Installation

Holo uses unstable Rust features, so building it from the source code requires a nightly version of the Rust compiler.

Also, Holo has a runtime dependency of the `zebra` daemon from [FRRouting (v8.4..v8.5)](https://github.com/FRRouting/frr).
`zebra` is used as a proxy to communicate with the Linux kernel.
This dependency shall be removed in the future.

### Build from source

1. Install the Rust toolchain

If you don't already have Rust in your system, the best way to install it is via [rustup](https://rustup.rs/) (be sure to choose the nightly toolchain).

2. Clone Holo's git repository

```
$ git clone https://github.com/rwestphal/holo.git
```

3. Build `holod` and `holo-cli`

```
$ cd holo/
$ cargo build --release
```

4. Installation

Copy the `holod` and `holo-cli` binaries from the `target/release` directory to your preferred location.

## Configuration

`holod` configuration consists of the following:
* `/etc/holod.toml`: static configuration that can't change once the daemon starts. It's meant to configure which features are enabled, plugins parameters, among other things.
  Here's an [example](holo-daemon/holod.toml) containing the default values. If this file doesn't exist, the default values will be used.
* Running configuration: this is the normal YANG-modeled
configuration that can only be changed through a northbound client
(e.g. [gRPC](https://github.com/rwestphal/holo/wiki/gRPC),
[gNMI](https://github.com/rwestphal/holo/wiki/gNMI),
[CLI](https://github.com/rwestphal/holo/wiki/CLI), etc).
