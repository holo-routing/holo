## Installation

### Build from source

1. Install the Rust toolchain

If you don't already have Rust in your system, the best way to install it is via [rustup](https://rustup.rs/).

2. Clone Holo's git repositories

```
$ git clone https://github.com/holo-routing/holo.git
$ git clone https://github.com/holo-routing/holo-cli.git
```

3. Install build dependencies:

Holo requires a few dependencies for building and embedding the libyang library.
You can install them using your system's package manager. For example, on Debian-based systems:

```
# apt-get install build-essential cmake libpcre2-dev protobuf-compiler
```

4. Build `holod` and `holo-cli`

```
$ cd holo/
$ cargo build --release
$ cd ../holo-cli/
$ cargo build --release
```

5. Add `holo` user and group:

```sh
# groupadd -r holo
# mkdir /var/opt/holo
# useradd --system --shell /sbin/nologin --home-dir /var/opt/holo/ -g holo holo
# chown holo:holo /var/opt/holo
```

6. Installation

Copy the `holod` and `holo-cli` binaries from the `target/release` directories to your preferred location.

Alternatively, you can use `cargo install` to install these binaries into the `$HOME/.cargo/bin` directory.

## Configuration

`holod` configuration consists of the following:
* `/etc/holod.toml`: static configuration that can't change once the daemon starts. It's meant to configure which features are enabled, plugins parameters, among other things.
  Here's an [example](holo-daemon/holod.toml) containing the default values. If this file doesn't exist, the default values will be used.
* Running configuration: this is the normal YANG-modeled
configuration that can only be changed through a northbound client
(e.g. [gRPC](https://github.com/holo-routing/holo/wiki/gRPC),
[gNMI](https://github.com/holo-routing/holo/wiki/gNMI),
[CLI](https://github.com/holo-routing/holo/wiki/CLI), etc).
