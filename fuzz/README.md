## Fuzzing overview in holo

Fuzzing is a security testing technique that involves sending random, malformed, or unexpected inputs to software to uncover vulnerabilities or bugs. It helps identify issues like crashes, memory leaks, and buffer overflows that attackers could exploit.

Rust has a profile of being very secure when it comes to memory issues but that is not a complete shield from some other vectors of attack that could be used apart from memory. In Rust, two main tools exist for fuzzing: `cargo-fuzz` which is essentially a wrapper around libfuzzer and `afl.rs` which implement American Fuzzy Loop (AFL).  In holo, we use `cargo-fuzz` to do our fuzzing.

The individual fuzzes are contained inside the `fuzz/fuzz_targets` directory. We mainly fuzz the packet decoders.

Before we begin, you will need to have `cargo-fuzz` installed in your system. Therefore run:
```
$ cargo install cargo-fuzz
```

### Listing available fuzz targets

To list all the fuzz targets that we currently have, go to the holo root directory and run:

```
$ cargo fuzz list
```

Output should be something like:

```
bgp_aggregator_decode
bgp_as_path_decode
bgp_as_path_segment_decode
bgp_attrs_decode
bgp_capability_decode
bgp_comm_decode
bgp_ext_comm_decode
bgp_extv6_comm_decode
bgp_ipv4_prefix_decode
bgp_ipv6_prefix_decode
bgp_keepalivemsg_decode
bgp_large_comm_decode
bgp_message_decode
bgp_mpreachnlri_decode
bgp_notificationmsg_decode
bgp_openmsg_decode
bgp_routerefreshmsg_decode
bgp_updatemsg_decode
vrrp_vrrphdr_ipv4_decode
vrrp_vrrphdr_ipv6_decode
```
As said earlier, we primarily fuzz decoders in holo.

### Fuzz a single target

If we want to fuzz a single target, let's say `bgp_aggregator_decode` we'll run the following command (remember, still from holo's root directory):

```
$ cargo fuzz run bgp_aggregator_decode
```
The fuzzer will run infinitely until you stop it yourself (`Ctrl+C`).

What if you want it to run for a specific amount of time. Say five minutes:

```
$ cargo fuzz run bgp_aggregator_decode -- -timeout=300
```

We'll add `-timeout={number-of-seconds}` as arguments for our run command.

### Fuzzing all targets.

Running individual targets, especially as they increase in number can be hectic.

You can therefore run the following(still from the root directory) to fuzz all the targets:

```
./fuzz-all.sh
```

This will run each of the fuzz targets we have created for 5 minutes.
