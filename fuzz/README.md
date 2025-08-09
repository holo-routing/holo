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
bfd_packet_decode
bgp_attr_aggregator_decode
bgp_attr_as_path_decode
bgp_attr_as_path_segment_decode
bgp_attr_comm_decode
bgp_attr_ext_comm_decode
bgp_attr_extv6_comm_decode
bgp_attr_large_comm_decode
bgp_attr_mpreachnlri_decode
bgp_attrs_decode
bgp_ipv4_prefix_decode
bgp_ipv6_prefix_decode
bgp_message_decode
bgp_message_keepalive_decode
bgp_message_notification_decode
bgp_message_open_capability_decode
bgp_message_open_decode
bgp_message_routerefresh_decode
bgp_message_update_decode
isis_pdu_decode
ldp_pdu_decode
ospfv2_lsa_decode
ospfv2_packet_decode
ospfv3_ipv4_lsa_decode
ospfv3_ipv4_packet_decode
ospfv3_ipv6_lsa_decode
ospfv3_ipv6_packet_decode
ripng_pdu_decode
ripv2_pdu_decode
vrrp_vrrphdr_ipv4_decode
vrrp_vrrphdr_ipv6_decode
```
As said earlier, we primarily fuzz decoders in holo.

### Fuzz a single target

If we want to fuzz a single target, let's say `bgp_attr_aggregator_decode` we'll run the following command (remember, still from holo's root directory):

```
$ RUST_BACKTRACE=1 cargo fuzz run bgp_attr_aggregator_decode
```
The fuzzer will run infinitely until you stop it yourself (`Ctrl+C`).

What if you want it to run for a specific amount of time. Say five minutes:

```
$ RUST_BACKTRACE=1 cargo fuzz run bgp_attr_aggregator_decode -- -timeout=300
```

We'll add `-timeout={number-of-seconds}` as arguments for our run command.

### Fuzzing all targets.

Running individual targets, especially as they increase in number can be hectic.

You can therefore run the following(still from the root directory) to fuzz all the targets:

```
./fuzz-all.sh
```

This will run each of the fuzz targets we have created for 5 minutes.

### Generate code-coverage data

Code coverage data helps identify which code paths are exercised during fuzzing. This information shows which parts of the code remain untested, so you can take steps such as adding fuzz targets with different entry points or expanding the corpus with new seed inputs. You can find more details in the [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/coverage.html).

The following instructions use the `isis_pdu_decode` fuzz target as an example.

#### 1. Run the fuzz target

Begin by running the fuzz target for a long period to exercise as many code paths as possible. The `-j` option allows multiple fuzzer instances to run in parallel while sharing the same corpus.
```
cargo fuzz run -j 8 isis_pdu_decode
```

#### 2. Generate coverage data

Once the fuzz run has completed, generate coverage information:
```
cargo fuzz coverage isis_pdu_decode
```

#### 3. Generate a coverage report

A text-based coverage report can be generated using `llvm-cov` as follows:
```
~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov report \
  -instr-profile=fuzz/coverage/isis_pdu_decode/coverage.profdata \
  target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/isis_pdu_decode \
  $(find holo-isis/src/packet -name '*.rs')
```

Example output:
```
$ ~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov report \
  -instr-profile=fuzz/coverage/isis_pdu_decode/coverage.profdata \
  target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/isis_pdu_decode \
  $(find holo-isis/src/packet -name '*.rs')
Filename                      Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
tlv.rs                           1954              1098    43.81%         122               100    18.03%        1311               706    46.15%           0                 0         -
pdu.rs                           1898              1241    34.62%         114               107     6.14%        1299               934    28.10%           0                 0         -
error.rs                          100                94     6.00%           5                 3    40.00%          53                47    11.32%           0                 0         -
mod.rs                            198               150    24.24%          31                24    22.58%         164               126    23.17%           0                 0         -
consts.rs                           3                 3     0.00%           1                 1     0.00%           3                 3     0.00%           0                 0         -
subtlvs/capability.rs             222               118    46.85%          19                14    26.32%         151                76    49.67%           0                 0         -
subtlvs/prefix.rs                 280               158    43.57%          20                15    25.00%         177                90    49.15%           0                 0         -
subtlvs/neighbor.rs               254               158    37.80%          23                15    34.78%         176                84    52.27%           0                 0         -
auth.rs                            56                56     0.00%           5                 5     0.00%          46                46     0.00%           0                 0         -                                                     -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                            4965              3076    38.05%         340               284    16.47%        3380              2112    37.51%           0                 0         -
```

#### 4. Generate an HTML coverage report

Generating an HTML report lets you visually identify which lines were not executed during fuzzing:
```
~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov show \
  -instr-profile=fuzz/coverage/isis_pdu_decode/coverage.profdata \
  target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/isis_pdu_decode \
  -format=html \
  $(find holo-isis/src/packet -name '*.rs') > cov-isis-pdu-decode.html
```

In the resulting HTML report, lines highlighted in red indicate code that was not executed, while other lines represent covered code paths.

Since most fuzz targets focus on packet decoding, it's normal for code related to packet encoding and various helper functions to remain uncovered.
