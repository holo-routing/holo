[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]
[![codecov][codecov-badge]][codecov-url]
[![Discord][discord-badge]][discord-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/rwestphal/holo/blob/master/LICENSE
[actions-badge]: https://github.com/rwestphal/holo/workflows/CI/badge.svg
[actions-url]: https://github.com/rwestphal/holo/actions?query=workflow%3ACI+branch%3Amaster
[codecov-badge]: https://codecov.io/gh/rwestphal/holo/branch/master/graph/badge.svg?token=OMV0RMNVY8
[codecov-url]: https://codecov.io/gh/rwestphal/holo
[discord-badge]: https://img.shields.io/discord/1090816494524452935.svg?logo=discord
[discord-url]: https://discord.gg/deqkRvhHB9

Holo is a suite of routing protocols designed to support high-scale and
automation-driven networks.

For a description of what a routing protocol is, please refer to this
[Wikipedia page](https://en.wikipedia.org/wiki/Routing_protocol).

## Features

#### Focus on simplicity and correctness

Holo's main goal is to create a reliable, easy-to-maintain, and
extensible codebase.  With the ever increasing complexity of routing
protocols and their extensions, it's crucial to have routing protocol
implementations built on a robust foundation.  To that end, Holo's
codebase prioritizes simplicity, modularity, and thorough documentation.
Thanks to the strictness of the Rust compiler and extensive unit
tests, it's expected that most regressions will be caught early in the
development cycle of new features. For more details, please refer to the
[Architecture](https://github.com/rwestphal/holo/wiki/Architecture) page.

#### Automation-ready

Holo was developed specifically for high-scale, automation-driven
networks that require programmable configuration and monitoring
using structured and modeled data.  Holo natively implements standard
YANG modules from IETF and supports multiple management interfaces,
including native [gRPC](https://github.com/rwestphal/holo/wiki/gRPC) and
[gNMI](https://github.com/rwestphal/holo/wiki/gNMI).  Additionally, Holo
features a standalone [CLI](https://github.com/rwestphal/holo/wiki/CLI)
that dynamically renders commands from YANG modules and communicates with
the Holo daemon through gRPC.

The changes made to the configuration are processed as transactions,
guaranteeing that either all the changes are applied or none at all.
This feature is a significant facilitator of network automation as it
eliminates the need for error recovery in management applications.  Holo also
supports network-wide transactions involving multiple network devices.
Additional network automation capabilities include confirmed commits and
configuration rollback support.

#### Security

By virtue of being written in a memory-safe language, Holo is immune to a
wide variety of memory-related bugs and security vulnerabilities.  Besides the
safety guarantees provided by Rust, the Holo daemon runs in a chroot jail and
drops privileges at startup.  For certain operations, like binding sockets,
Linux [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
are used to gain the minimum required permission for the least amount of time.

#### Integrated protocol implementations

Some protocols, such as OSPF and RIP, have different versions that are widely
deployed, typically one for IPv4 and another for IPv6.  Holo leverages Rust's
generics to have version-agnostic protocol implementations, where most
of the code is shared by the different protocol versions.  This approach
reduces the maintenance cost of these protocols and facilitates shipping
new features that benefit all protocol versions.

#### Parallelism

Holo makes extensive use of asynchronous operations and relies on the
[Tokio](https://github.com/tokio-rs/tokio) runtime to schedule tasks
and run them on a thread pool.  In order to achieve better performance,
both I/O requests and CPU-intensive algorithms are offloaded to separate
tasks, maximizing the utilization of all available CPU cores.  Support
for runtime-agnostic code is planned for the future, once the necessary
abstractions are standardized by the Rust language team.

#### Structured logging

Holo generates log messages that contain structured data, which can be
presented in various formats such as JSON, text, etc.
As logging is carried out through the *tracing* facade, diverse *tracing*
subscribers can be utilized to meet different user requirements. For instance,
logging can be directed to a file, journald, a centralized OpenTelemetry
collector, or any combination of these options with potentially varying
logging levels.

#### Reproducible bugs

Holo provides record-and-replay functionality, enabling easy reproduction
of any user-reported bug.  The Holo daemon can be set up to record the
complete lifespan of a protocol instance to a file. That file can then be
played back on another machine, reproducing the same sequence of events.
While a recording session may last for hours or days, the playback process
should take only a few seconds.  This is feasible thanks to Holo's modular
architecture, where all time-related and I/O operations are performed in
separate tasks and abstracted as event messages.

## Installation

Holo uses unstable Rust features, so building it from the source code requires
a nightly version of the Rust compiler.

For detailed instructions on installation, please refer to the
[INSTALL.md](INSTALL.md) file.

#### Supported Platforms

At present, Holo is only compatible with Linux operating systems.

WebAssembly support is planned for the future. This addition will enable
simulation of large networks from within your browser, making network
experimentation more convenient and accessible to everyone.

## Compliance

Holo supports the following IETF RFCs and Internet drafts:

##### BFD

* RFC 5880 - Bidirectional Forwarding Detection (BFD)
* RFC 5881 - Bidirectional Forwarding Detection (BFD) for IPv4 and IPv6 (Single Hop)
* RFC 5882 - Generic Application of Bidirectional Forwarding Detection (BFD)
* RFC 5883 - Bidirectional Forwarding Detection (BFD) for Multihop Paths

##### MPLS LDP

* RFC 5036 - LDP Specification
* RFC 5561 - LDP Capabilities
* RFC 5918 - Label Distribution Protocol (LDP) 'Typed Wildcard' Forward Equivalence Class (FEC)
* RFC 5919 - Signaling LDP Label Advertisement Completion
* RFC 6720 - The Generalized TTL Security Mechanism (GTSM) for the Label Distribution Protocol (LDP)

##### OSPF

* RFC 2328 - OSPF Version 2
* RFC 5243 - OSPF Database Exchange Summary List Optimization
* RFC 5250 - The OSPF Opaque LSA Option
* RFC 5340 - OSPF for IPv6
* RFC 5838 - Support of Address Families in OSPFv3
* RFC 6987 - OSPF Stub Router Advertisement
* RFC 7684 - OSPFv2 Prefix/Link Attribute Advertisement
* RFC 7770 - Extensions to OSPF for Advertising Optional Router Capabilities
* RFC 8362 - OSPFv3 Link State Advertisement (LSA) Extensibility
* RFC 8405 - Shortest Path First (SPF) Back-Off Delay Algorithm for Link-State IGPs
* RFC 8476 - Signaling Maximum SID Depth (MSD) Using OSPF
* RFC 8665 - OSPF Extensions for Segment Routing
* RFC 8666 - OSPFv3 Extensions for Segment Routing

##### RIP

* RFC 2080 - RIPng for IPv6
* RFC 2453 - RIP Version 2
* RFC 4822 - RIPv2 Cryptographic Authentication

##### IETF YANG implementation coverage

| Module | Configuration | State | RPCs | Notifications | Total |
| -- | -- | -- | -- | -- | -- |
| ietf-bfd-ip-mh@2022-09-22 | 100.00% | 100.00% | - | 100.00% | [100.00%](http://westphal.com.br/holo/ietf-bfd-ip-mh.html) |
| ietf-bfd-ip-sh@2022-09-22 | 100.00% | 100.00% | - | 100.00% | [100.00%](http://westphal.com.br/holo/ietf-bfd-ip-sh.html) |
| ietf-bfd@2022-09-22 | 100.00% | 100.00% | - | - | [100.00%](http://westphal.com.br/holo/ietf-bfd.html) |
| ietf-interfaces@2018-01-09 | 100.00% | 0.00% | - | - | [22.22%](http://westphal.com.br/holo/ietf-interfaces.html) |
| ietf-ip@2018-01-09 | 17.39% | 0.00% | - | - | [13.33%](http://westphal.com.br/holo/ietf-ip.html) |
| ietf-key-chain@2017-04-18 | 25.00% | 0.00% | - | - | [21.05%](http://westphal.com.br/holo/ietf-key-chain.html) |
| ietf-mpls-ldp@2022-03-14 | 86.96% | 92.31% | 100.00% | 100.00% | [92.38%](http://westphal.com.br/holo/ietf-mpls-ldp.html) |
| ietf-ospf-sr@2023-01-01 | 16.67% | 56.52% | - | - | [53.33%](http://westphal.com.br/holo/ietf-ospf-sr.html) |
| ietf-ospf@2019-10-17 | 73.24% | 59.36% | 100.00% | 31.18% | [58.20%](http://westphal.com.br/holo/ietf-ospf.html) |
| ietf-ospfv3-extended-lsa@2022-03-06 | 50.00% | 84.82% | - | - | [84.46%](http://westphal.com.br/holo/ietf-ospfv3-extended-lsa.html) |
| ietf-ospfv3-sr@2022-10-21 | - | 51.63% | - | - | [51.63%](http://westphal.com.br/holo/ietf-ospfv3-sr.html) |
| ietf-rip@2020-02-20 | 27.91% | 93.33% | 100.00% | - | [55.41%](http://westphal.com.br/holo/ietf-rip.html) |
| ietf-routing@2018-03-13 | 50.00% | 0.00% | - | - | [23.08%](http://westphal.com.br/holo/ietf-routing.html) |
| ietf-segment-routing-mpls@2021-05-26 | 62.50% | 0.00% | - | 23.53% | [32.76%](http://westphal.com.br/holo/ietf-segment-routing-mpls.html) |
| ietf-segment-routing@2021-05-26 | 100.00% | - | - | - | [100.00%](http://westphal.com.br/holo/ietf-segment-routing.html) |

## License

This project is licensed under the [MIT license].

[MIT license]: https://github.com/rwestphal/holo/blob/master/LICENSE

### Contribution

We welcome any contributions, from bug reports to Pull Requests. Please refer
to our [Project Wishlist](https://github.com/users/rwestphal/projects/3)
for ideas on where to contribute.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Holo by you, shall be licensed as MIT, without any additional
terms or conditions.
