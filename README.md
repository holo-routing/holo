[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]
[![codecov][codecov-badge]][codecov-url]
[![Discord][discord-badge]][discord-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/holo-routing/holo/blob/master/LICENSE
[actions-badge]: https://github.com/holo-routing/holo/actions/workflows/ci.yaml/badge.svg?branch=master
[actions-url]: https://github.com/holo-routing/holo/actions?query=workflow%3ACI+branch%3Amaster
[codecov-badge]: https://codecov.io/gh/holo-routing/holo/branch/master/graph/badge.svg?token=OMV0RMNVY8
[codecov-url]: https://codecov.io/gh/holo-routing/holo
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
including native [gRPC](https://github.com/holo-routing/holo/wiki/gRPC) and
[gNMI](https://github.com/holo-routing/holo/wiki/gNMI).  Additionally, Holo
features a standalone [CLI](https://github.com/holo-routing/holo/wiki/CLI)
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
safety guarantees provided by Rust, the Holo daemon also drops privileges
at startup. For certain operations, like binding sockets,
Linux [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
are used to gain the minimum required permission for the least amount of time.

Holo also provides robust protection against the most common attack vector in
routing protocol stacks: denial-of-service (DoS) attacks via malicious packet
input. Incoming packets are decoded in isolated, supervised async tasks,
allowing the protocol implementations to recover gracefully from panics,
such as by ignoring malformed packets or closing only the affected TCP stream,
without compromising the stability of the entire daemon. Additionally, thanks
to Holo's modular design and built-in support for coverage-guided fuzzing,
most parsing bugs are expected to be detected and addressed during development.

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

For detailed instructions on installation, please refer to the
[INSTALL.md](INSTALL.md) file.

#### Supported Platforms

At present, Holo is only compatible with Linux operating systems.
WebAssembly support is planned for the future.

#### Getting Started

The easiest way to start using Holo is by using pre-built Docker containers
in combination with the [containerlab](https://containerlab.dev/) software.
You can find a variety of pre-configured network topologies at [this
link](https://github.com/holo-routing/containerlab-topologies).  These topologies
can be deployed with a single command, allowing you to test Holo in various
network setups, including interoperability testing with other implementations.

Additionally, Holo can be used wherever a routing stack is required, such
as in software routers, provided that the feature set aligns with your
specific needs.

## Compliance

Holo supports the following Internet Standards:

##### BFD

* RFC 5880 - Bidirectional Forwarding Detection (BFD)
* RFC 5881 - Bidirectional Forwarding Detection (BFD) for IPv4 and IPv6 (Single Hop)
* RFC 5882 - Generic Application of Bidirectional Forwarding Detection (BFD)
* RFC 5883 - Bidirectional Forwarding Detection (BFD) for Multihop Paths

##### BGP

* RFC 1997 - BGP Communities Attribute
* RFC 2385 - Protection of BGP Sessions via the TCP MD5 Signature Option
* RFC 2545 - Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain Routing
* RFC 2918 - Route Refresh Capability for BGP-4
* RFC 4271 - A Border Gateway Protocol 4 (BGP-4)
* RFC 4360 - BGP Extended Communities Attribute
* RFC 4486 - Subcodes for BGP Cease Notification Message
* RFC 4760 - Multiprotocol Extensions for BGP-4
* RFC 5082 - The Generalized TTL Security Mechanism (GTSM)
* RFC 5492 - Capabilities Advertisement with BGP-4
* RFC 5668 - 4-Octet AS Specific BGP Extended Community
* RFC 5701 - IPv6 Address Specific BGP Extended Community Attribute
* RFC 6286 - Autonomous-System-Wide Unique BGP Identifier for BGP-4
* RFC 6608 - Subcodes for BGP Finite State Machine Error
* RFC 6793 - BGP Support for Four-Octet Autonomous System (AS) Number Space
* RFC 7606 - Revised Error Handling for BGP UPDATE Messages
* RFC 7607 - Codification of AS 0 Processing
* RFC 8092 - BGP Large Communities Attribute
* RFC 8212 - Default External BGP (EBGP) Route Propagation Behavior without Policies
* RFC 8642 - Policy Behavior for Well-Known BGP Communities
* RFC 9774 - Deprecation of AS_SET and AS_CONFED_SET in BGP

##### IS-IS

* ISO/IEC 10589 - Information technology — Telecommunications and information exchange between systems — Intermediate System to Intermediate System intra-domain routeing information exchange protocol for use in conjunction with the protocol for providing the connectionless-mode network service (ISO 8473)
* RFC 1195 - Use of OSI IS-IS for Routing in TCP/IP and Dual Environments
* RFC 3719 - Recommendations for Interoperable Networks using Intermediate System to Intermediate System (IS-IS)
* RFC 3787 - Recommendations for Interoperable IP Networks using Intermediate System to Intermediate System (IS-IS)
* RFC 5120 - M-ISIS: Multi Topology (MT) Routing in Intermediate System to Intermediate Systems (IS-ISs)
* RFC 5301 - Dynamic Hostname Exchange Mechanism for IS-IS
* RFC 5303 - Three-Way Handshake for IS-IS Point-to-Point Adjacencies
* RFC 5304 - IS-IS Cryptographic Authentication
* RFC 5305 - IS-IS Extensions for Traffic Engineering
* RFC 5308 - Routing IPv6 with IS-IS
* RFC 5310 - IS-IS Generic Cryptographic Authentication
* RFC 6232 - Purge Originator Identification TLV for IS-IS
* RFC 6233 - IS-IS Registry Extension for Purges
* RFC 7602 - IS-IS Extended Sequence Number TLV
* RFC 7794 - IS-IS Prefix Attributes for Extended IPv4 and IPv6 Reachability
* RFC 7917 - Advertising Node Administrative Tags in IS-IS
* RFC 7981 - IS-IS Extensions for Advertising Router Information
* RFC 7987 - IS-IS Minimum Remaining Lifetime
* RFC 8401 - Bit Index Explicit Replication (BIER) Support via IS-IS
* RFC 8405 - Shortest Path First (SPF) Back-Off Delay Algorithm for Link-State IGPs
* RFC 8491 - Signaling Maximum SID Depth (MSD) Using IS-IS
* RFC 8667 - IS-IS Extensions for Segment Routing
* RFC 8918 - Invalid TLV Handling in IS-IS
* draft-ietf-bier-lsr-non-mpls-extensions-03 - LSR Extensions for BIER non-MPLS Encapsulation

##### MPLS LDP

* RFC 5036 - LDP Specification
* RFC 5561 - LDP Capabilities
* RFC 5918 - Label Distribution Protocol (LDP) 'Typed Wildcard' Forward Equivalence Class (FEC)
* RFC 5919 - Signaling LDP Label Advertisement Completion
* RFC 6720 - The Generalized TTL Security Mechanism (GTSM) for the Label Distribution Protocol (LDP)

##### OSPF

* RFC 2328 - OSPF Version 2
* RFC 3623 - Graceful OSPF Restart
* RFC 5187 - OSPFv3 Graceful Restart
* RFC 5243 - OSPF Database Exchange Summary List Optimization
* RFC 5250 - The OSPF Opaque LSA Option
* RFC 5340 - OSPF for IPv6
* RFC 5613 - OSPF Link-Local Signaling
* RFC 5642 - Dynamic Hostname Exchange Mechanism for OSPF
* RFC 5709 - OSPFv2 HMAC-SHA Cryptographic Authentication
* RFC 5838 - Support of Address Families in OSPFv3
* RFC 6987 - OSPF Stub Router Advertisement
* RFC 7166 - Supporting Authentication Trailer for OSPFv3
* RFC 7684 - OSPFv2 Prefix/Link Attribute Advertisement
* RFC 7770 - Extensions to OSPF for Advertising Optional Router Capabilities
* RFC 7777 - Advertising Node Administrative Tags in OSPF
* RFC 8362 - OSPFv3 Link State Advertisement (LSA) Extensibility
* RFC 8405 - Shortest Path First (SPF) Back-Off Delay Algorithm for Link-State IGPs
* RFC 8476 - Signaling Maximum SID Depth (MSD) Using OSPF
* RFC 8665 - OSPF Extensions for Segment Routing
* RFC 8666 - OSPFv3 Extensions for Segment Routing
* draft-ietf-bier-ospfv3-extensions-07 - OSPFv3 Extensions for BIER
* draft-ietf-bier-lsr-non-mpls-extensions-03 - LSR Extensions for BIER non-MPLS Encapsulation

##### RIP

* RFC 2080 - RIPng for IPv6
* RFC 2453 - RIP Version 2
* RFC 4822 - RIPv2 Cryptographic Authentication

##### VRRP

* RFC 3768 - Virtual Router Redundancy Protocol (VRRP)
* RFC 5798 - Virtual Router Redundancy Protocol (VRRP) Version 3 for IPv4 and IPv6

##### IETF YANG implementation coverage

| Module | Configuration | State | RPCs | Notifications | Total |
| -- | -- | -- | -- | -- | -- |
| ietf-bfd-ip-mh@2022-09-22 | 100.00% | 100.00% | - | 100.00% | [100.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-bfd-ip-mh@2022-09-22.html) |
| ietf-bfd-ip-sh@2022-09-22 | 100.00% | 100.00% | - | 100.00% | [100.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-bfd-ip-sh@2022-09-22.html) |
| ietf-bfd@2022-09-22 | 100.00% | 100.00% | - | - | [100.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-bfd@2022-09-22.html) |
| ietf-bgp-policy@2023-07-05 | 100.00% | - | - | - | [100.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-bgp-policy@2023-07-05.html) |
| ietf-bgp@2023-07-05 | 32.38% | 85.95% | - | - | [60.40%](https://holo-routing.github.io/ietf-yang-coverage/ietf-bgp@2023-07-05.html) |
| ietf-bier@2023-09-12 | 100.00% | - | - | 0.00% | [72.50%](https://holo-routing.github.io/ietf-yang-coverage/ietf-bier@2023-09-12.html) |
| ietf-if-extensions@2023-01-26 | 100.00% | 0.00% | - | - | [50.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-if-extensions@2023-01-26.html) |
| ietf-if-vlan-encapsulation@2023-01-26 | 42.86% | - | - | - | [42.86%](https://holo-routing.github.io/ietf-yang-coverage/ietf-if-vlan-encapsulation@2023-01-26.html) |
| ietf-interfaces@2018-02-20 | 100.00% | 0.00% | - | - | [22.22%](https://holo-routing.github.io/ietf-yang-coverage/ietf-interfaces@2018-02-20.html) |
| ietf-ip@2018-02-22 | 52.17% | 0.00% | - | - | [40.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-ip@2018-02-22.html) |
| ietf-ipv4-unicast-routing@2018-03-13 | 100.00% | 100.00% | - | - | [100.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-ipv4-unicast-routing@2018-03-13.html) |
| ietf-ipv6-unicast-routing@2018-03-13 | 40.62% | 100.00% | - | - | [45.71%](https://holo-routing.github.io/ietf-yang-coverage/ietf-ipv6-unicast-routing@2018-03-13.html) |
| ietf-isis-msd@2024-09-02 | - | 100.00% | - | - | [100.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-isis-msd@2024-09-02.html) |
| ietf-isis-sr-mpls@2025-05-06 | 15.38% | 57.27% | - | - | [52.85%](https://holo-routing.github.io/ietf-yang-coverage/ietf-isis-sr-mpls@2025-05-06.html) |
| ietf-isis@2022-10-19 | 93.62% | 70.37% | 100.00% | 100.00% | [80.92%](https://holo-routing.github.io/ietf-yang-coverage/ietf-isis@2022-10-19.html) |
| ietf-key-chain@2017-06-15 | 100.00% | 100.00% | - | - | [100.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-key-chain@2017-06-15.html) |
| ietf-mpls-ldp@2022-03-14 | 86.96% | 92.31% | 100.00% | 100.00% | [92.38%](https://holo-routing.github.io/ietf-yang-coverage/ietf-mpls-ldp@2022-03-14.html) |
| ietf-mpls@2020-12-18 | 0.00% | 57.14% | - | - | [35.29%](https://holo-routing.github.io/ietf-yang-coverage/ietf-mpls@2020-12-18.html) |
| ietf-ospf-sr-mpls@2025-05-05 | 20.00% | 51.36% | - | - | [49.63%](https://holo-routing.github.io/ietf-yang-coverage/ietf-ospf-sr-mpls@2025-05-05.html) |
| ietf-ospf@2022-10-19 | 75.82% | 64.25% | 100.00% | 41.94% | [63.58%](https://holo-routing.github.io/ietf-yang-coverage/ietf-ospf@2022-10-19.html) |
| ietf-ospfv3-extended-lsa@2024-06-07 | 50.00% | 85.28% | - | - | [84.85%](https://holo-routing.github.io/ietf-yang-coverage/ietf-ospfv3-extended-lsa@2024-06-07.html) |
| ietf-rip@2020-02-20 | 27.91% | 93.33% | 100.00% | - | [55.41%](https://holo-routing.github.io/ietf-yang-coverage/ietf-rip@2020-02-20.html) |
| ietf-routing-policy@2021-10-11 | 100.00% | 0.00% | - | - | [98.11%](https://holo-routing.github.io/ietf-yang-coverage/ietf-routing-policy@2021-10-11.html) |
| ietf-routing@2018-03-13 | 100.00% | 85.71% | - | - | [92.31%](https://holo-routing.github.io/ietf-yang-coverage/ietf-routing@2018-03-13.html) |
| ietf-segment-routing-mpls@2021-05-26 | 62.50% | 0.00% | - | 23.53% | [32.76%](https://holo-routing.github.io/ietf-yang-coverage/ietf-segment-routing-mpls@2021-05-26.html) |
| ietf-segment-routing@2021-05-26 | 100.00% | - | - | - | [100.00%](https://holo-routing.github.io/ietf-yang-coverage/ietf-segment-routing@2021-05-26.html) |
| ietf-system@2014-08-06 | 26.67% | 60.00% | 0.00% | - | [38.24%](https://holo-routing.github.io/ietf-yang-coverage/ietf-system@2014-08-06.html) |
| ietf-vrrp@2018-03-13 | 53.19% | 80.00% | - | 66.67% | [66.35%](https://holo-routing.github.io/ietf-yang-coverage/ietf-vrrp@2018-03-13.html) |

## Funding

This project is funded through [NGI Zero Core](https://nlnet.nl/core), a
fund established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/HoloRouting/).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/core)

## License

This project is licensed under the [MIT license].

[MIT license]: https://github.com/holo-routing/holo/blob/master/LICENSE

### Contribution

We welcome any contributions, from bug reports to Pull Requests. Please refer
to our [Project Wishlist](https://github.com/users/holo-routing/projects/2)
for ideas on where to contribute.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Holo by you, shall be licensed as MIT, without any additional
terms or conditions.
