#/bin/sh

cargo run --bin yang_coverage --\
  -m ietf-interfaces\
  -m ietf-if-extensions\
  -m ietf-if-vlan-encapsulation\
  -m ietf-ip\
  -m ietf-ipv4-unicast-routing\
  -m ietf-ipv6-unicast-routing\
  -m ietf-mpls\
  -m ietf-routing\
  -m ietf-routing-policy\
  -m ietf-segment-routing\
  -m ietf-segment-routing-mpls\
  -m ietf-key-chain\
  -m ietf-bfd\
  -m ietf-bfd-ip-mh\
  -m ietf-bfd-ip-sh\
  -m ietf-bgp\
  -m ietf-bgp-policy\
  -m ietf-mpls-ldp\
  -m ietf-ospf\
  -m ietf-ospf-sr-mpls\
  -m ietf-ospfv3-extended-lsa\
  -m ietf-rip\
  -m ietf-vrrp
