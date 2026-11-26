#!/usr/bin/env bash
#
# End-to-end acceptance test for kernel-table ingestion + RIB leaking,
# verified via BGP redistribution (no OSPF involved).
#
# Topology (two network namespaces):
#
#   holo-a (AS 64661) --veth-- holo-b (AS 64662)
#     ts0 dummy, kernel table 52 carries the "Tailscale" routes
#
# Asserts:
#   a) routes in table 52 are ingested into RIBs tailscale-v4/v6;
#   b) they are leaked into the default RIBs via IMPORT-TAILSCALE,
#      policy-filtered, and never written back to the main table;
#   c) BGP redistribute kernel advertises them (Adj-RIB-Out) and
#      withdraws them when deleted from table 52.
#
# Requires root (netns + netlink) and a built target/debug/holod.
#
set -euo pipefail
cd "$(dirname "$0")"
REPO=$(cd ../.. && pwd)

VENV=${HOLO_TEST_VENV:-$HOME/.hermes/cache/scratch/holovenv}
HOLOD=$REPO/target/debug/holod
NS_A=holo-a
NS_B=holo-b
WORK=$(mktemp -d /tmp/holo-kernel-leak.XXXXXX)
GEN=$WORK/gen
SOCK_A=$WORK/a/holod.sock
SOCK_B=$WORK/b/holod.sock
PIDS=()
FAILED=0

fail() { echo "FAIL: $*" >&2; FAILED=1; }
ok()   { echo "ok:   $*"; }

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    ip netns del $NS_A 2>/dev/null || true
    ip netns del $NS_B 2>/dev/null || true
    # Keep the last run's logs around for debugging.
    rm -rf /tmp/holo-kernel-leak-last
    mkdir -p /tmp/holo-kernel-leak-last
    cp -r "$WORK/logs" /tmp/holo-kernel-leak-last/ 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

nb() { "$VENV/bin/python" nb.py "$@"; }

# Poll `nb get <socket> <path>` until the output contains $3.
assert_contains() {
    local socket=$1 path=$2 pattern=$3 out
    for _ in $(seq 100); do
        out=$(nb get "$socket" "$path" 2>/dev/null || true)
        if grep -q -- "$pattern" <<<"$out"; then
            ok "$path contains $pattern"
            return 0
        fi
        sleep 0.1
    done
    fail "$path never contained $pattern (last: ${out:0:400})"
}

# Assert `nb get <socket> <path>` never contains $3 within the window.
assert_absent() {
    local socket=$1 path=$2 pattern=$3 out
    sleep 1
    for _ in $(seq 20); do
        out=$(nb get "$socket" "$path" 2>/dev/null || true)
        if grep -q -- "$pattern" <<<"$out"; then
            fail "$path unexpectedly contains $pattern"
            return 1
        fi
        sleep 0.1
    done
    ok "$path does not contain $pattern"
}

# --- Toolchain -------------------------------------------------------------
[ -x "$HOLOD" ] || { echo "build holod first: cargo build -p holo-daemon"; exit 1; }
[ -x "$VENV/bin/python" ] || { echo "missing venv $VENV (python3 -m venv + pip install grpcio grpcio-tools)"; exit 1; }
mkdir -p "$GEN" "$WORK/a" "$WORK/b"
# holod drops privileges to the holo user, which owns its state dirs.
chown holo:holoadm "$WORK" "$WORK/a" "$WORK/b"
"$VENV/bin/python" -m grpc_tools.protoc -I "$REPO/proto" \
    --python_out="$GEN" --grpc_python_out="$GEN" "$REPO/proto/holo.proto"
export HOLO_GEN=$GEN

# --- Namespaces ------------------------------------------------------------
ip netns add $NS_A
ip netns add $NS_B
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns $NS_A
ip link set veth-b netns $NS_B
ip netns exec $NS_A ip link set lo up
ip netns exec $NS_A ip link set veth-a up
ip netns exec $NS_A ip addr add 10.128.0.1/24 dev veth-a
ip netns exec $NS_A ip link add ts0 type dummy
ip netns exec $NS_A ip link set ts0 up
ip netns exec $NS_B ip link set lo up
ip netns exec $NS_B ip link set veth-b up
ip netns exec $NS_B ip addr add 10.128.0.2/24 dev veth-b

# --- Daemon instances ------------------------------------------------------
mkdir -p "$WORK/logs"
chown holo:holoadm "$WORK/logs"
for inst in a b; do
    cat > "$WORK/$inst.toml" <<EOF
user = "holo"
group = "holoadm"
state_dir = "$WORK/$inst"

[logging.journald]
enabled = false

[logging.file]
enabled = true
dir = "$WORK/logs"
name = "$inst.log"
rotation = "never"
style = "compact"

[logging.stdout]
enabled = false
EOF
done
ip netns exec $NS_A "$HOLOD" -c "$WORK/a.toml" &
PIDS+=($!)
ip netns exec $NS_B "$HOLOD" -c "$WORK/b.toml" &
PIDS+=($!)
for sock in "$SOCK_A" "$SOCK_B"; do
    for _ in $(seq 50); do
        [ -S "$sock" ] && break
        sleep 0.2
    done
    [ -S "$sock" ] || { echo "holod did not create $sock"; exit 1; }
done

# --- Configuration ----------------------------------------------------------
nb commit "$SOCK_A" config-a.json
nb commit "$SOCK_B" config-b.json

# --- Inject the "Tailscale" routes into kernel table 52 ---------------------
ip netns exec $NS_A ip route add 100.64.0.42/32 dev ts0 table 52
ip netns exec $NS_A ip route add 192.168.1.0/24 dev ts0 table 52  # policy-blocked
ip netns exec $NS_A ip -6 route add fd7a:115c:a1e0::42/128 dev ts0 table 52

RIB_A=/ietf-routing:routing/ribs/rib=name=tailscale-v4/routes/route
RIB_B6=/ietf-routing:routing/ribs/rib=name=tailscale-v6/routes/route
RIB_4=/ietf-routing:routing/ribs/rib=name=ipv4/routes/route
RIB_6=/ietf-routing:routing/ribs/rib=name=ipv6/routes/route
ADJ4=/ietf-routing:routing/control-plane-protocols/control-plane-protocol=type=ietf-bgp:bgp,name=main/ietf-bgp:bgp/rib/afi-safis/afi-safi=name=iana-bgp-types:ipv4-unicast/ipv4-unicast/neighbors/neighbor=neighbor-address=10.128.0.2/adj-rib-out-post/routes/route
ADJ6=/ietf-routing:routing/control-plane-protocols/control-plane-protocol=type=ietf-bgp:bgp,name=main/ietf-bgp:bgp/rib/afi-safis/afi-safi=name=iana-bgp-types:ipv6-unicast/ipv6-unicast/neighbors/neighbor=neighbor-address=10.128.0.2/adj-rib-out-post/routes/route
NEIGHBOR=/ietf-routing:routing/control-plane-protocols/control-plane-protocol=type=ietf-bgp:bgp,name=main/ietf-bgp:bgp/neighbors/neighbor=remote-address=10.128.0.2/session-state

# a) Ingestion into the kernel-bound RIBs.
assert_contains "$SOCK_A" "$RIB_A" "100.64.0.42/32"
assert_contains "$SOCK_A" "$RIB_A" "192.168.1.0/24"
assert_contains "$SOCK_A" "$RIB_B6" "fd7a:115c:a1e0::42/128"

# b) Policy-filtered leak into the default RIBs.
assert_contains "$SOCK_A" "$RIB_4" "100.64.0.42/32"
assert_absent   "$SOCK_A" "$RIB_4" "192.168.1.0/24"
assert_contains "$SOCK_A" "$RIB_6" "fd7a:115c:a1e0::42/128"

# b') No write-back to the main table (no_fib on leaked routes).
if ip netns exec $NS_A ip route show | grep -q "100.64.0.42"; then
    fail "leaked route was written back to the main table"
else
    ok "main table untouched by leaked routes"
fi

# c) BGP session up, then Adj-RIB-Out carries the leaked routes.
assert_contains "$SOCK_A" "$NEIGHBOR" "established"
assert_contains "$SOCK_A" "$ADJ4" "100.64.0.42/32"
assert_contains "$SOCK_A" "$ADJ6" "fd7a:115c:a1e0::42/128"

# d) Withdrawal on deletion from table 52.
ip netns exec $NS_A ip route del 100.64.0.42/32 table 52
ip netns exec $NS_A ip -6 route del fd7a:115c:a1e0::42/128 table 52
assert_absent "$SOCK_A" "$RIB_A" "100.64.0.42/32"
assert_absent "$SOCK_A" "$RIB_4" "100.64.0.42/32"
assert_absent "$SOCK_A" "$ADJ4" "100.64.0.42/32"
assert_absent "$SOCK_A" "$ADJ6" "fd7a:115c:a1e0::42/128"

# e) Churn: bulk add/remove of 500 host routes.
for i in $(seq 0 499); do
    o=$((1 + i / 256)); p=$((i % 256))
    ip netns exec $NS_A ip route add "100.64.$o.$p/32" dev ts0 table 52
done
assert_contains "$SOCK_A" "$RIB_4" "100.64.1.100/32"
for i in $(seq 0 499); do
    o=$((1 + i / 256)); p=$((i % 256))
    ip netns exec $NS_A ip route del "100.64.$o.$p/32" table 52
done
assert_absent "$SOCK_A" "$RIB_4" "100.64.1.100/32"
assert_absent "$SOCK_A" "$RIB_A" "100.64.2.244/32"

# f) Live policy change: accepting 192.168.1.0/24 leaks it immediately.
cat > "$WORK/policy-extra.json" <<'EOF'
{
  "ietf-routing-policy:routing-policy": {
    "defined-sets": {
      "prefix-sets": {
        "prefix-set": [
          {
            "name": "TS-EXTRA",
            "mode": "ipv4",
            "prefixes": {
              "prefix-list": [
                {
                  "ip-prefix": "192.168.1.0/24",
                  "mask-length-lower": 24,
                  "mask-length-upper": 24
                }
              ]
            }
          }
        ]
      }
    },
    "policy-definitions": {
      "policy-definition": [
        {
          "name": "IMPORT-TAILSCALE",
          "statements": {
            "statement": [
              {
                "name": "30",
                "conditions": {
                  "match-prefix-set": { "prefix-set": "TS-EXTRA" }
                },
                "actions": { "policy-result": "accept-route" }
              }
            ]
          }
        }
      ]
    }
  }
}
EOF
nb commit "$SOCK_A" "$WORK/policy-extra.json" > /dev/null
assert_contains "$SOCK_A" "$RIB_4" "192.168.1.0/24"

# g) Removing import-rib withdraws leaked routes, ingestion continues.
python3 - <<EOF
import json
d = json.load(open("config-a.json"))
for rib in d["ietf-routing:routing"]["ribs"]["rib"]:
    rib.pop("holo-routing:import-rib", None)
json.dump(d, open("$WORK/config-no-import.json", "w"))
EOF
nb commit-replace "$SOCK_A" "$WORK/config-no-import.json" > /dev/null
assert_absent "$SOCK_A" "$RIB_4" "192.168.1.0/24"
assert_contains "$SOCK_A" "$RIB_A" "192.168.1.0/24"

# h) Removing kernel-table-id unbinds the RIB from the kernel table.
python3 - <<EOF
import json
d = json.load(open("config-a.json"))
for rib in d["ietf-routing:routing"]["ribs"]["rib"]:
    rib.pop("holo-routing:kernel-table-id", None)
json.dump(d, open("$WORK/config-no-kernel.json", "w"))
EOF
nb commit-replace "$SOCK_A" "$WORK/config-no-kernel.json" > /dev/null
assert_absent "$SOCK_A" "$RIB_A" "192.168.1.0/24"

if [ "$FAILED" -eq 0 ]; then
    echo "PASS: kernel-leak-bgp acceptance test"
else
    echo "FAIL: kernel-leak-bgp acceptance test"
    exit 1
fi
