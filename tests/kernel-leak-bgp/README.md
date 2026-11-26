# kernel-table leak → BGP redistribution acceptance test

End-to-end acceptance test for `kernel-table-id` ingestion and `import-rib`
route leaking (see `PR_DESCRIPTION.md` at the repo root).

## What it proves

Two `holod` instances in separate network namespaces connected by a veth:

| Scenario | Assertion |
| --- | --- |
| a | routes injected into kernel table 52 are ingested into custom RIBs `tailscale-v4`/`tailscale-v6` |
| b | routes leak into the default RIBs only if the `IMPORT-TAILSCALE` policy accepts them; leaked routes are never written back to the kernel main table (`no_fib`) |
| c | the eBGP session comes up and `redistribute kernel` places the leaked routes in Adj-RIB-Out-post; deleting them from table 52 withdraws them end-to-end |
| e | churn: 500 bulk-added host routes leak and un-leak correctly |
| f | a live policy change (new accept statement) immediately re-leaks previously rejected routes |
| g | removing `import-rib` withdraws leaked routes while ingestion continues |
| h | removing `kernel-table-id` unbinds and empties the custom RIB |

## Requirements

- root (netns, veth, `ip route` manipulation)
- a built `./target/debug/holod` (`cargo build -p holo-daemon`)
- a Python 3 venv with `grpcio` and `grpcio-tools`
- generated gRPC stubs (env `HOLO_GEN`), produced by the repo's proto build

## Running

```sh
sudo HOLO_TEST_VENV=/path/to/venv bash tests/kernel-leak-bgp/run.sh
```

Exit code 0 and `PASS: kernel-leak-bgp acceptance test` on success; each
assertion prints `ok:`/`FAIL:` lines. Artifacts of the last run (daemon logs,
configs, sockets) are kept under `/tmp/holo-kernel-leak-last/` for debugging.

## Files

- `run.sh` — the test driver (namespaces, daemons, assertions)
- `config-a.json` / `config-b.json` — full candidate configs committed over
  gRPC (routing-policy, custom RIBs, BGP)
- `nb.py` — minimal gRPC client: `commit` (MERGE), `commit-replace` (REPLACE),
  `get` (GetState), `config` (GetConfig)
