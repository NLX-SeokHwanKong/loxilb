# Fenced QUIC VIP handoff

The optional Linux flag `--cid-handoff=198.18.244.10@eth1,eth0` enables a root-only Unix packet socket inside the LB network namespace. The default has no listener. The native operation deletes owned IPv4 FullNAT UDP entries on the local service port, rule ID, zone and backend transformations, with an independent CT/flow-cache readback before publication. Each request returns deletion counts, including partial progress on error. Every fresh request must pass both carrier checks and look up the current NAT rule. NAT configuration and backend withdrawal history are preserved.

The reference coordinator below holds the exclusive switch/config writer for a dedicated VIP, including both front and return paths. A BFD alarm wakes the coordinator. It compares live owner identity, rules and backend histories, disconnects the data paths, invokes each instance, verifies residual state, transfers the guard while the userspace writers are paused and publishes one owner. Ambiguous state, unreachable donors and in-flight exclusions without a matching durable guard hold publication. The two gates must stay under external control through verification. Installations with shared interfaces require an alternative per-service fence. This adapter uses same-host Linux network namespaces and a monotonic clock shared with the two containers.

## Reproduce on an isolated Linux host

1. Build the parent with its pinned submodules and the IPv4 CID profile. Prepare two locally named Docker images, the old natural-drain build and this build. Use private BPF mount propagation for both.
2. Set `QMZ_STAGE` to the test kit directory containing `bin/mvp-client`, `bin/connect-ip`, `bin/bfd-peer` and a `cert` directory. The server certificate must cover `masque-poc.test`. CONNECT-IP requires a trusted client certificate `allow.pem` and `allow.key` for CN `masque-poc-qa-device`. An alternate certificate directory can be supplied as `QMZ_CERT`.
3. Open a root shell on the isolated host with Docker, GoBGP tools in the image, Linux SCTP, Python with pidfd support, bpftool, tc, tcpdump, curl and iproute2. In this directory, export the image names as BASE and CANDIDATE. Use a fresh output directory name on every invocation.

```bash
QMZ_TEST_IMAGE="$BASE" QMZ_DETECTOR=bfd python3 planned-lb-demo.py fabric udp-baseline
QMZ_TEST_IMAGE="$CANDIDATE" QMZ_DETECTOR=bfd QMZ_DRAIN=selective python3 planned-lb-demo.py fabric udp-candidate
QMZ_TEST_IMAGE="$CANDIDATE" QMZ_DETECTOR=bfd QMZ_DRAIN=selective QMZ_TUNNEL=ip python3 planned-lb-demo.py fabric ip-candidate
QMZ_TEST_IMAGE="$CANDIDATE" QMZ_DETECTOR=bfd QMZ_DRAIN=selective QMZ_LEGACY_IMAGE="$CANDIDATE" python3 planned-lb-demo.py fabric legacy-candidate
QMZ_TEST_IMAGE="$CANDIDATE" QMZ_DETECTOR=bfd QMZ_DRAIN=selective QMZ_VERIFY_SCOPE=1 python3 planned-lb-demo.py fabric scope-candidate
```

4. Repeat both drain modes with each tunnel. Record the interval from first donor link-down to confirmed publication (`admitted_s`) and to the first valid client payload (`app_echo_s`). Retain failed runs. Confirm a fresh UDP CONNECT and echo, or the permitted inner TCP echo for CONNECT-IP, plus the blocked destination policy. The independent legacy trial checks new connections and continuously exchanges payloads on the same TCP, UDP and SCTP sockets through their own VIP. The scope trial also checks refusal on live/one-sided paths and stale identity, unrelated map witnesses and an idempotent replay. Socket continuity of the dedicated tunnel and of the ordinary VIP are separate measurements.
5. The harness deletes its containers and network namespaces on exit. For rollback, keep the candidate fenced and resume the earlier natural-drain release using the same ownership and history checks.

The excluded-backend history still requires a live donor. The fork does not elect a replacement from BFD alone.

## Established IPv4 TCP FullNAT during native BFD failover

Use the same isolated Linux host and the two fork images. The TCP fixture starts two native BFD peers (200 ms × 3), XSync, one backend and a client that opens the held socket only once. Run from this directory in a root shell. Use bash with pipefail so a failed trial is visible.

```bash
set -o pipefail
QMZ_TEST_IMAGE="$BASE" python3 -u tcp-path.py tcp-before | tee tcp-before.jsonl
QMZ_TEST_IMAGE="$CANDIDATE" python3 -u tcp-path.py tcp-after | tee tcp-after.jsonl
FLIP=1 QMZ_TEST_IMAGE="$CANDIDATE" python3 -u tcp-path.py tcp-reversed | tee tcp-reversed.jsonl
python3 check-packets.py --expect lost tcp-before
python3 check-packets.py --expect kept tcp-after tcp-reversed
QMZ_TEST_IMAGE="$BASE" python3 -u steady.py steady-before | tee steady-before.jsonl
QMZ_TEST_IMAGE="$CANDIDATE" python3 -u steady.py steady-after | tee steady-after.jsonl
```

The baseline assertion applies to parent `90cbcd73` with eBPF `68c2f56e`. Inspect the original client SYN, the unacknowledged payload and its TCP sequence number on the promoted wire, the backend destination MAC, and the returned ACK in `packet-verdict.json`. Compare `*-promoted.json` and `*-plus3.json` on the candidate. The expected forward action list after recovery is 2, 3, 5 (DNAT, neighbor rewrite, output). The trial changes only its own veths and leaves its raw captures and map snapshots in the named directory.

Install iperf3 on the host for the steady-flow test. Compare receiver goodput using alternating image order on an idle host. The warm interval uses 1,000 TCP echoes, the forward CT packet counter and the CT slow-path last-use timestamp. L2 checks configure bridge domain 77 and verify both endpoint MACs in the eBPF destination map. DSR checks put a /32 on the backend and capture replies on a separate direct interface. Run the two MASQUE modes above to check the independent CID failover and legacy sockets.
