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

For a paced run set `IPERF_TARGET=10G` when invoking steady.py on each image. A `warm_rate_unresolved` event means the slow-path timestamp moved within that sample and the two snapshots cannot give an exact hit fraction.

### Fork verification on 2026-11-21

Native BFD and XSync on an isolated Linux 6.8.0-107-generic amd64 host were tested on the previous fork pair and on parent product code `680d6bcc` with eBPF `4c498cd8`. Both promotion directions were exercised. Before the fix the established socket failed in all three trials, despite both CT directions on the standby. After the fix all three retained the one original socket. The first post-promotion echo was 2.565–2.590 s after fault injection. The client capture contained a single SYN per held connection. Matching sequence numbers, backend MAC, returned ACK and payload confirmed the resumed path. The old candidate learned actions 2 and 5. The patched candidate had no forward entry at the promotion snapshot and subsequently learned actions 2, 3 and 5.

Under the isolated ABBA comparison, the warm forward hit fraction inferred from the directional CT counter and slow-path timestamp was 2,004/2,004 on each image. Saturation goodput (one iperf3 stream, six samples per image) had medians of 24.120 and 23.666 Gbit/s respectively, a 1.88% lower candidate median. Ranges overlapped (21.070–25.637 and 19.463–26.099 Gbit/s). A separate 10 Gbit/s paced comparison (three per image) gave 9.9985 and 9.9988 Gbit/s. These are single-host veth measurements. The earlier overlapping-workload series included a baseline warm sample with a changing CT timestamp, so its exact hit fraction is unresolved.

Both builds passed transparent L2 and TCP DSR echo with a captured direct reply, and separate TCP/UDP/SCTP control sockets had zero reconnects (275 baseline and 288 candidate round trips per protocol across the two MASQUE runs). Candidate BFD publication/first app echo were 1.408/3.317 s for CONNECT-UDP and 1.388/3.706 s for CONNECT-IP (one run per mode). This campaign exercised matching versions on the two peers and fresh flow maps.

## Preparing the return gateway for selected TCP VIPs

On both clustered peers, add one process argument per IPv4 TCP FullNAT VIP that needs faster recovery. For example, add `--tcp-return-vip=198.18.242.90 --tcp-return-vip=198.18.242.91` to the existing LoxiLB arguments. Omitting both disables this feature. Remove them on the standby first and follow the normal rolling maintenance procedure to roll back.

The BACKUP uses an established forward CT successfully installed by XSync and checks the current service rule and cluster role. It looks up the local IPv4 route to the client. For a routed client it prepares the gateway on that egress interface. For an on-link client it uses that client address. A missing neighbor can trigger a link-bound TTL-one ICMP echo so Linux performs ordinary neighbor discovery. VIPs and clients that share a gateway share the same MAC entry. Selection controls who can initiate preparation. Another service using the same entry can benefit from it.

The queue and tracked set each hold up to 256 flows. One worker rechecks at most one flow per 100 ms and limits probe attempts to one per interface/next-hop pair per 30 s. Linux ARP retries have their own timing. Preparation is best-effort and is independent of permission to promote. Keep the existing BFD, XSync and return routing configuration. The validated topology uses one IPv4 unicast route in the default routing domain.

1. Build the previous fork parent `beedb10d` as BASE and the new product commit `afb1d5c9` as CANDIDATE. Both pin eBPF `4c498cd8`. Use the tools from the current PR checkout for **both** images. Export BASE and CANDIDATE as the local image tags. In a root shell on the isolated Linux host, enter `cicd/quic-cid-handoff`.
2. Run these commands **sequentially**, with a new directory name every time. The fixture runs a two-interface Linux router, 3 routed client addresses, 3 service VIPs, a backend and two LBs. It opens 9 long-lived TCP sockets exactly once. LATE=1 suppresses only candidate ARP at the router during route setup. The fixture removes that filter before starting the held clients. Normal background resolution can still warm a candidate before failure.

   ```bash
   export SELECTED=198.18.242.90,198.18.242.91
   LATE=1 QMZ_TEST_IMAGE="$BASE" python3 gateway-trial.py routed-before
   LATE=1 QMZ_TEST_IMAGE="$CANDIDATE" python3 gateway-trial.py routed-off
   LATE=1 PREP="$SELECTED" QMZ_TEST_IMAGE="$CANDIDATE" python3 gateway-trial.py routed-on
   FLIP=1 LATE=1 PREP="$SELECTED" QMZ_TEST_IMAGE="$CANDIDATE" python3 gateway-trial.py routed-reverse
   PREP="$SELECTED" QMZ_TEST_IMAGE="$CANDIDATE" python3 gateway-trial.py routed-warm
   NONFULL=1 LATE=1 PREP=198.18.242.93 QMZ_TEST_IMAGE="$CANDIDATE" python3 gateway-trial.py routed-scope
   OBSERVE_SECONDS=70 LATE=1 PREP="$SELECTED" QMZ_TEST_IMAGE="$CANDIDATE" python3 gateway-trial.py routed-long
   python3 read-gateway.py routed-before routed-off routed-on routed-reverse routed-warm routed-scope routed-long
   ```

3. Check `routes.json` for forwarding and the actual gateway, `prefault.json` for the candidate neighbor and nine synced flows, and `events.jsonl` for fault and MASTER timestamps. In the parser output, delays are measured from donor link failure to the first matching application echo from the promoted MAC. It checks the app sequence, original SYN sequence and absence of a later SYN. ARP counts refer to the router's LB-facing interface. Distinguish candidate who-has for the gateway, native gratuitous ARP and the TTL-one feature probe. The scope case selects a real OneArm TCP VIP also serving UDP/SCTP and ends before promotion.
4. Inspect the actual packets and per-protocol results. A missing reply is a failed measurement. Keep its directory even when the harness exits nonzero.

   ```bash
   tcpdump -tt -enn -r routed-on/front.pcap 'arp or icmp'
   tcpdump -tt -enn -r routed-on/backend.pcap 'udp port 18080 or sctp'
   cat routed-on/result.json
   ```

5. Run the independent paced TCP, bridge, DSR and MASQUE comparisons above on the same two images. Use `QMZ_DRAIN=selective` on both for this comparison. Preserve image IDs, both PR heads and raw observations before updating either fork.

### Routed verification on 2026-11-21

Three service VIPs and three routed client addresses shared one Linux IPv4 gateway on the remote test host. Both promotion directions were exercised. With a cold candidate the previous image took 2.553 and 2.601 s (per-trial median over nine original sockets); it took 0.895 s when native discovery had already resolved the gateway. Five enabled failovers retained 45/45 sockets, with per-trial medians of 0.852–0.932 s. In the trial with a captured feature probe, 31 ms after the nine CTs were observed, two selected VIPs shared one gateway ARP followed by one link-local echo. There were zero gateway ARP requests during that handoff; the cold baseline had 12–13. The other enabled trials already had native discovery. In 83.2 s enabled vs 87.5 s disabled before the fault, both had one candidate who-has for the gateway and eight total observed ARP frames. An unselected VIP shared the prepared route. The scope control with a selected OneArm TCP VIP also serving UDP/SCTP emitted no feature echo.

Four completed disabled runs had medians of 0.842–1.293 s. A **fifth disabled run** had only 5/9 TCP responses before observation ended. Its post-failover UDP request reached the promoted MAC and no reply appeared on the router capture before the 2 s socket timeout. SCTP was not reached in that run. Both a baseline repeat and a disabled repeat with backend capture passed all nine sockets and both control protocols. The loss point in the failing sample remains open. An intermediate startup-only trial also timed out before traffic.

Both builds passed transparent L2 and TCP DSR, the independent MASQUE CONNECT-UDP/IP BFD checks and separate long-lived TCP/UDP/SCTP controls (no reconnects). Final MASQUE publication/application response were 1.878/3.281 s and 1.836/3.693 s respectively. At a 10 Gbit/s target, receiver goodput was 9.9989 Gbit/s before and 9.9986–9.9990 Gbit/s after. One candidate cache sample had an advancing slow-path timestamp; the repeat showed an unchanged timestamp across 1,002 packets, as did the baseline. These are single-host routed PoC measurements. Performance with physical routers, ECMP/VRF, sustained gateway loss and production-scale client diversity remains unmeasured.
