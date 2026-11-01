#!/usr/bin/env bash
# Start one loxilb image on this kernel, install one LB rule, and report the verified instructions of
# every eBPF program it loaded, as CSV.
#   cload.sh <image> <out.csv>
# Env: CLOAD_CTR (container name), UAPI_INC (directory with a linux/bpf.h that has verified_insns; the
# 22.04 system header is too old).
set -euo pipefail
image=$1; out=$2
ctr=${CLOAD_CTR:-cload-loxilb}
uapi=${UAPI_INC:-src/loxilb-ebpf/libbpf/include/uapi}
here=$(cd "$(dirname "$0")" && pwd)
api=http://127.0.0.1:11111/netlox/v1
limit=1000000
expected="tc_csum_func1 tc_csum_func2 tc_packet_func tc_packet_func_fast tc_packet_func_fw tc_packet_func_masq tc_packet_func_slow tc_slow_unp_func xdp_packet_func"

fail() {
  echo "cload: $*" >&2
  echo "--- kernel $(uname -r), loxilb log tail" >&2
  docker exec "$ctr" tail -80 /var/log/cload.log >&2 || true
  echo "--- docker logs $ctr" >&2
  docker logs --tail 80 "$ctr" >&2 || true
  exit 1
}

bin=$(mktemp)
gcc -O2 -I "$uapi" -o "$bin" "$here/progstat.c"

docker run -d --name "$ctr" --privileged --net=none --entrypoint /bin/bash -t "$image" > /dev/null
trap 'docker rm -f "$ctr" > /dev/null 2>&1 || true; rm -f "$bin"' EXIT
docker exec "$ctr" sh -c 'ip link set lo up && ip link add cload0 type veth peer name cload1 &&
  ip addr add 192.0.2.2/24 dev cload0 && ip addr add 198.51.100.2/24 dev cload1 &&
  ip link set cload0 up && ip link set cload1 up'
docker exec -d "$ctr" bash -c "/root/loxilb-io/loxilb/loxilb > /var/log/cload.log 2>&1"
# The image has no curl: reach the API from the host, inside the container's network namespace.
pid=$(docker inspect -f '{{.State.Pid}}' "$ctr")
# Every call goes through this with its exit code captured, so that a curl failure reaches fail() and not set -e.
api_curl() { sudo nsenter -t "$pid" -n curl -s -m "${API_TIMEOUT:-5}" "$@"; }

rc=0
for i in $(seq 1 90); do
  rc=0; api_curl "$api/config/loadbalancer/all" > /dev/null 2>&1 || rc=$?
  [[ $rc -eq 0 ]] && break
  sleep 1; [[ $i -eq 90 ]] && fail "API did not come up: last curl exit code $rc"
done
# A rule created before the port addresses are known misbehaves.
for i in $(seq 1 30); do
  docker exec "$ctr" grep -q "ifa added 198.51.100.2:cload1" /var/log/cload.log 2>/dev/null && break
  sleep 1; [[ $i -eq 30 ]] && fail "port address never registered"
done
rule='{"serviceArguments":{"externalIP":"192.0.2.100","port":443,"protocol":"udp","sel":1,"mode":0},"endpoints":[{"endpointIP":"198.51.100.21","targetPort":443,"weight":1},{"endpointIP":"198.51.100.22","targetPort":443,"weight":1},{"endpointIP":"198.51.100.23","targetPort":443,"weight":1}]}'
# A POST that timed out may still have installed the rule, and a second POST of it would be refused,
# so after any attempt that did not report success, look for the rule before trying again.
rule_installed() { local all=""; all=$(api_curl "$api/config/loadbalancer/all" 2>/dev/null) || return 1; [[ "$all" == *192.0.2.100* ]]; }
done_rule=no
for i in $(seq 1 10); do
  rc=0; r=$(API_TIMEOUT=30 api_curl -X POST -H 'Content-Type: application/json' -d "$rule" "$api/config/loadbalancer") || rc=$?
  if [[ $rc -eq 0 && "$r" == *Success* ]]; then done_rule=yes; break; fi
  echo "cload: rule POST attempt $i: curl exit code $rc, response [$r]" >&2
  if rule_installed; then echo "cload: the rule is installed after attempt $i" >&2; done_rule=yes; break; fi
  sleep 3
done
[[ "$done_rule" == yes ]] || fail "rule not installed after 10 attempts: last curl exit code $rc, response [$r]"

# Programs of this container: those using one of its pinned maps.
map_ids() {
  local m id
  for m in $(docker exec "$ctr" ls /opt/loxilb/dp/bpf); do
    id=$(docker exec "$ctr" bpftool map show pinned "/opt/loxilb/dp/bpf/$m" 2>/dev/null | sed -n '1s/:.*//p') || true
    [[ -n "$id" ]] && echo "$id"
  done
  return 0
}
programs() {
  docker exec "$ctr" bpftool prog show -j | python3 -c '
import json, sys
want = {int(x) for x in sys.argv[1].split()}
for p in json.load(sys.stdin):
    if want & set(p.get("map_ids", [])):
        print(p["id"], p.get("name", "?"))' "$1"
}
want=$(printf '%s\n' $expected | sort | tr '\n' ' ')
got=""
for i in $(seq 1 60); do
  ids=$(map_ids | tr '\n' ' ')
  [[ -n "$ids" ]] && got=$(programs "$ids" | awk '{print $2}' | sort -u | tr '\n' ' ')
  [[ "$got" == "$want" ]] && break
  sleep 1
done
[[ "$got" == "$want" ]] || fail "programs differ from the expected set: got [$got], want [$want]"

programs "$ids" | while read -r pid name; do
  sudo "$bin" "$pid" | awk -v n="$name" '{print n, $3, $4}'
done | python3 -c '
import collections, sys
limit = int(sys.argv[1])
rows = collections.defaultdict(list)
for line in sys.stdin:
    n, v, x = line.split()
    rows[n].append((int(v), int(x)))
print("program,instances,verified_insns,xlated_insns,margin_to_limit")
for n, r in sorted(rows.items(), key=lambda kv: -max(a for a, _ in kv[1])):
    v = max(a for a, _ in r)
    print(f"{n},{len(r)},{v},{max(b for _, b in r)},{limit - v}")' "$limit" > "$out"
cat "$out"
