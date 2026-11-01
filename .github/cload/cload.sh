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
  docker exec "$ctr" tail -40 /var/log/cload.log >&2 || true
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
api_curl() { sudo nsenter -t "$pid" -n curl -s -m 5 "$@"; }

for i in $(seq 1 90); do
  api_curl "$api/config/loadbalancer/all" > /dev/null 2>&1 && break
  sleep 1; [[ $i -eq 90 ]] && fail "API did not come up"
done
# A rule created before the port addresses are known misbehaves.
for i in $(seq 1 30); do
  docker exec "$ctr" grep -q "ifa added 198.51.100.2:cload1" /var/log/cload.log 2>/dev/null && break
  sleep 1; [[ $i -eq 30 ]] && fail "port address never registered"
done
rule='{"serviceArguments":{"externalIP":"192.0.2.100","port":443,"protocol":"udp","sel":1,"mode":0},"endpoints":[{"endpointIP":"198.51.100.21","targetPort":443,"weight":1},{"endpointIP":"198.51.100.22","targetPort":443,"weight":1},{"endpointIP":"198.51.100.23","targetPort":443,"weight":1}]}'
r=$(api_curl -X POST -H 'Content-Type: application/json' -d "$rule" "$api/config/loadbalancer")
[[ "$r" == *Success* ]] || fail "rule rejected: $r"

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
