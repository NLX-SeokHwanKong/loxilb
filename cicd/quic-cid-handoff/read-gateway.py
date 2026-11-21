"""Match each existing TCP socket and count frames on the router's LB-facing NIC."""
import collections
import ipaddress
import json
import statistics
import struct
import sys
from pathlib import Path


def ip(b):
    return str(ipaddress.IPv4Address(b))


def analyze(path):
    meta = json.loads((path / "meta.json").read_text())
    marks = {
        e["event"]: e["epoch"]
        for e in map(json.loads, (path / "events.jsonl").read_text().splitlines())
    }
    arp = collections.defaultdict(collections.Counter)
    probes = []
    syn = collections.defaultdict(list)
    received = {}
    window_end = marks.get("end", marks.get("scope-end"))
    split = marks.get("fault", window_end)
    assert window_end is not None
    with (path / "front.pcap").open("rb") as f:
        h = f.read(24)
        order = "<" if h[:2] == b"\xd4\xc3" else ">"
        assert struct.unpack_from(order + "I", h, 20)[0] == 1
        while hdr := f.read(16):
            sec, us, size, _ = struct.unpack(order + "IIII", hdr)
            t = sec + us / 1e6
            b = f.read(size)
            phase = (
                "setup"
                if t < marks["available"]
                else "before"
                if t < split
                else "handoff"
            )
            if t > window_end:
                continue
            candidate = b[6:12].hex(":") == meta["mac"]
            if b[12:14] == b"\x08\x06" and len(b) >= 42:
                op = int.from_bytes(b[20:22], "big")
                sip, dip = ip(b[28:32]), ip(b[38:42])
                arp[phase]["frames"] += 1
                if candidate and op == 1 and dip == meta["gw"]:
                    arp[phase]["candidate_who_has_gateway"] += 1
                if candidate and op == 1 and dip.startswith("198.18.241."):
                    arp[phase]["candidate_who_has_remote_client"] += 1
                if candidate and sip == dip:
                    arp[phase]["candidate_gratuitous"] += 1
            if b[12:14] != b"\x08\x00" or len(b) < 42:
                continue
            off = 14 + (b[14] & 15) * 4
            src, dst = ip(b[26:30]), ip(b[30:34])
            if (
                b[23] == 1
                and candidate
                and b[off] == 8
                and dst == meta["gw"]
                and b[22] == 1
            ):
                probes.append(round(t - marks["available"], 4))
            if b[23] != 6 or len(b) < off + 20:
                continue
            sport, dport, seq, ack = struct.unpack_from("!HHII", b, off)
            if 54170 <= sport <= 54178 and b[off + 13] & 2 and dst in meta["vips"]:
                syn[sport].append((seq, t))
            if (
                54170 <= dport <= 54178
                and src in meta["vips"]
                and candidate
                and t >= split
            ):
                hdrlen = 4 * (b[off + 12] >> 4)
                payload = b[off + hdrlen :]
                if payload.startswith(f"A/{dport}.".encode()) and dport not in received:
                    received[dport] = (int(payload.split(b".")[1]), t)
    if "scope-end" in marks:
        scope = json.loads((path / "scope.json").read_text())
        return dict(
            name=path.name,
            eligible=meta["enabled"],
            ct_count=scope["ct_count"],
            legacy=scope["legacy"],
            probe_seconds=probes,
            arp={k: dict(v) for k, v in arp.items()},
            pre_s=round(window_end - marks["available"], 3),
        )
    res = json.loads((path / "result.json").read_text())
    app = [
        json.loads(l)
        for l in (path / "app.jsonl").read_text().splitlines()
        if l.endswith("}")
    ]
    delays = {}
    for flow in res["flows"]:
        port = flow["port"]
        assert not flow["errors"] and flow["pre"] and flow["post"]
        assert len({i for i, t in syn[port]}) == 1 and all(
            t < marks["fault"] for i, t in syn[port]
        )
        i, t = received[port]
        matched = next(row for row in app if row["sport"] == port and row.get("i") == i)
        assert abs(matched["epoch"] - t) < 0.1
        delays[port] = round(matched["epoch"] - marks["fault"], 4)
    return dict(
        name=path.name,
        eligible=meta["enabled"],
        shared_gateway=meta["gw"],
        promotion=res["promotion"],
        delays=delays,
        median=statistics.median(delays.values()),
        arp={k: dict(v) for k, v in arp.items()},
        probe_seconds=probes,
        pre_s=round(marks["fault"] - marks["available"], 3),
        handoff_s=round(marks["end"] - marks["fault"], 3),
        kernel_neighbor=json.loads(
            json.loads((path / "prefault.json").read_text())["neigh"]
        ),
        legacy=res["legacy"],
    )


if __name__ == "__main__":
    for name in sys.argv[1:]:
        path = Path(name)
        print(json.dumps(analyze(path)))
