"""Routed IPv4 FullNAT lab with native BFD, XSync and shared return gateway."""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here / "fabric"))
spec = importlib.util.spec_from_file_location("fabric", here / "fabric/fabric-trial.py")
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
out = Path(sys.argv[1]).resolve()
out.mkdir()
vip, backend, client = f.FRONT + "90", f.FRONT + "20", "198.18.241.1"


def api(owner, path):
    return json.loads(
        f.enter(
            owner,
            "curl",
            "-fsS",
            "--max-time",
            "2",
            "http://127.0.0.1:11111/netlox/v1/config/" + path,
        )
    )


def state(owner):
    return next(
        x["state"]
        for x in api(owner, "cistate/all")["Attr"]
        if x["instance"] == "llb-inst0"
    )


def snapshot(path, data):
    (out / path).write_text(json.dumps(data, indent=2))


def wait(predicate, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if predicate():
                return
        except RuntimeError:
            pass
        time.sleep(0.1)
    raise RuntimeError("timeout waiting for " + predicate.__name__)


def proc(stack, cmd, filename):
    log = stack.enter_context((out / filename).open("w"))
    p = subprocess.Popen(list(map(str, cmd)), stdout=log, stderr=subprocess.STDOUT)

    def stop():
        p.terminate()
        p.wait(timeout=5)

    stack.callback(stop)
    return p


def keep_logs(owner):
    (out / (owner + ".log")).write_text(f.run("docker", "logs", f.NAMES[owner]) + "\n")
    # LoxiLB also writes its detailed logs to /var/log.
    result = subprocess.run(
        [
            "docker",
            "exec",
            f.NAMES[owner],
            "sh",
            "-c",
            "tail -250 /var/log/loxilb*.log",
        ],
        capture_output=True,
        text=True,
    )
    (out / (owner + "-tail.log")).write_text(result.stdout)


router = f.TAG + "rt"
gw = f.FRONT + "10"
scope = os.getenv("NONFULL") == "1"
vips = [f.FRONT + str(n) for n in (90, 91, 93 if scope else 92)]
enabled = os.getenv("PREP", "")  # off, or a comma-separated list
late = os.getenv("LATE") == "1"


def mark(event):
    with (out / "events.jsonl").open("a") as log:
        print(json.dumps(dict(event=event, epoch=time.time())), file=log)


with ExitStack() as stack:
    for ns in (f.SW, f.CLIENT, f.BENS[0], router):
        f.run("ip", "netns", "add", ns)
        stack.callback(f.run, "ip", "netns", "delete", ns)
        f.n(ns, "ip", "link", "set", "lo", "up")
    for bridge in ("lan", "sync", "remote"):
        f.n(f.SW, "ip", "link", "add", bridge, "type", "bridge")
        f.n(f.SW, "ip", "link", "set", bridge, "up")
    f.attach(1, f.CLIENT, "remote", client, "eth0", True)
    for i in (2, 3):
        f.n(
            f.CLIENT, "ip", "addr", "add", "198.18.241." + str(i) + "/24", "dev", "eth0"
        )
    f.attach(8, router, "remote", "198.18.241.254", "clients", True)
    f.attach(9, router, "lan", gw, "front", True)
    f.n(router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    f.n(f.CLIENT, "ip", "route", "add", f.FRONT + "0/24", "via", "198.18.241.254")
    f.attach(2, f.BENS[0], "lan", backend, "eth0", True)
    proc(
        stack,
        ["ip", "netns", "exec", f.BENS[0], "python3", here / "fabric/echo.py", "A"],
        "server.log",
    )
    for i, owner in enumerate(("old", "new")):
        addr_idx = 1 - i if os.getenv("FLIP") else i
        idx, peer = str(30 + addr_idx), str(31 - addr_idx)
        name = f.NAMES[owner] = f.TAG + "-" + owner
        args = ["--egr-hooks", "--self=" + str(i), "--cluster=" + f.BACK + peer]
        if enabled:
            args.extend("--tcp-return-vip=" + ip for ip in enabled.split(","))
        f.run(
            "docker",
            "run",
            "--pull",
            "never",
            "-d",
            "--network",
            "none",
            "--privileged",
            "--name",
            name,
            "--entrypoint",
            "/bin/sh",
            f.V7,
            "-ec",
            'mount --make-rprivate /; until test -f /tmp/q7-ready; do sleep .1; done; exec /root/loxilb-io/loxilb/loxilb "$@"',
            "sh",
            *args
        )
        stack.callback(f.run, "docker", "rm", "-f", name)
        stack.callback(keep_logs, owner)
        f.IDS[owner] = f.docker_id(owner)
        f.PORT[owner] = [
            f.attach(3 + i * 2 + j, owner, br, prefix + idx, dev, True, f.IDS[owner][1])
            for j, (br, prefix, dev) in enumerate(
                [("lan", f.FRONT, "eth1"), ("sync", f.BACK, "eth0")]
            )
        ]
    for owner in f.IDS:
        f.run("docker", "exec", f.NAMES[owner], "touch", "/tmp/q7-ready")

        def api_ready():
            try:
                state(owner)
                return ":3784" in f.enter(owner, "ss", "-uln")
            except (RuntimeError, StopIteration, KeyError):
                return False

        wait(api_ready, 40)
    for i, owner in enumerate(f.IDS):
        addr_idx = 1 - i if os.getenv("FLIP") else i
        body = dict(
            instance="llb-inst0",
            sourceIp=f.BACK + str(30 + addr_idx),
            remoteIp=f.BACK + str(31 - addr_idx),
            interval=200000,
            retryCount=3,
        )
        res = f.enter(
            owner,
            "curl",
            "-fsS",
            "-H",
            "Content-Type: application/json",
            "-d",
            json.dumps(body),
            "http://127.0.0.1:11111/netlox/v1/config/bfd",
        )
        assert json.loads(res).get("result") == "Success", res

    def elected():
        try:
            states = {x: state(x) for x in f.IDS}
            return set(states.values()) == {"MASTER", "BACKUP"} and all(
                "BFDUp" in str(api(x, "bfd/all")) for x in f.IDS
            )
        except (RuntimeError, StopIteration):
            return False

    wait(elected, 150)
    master = next(x for x in f.IDS if state(x) == "MASTER")
    backup = next(x for x in f.IDS if x != master)
    mac = json.loads(f.enter(backup, "ip", "-j", "link", "show", "eth1"))[0]["address"]
    capture_log = out / "router-capture.log"
    proc(
        stack,
        [
            "ip",
            "netns",
            "exec",
            router,
            "tcpdump",
            "-p",
            "-U",
            "--immediate-mode",
            "-nn",
            "-s",
            "160",
            "-i",
            "front",
            "-w",
            out / "front.pcap",
            "arp or icmp or tcp port 18081 or udp port 18082 or sctp",
        ],
        capture_log.name,
    )
    wait(lambda: "listening on" in capture_log.read_text(), 5)
    proc(
        stack,
        [
            "ip",
            "netns",
            "exec",
            f.BENS[0],
            "tcpdump",
            "-p",
            "-U",
            "--immediate-mode",
            "-nn",
            "-s",
            "160",
            "-i",
            "eth0",
            "-w",
            out / "backend.pcap",
            "arp or tcp port 18080 or udp port 18080 or sctp",
        ],
        "backend-capture.log",
    )
    wait(lambda: "listening on" in (out / "backend-capture.log").read_text(), 5)
    # Optional late-availability fixture blocks only candidate ARP at the router
    # during route installation. It is removed before the measured fault.
    if late:
        f.n(router, "tc", "qdisc", "add", "dev", "front", "clsact")
        f.n(
            router,
            "tc",
            "filter",
            "add",
            "dev",
            "front",
            "ingress",
            "protocol",
            "arp",
            "flower",
            "src_mac",
            mac,
            "action",
            "drop",
        )
    for owner in f.IDS:
        f.enter(
            owner, "ip", "route", "add", "198.18.241.0/24", "via", gw, "dev", "eth1"
        )
        for address in vips:
            if scope and address == vips[-1]:
                f.api(
                    owner,
                    "POST",
                    body=dict(
                        serviceArguments=dict(
                            externalIP=address,
                            protocol="tcp",
                            port=18081,
                            mode=1,
                            sel=0,
                        ),
                        endpoints=[
                            dict(endpointIP=backend, targetPort=18080, weight=1)
                        ],
                    ),
                )
            else:
                f.setup_rule(owner, address, "tcp", 18081, [backend])
        for proto, port in (("udp", 18082), ("sctp", 18083)):
            f.setup_rule(owner, vips[2], proto, port, [backend])
    snapshot(
        "routes.json",
        dict(
            candidate=f.enter(backup, "ip", "-j", "route", "get", client),
            router=f.n(router, "ip", "-j", "route", "get", client),
            client=f.n(f.CLIENT, "ip", "-j", "route", "get", vip),
            forward=f.n(router, "sysctl", "-n", "net.ipv4.ip_forward"),
        ),
    )
    snapshot(
        "meta.json",
        dict(
            master=master,
            backup=backup,
            mac=mac,
            gw=gw,
            vips=vips,
            enabled=enabled,
            late=late,
            image=f.V7,
        ),
    )
    # Establish services through MASTER while leaving the peer neighbor untouched.
    wait(lambda: all(f.result(f.CLIENT, v, 6, 18081) == "A" for v in vips), 30)

    def legacy():
        answers = {}
        for proto, num, port in [("udp", 17, 18082), ("sctp", 132, 18083)]:
            try:
                answers[proto] = f.result(f.CLIENT, vips[2], num, port)
            except RuntimeError as error:
                answers[proto] = {"error": str(error)}
        return answers

    before = legacy()
    assert before == {"udp": "A", "sctp": "A"}, before
    if late:
        f.n(router, "tc", "qdisc", "del", "dev", "front", "clsact")
    mark("available")
    proc(
        stack,
        [
            "ip",
            "netns",
            "exec",
            f.CLIENT,
            "python3",
            "-u",
            here / "gw-stream.py",
            *vips,
        ],
        "app.jsonl",
    )

    def cts():
        return [
            r
            for r in f.rows(backup, "ct_map")
            if r["key"]["l4proto"] == 6
            and 54170 <= socket.ntohs(r["key"]["sport"]) <= 54178
        ]

    wait(lambda: len(cts()) == 9, 55)
    mark("synced")
    time.sleep(float(os.environ.get("OBSERVE_SECONDS", "2.5")))

    def observe():
        return dict(
            neigh=f.enter(backup, "ip", "-j", "neigh", "show", "to", gw),
            ct=cts(),
            route=f.rows(backup, "rt_v4_map"),
        )

    snapshot("prefault.json", observe())
    if scope:
        snapshot(
            "scope.json",
            dict(
                ct_count=len(cts()), legacy=before, rules=f.api(backup, "GET", "/all")
            ),
        )
        mark("scope-end")
        sys.exit(0)
    mark("fault")
    for dev in f.PORT[master]:
        f.n(f.SW, "ip", "link", "set", dev, "down")
    wait(lambda: state(backup) == "MASTER", 12)
    mark("master")
    time.sleep(5)
    after = legacy()
    snapshot("post.json", observe())
    events = [json.loads(l) for l in (out / "events.jsonl").read_text().splitlines()]
    epoch = {r["event"]: r["epoch"] for r in events}
    lines = [
        json.loads(l)
        for l in (out / "app.jsonl").read_text().splitlines()
        if l.endswith("}")
    ]
    result = []
    for port in range(54170, 54179):
        entries = [r for r in lines if r["sport"] == port]
        pre = next(
            (r for r in reversed(entries) if "i" in r and r["epoch"] < epoch["fault"]),
            None,
        )
        post = next(
            (r for r in entries if "i" in r and r["epoch"] >= epoch["master"]), None
        )
        result.append(
            dict(
                port=port,
                pre=pre,
                post=post,
                delay=post["epoch"] - epoch["fault"] if post else None,
                errors=[r for r in entries if "error" in r],
            )
        )
    snapshot(
        "result.json",
        dict(
            flows=result,
            legacy=[before, after],
            promotion=epoch["master"] - epoch["fault"],
        ),
    )
    mark("end")
    assert after == before, after
    assert all(v["pre"] and v["post"] and not v["errors"] for v in result)
