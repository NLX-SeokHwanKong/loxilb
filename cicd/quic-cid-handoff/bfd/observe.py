"""Watch a real GoBGP adjacency and optionally the fork's BFD state machine."""
import json
import subprocess
import time
from pathlib import Path


class Monitor:
    def __init__(self, fabric, stack, spawn, out, stage, detector):
        self.f = fabric
        self.out = out.resolve()
        self.detector = detector
        client = ["ip", "netns", "exec", fabric.CLIENT]
        donor = ["nsenter", "-t", str(fabric.IDS["old"][1]), "-n"]
        root = Path(f"/proc/{fabric.IDS['old'][1]}/root/usr/sbin")
        self.cli = client + [str(root / "gobgp"), "-p", "55051", "-j", "neighbor"]
        for side, ns, local, peer, local_as, peer_as in (
            ("donor", donor, fabric.FRONT+"30", fabric.FRONT+"1", 65030, 65001),
            ("observer", client, fabric.FRONT+"1", fabric.FRONT+"30", 65001, 65030),
        ):
            conf = self.out / (side + ".toml")
            conf.write_text(f"""
[global.config]
  as = {local_as}
  router-id = "{local}"
  port = 21179
[[neighbors]]
  [neighbors.config]
    neighbor-address = "{peer}"
    peer-as = {peer_as}
  [neighbors.transport.config]
    local-address = "{local}"
    remote-port = 21179
  [neighbors.timers.config]
    hold-time = 9
    keepalive-interval = 3
    connect-retry = 1
""")
            spawn(stack, ns + [root/"gobgpd", "-f", conf, "--api-hosts", "127.0.0.1:55051"], self.out/(side+"-bgp.log"))
            if detector == "bfd" and side == "donor":
                body = json.dumps(dict(instance="llb-inst0", remoteIp=peer, sourceIp=local, interval=200000, retryCount=3))
                res = fabric.enter("old", "curl", "-fsS", "-H", "Content-Type: application/json",
                                   "-d", body, "http://127.0.0.1:11111/netlox/v1/config/bfd")
                if json.loads(res).get("result") != "Success":
                    raise RuntimeError(("BFD configuration", res))
            if detector == "bfd" and side == "observer":
                spawn(stack, ns + [stage/"bin/bfd-peer", local, peer], self.out/(side+"-bfd.log"))
        self.wait_ready()
        self.save_bfd("ready")

    def save_bfd(self, phase):
        if self.detector == "bfd":
            receipt = self.f.enter("old", "curl", "-fsS", "http://127.0.0.1:11111/netlox/v1/config/bfd/all")
            (self.out / ("donor-bfd-" + phase + ".json")).write_text(receipt)

    def bgp_state(self):
        p = subprocess.run(self.cli, capture_output=True, text=True, timeout=3)
        if p.returncode:
            return None
        rows = json.loads(p.stdout)
        if not rows:
            return None
        row = rows[0]
        return row["state"]["session_state"]

    def bfd_state(self):
        rows = (self.out / "observer-bfd.log").read_text().splitlines()
        for row in reversed(rows):
            if row.startswith('{"epoch_ns"') and row.endswith("}"):
                return json.loads(row)["state"]

    def wait_ready(self):
        end = time.monotonic() + 75
        while time.monotonic() < end:
            if self.bgp_state() in (6, "ESTABLISHED") and (self.detector != "bfd" or self.bfd_state() == "BFDUp"):
                return
            time.sleep(.12)
        raise RuntimeError("BGP/BFD peer did not become ready")

    def wait_alarm(self):
        end = time.monotonic() + 17
        while time.monotonic() < end:
            if self.detector == "bfd":
                if self.bfd_state() == "BFDDown":
                    return
            else:
                state = self.bgp_state()
                if state is not None and state not in (6, "ESTABLISHED"):
                    return
            time.sleep(.04)
        raise RuntimeError("no detector transition")
