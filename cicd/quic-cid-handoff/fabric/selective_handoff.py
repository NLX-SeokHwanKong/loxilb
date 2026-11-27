"""Selective drain for the exclusive, isolated two-port Linux fabric adapter."""
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import sys
import time

from handoff import Hold

def rpc(vip, port, rule):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as sock:
        sock.settimeout(5)
        sock.connect('\0loxilb-cid-handoff-v1')
        sock.sendall(json.dumps(dict(vip=vip, port=port, rule=rule)).encode())
        reply = json.loads(sock.recv(1024))
    if 'error' in reply:
        raise Hold(str(reply))
    return reply

def adapter(f):
    class SelectiveFabric(f.Fabric):
        def __init__(self):
            self.incarnations = {}

        def identity(self, lb):
            # A pidfd stays attached to the original process through PID reuse.
            import os
            import select
            if lb not in self.incarnations:
                pinned = super().identity(lb)
                fd = os.pidfd_open(pinned[1])
                try:
                    super().identity(lb)
                except BaseException:
                    os.close(fd)
                    raise
                self.incarnations[lb] = (pinned, fd)
            ident, fd = self.incarnations[lb]
            if select.select([fd], [], [], 0)[0]:
                raise Hold('pinned owner exited')
            return ident

        def release(self):
            import os
            for _, fd in self.incarnations.values():
                os.close(fd)
            self.incarnations.clear()

        def drained(self, lb):
            if not super().drained(lb):
                return False
            vip = f.u32(f.CID)
            for row in f.rows(lb, 'fc_v4_map'):
                k = row['key']
                if row['value']['zone'] == 1 and k['l4proto'] == 17 and vip in (k['saddr'], k['daddr']):
                    return False
            return True

        def read(self, lb):
            view = super().read(lb)
            for row in f.rows(lb, 'cid_retired'):
                k = row['key']
                key = tuple(k[n] for n in ('vip', 'backend', 'sport', 'zone'))
                # Check on this host's monotonic clock. A permanent dormant
                # guard is stronger than the remaining timed rejection.
                if row['value'] > time.monotonic_ns() and view.guard.get(key) != 0:
                    raise Hold('uncovered timed backend exclusion')
            return view

        def prepare(self, donor, candidate):
            if not self.is_open(donor) or self.is_open(candidate):
                raise Hold('unexpected gate ownership')
            with ThreadPoolExecutor(2) as pool:
                old, new = pool.map(self.read, (donor, candidate))
            old.validate()
            new.validate()
            if old.identity == new.identity or old.rules != new.rules or old.expected != new.expected:
                raise Hold('owner or rule generation mismatch')
            for key, value in new.guard.items():
                if key not in old.guard or (value & 0x80000000 and not old.guard[key] & 0x80000000):
                    raise Hold('unexpected target history')
            for owner in (donor, candidate):
                for port in f.PORT[owner]:
                    f.n(f.SW, 'ip', 'link', 'set', port, 'down')
            def purge(owner, view):
                self.identity(owner)
                for rule in view.rules:
                    k, v = json.loads(rule)
                    port = socket.ntohs(k['dport'])
                    reply = json.loads(f.enter(owner, sys.executable, __file__, f.CID, port, v['ca']['cidx']))
                    f.event('selective_drain', owner=owner, port=port, **reply)
            with ThreadPoolExecutor(2) as pool:
                list(pool.map(purge, (donor, candidate), (old, new)))
                after = list(pool.map(self.read, (donor, candidate)))
            if after != [old, new]:
                raise Hold('state changed during drain')

        def open(self, lb):
            super().open(lb)
            for dev in f.PORT[lb]:
                f.n(f.SW, 'ip', 'link', 'set', dev, 'up')
    return SelectiveFabric()

if __name__ == '__main__':
    print(json.dumps(rpc(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))))
