"""Planned transfer of one dedicated CID VIP through an exclusive port owner.

The adapter must serialize config writers, fence both data directions and
identify a live owner by immutable instance identity. No bootstrap on failure.
"""
from contextlib import ExitStack
from dataclasses import dataclass

class Hold(Exception):
    """The CID VIP cannot safely be admitted on the candidate."""

@dataclass(frozen=True)
class View:
    identity: object
    rules: tuple
    expected: dict
    guard: dict

    def validate(self):
        active = {k: v & 0x7fffffff for k, v in self.guard.items() if v}
        if not self.expected or self.expected != active:
            raise Hold("active reference counts disagree with published rules")

def transfer(link, donor, candidate):
    """Caller owns the fabric lock. A failed cutover can leave both ports closed."""
    if donor == candidate or link.is_open(candidate):
        raise Hold("target must be a distinct fenced instance")
    with ExitStack() as recovery:
        with link.quiesce(donor, candidate):
            if not link.is_open(donor):
                raise Hold("no live prior owner")
            if not link.drained(donor) or not link.drained(candidate):
                raise Hold("drain connections before handoff")
            old = link.read(donor)
            new = link.read(candidate)
            target_identity = new.identity
            old.validate()
            new.validate()
            if old.identity == new.identity or old.rules != new.rules or old.expected != new.expected:
                raise Hold("rule generation mismatch")
            # An unexpected target history cannot be silently erased.
            for key, value in new.guard.items():
                if key not in old.guard or (value & 0x80000000 and not old.guard[key] & 0x80000000):
                    raise Hold("unexpected target history")
            for key, value in old.guard.items():
                if new.guard.get(key) != value:
                    if (link.is_open(candidate) or not link.is_open(donor)
                            or link.identity(candidate) != target_identity or link.identity(donor) != old.identity):
                        raise Hold("fence or identity changed before copy")
                    link.restore(candidate, key, value)
            new = link.read(candidate)
            if link.read(donor) != old or new.guard != old.guard or new.expected != old.expected or new.rules != old.rules:
                raise Hold("final state differs")
            if new.identity != target_identity or new.identity != link.identity(candidate) or old.identity != link.identity(donor):
                raise Hold("instance replaced")
            link.close(donor)
            if link.is_open(donor) or link.is_open(candidate):
                raise Hold("exclusive fence failed")
            if new != link.read(candidate) or old != link.read(donor):
                raise Hold("state changed after fencing")
            if not link.drained(donor) or not link.drained(candidate):
                raise Hold("connection arrived during handoff")
            # Keep compensation armed until writer resumption succeeds, too.
            recovery.callback(link.close, candidate)
            link.open(candidate)
            if not link.is_open(candidate) or link.is_open(donor):
                raise Hold("target activation not verified")
        recovery.pop_all()
    return old
