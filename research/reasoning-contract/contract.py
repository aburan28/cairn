"""Experimental information contract; credits are local and never Cairn balances.

The outcome is an exogenous input to this model. There is no authentication,
oracle, deadline service, provider gateway, or network ledger behind these APIs.
"""

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json


def integer(value, name, low=0, high=10**12):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low}, {high}]")
    return value


def probability(value, scale):
    return integer(value, "probability", 0, scale)


def score_delta(previous, report, outcome, scale):
    """Signed improvement in quadratic score, without a rounding operation."""
    integer(scale, "scale", 1, 10_000)
    probability(previous, scale)
    probability(report, scale)
    integer(outcome, "outcome", 0, 1)
    target = outcome * scale
    return (previous - target) ** 2 - (report - target) ** 2


def report_commitment(task, slot, previous, owner, report, nonce, scale):
    integer(scale, "scale", 1, 10_000)
    integer(slot, "slot", 0, 1023)
    probability(previous, scale)
    probability(report, scale)
    if not isinstance(task, str) or not task or not isinstance(owner, str) or not owner:
        raise ValueError("task and owner must be nonempty strings")
    if not isinstance(nonce, str) or len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("nonce must encode 32 bytes as lowercase hex")
    # This is a new experiment domain, not an encoding of a Cairn record.
    payload = json.dumps(
        {"task": task, "slot": slot, "previous": previous, "owner": owner,
         "report": report, "nonce": nonce, "scale": scale},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()
    return sha256(b"cairn/research/information-contract/v1\x00" + payload).hexdigest()


@dataclass(frozen=True)
class Update:
    owner: str
    previous: int
    report: int


@dataclass(frozen=True)
class Resolution:
    outcome: int | None
    deltas: tuple[int, ...]
    sponsor_change: int


class Contract:
    """Finite report rights and fully reserved, simultaneous score transfers.

    Reports form one chain starting from a sponsor-frozen baseline. Full signed
    differences telescope even if one person controls many reports. Releasing
    only the positive differences destroys that property.
    """

    def __init__(self, task, baseline, sponsor_credits, worker_credits, *, scale=100, slots=3):
        integer(scale, "scale", 1, 10_000)
        probability(baseline, scale)
        integer(slots, "slots", 1, 1024)
        integer(sponsor_credits, "sponsor credits", scale**2)
        if not isinstance(task, str) or not task:
            raise ValueError("task must be a nonempty string")
        if not worker_credits or any(not isinstance(k, str) or not k for k in worker_credits):
            raise ValueError("worker credits need nonempty owner labels")
        for value in worker_credits.values():
            integer(value, "worker credits")
        self.task = task
        self.scale = scale
        self.slots = slots
        self.baseline = baseline
        self.current = baseline
        self.sponsor = sponsor_credits
        self.available = dict(worker_credits)
        self.updates = []
        self.pending = None
        self.state = "open"
        self.resolution = None
        self.initial_total = self.total()

    @property
    def bond(self):
        # Uniform worst-case collateral hides the forecast while it is sealed.
        return self.scale**2

    def total(self):
        held = 0 if self.resolution is not None else self.bond * (
            len(self.updates) + int(self.pending is not None)
        )
        return self.sponsor + sum(self.available.values()) + held

    def commit(self, owner, commitment):
        if self.state != "open" or self.pending is not None or len(self.updates) >= self.slots:
            raise ValueError("no open report right")
        if not isinstance(commitment, str) or len(commitment) != 64 or any(c not in "0123456789abcdef" for c in commitment):
            raise ValueError("invalid report commitment")
        if self.available.get(owner, 0) < self.bond:
            raise ValueError("collateral must exist before this report")
        self.available[owner] -= self.bond
        self.pending = (owner, commitment)

    def reveal(self, report, nonce):
        if self.state != "open" or self.pending is None:
            raise ValueError("no report awaiting reveal")
        owner, sealed = self.pending
        expected = report_commitment(
            self.task, len(self.updates), self.current, owner, report, nonce, self.scale
        )
        if not compare_digest(sealed, expected):
            raise ValueError("report does not open this task, slot, baseline and owner")
        self.updates.append(Update(owner, self.current, report))
        self.current = report
        self.pending = None

    def close(self):
        if self.state != "open":
            raise ValueError("report window already closed")
        if self.pending is not None:
            owner, _ = self.pending
            self.available[owner] += self.bond
            self.pending = None
        self.state = "closed"

    def resolve(self, outcome):
        if outcome is not None:
            integer(outcome, "outcome", 0, 1)
        if self.resolution is not None:
            if outcome != self.resolution.outcome:
                raise ValueError("a resolved outcome cannot be changed")
            return self.resolution
        if self.state != "closed":
            raise ValueError("close reports before revealing the external outcome")
        deltas = tuple(
            0 if outcome is None else score_delta(u.previous, u.report, outcome, self.scale)
            for u in self.updates
        )
        sponsor = self.sponsor - sum(deltas)
        available = dict(self.available)
        for update, delta in zip(self.updates, deltas):
            available[update.owner] += self.bond + delta
        if sponsor < 0 or any(v < 0 for v in available.values()):
            raise ValueError("unfunded settlement")
        self.sponsor = sponsor
        self.available = available
        self.resolution = Resolution(outcome, deltas, -sum(deltas))
        self.state = "unavailable" if outcome is None else "resolved"
        if self.total() != self.initial_total:
            raise AssertionError("credits were created or lost")
        return self.resolution
