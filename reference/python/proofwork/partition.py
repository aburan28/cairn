"""Work assignment without a coordinator.

The reflex when thousands of nodes must avoid duplicating work is to build a
dispatcher: a server that hands out work units and tracks who holds what. BOINC
does this and it is the right call there, because BOINC's participants are not
adversarial. Here they are, and a dispatcher is a single point of censorship, a
liveness bottleneck, and a thing that must itself be replicated and agreed on.

None of that is necessary, because **work assignment does not need agreement.**
Two nodes searching the same region is not an error -- it is a little wasted
compute, self-correcting the moment either publishes. So assignment can be a
pure function every node evaluates locally:

    partition = H(beacon(epoch) ‖ node_id ‖ objective_id) mod n

No messages, no locks, no reservations, no coordinator. Every node computes its
own assignment and can compute anyone else's, which is what makes "did you
actually search your region" a checkable question later.

**Why the beacon.** Without an epoch-varying input the mapping is fixed forever:
a node permanently owns a region, and an adversary who wants a region left
unsearched simply generates identities until one lands there and then does
nothing. Mixing in a per-epoch beacon rotates every assignment, so squatting a
region costs a fresh grinding effort each epoch and blocking one indefinitely
becomes impractical.

The beacon must be **unpredictable before the epoch and verifiable after**. This
module derives it from a chain of ledger heads, which is honest about what it
provides: any value the sequencer could have chosen freely is a value the
sequencer could have ground to place itself favourably. At Stage 0 the sequencer
is trusted not to; at Stage 2 this must become a real randomness beacon (VDF or
threshold signature) and the docstring should stop making excuses for it.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

EPOCH_SECONDS = 600


def beacon(epoch: int, anchor: str) -> str:
    """Per-epoch randomness. ``anchor`` is a ledger head or equivalent commitment."""
    return hashlib.sha256(f"{epoch}:{anchor}".encode()).hexdigest()


def assign(node_id: str, objective_id: str, epoch_beacon: str, partitions: int) -> int:
    """Which slice of the search space this node takes. Pure, local, checkable."""
    if partitions < 1:
        raise ValueError("partitions must be positive")
    mac = hmac.new(
        epoch_beacon.encode(), f"{node_id}|{objective_id}".encode(), hashlib.sha256
    ).digest()
    return int.from_bytes(mac[:8], "big") % partitions


def epoch_of(timestamp_seconds: int, epoch_seconds: int = EPOCH_SECONDS) -> int:
    return timestamp_seconds // epoch_seconds


@dataclass(frozen=True)
class Assignment:
    node_id: str
    objective_id: str
    epoch: int
    partition: int
    partitions: int

    @property
    def share(self) -> tuple[int, int]:
        """The half-open slice ``[lo, hi)`` of a unit interval scaled to 2**32."""
        step = (1 << 32) // self.partitions
        lo = self.partition * step
        hi = (1 << 32) if self.partition == self.partitions - 1 else lo + step
        return lo, hi

    def covers(self, item_id: str) -> bool:
        """Does ``item_id`` fall in this node's slice?

        Lets a node filter a candidate stream to its own region, and lets anyone
        else check that a submitted result came from the region the submitter
        was assigned.
        """
        value = int(hashlib.sha256(item_id.encode()).hexdigest()[:8], 16)
        lo, hi = self.share
        return lo <= value < hi


def assignment_for(
    node_id: str,
    objective_id: str,
    epoch: int,
    anchor: str,
    partitions: int,
) -> Assignment:
    return Assignment(
        node_id=node_id,
        objective_id=objective_id,
        epoch=epoch,
        partition=assign(node_id, objective_id, beacon(epoch, anchor), partitions),
        partitions=partitions,
    )
