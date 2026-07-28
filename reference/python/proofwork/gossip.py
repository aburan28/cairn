"""The candidate population: a CRDT, deliberately not a consensus problem.

The single most expensive mistake available here is running the whole network
through one agreement protocol. Three kinds of shared state live in a research
network and they have three completely different consistency requirements:

    frontier    who holds the best score. Payment depends on it, so it needs a
                total order -- but it changes only on improvement, so it is
                low-volume. This is the *only* part that needs consensus.

    population  the pile of scored candidates worth mutating. High volume,
                order-irrelevant, loss-tolerant, and divergence between nodes is
                actively *useful* (it preserves search diversity). Gossip.

    work split  which region a node searches. Needs no agreement at all --
                see partition.py.

Pushing the population through consensus would cost orders of magnitude in
throughput to buy a property the workload does not want. So the population is a
join-semilattice: nodes gossip whatever they have, merges are commutative,
associative, and idempotent, and any two nodes that have seen the same set of
messages agree -- with no rounds, no leader, and no voting.

**Bounded, and still confluent.** Keeping every candidate forever is not an
option, so each island retains only its top K. That pruning is safe: if a
candidate is not in the top K of A ∪ B, then K candidates in A ∪ B beat it, and
those all survive into A ∪ B ∪ C, so it is not in the top K of the union either.
Dropping it early therefore never changes the answer, and merge stays
associative. Tie-breaks go to the content hash so the order is total and every
node prunes identically.

**Islands.** Retention is per-island rather than global, so one strong candidate
cannot wipe out the diversity the search depends on -- the island model
FunSearch uses, expressed as a data structure instead of a scheduler.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Iterator

from .canonical import digest

DEFAULT_ISLANDS = 8
DEFAULT_CAPACITY = 32


@dataclass(frozen=True)
class Candidate:
    """A scored artifact worth building on. Not a claim; nothing is owed for it."""

    objective_id: str
    artifact: dict[str, Any]
    score: int
    origin: str

    def __post_init__(self) -> None:
        if isinstance(self.score, bool) or not isinstance(self.score, int):
            raise ValueError("score must be an integer")

    @property
    def id(self) -> str:
        """Identity includes the claimed score, and must.

        A gossiped score is an *assertion by a peer*, not a verified fact, and
        two peers can gossip the same artifact with different scores -- one
        honestly, one lying to crowd better candidates out of the population.
        If identity ignored the score, merge would have to pick a winner between
        two values that are equal under the key, and any tiebreak not derived
        from the values themselves (insertion order, arrival time, sender)
        destroys convergence: two nodes seeing the same messages in different
        orders end up with different populations and never find out.

        Keeping the score in the identity makes disagreement *representable* --
        both entries survive, side by side, which is what lets a node notice a
        peer is lying instead of silently absorbing it. See ``ingest``.
        """
        return digest(
            {"objective_id": self.objective_id, "artifact": self.artifact, "score": self.score}
        )

    @property
    def artifact_id(self) -> str:
        """Identity of the artifact alone, ignoring any claimed score."""
        return digest({"objective_id": self.objective_id, "artifact": self.artifact})

    def island(self, islands: int = DEFAULT_ISLANDS) -> int:
        # By artifact, so an artifact's honest and inflated variants land in the
        # same island and compete directly rather than occupying two slots.
        return int(self.artifact_id[-8:], 16) % islands

    #: Total order: score first, then content hash so ties break identically
    #: on every node. Without a total order, pruning is not deterministic and
    #: merge stops converging.
    @property
    def rank(self) -> tuple[int, str]:
        return (self.score, self.id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "artifact": self.artifact,
            "score": self.score,
            "origin": self.origin,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Candidate":
        return cls(
            objective_id=data["objective_id"],
            artifact=data["artifact"],
            score=data["score"],
            origin=data["origin"],
        )


class Population:
    """A bounded join-semilattice of candidates, replicated by gossip."""

    def __init__(
        self,
        islands: int = DEFAULT_ISLANDS,
        capacity: int = DEFAULT_CAPACITY,
        candidates: Iterable[Candidate] = (),
    ):
        if islands < 1 or capacity < 1:
            raise ValueError("islands and capacity must be positive")
        self.islands = islands
        self.capacity = capacity
        self._by_island: dict[int, dict[str, Candidate]] = {}
        for candidate in candidates:
            self._insert(candidate)
        self._prune()

    # -- lattice ---------------------------------------------------------
    def _insert(self, candidate: Candidate) -> None:
        island = candidate.island(self.islands)
        bucket = self._by_island.setdefault(island, {})
        existing = bucket.get(candidate.id)
        # Identical content from two peers. Keep the lexicographically smaller
        # origin -- a function of the values, so every node picks the same one.
        if existing is None or candidate.origin < existing.origin:
            bucket[candidate.id] = candidate

    def _prune(self) -> None:
        for island, bucket in self._by_island.items():
            if len(bucket) <= self.capacity:
                continue
            keep = sorted(bucket.values(), key=lambda c: c.rank, reverse=True)[: self.capacity]
            self._by_island[island] = {c.id: c for c in keep}

    def add(self, candidate: Candidate) -> "Population":
        self._insert(candidate)
        self._prune()
        return self

    def merge(self, other: "Population") -> "Population":
        """Join. Commutative, associative, idempotent -- order never matters."""
        if other.islands != self.islands:
            raise ValueError("cannot merge populations with different island counts")
        merged = Population(self.islands, min(self.capacity, other.capacity))
        for candidate in list(self) + list(other):
            merged._insert(candidate)
        merged._prune()
        return merged

    # -- reading ---------------------------------------------------------
    def __iter__(self) -> Iterator[Candidate]:
        for bucket in self._by_island.values():
            yield from bucket.values()

    def __len__(self) -> int:
        return sum(len(b) for b in self._by_island.values())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Population):
            return NotImplemented
        return {c.id: c for c in self} == {c.id: c for c in other}

    def top(self, k: int = 1) -> list[Candidate]:
        return sorted(self, key=lambda c: c.rank, reverse=True)[:k]

    def best(self) -> Candidate | None:
        top = self.top(1)
        return top[0] if top else None

    def island(self, index: int) -> list[Candidate]:
        return sorted(
            self._by_island.get(index, {}).values(), key=lambda c: c.rank, reverse=True
        )

    def digest(self) -> str:
        """Content address of the whole population -- cheap gossip reconciliation.

        Two peers exchange digests; equal digests mean there is nothing to send.
        """
        return digest(sorted(c.id for c in self))

    def to_dict(self) -> dict[str, Any]:
        return {
            "islands": self.islands,
            "capacity": self.capacity,
            "candidates": [c.to_dict() for c in sorted(self, key=lambda c: c.id)],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Population":
        return cls(
            islands=data["islands"],
            capacity=data["capacity"],
            candidates=[Candidate.from_dict(c) for c in data["candidates"]],
        )


def ingest(population: Population, candidate: Candidate, rescore) -> bool:
    """Add a gossiped candidate only if its claimed score is locally reproducible.

    **Gossip is untrusted.** A peer can assert any score it likes, and an
    inflated one would otherwise crowd genuine candidates out of a bounded
    population -- a cheap and effective denial of service against the search
    itself.

    The defence is the same property the whole network is built on: for the
    objectives worth running here, checking costs one evaluation, which is the
    evaluation the node was going to spend on this candidate anyway. So verify
    on ingest and drop what does not reproduce. Untrusted input plus free
    verification is not a hard problem; it only becomes one if you skip the
    verification because it looked like overhead.

    Returns True if the candidate was accepted.
    """
    try:
        observed = rescore(candidate.artifact)
    except Exception:
        # A crash while scoring a peer's candidate says nothing about the
        # candidate and must not be recorded as a score of its own.
        return False
    if isinstance(observed, bool) or not isinstance(observed, int):
        return False
    if observed != candidate.score:
        return False
    population.add(candidate)
    return True
