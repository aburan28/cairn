"""The three records the network is built from: Objective, Commitment, Claim.

Every record is content-addressed: its id *is* the hash of its canonical form.
Two consequences carry most of the design's weight.

1. **The verifier is part of the objective's identity.** Editing an evaluator
   does not silently rescore work already done against it -- it produces a
   different objective id. There is no such thing as changing the rules of a
   funded objective; there is only forking it and funding the fork.

2. **A claim names the claims it built on.** The result is a hash-linked DAG,
   which is what makes automatic attribution computable (see attribution.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canonical import digest, digest_bytes


class RecordError(ValueError):
    """A record is structurally invalid."""


@dataclass(frozen=True)
class Objective:
    """A funded, checkable question.

    ``reward`` is an integer in the smallest unit of account. No floats
    anywhere near money.
    """

    goal: str
    statement: str
    verifier: dict[str, Any]
    reward: int
    funder: str
    created_at: str
    deadline: str | None = None
    #: Optional progressive-bounty parameters (see frontier.Ratchet). When
    #: present the objective pays out along an improvement curve instead of
    #: once to a single winner, which is what makes immediate publication the
    #: profitable move rather than a gift to your competitors.
    ratchet: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.statement.strip():
            raise RecordError("objective needs a statement")
        if not isinstance(self.verifier, dict) or "kind" not in self.verifier:
            raise RecordError("objective needs a verifier with a 'kind'")
        if isinstance(self.reward, bool) or not isinstance(self.reward, int):
            raise RecordError("reward must be an integer unit count")
        if self.reward < 0:
            raise RecordError("reward must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "type": "objective",
            "goal": self.goal,
            "statement": self.statement,
            "verifier": self.verifier,
            "reward": self.reward,
            "funder": self.funder,
            "created_at": self.created_at,
        }
        if self.deadline is not None:
            body["deadline"] = self.deadline
        if self.ratchet is not None:
            body["ratchet"] = self.ratchet
        return body

    @property
    def id(self) -> str:
        return digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Objective":
        return cls(
            goal=data["goal"],
            statement=data["statement"],
            verifier=data["verifier"],
            reward=data["reward"],
            funder=data["funder"],
            created_at=data["created_at"],
            deadline=data.get("deadline"),
            ratchet=data.get("ratchet"),
        )


def commitment_hash(objective_id: str, submitter: str, artifact: dict, nonce: str) -> str:
    """Binding commitment to an artifact, revealed later.

    Without this, a plaintext artifact is stolen by the first party who sees it
    -- the solver does the work and someone else collects. The submitter is
    bound into the hash so the commitment cannot be replayed by an observer
    under their own name.
    """
    return digest_bytes(
        digest({"objective_id": objective_id, "artifact": artifact}).encode()
        + b"|"
        + submitter.encode()
        + b"|"
        + nonce.encode()
    )


@dataclass(frozen=True)
class Commitment:
    """Phase 1: bind to an artifact without revealing it."""

    objective_id: str
    submitter: str
    hash: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "commitment",
            "objective_id": self.objective_id,
            "submitter": self.submitter,
            "hash": self.hash,
            "created_at": self.created_at,
        }

    @property
    def id(self) -> str:
        return digest(self.to_dict())


@dataclass(frozen=True)
class Claim:
    """Phase 2: reveal the artifact, with the citations it builds on."""

    objective_id: str
    submitter: str
    artifact: dict[str, Any]
    nonce: str
    created_at: str
    cites: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.artifact, dict):
            raise RecordError("artifact must be an object")
        if len(set(self.cites)) != len(self.cites):
            raise RecordError("duplicate citation")

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "claim",
            "objective_id": self.objective_id,
            "submitter": self.submitter,
            "artifact": self.artifact,
            "nonce": self.nonce,
            "created_at": self.created_at,
            "cites": list(self.cites),
        }

    @property
    def id(self) -> str:
        return digest(self.to_dict())

    @property
    def artifact_id(self) -> str:
        """Identity of the artifact alone -- used to detect duplicate submissions."""
        return digest({"objective_id": self.objective_id, "artifact": self.artifact})

    def commitment_hash(self) -> str:
        return commitment_hash(self.objective_id, self.submitter, self.artifact, self.nonce)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Claim":
        return cls(
            objective_id=data["objective_id"],
            submitter=data["submitter"],
            artifact=data["artifact"],
            nonce=data["nonce"],
            created_at=data["created_at"],
            cites=tuple(data.get("cites", ())),
        )
