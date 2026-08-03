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

from .canonical import MAX_UNITS, digest, digest_bytes


class RecordError(ValueError):
    """A record is structurally invalid."""


#: When an objective's settled artifacts become public -- never *whether*.
#:
#: The guarantee this system makes is that anyone can re-derive every settled
#: result, and that requires settled artifacts to be readable. A class moves the
#: moment of disclosure; it cannot remove it.
#:
#: - ``public``    revealed at epoch end. The default.
#: - ``embargoed`` revealed later, with priority timestamped immediately by the
#:                 commitment. This is what coordinated disclosure needs, and it
#:                 breaks the implication "settled result => published result".
#: - ``sealed``    never revealed. Requires zero-knowledge verification and is
#:                 **refused** below; it exists here so the limitation is
#:                 explicit rather than discovered after an objective is funded.
CONFIDENTIALITY_CLASSES = ("public", "embargoed", "sealed")

#: Omitted from the canonical form, so adding this field reissued no ids.
DEFAULT_CONFIDENTIALITY = "public"


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
    #: When settled artifacts become public. See CONFIDENTIALITY_CLASSES.
    #: Omitted from the canonical form when "public", exactly like ``deadline``
    #: and ``ratchet`` when unset, so adding this field did not change the id of
    #: a single existing objective.
    confidentiality: str = DEFAULT_CONFIDENTIALITY
    #: What shape of artifact the verifier expects, for a submitter who has
    #: only the record.
    #:
    #: Documentation, **not** a rule. Nothing validates an artifact against it
    #: and nothing may start: the pinned verifier is the only thing that
    #: decides what passes, and a second gate here would be a second answer to
    #: that question -- one the two implementations could disagree about, on a
    #: field the funder writes. It exists because otherwise an agent's only
    #: source for the artifact's shape is the attacker-authored statement.
    #: Omitted when absent, so adding it moved no ids.
    artifact_schema: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.statement.strip():
            raise RecordError("objective needs a statement")
        if not isinstance(self.verifier, dict) or "kind" not in self.verifier:
            raise RecordError("objective needs a verifier with a 'kind'")
        if isinstance(self.reward, bool) or not isinstance(self.reward, int):
            raise RecordError("reward must be an integer unit count")
        if self.reward < 0:
            raise RecordError("reward must be non-negative")
        if self.reward > MAX_UNITS:
            raise RecordError(
                f"reward {self.reward} exceeds the format maximum {MAX_UNITS}; "
                "a record above it cannot be read by a 64-bit implementation"
            )
        # Unknown classes are refused, never defaulted: guessing here decides
        # disclosure on the funder's behalf.
        if self.confidentiality not in CONFIDENTIALITY_CLASSES:
            raise RecordError(
                f"unknown confidentiality class {self.confidentiality!r} "
                f"(expected one of {', '.join(map(repr, CONFIDENTIALITY_CLASSES))})"
            )
        # Refused, not downgraded. Paying for an artifact nobody may read needs
        # a zero-knowledge proof that the pinned verifier accepts it. Quietly
        # treating the request as "embargoed" would tell a funder their result
        # stays secret when it does not.
        if self.confidentiality == "sealed":
            raise RecordError(
                'confidentiality "sealed" requires zero-knowledge verification, '
                'which is not implemented; use "embargoed" for delayed disclosure'
            )
        # Shape only. What the hint *says* is never checked -- see the field.
        if self.artifact_schema is not None and not isinstance(self.artifact_schema, dict):
            raise RecordError("artifact_schema must be an object")

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
        # Omitted when "public" for the same reason the optional fields above
        # are omitted when unset: emitting the default would change the digest
        # of every objective ever written, break the conformance vectors, and
        # orphan every claim already posted against a live bounty.
        if self.confidentiality != DEFAULT_CONFIDENTIALITY:
            body["confidentiality"] = self.confidentiality
        # Omitted when absent, for the reason every optional field here is.
        if self.artifact_schema is not None:
            body["artifact_schema"] = self.artifact_schema
        return body

    @property
    def id(self) -> str:
        return digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Objective":
        # An absent key and an explicit null both mean "unset". Everything
        # else must be a string: the previous `or DEFAULT` treated every falsy
        # value -- `""`, `0`, `False` -- as unset, so a record the Rust
        # implementation refuses decoded here as a public objective. Same
        # bytes, two verdicts on validity, is a consensus split.
        confidentiality = data.get("confidentiality")
        if confidentiality is None:
            confidentiality = DEFAULT_CONFIDENTIALITY
        elif not isinstance(confidentiality, str):
            raise RecordError("confidentiality must be a string naming a confidentiality class")
        return cls(
            goal=data["goal"],
            statement=data["statement"],
            verifier=data["verifier"],
            reward=data["reward"],
            funder=data["funder"],
            created_at=data["created_at"],
            deadline=data.get("deadline"),
            ratchet=data.get("ratchet"),
            confidentiality=confidentiality,
            # Absent and null both mean "no hint", exactly as for ``ratchet``.
            artifact_schema=data.get("artifact_schema"),
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
        # Missing `cites` reads as empty; anything present must be an array of
        # strings, matching the Rust decoder. `tuple(...)` alone iterated
        # whatever it was handed, so `"cites": "abc"` decoded as three
        # one-letter citations here while the Rust side refused the record --
        # and those phantom edges would have carried citation flow.
        cites = data.get("cites", ())
        if isinstance(cites, str) or not isinstance(cites, (list, tuple)):
            raise RecordError("cites must be an array of claim ids")
        if any(not isinstance(cited, str) for cited in cites):
            raise RecordError("cites must be an array of claim ids")
        return cls(
            objective_id=data["objective_id"],
            submitter=data["submitter"],
            artifact=data["artifact"],
            nonce=data["nonce"],
            created_at=data["created_at"],
            cites=tuple(cites),
        )
