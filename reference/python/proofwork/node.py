"""The rules: what may be posted, what settles, and what mints nothing.

Everything here is a policy decision that the design notes argue for. The code
is the enforceable version of those arguments.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import verifiers
from .frontier import FrontierEntry, Ratchet
from .ledger import Ledger
from .records import Claim, Commitment, Objective
from .verifiers import Status, Verdict


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RuleViolation(Exception):
    """A submission the network refuses to record."""


@dataclass
class Outcome:
    claim_id: str
    verdict: Verdict
    settled: bool
    reward: int = 0
    note: str = ""


class Node:
    def __init__(self, ledger: Ledger, root: str = "."):
        self.ledger = ledger
        self.root = root
        verifiers.set_root(root)

    # -- objectives ------------------------------------------------------
    def post_objective(self, objective: Objective, ts: str | None = None) -> str:
        """Fund a checkable question.

        Refused if no verifier is registered for its kind. An objective whose
        verifier cannot run is an objective whose payout is somebody's opinion,
        and admitting it is how a results market turns into a popularity
        contest.
        """
        kind = objective.verifier.get("kind")
        if verifiers.get(kind) is None:
            raise RuleViolation(
                f"no verifier registered for kind {kind!r}; known: {verifiers.kinds()}"
            )
        if objective.id in self.objectives():
            raise RuleViolation("objective already posted")
        if objective.ratchet is not None:
            ratchet = Ratchet.from_dict(objective.ratchet)
            if kind != "evaluator":
                raise RuleViolation(
                    "a ratchet objective needs a score-producing verifier "
                    f"(evaluator), not {kind!r}"
                )
            if ratchet.reward != objective.reward:
                raise RuleViolation(
                    "ratchet.reward and objective.reward must agree; there is "
                    "one pool, not two"
                )
        self.ledger.append("objective", objective.to_dict(), ts or now())
        return objective.id

    def objectives(self) -> dict[str, Objective]:
        return {
            Objective.from_dict(e.payload).id: Objective.from_dict(e.payload)
            for e in self.ledger.entries("objective")
        }

    def settlement_of(self, objective_id: str) -> dict[str, Any] | None:
        for entry in self.ledger.entries("settlement"):
            if entry.payload["objective_id"] == objective_id:
                return entry.payload
        return None

    def frontier_of(self, objective_id: str) -> FrontierEntry | None:
        """The current best-known score for a progressive objective."""
        latest = None
        for entry in self.ledger.entries("frontier"):
            if entry.payload["objective_id"] == objective_id:
                latest = entry.payload
        if latest is None:
            return None
        return FrontierEntry(**latest)

    # -- commit / reveal --------------------------------------------------
    def commit(self, commitment: Commitment, ts: str | None = None) -> str:
        if commitment.objective_id not in self.objectives():
            raise RuleViolation("commitment references an unknown objective")
        objective = self.objectives()[commitment.objective_id]
        # A progressive objective stays open until its pool is exhausted: the
        # whole point is that improvements keep arriving.
        if objective.ratchet is None and self.settlement_of(commitment.objective_id):
            raise RuleViolation("objective is already settled")
        self.ledger.append("commitment", commitment.to_dict(), ts or now())
        return commitment.id

    def _matching_commitment(self, claim: Claim) -> dict[str, Any] | None:
        target = claim.commitment_hash()
        for entry in self.ledger.entries("commitment"):
            payload = entry.payload
            if (
                payload["objective_id"] == claim.objective_id
                and payload["submitter"] == claim.submitter
                and payload["hash"] == target
            ):
                return payload
        return None

    def accepted_claims(self) -> dict[str, Claim]:
        """Claims whose verdict was ACCEPT, keyed by claim id."""
        accepted = {
            e.payload["claim_id"]
            for e in self.ledger.entries("verdict")
            if e.payload["verdict"]["status"] == Status.ACCEPT.value
        }
        return {
            Claim.from_dict(e.payload).id: Claim.from_dict(e.payload)
            for e in self.ledger.entries("claim")
            if Claim.from_dict(e.payload).id in accepted
        }

    def _known_artifact_ids(self, objective_id: str) -> set[str]:
        out = set()
        for entry in self.ledger.entries("claim"):
            claim = Claim.from_dict(entry.payload)
            if claim.objective_id == objective_id:
                out.add(claim.artifact_id)
        return out

    def reveal(self, claim: Claim, ts: str | None = None) -> Outcome:
        """Reveal a committed artifact, verify it, and settle if it is accepted."""
        objectives = self.objectives()
        objective = objectives.get(claim.objective_id)
        if objective is None:
            raise RuleViolation("claim references an unknown objective")

        if self._matching_commitment(claim) is None:
            # Without a prior commitment, an observer could copy a revealed
            # artifact out of the mempool and submit it as their own.
            raise RuleViolation(
                "no matching prior commitment: commit H(artifact‖submitter‖nonce) first"
            )

        known = self._known_artifact_ids(claim.objective_id)
        duplicate = claim.artifact_id in known

        for cited in claim.cites:
            if cited not in self.accepted_claims():
                raise RuleViolation(
                    f"citation {cited} is not an accepted claim in this log; "
                    "citations point backwards only"
                )

        ratchet = Ratchet.from_dict(objective.ratchet) if objective.ratchet else None
        held = self.frontier_of(claim.objective_id) if ratchet else None
        if held is not None and held.claim_id not in claim.cites:
            # Mechanical, not a judgement call: you improved on the public
            # frontier, so you cite it, and citation flow pays its holder. This
            # is what makes "standing on shoulders" a submission rule instead of
            # an etiquette anyone can ignore.
            raise RuleViolation(
                f"an improvement must cite the frontier it improves on ({held.claim_id})"
            )

        already_settled = self.settlement_of(claim.objective_id)

        self.ledger.append("claim", claim.to_dict(), ts or now())

        verdict = verifiers.run(objective.verifier, claim.artifact)
        self.ledger.append(
            "verdict",
            {
                "claim_id": claim.id,
                "objective_id": claim.objective_id,
                "verdict": verdict.to_dict(),
            },
            ts or now(),
        )

        # A non-settling verdict records what happened and moves nothing. An
        # unavailable toolchain is an infrastructure fact, not a refutation, and
        # the objective stays open for a node that can actually run the check.
        if not verdict.status.settles:
            return Outcome(claim.id, verdict, False, 0, "verdict does not settle")
        if not verdict.accepted:
            return Outcome(claim.id, verdict, False, 0, "rejected")

        if ratchet is not None:
            return self._settle_improvement(claim, verdict, ratchet, held, ts or now())

        if duplicate:
            # Novelty is necessary but never sufficient. Resubmitting an
            # artifact that is already in the log verifies fine and mints zero.
            # Checked before settlement status so the note names the real reason.
            return Outcome(claim.id, verdict, False, 0, "duplicate artifact mints nothing")
        if already_settled:
            return Outcome(claim.id, verdict, False, 0, "objective already settled")

        self.ledger.append(
            "settlement",
            {
                "objective_id": claim.objective_id,
                "claim_id": claim.id,
                "submitter": claim.submitter,
                "reward": objective.reward,
            },
            ts or now(),
        )
        return Outcome(claim.id, verdict, True, objective.reward, "settled")

    def _settle_improvement(
        self,
        claim: Claim,
        verdict: Verdict,
        ratchet: Ratchet,
        held: FrontierEntry | None,
        ts: str,
    ) -> Outcome:
        """Pay for distance moved along a progressive objective's curve."""
        score = verdict.evidence.get("score")
        if isinstance(score, bool) or not isinstance(score, int):
            return Outcome(claim.id, verdict, False, 0, "verifier produced no integer score")

        previous = held.score if held else None
        if not ratchet.improves(previous, score):
            # Not a rejection of the artifact -- it verified. It just does not
            # move the frontier, so it earns nothing. Copying is worthless here
            # by construction, which is precisely why publishing is safe.
            return Outcome(
                claim.id, verdict, False, 0,
                f"score {score} does not improve on {previous} by at least "
                f"{ratchet.min_improvement}",
            )

        reward = ratchet.payout(previous, score)
        paid_cumulative = (held.paid_cumulative if held else 0) + reward
        self.ledger.append(
            "frontier",
            FrontierEntry(
                objective_id=claim.objective_id,
                claim_id=claim.id,
                holder=claim.submitter,
                score=score,
                paid_cumulative=paid_cumulative,
            ).to_dict(),
            ts,
        )
        if reward:
            self.ledger.append(
                "settlement",
                {
                    "objective_id": claim.objective_id,
                    "claim_id": claim.id,
                    "submitter": claim.submitter,
                    "reward": reward,
                },
                ts,
            )
        note = "frontier advanced"
        if ratchet.exhausted(score):
            note += "; target reached, pool exhausted"
        return Outcome(claim.id, verdict, True, reward, note)

    # -- independent verification ----------------------------------------
    def audit(self, rerun: bool = True) -> list[str]:
        """Re-derive the whole log from scratch. Empty result means it checks out.

        This is the function that makes a single-sequencer network honest: any
        reader with a copy of the log runs it and confirms every settled claim,
        without trusting the operator at all.
        """
        problems = list(self.ledger.verify_chain())
        objectives = self.objectives()

        recorded: dict[str, dict[str, Any]] = {}
        for entry in self.ledger.entries("verdict"):
            recorded[entry.payload["claim_id"]] = entry.payload["verdict"]

        claims = {Claim.from_dict(e.payload).id: Claim.from_dict(e.payload)
                  for e in self.ledger.entries("claim")}
        paid = {e.payload["claim_id"] for e in self.ledger.entries("settlement")}

        for claim_id, claim in claims.items():
            if self._matching_commitment(claim) is None:
                problems.append(f"claim {claim_id}: no matching commitment")
            if claim_id not in recorded:
                problems.append(f"claim {claim_id}: no verdict recorded")
                continue
            if rerun:
                objective = objectives.get(claim.objective_id)
                if objective is None:
                    problems.append(f"claim {claim_id}: unknown objective")
                    continue
                fresh = verifiers.run(objective.verifier, claim.artifact)
                if not fresh.status.settles:
                    # For an unsettled claim this is only an infrastructure fact
                    # and says nothing. For a claim that was *paid*, it means the
                    # payment can no longer be independently re-derived -- which
                    # is exactly what an auditor needs told. Reporting "log
                    # verified" here would be a lie of omission: nothing was
                    # actually checked.
                    if claim_id in paid:
                        problems.append(
                            f"claim {claim_id}: was settled but can no longer be "
                            f"re-verified ({fresh.status.value}: {fresh.detail})"
                        )
                    continue
                if fresh.status.value != recorded[claim_id]["status"]:
                    problems.append(
                        f"claim {claim_id}: recorded {recorded[claim_id]['status']}, "
                        f"re-verification says {fresh.status.value}"
                    )

        for entry in self.ledger.entries("settlement"):
            payload = entry.payload
            verdict = recorded.get(payload["claim_id"])
            if verdict is None or verdict["status"] != Status.ACCEPT.value:
                problems.append(
                    f"settlement of {payload['objective_id']}: paid a claim that was not accepted"
                )

        seen: set[str] = set()
        paid_total: dict[str, int] = {}
        for entry in self.ledger.entries("settlement"):
            oid = entry.payload["objective_id"]
            objective = objectives.get(oid)
            progressive = objective is not None and objective.ratchet is not None
            if oid in seen and not progressive:
                problems.append(f"objective {oid}: settled more than once")
            seen.add(oid)
            paid_total[oid] = paid_total.get(oid, 0) + entry.payload["reward"]

        # A progressive objective pays along a curve, so "settled once" is the
        # wrong invariant. The one that must hold is that the pool is never
        # overspent and the frontier never moves backwards.
        for oid, total in paid_total.items():
            objective = objectives.get(oid)
            if objective is None:
                problems.append(f"settlement references unknown objective {oid}")
                continue
            if total > objective.reward:
                problems.append(
                    f"objective {oid}: paid {total} against a pool of {objective.reward}"
                )

        for oid, objective in objectives.items():
            if objective.ratchet is None:
                continue
            ratchet = Ratchet.from_dict(objective.ratchet)
            best: int | None = None
            for entry in self.ledger.entries("frontier"):
                if entry.payload["objective_id"] != oid:
                    continue
                score = entry.payload["score"]
                if best is not None and not ratchet.improves(best, score):
                    problems.append(
                        f"objective {oid}: frontier moved to {score} without improving on {best}"
                    )
                best = score

        return problems
