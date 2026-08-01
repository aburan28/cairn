"""The rules: what may be posted, what settles, and what mints nothing.

Everything here is a policy decision that the design notes argue for. The code
is the enforceable version of those arguments.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import blobs, verifiers
from .frontier import FrontierEntry, Ratchet
from .ledger import Ledger
from .partition import epoch_of, epoch_seconds, settlement_rank
from .records import Claim, Commitment, Objective
from .verifiers import Status, Verdict

#: Ledger entry kind marking one reveal epoch as settled. See ``Node.settle_due``.
BATCH = "batch"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def unix_seconds(ts: str) -> int | None:
    """An RFC-3339 instant as seconds since the Unix epoch, or ``None``.

    ``datetime.fromisoformat`` accepts a naive timestamp, which names no
    instant, and before 3.11 it rejects a trailing ``Z``. Both are handled here
    rather than at four call sites, and a naive value is refused rather than
    assumed to be UTC: guessing a timezone means guessing an epoch, and the
    epoch decides which reveals were legal.
    """
    text = ts.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        return None
    return int(moment.timestamp())


def epoch_of_timestamp(record: str, ts: str) -> int:
    """Which epoch an instant falls in, or a refusal.

    Pre-1970 instants are refused with the unparsable ones: they key a beacon,
    and there is no sensible epoch number for a record this network could not
    have produced.
    """
    seconds = unix_seconds(ts)
    if seconds is None or seconds < 0:
        raise RuleViolation(
            f"{record} timestamp {ts!r} is not an RFC-3339 instant, so the epoch "
            "it settles in cannot be derived"
        )
    return epoch_of(seconds, epoch_seconds())


class RuleViolation(Exception):
    """A submission the network refuses to record."""


@dataclass
class Outcome:
    claim_id: str
    verdict: Verdict
    settled: bool
    reward: int = 0
    note: str = ""
    #: The reveal epoch this claim will settle in, when it has been accepted but
    #: its epoch has not closed. ``settled is False`` does not mean "earned
    #: nothing" while this is set.
    pending_epoch: int | None = None

    @property
    def is_pending(self) -> bool:
        return self.pending_epoch is not None


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
        # How pinned code becomes available to anyone who does not share this
        # filesystem: the funder has the checker on disk, and this copies it into
        # the content-addressed store under the same root, where its name is the
        # pin the objective already declares.
        #
        # After the append and deliberately without raising. This same method
        # admits objectives replayed from another node's log, where there is no
        # bundle to publish from; a failure to cache code that was never provided
        # is not a reason to refuse the record.
        verifiers.publish_code(self.root, objective.verifier)
        return objective.id

    # -- pinned verifier code ---------------------------------------------
    def pinned_code(self) -> set[str]:
        """Every content address the log's objectives pin.

        The reachable set: a blob outside it is pinned by no objective this node
        knows of. Computed from the log rather than remembered, so it cannot
        drift and an objective learned a moment ago is protected with no
        bookkeeping step.
        """
        return {
            sha
            for objective in self.objectives().values()
            for _role, _path, sha in verifiers.pinned_code(objective.verifier)
            if blobs.is_address(sha)
        }

    def missing_code(self) -> set[str]:
        """Content addresses this node needs and does not have.

        Why a verdict came back UNAVAILABLE, and what a peer would have to serve
        to make the log re-derivable here.
        """
        out: set[str] = set()
        for objective in self.objectives().values():
            out.update(verifiers.missing_code(self.root, objective.verifier))
        return out

    def publish_local_code(self) -> int:
        """Copy every pinned file the bundle has into the store, for every
        objective in the log. Returns how many addresses are now servable.

        Idempotent. A log written before verifier code was content-addressed has
        objectives whose checkers were never published, and this is what fixes
        that without reposting anything.
        """
        published: set[str] = set()
        for objective in self.objectives().values():
            published.update(verifiers.publish_code(self.root, objective.verifier))
        return len(published)

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
        ts = ts or now()
        # Refused here rather than at reveal. The commitment's ``created_at`` is
        # what fixes the epoch a reveal must beat, so a commitment whose
        # timestamp cannot be read can never be opened.
        epoch_of_timestamp("commitment", commitment.created_at)
        # Draining on the way in keeps "already settled" honest: a commitment
        # against an objective whose winner is sitting in an unsettled batch
        # would otherwise be admitted as though the objective were still open.
        self.settle_due(epoch_of_timestamp("commit", ts), ts)
        if commitment.objective_id not in self.objectives():
            raise RuleViolation("commitment references an unknown objective")
        objective = self.objectives()[commitment.objective_id]
        # A progressive objective stays open until its pool is exhausted: the
        # whole point is that improvements keep arriving.
        if objective.ratchet is None and self.settlement_of(commitment.objective_id):
            raise RuleViolation("objective is already settled")
        self.ledger.append("commitment", commitment.to_dict(), ts)
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

    def _artifact_ids_before(self, objective_id: str, epoch: int) -> set[str]:
        """Artifact identities revealed against an objective before ``epoch``.

        Deliberately not filtered by verdict: an artifact that was *rejected* is
        still not novel, and re-revealing it must not become a way to mint on
        the second try if the verifier later starts accepting it.

        Cut at the epoch boundary rather than at "everything in the log", so a
        claim is never made a duplicate of one revealed in its own batch by
        arrival order; that comparison belongs to the beacon ordering.
        """
        out = set()
        for entry in self.ledger.entries("claim"):
            seconds = unix_seconds(entry.ts)
            if seconds is None or seconds < 0:
                continue
            if epoch_of(seconds, epoch_seconds()) >= epoch:
                continue
            claim = Claim.from_dict(entry.payload)
            if claim.objective_id == objective_id:
                out.add(claim.artifact_id)
        return out

    def reveal(self, claim: Claim, ts: str | None = None) -> Outcome:
        """Reveal a committed artifact and verify it.

        Settlement is deferred to the close of the reveal epoch, and that is not
        a caching decision -- it falls out of the ordering rule. Settlement
        order inside an epoch is ``H(beacon(epoch, anchor) ‖ claim_id)``, a
        function of the *set* of claims in the epoch, and that set is not known
        until the epoch is over. Paying the first arrival and re-ordering
        afterwards is impossible in an append-only log, so the payment waits.
        """
        ts = ts or now()
        reveal_epoch = epoch_of_timestamp("reveal", ts)
        # Drain first. An epoch that closed while this node was idle must settle
        # before this claim's admission checks read the frontier, or an
        # improvement would be measured against a stale one.
        self.settle_due(reveal_epoch, ts)

        objectives = self.objectives()
        objective = objectives.get(claim.objective_id)
        if objective is None:
            raise RuleViolation("claim references an unknown objective")

        commitment = self._matching_commitment(claim)
        if commitment is None:
            # Without a prior commitment, an observer could copy a revealed
            # artifact out of the mempool and submit it as their own.
            raise RuleViolation(
                "no matching prior commitment: commit H(artifact‖submitter‖nonce) first"
            )
        commit_epoch = epoch_of_timestamp("commitment", commitment["created_at"])
        if reveal_epoch <= commit_epoch:
            # The commitment hides the artifact, but it does not stop the
            # sequencer -- who sees reveals first -- from opening a commitment
            # of its own in the same breath. A strictly later epoch means the
            # reveal is public before a competitor's commitment can be written.
            raise RuleViolation(
                f"reveal is in epoch {reveal_epoch} but its commitment is in epoch "
                f"{commit_epoch}; a reveal must wait for a strictly later epoch"
            )
        if reveal_epoch in self._drained_epochs():
            raise RuleViolation(
                f"epoch {reveal_epoch} has already settled; a reveal cannot join "
                "a batch that has been paid"
            )

        for cited in claim.cites:
            if cited not in self.accepted_claims():
                raise RuleViolation(
                    f"citation {cited} is not an accepted claim in this log; "
                    "citations point backwards only"
                )

        # The frontier citation is an *admission* rule and stays here, at reveal
        # time, rather than moving into the batch: a submitter can only cite
        # what was public when they built. Whether the claim actually improves
        # on the frontier is a settlement question, asked later.
        if objective.ratchet:
            held = self.frontier_of(claim.objective_id)
            if held is not None and held.claim_id not in claim.cites:
                raise RuleViolation(
                    f"an improvement must cite the frontier it improves on ({held.claim_id})"
                )

        self.ledger.append("claim", claim.to_dict(), ts)

        verdict = verifiers.run(objective.verifier, claim.artifact)
        self.ledger.append(
            "verdict",
            {
                "claim_id": claim.id,
                "objective_id": claim.objective_id,
                "verdict": verdict.to_dict(),
            },
            ts,
        )

        # A non-settling verdict records what happened and moves nothing. An
        # unavailable toolchain is an infrastructure fact, not a refutation, and
        # the objective stays open for a node that can actually run the check.
        if not verdict.status.settles:
            return Outcome(claim.id, verdict, False, 0, "verdict does not settle")
        if not verdict.accepted:
            return Outcome(claim.id, verdict, False, 0, "rejected")
        return Outcome(
            claim.id,
            verdict,
            False,
            0,
            f"accepted; settles when epoch {reveal_epoch} closes",
            pending_epoch=reveal_epoch,
        )

    # -- epoch-batched settlement ------------------------------------------
    def _drained_epochs(self) -> set[int]:
        return {e.payload["epoch"] for e in self.ledger.entries(BATCH)}

    def epoch_is_drained(self, epoch: int) -> bool:
        return epoch in self._drained_epochs()

    def _accepted_claims_by_epoch(self) -> list[tuple[int, Claim]]:
        accepted = self.accepted_claims()
        out: list[tuple[int, Claim]] = []
        seen: set[str] = set()
        for entry in self.ledger.entries("claim"):
            claim = Claim.from_dict(entry.payload)
            if claim.id not in accepted or claim.id in seen:
                continue
            seconds = unix_seconds(entry.ts)
            if seconds is None or seconds < 0:
                # Skipped rather than settled into some default epoch: a claim
                # whose epoch cannot be derived cannot be ordered against its
                # peers, and paying it out of order is worse than not paying it.
                continue
            seen.add(claim.id)
            out.append((epoch_of(seconds, epoch_seconds()), claim))
        return out

    def _anchor_of_epoch(self, epoch: int) -> str:
        """The log head as of the start of ``epoch``.

        Derived from the log rather than from a clock, so an auditor reaches the
        same value. It is also recorded in the batch entry, because a back-dated
        append could otherwise change what this returns for an epoch that has
        already settled -- ``audit`` compares the two.
        """
        anchor = ""
        for entry in self.ledger:
            seconds = unix_seconds(entry.ts)
            if seconds is None or seconds < 0:
                continue
            if epoch_of(seconds, epoch_seconds()) < epoch:
                anchor = entry.hash
        return anchor

    def settle_due(self, now_epoch: int, ts: str | None = None) -> list[Outcome]:
        """Settle every reveal epoch that has closed, in beacon order.

        Inside one epoch the order is ``H(beacon(epoch, anchor) ‖ commitment)``
        ascending, where ``anchor`` is the log head as of the epoch's start.

        The key is the commitment hash and not the claim id, and the difference
        matters. By reveal time the anchor is public, and a claim id covers
        ``created_at`` and ``cites`` -- fields the commitment does not bind and
        nothing checks against the reveal, so a submitter could try timestamps
        until one sorted first and the rule would bind nobody. The commitment
        hash covers only what was frozen an epoch earlier.

        The residual gap is real: a submitter who lands the final append of
        their commit epoch influences both their own key and the anchor, and can
        grind the pair. Closing it needs an unpredictable beacon rather than the
        log head. ``docs/threat-model.md`` carries the row.

        A ``batch`` record is appended per drained epoch, holding the anchor
        used and the resulting order. That record makes the drain idempotent and
        lets an auditor recompute the ordering without guessing which anchor was
        in force.

        Rule failures inside a batch become unsettled outcomes rather than
        aborting the drain: one bad objective must not be able to wedge
        settlement for every other objective in the same epoch.
        """
        ts = ts or now()
        drained = self._drained_epochs()
        pending = self._accepted_claims_by_epoch()
        due = sorted({epoch for epoch, _ in pending if epoch < now_epoch} - drained)

        outcomes: list[Outcome] = []
        for epoch in due:
            anchor = self._anchor_of_epoch(epoch)
            batch = [claim for candidate, claim in pending if candidate == epoch]
            # Sorted by (rank, id): two claims with the same rank would
            # otherwise keep append order, quietly restoring the lever this
            # exists to remove. A collision needs a SHA-256 preimage, but
            # "unreachable" is not a tie-break rule.
            batch.sort(
                key=lambda c: (settlement_rank(epoch, anchor, c.commitment_hash()), c.id)
            )
            consumed: set[str] = set()
            for claim in batch:
                outcomes.append(self._settle_one(claim, epoch, consumed, ts))
                consumed.add(claim.artifact_id)
            self.ledger.append(
                BATCH,
                {"epoch": epoch, "anchor": anchor, "claims": [c.id for c in batch]},
                ts,
            )
        return outcomes

    def settle_at(self, ts: str | None = None) -> list[Outcome]:
        """Settle the batch for the epoch containing ``ts``, and every earlier one."""
        ts = ts or now()
        return self.settle_due(epoch_of_timestamp("settle", ts), ts)

    def _settle_one(
        self, claim: Claim, epoch: int, consumed: set[str], ts: str
    ) -> Outcome:
        # The verdict is re-read from the log rather than re-run: this claim was
        # accepted when it was revealed, and re-running here would let a
        # verifier that has since gone unavailable retract a payment nobody
        # disputed. ``audit(rerun=True)`` is where re-verification belongs.
        verdict = self._recorded_verdict(claim.id)
        objective = self.objectives().get(claim.objective_id)
        if objective is None:
            return Outcome(claim.id, verdict, False, 0, "objective is no longer readable")

        if objective.ratchet:
            try:
                ratchet = Ratchet.from_dict(objective.ratchet)
            except (KeyError, TypeError, ValueError) as exc:
                return Outcome(
                    claim.id, verdict, False, 0,
                    f"objective carries an unusable ratchet: {exc}",
                )
            held = self.frontier_of(claim.objective_id)
            return self._settle_improvement(claim, verdict, ratchet, held, ts)

        # Novelty is necessary but never sufficient. "Already in the log" means
        # revealed strictly earlier, which inside a batch means earlier in
        # beacon order -- not earlier in append order.
        if claim.artifact_id in consumed or claim.artifact_id in self._artifact_ids_before(
            claim.objective_id, epoch
        ):
            return Outcome(claim.id, verdict, False, 0, "duplicate artifact mints nothing")
        if self.settlement_of(claim.objective_id):
            return Outcome(claim.id, verdict, False, 0, "objective already settled")

        self.ledger.append(
            "settlement",
            {
                "objective_id": claim.objective_id,
                "claim_id": claim.id,
                "submitter": claim.submitter,
                "reward": objective.reward,
            },
            ts,
        )
        return Outcome(claim.id, verdict, True, objective.reward, "settled")

    def _recorded_verdict(self, claim_id: str) -> Verdict:
        found = None
        for entry in self.ledger.entries("verdict"):
            if entry.payload["claim_id"] == claim_id:
                found = entry.payload["verdict"]
        if found is None:
            return Verdict(Status.ACCEPT, "recorded acceptance")
        return Verdict(
            Status(found["status"]), found.get("detail", ""), found.get("evidence", {})
        )

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

        problems.extend(self._audit_batches())
        return problems

    def _audit_batches(self) -> list[str]:
        """Re-derive every settlement batch's ordering from the log.

        This is the check that makes beacon ordering worth having: the rule
        constrains an honest node, and only an auditor recomputing
        ``H(beacon(epoch, anchor) ‖ claim_id)`` constrains a dishonest one.
        Three ways a batch can be wrong, all of them somebody paid out of turn:
        a recorded anchor that is not the head at the epoch's start (how a
        sequencer would grind an order after seeing the reveals), an order the
        beacon does not produce, or a missing claim -- censorship by omission,
        which pays whoever was behind it.
        """
        # ``H(beacon(epoch, anchor) ‖ commitment_hash)``, matching settle_due.
        problems: list[str] = []
        seen: set[int] = set()
        for entry in self.ledger.entries(BATCH):
            epoch = entry.payload.get("epoch")
            if not isinstance(epoch, int) or isinstance(epoch, bool):
                problems.append(f"batch at entry {entry.seq}: no epoch")
                continue
            if epoch in seen:
                problems.append(f"epoch {epoch}: settled in more than one batch")
            seen.add(epoch)

            recorded_anchor = entry.payload.get("anchor", "")
            derived_anchor = self._anchor_of_epoch(epoch)
            if recorded_anchor != derived_anchor:
                problems.append(
                    f"batch for epoch {epoch}: anchor {recorded_anchor[:12]} is not "
                    f"the log head at the epoch's start ({derived_anchor[:12]})"
                )

            recorded = entry.payload.get("claims")
            if not isinstance(recorded, list):
                problems.append(f"batch for epoch {epoch}: no claim list")
                continue

            # Recomputed against the *recorded* anchor: if that anchor is wrong
            # the line above already says so, and re-deriving from a different
            # one would report the same fault twice under two names.
            expected = [
                c.id
                for _, c in sorted(
                    (
                        (
                            settlement_rank(epoch, recorded_anchor, c.commitment_hash()),
                            c,
                        )
                        for e, c in self._accepted_claims_by_epoch()
                        if e == epoch
                    ),
                    key=lambda pair: (pair[0], pair[1].id),
                )
            ]
            if recorded != expected:
                problems.append(
                    f"batch for epoch {epoch}: settled {len(recorded)} claim(s) in "
                    "an order the beacon does not produce"
                )
        return problems
