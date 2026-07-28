"""The ratchet: progressive bounties that make publishing the profitable move.

The coordination problem in a research network is mostly self-inflicted. A
winner-take-all bounty gives every participant a reason to hoard: if I publish an
improvement so you can build on it, you can extend it by epsilon and take the
whole prize. So nobody shares, everybody duplicates each other's work, and the
network's throughput collapses to that of its best solo participant. People then
try to fix this with elaborate coordination machinery -- work-unit dispatchers,
locks, reservation protocols -- when the actual bug is the payment structure.

Change the structure and most of the problem dissolves:

    An objective carries a monotone best-known score. Whoever moves it from s0
    to s1 is paid in proportion to the distance moved. Publishing is how you get
    paid, so publishing immediately is optimal, and the ledger records who moved
    the frontier as a side effect of paying them.

Three consequences worth stating:

- **Copying is worthless.** Resubmitting a known artifact scores no improvement
  and pays zero. The thing that made hoarding rational is gone.
- **Duplicated work becomes visible.** The frontier is public, so nobody wastes
  compute rediscovering a solution that is already beaten.
- **Attribution is mechanical.** An improvement must cite the frontier entry it
  improved on -- checkable, not a judgement call -- so citation flow pays the
  previous holder automatically. Standing on shoulders is enforced by the
  submission rule rather than by etiquette.

Payouts use a cumulative formula so they telescope exactly:

    cumulative(s) = reward * (clamp(s) - baseline) // (target - baseline)
    payout(s0 -> s1) = cumulative(s1) - cumulative(s0)

Total paid over any sequence of improvements equals cumulative(final_score) --
never more than `reward`, and exactly `reward` if the target is reached. Integer
arithmetic throughout: rounding cannot leak or invent a unit no matter how the
improvements are chopped up.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MAXIMIZE = "maximize"
MINIMIZE = "minimize"


class RatchetError(ValueError):
    pass


@dataclass(frozen=True)
class Ratchet:
    """Progressive-bounty parameters attached to an objective."""

    baseline: int
    target: int
    reward: int
    direction: str = MAXIMIZE
    #: Smallest score movement that counts. Raising this blocks epsilon-farming
    #: at the cost of also blocking genuine small gains -- a real tradeoff, not
    #: a free win.
    min_improvement: int = 1

    def __post_init__(self) -> None:
        if self.direction not in (MAXIMIZE, MINIMIZE):
            raise RatchetError(f"direction must be {MAXIMIZE} or {MINIMIZE}")
        for name in ("baseline", "target", "reward", "min_improvement"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise RatchetError(f"{name} must be an integer")
        if self.reward < 0:
            raise RatchetError("reward must be non-negative")
        if self.min_improvement < 1:
            raise RatchetError("min_improvement must be at least 1")
        if self.direction == MAXIMIZE and self.target <= self.baseline:
            raise RatchetError("target must exceed baseline when maximizing")
        if self.direction == MINIMIZE and self.target >= self.baseline:
            raise RatchetError("target must be below baseline when minimizing")

    # -- geometry ---------------------------------------------------------
    @property
    def span(self) -> int:
        return abs(self.target - self.baseline)

    def progress(self, score: int) -> int:
        """Distance from baseline toward target, clamped to [0, span]."""
        raw = score - self.baseline if self.direction == MAXIMIZE else self.baseline - score
        return max(0, min(raw, self.span))

    def improves(self, old: int | None, new: int) -> bool:
        if old is None:
            return self.progress(new) >= self.min_improvement
        gain = self.progress(new) - self.progress(old)
        return gain >= self.min_improvement

    # -- money ------------------------------------------------------------
    def cumulative(self, score: int) -> int:
        """Total the objective has paid out once the frontier reaches ``score``."""
        return self.reward * self.progress(score) // self.span

    def payout(self, old: int | None, new: int) -> int:
        """What an improvement from ``old`` to ``new`` earns. Never negative."""
        before = 0 if old is None else self.cumulative(old)
        return max(0, self.cumulative(new) - before)

    def exhausted(self, score: int) -> bool:
        return self.progress(score) >= self.span

    # -- serialization ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline,
            "target": self.target,
            "reward": self.reward,
            "direction": self.direction,
            "min_improvement": self.min_improvement,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Ratchet":
        return cls(
            baseline=data["baseline"],
            target=data["target"],
            reward=data["reward"],
            direction=data.get("direction", MAXIMIZE),
            min_improvement=data.get("min_improvement", 1),
        )


@dataclass(frozen=True)
class FrontierEntry:
    """Who currently holds an objective's best-known score."""

    objective_id: str
    claim_id: str
    holder: str
    score: int
    paid_cumulative: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "claim_id": self.claim_id,
            "holder": self.holder,
            "score": self.score,
            "paid_cumulative": self.paid_cumulative,
        }
