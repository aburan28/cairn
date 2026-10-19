"""Exact, reproducible payoff experiments. Run with Python 3.10 or newer."""

import argparse
from fractions import Fraction
from hashlib import sha256
from itertools import product
import json
from math import comb
from pathlib import Path

from contract import Contract, integer, report_commitment, score_delta


def exact(value):
    value = Fraction(value)
    return {"numerator": value.numerator, "denominator": value.denominator}


def expected(previous, report, belief, scale=100, *, positive_only=False, loss_cap=None):
    if not isinstance(belief, Fraction) or not 0 <= belief <= 1:
        raise ValueError("belief must be an exact Fraction in [0, 1]")
    if loss_cap is not None:
        integer(loss_cap, "loss cap", 0, scale**2)
    values = [score_delta(previous, report, y, scale) for y in (0, 1)]
    if positive_only:
        values = [max(0, v) for v in values]
    if loss_cap is not None:
        values = [max(-loss_cap, v) for v in values]
    return (1 - belief) * values[0] + belief * values[1]


def properness_check(scale=100):
    checked = 0
    for previous in (0, scale // 2, scale):
        for truth, report in product(range(scale + 1), repeat=2):
            belief = Fraction(truth, scale)
            advantage = expected(previous, truth, belief, scale) - expected(previous, report, belief, scale)
            if advantage != (truth - report) ** 2:
                raise RuntimeError("signed score is no longer strictly proper on this grid")
            checked += 1
    return checked


def telescope_check(scale=10):
    checked = 0
    for path in product(range(scale + 1), repeat=4):
        for outcome in (0, 1):
            chain = sum(score_delta(a, b, outcome, scale) for a, b in zip(path, path[1:]))
            if chain != score_delta(path[0], path[-1], outcome, scale):
                raise RuntimeError("splitting a report changed the aggregate signed transfer")
            checked += 1
    return checked


def committee_bound_exceeded(population, corrupted, committee, tolerated):
    """Sampling math only: this does not implement a bandwidth proof."""
    for name, value in (("population", population), ("corrupted", corrupted),
                        ("committee", committee), ("tolerated", tolerated)):
        integer(value, name, 0, 10_000)
    if not 0 <= corrupted <= population or not 0 <= tolerated < committee <= population:
        raise ValueError("invalid committee parameters")
    count = sum(
        comb(corrupted, k) * comb(population - corrupted, committee - k)
        for k in range(tolerated + 1, min(corrupted, committee) + 1)
        if committee - k <= population - corrupted
    )
    return Fraction(count, comb(population, committee))


def chain_demo(split):
    owners = ["worker-a", "worker-b", "worker-c"] if split else ["worker"] * 3
    funds = {owner: 10_000 * owners.count(owner) for owner in set(owners)}
    contract = Contract("fixed-checker-task", 50, 10_000, funds)
    for slot, (owner, report) in enumerate(zip(owners, (100, 0, 100))):
        nonce = f"{slot + 1:064x}"
        sealed = report_commitment(contract.task, slot, contract.current, owner, report, nonce, 100)
        contract.commit(owner, sealed)
        contract.reveal(report, nonce)
    contract.close()
    result = contract.resolve(1)
    return {"deltas": list(result.deltas), "worker_total": sum(contract.available.values()),
            "sponsor": contract.sponsor, "total": contract.total()}


def report():
    truth = Fraction(3, 5)
    signed = [expected(50, p, truth) for p in range(101)]
    clipped = [expected(50, p, truth, positive_only=True) for p in range(101)]
    no_information = Fraction(1, 2)
    defaults = [expected(50, p, no_information, loss_cap=0) for p in range(101)]
    path = (50, 100, 0, 100)
    cycle = [score_delta(a, b, 1, 100) for a, b in zip(path, path[1:])]
    effort = []
    for name, posteriors, cost in (
        ("no_signal", (50, 50), 0),
        ("cheap_signal", (40, 60), 50),
        ("deeper_signal", (20, 80), 300),
        ("overpriced_deeper_signal", (20, 80), 1200),
    ):
        # The equally likely posteriors average to the prior: no information
        # is manufactured by changing the distribution of the outcome.
        gross = sum(expected(50, p, Fraction(p, 100)) for p in posteriors) / 2
        effort.append({"strategy": name, "posterior_units": list(posteriors),
                       "gross": exact(gross), "private_cost": cost, "net": exact(gross - cost)})
    root = Path(__file__).resolve().parent
    return {
        "kind": "cairn/research/information-contract-experiment/v1",
        "scope": "Local credits, exogenous binary outcome, risk-neutral players; no ledger or provider calls.",
        "source_sha256": {name: sha256((root / name).read_bytes()).hexdigest()
                          for name in ("contract.py", "experiment.py", "test_contract.py")},
        "exhaustive_checks": {"properness_scale": 100, "properness_cases": properness_check(),
                              "telescoping_scale": 10, "three_update_paths_and_outcomes": telescope_check()},
        "truthful_reporting": {
            "belief": exact(truth), "baseline_units": 50,
            "signed_best_reports": [p for p, score in enumerate(signed) if score == max(signed)],
            "positive_only_best_reports": [p for p, score in enumerate(clipped) if score == max(clipped)],
            "signed_truthful_expected": exact(signed[60]),
            "positive_only_truthful_expected": exact(clipped[60]),
            "positive_only_optimal_expected": exact(max(clipped)),
        },
        "attack_controls": {
            "positive_only_cycle": {"path": list(path), "outcome": 1, "signed_deltas": cycle,
                                    "signed_total": sum(cycle), "clipped_total": sum(max(0, d) for d in cycle)},
            "unfunded_default_option": {"belief": exact(no_information), "actual_bond": 0,
                                       "honest_signed_expected": exact(expected(50, 50, no_information)),
                                       "best_default_expected": exact(max(defaults))},
            "worker_chosen_baseline": {"outcome": 1, "final_report": 100,
                                       "fixed_baseline_50_gain": score_delta(50, 100, 1, 100),
                                       "sandbagged_baseline_0_gain": score_delta(0, 100, 1, 100)},
            "worker_controlled_outcome": {"belief_before_action": exact(no_information),
                                          "report": 100, "chosen_outcome": 1,
                                          "gain_after_selecting_outcome": score_delta(50, 100, 1, 100)},
        },
        "effort_choice": effort,
        "funded_state_machine": {"one_owner": chain_demo(False), "three_owners": chain_demo(True)},
        "bandwidth_committee_sensitivity": {
            "scope": "Probability that a stated corruption bound fails; not probability of a successful attack.",
            "population": 1000,
            "ten_percent_corrupt_n10_f2": exact(committee_bound_exceeded(1000, 100, 10, 2)),
            "ten_percent_corrupt_n31_f10": exact(committee_bound_exceeded(1000, 100, 31, 10)),
            "sybil_admitted_sixty_percent_n10_f2": exact(committee_bound_exceeded(1000, 600, 10, 2)),
        },
        "unresolved_assumptions": [
            "A publicly verifiable outcome is independent of the worker's later actions.",
            "Reports close before the outcome or checker answer leaks; live clocks and oracle are absent.",
            "Sponsor purchases a fixed report capacity; identities cannot create additional paid rights.",
            "Risk preferences, private costs, collusion and task selection are not identified by the score.",
            "Bandwidth sampling requires a defensible admitted population and live measurement assumptions.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = json.dumps(report(), sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(data)
    else:
        print(data, end="")
