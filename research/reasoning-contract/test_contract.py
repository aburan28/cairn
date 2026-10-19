from fractions import Fraction
from itertools import product
import unittest

from contract import Contract, report_commitment, score_delta
from experiment import committee_bound_exceeded, expected


class InformationContractTests(unittest.TestCase):
    def add_report(self, contract, owner, report):
        nonce = f"{len(contract.updates) + 1:064x}"
        digest = report_commitment(contract.task, len(contract.updates), contract.current,
                                   owner, report, nonce, contract.scale)
        before = contract.total()
        contract.commit(owner, digest)
        self.assertEqual(contract.total(), before)
        contract.reveal(report, nonce)
        self.assertEqual(contract.total(), before)

    def test_truthfulness_matches_independent_squared_regret(self):
        for truth, report in product(range(101), repeat=2):
            # Compute both outcome branches, then compare against the analytic
            # regret identity rather than comparing the implementation to itself.
            belief = Fraction(truth, 100)
            truthful = expected(37, truth, belief)
            proposed = expected(37, report, belief)
            self.assertEqual(truthful - proposed, (report - truth) ** 2)
        belief = Fraction(2, 3)
        values = [expected(50, p, belief) for p in range(101)]
        self.assertEqual([p for p, v in enumerate(values) if v == max(values)], [67])

    def test_paid_only_gains_have_a_profitable_round_trip(self):
        deltas = [score_delta(a, b, 1, 100) for a, b in zip((50, 100, 0), (100, 0, 100))]
        self.assertEqual(sum(deltas), 2500)
        self.assertEqual(sum(max(0, x) for x in deltas), 12500)

    def test_budget_and_identity_splitting_conserve_every_outcome(self):
        for reports, outcome in product(product(range(11), repeat=2), (0, 1)):
            results = []
            for owners in (("one", "one"), ("first", "second")):
                funds = {owner: 100 * owners.count(owner) for owner in set(owners)}
                c = Contract("task", 5, 100, funds, scale=10, slots=2)
                for owner, report in zip(owners, reports):
                    self.add_report(c, owner, report)
                c.close()
                result = c.resolve(outcome)
                # Direct loss difference independently establishes the chain's
                # aggregate transfer, regardless of who owns its intermediate reports.
                target = 10 * outcome
                direct = (5 - target) ** 2 - (reports[-1] - target) ** 2
                self.assertEqual(sum(result.deltas), direct)
                self.assertEqual(c.total(), 300)
                self.assertTrue(all(v >= 0 for v in c.available.values()))
                self.assertGreaterEqual(c.sponsor, 0)
                results.append((c.sponsor, sum(c.available.values())))
            self.assertEqual(results[0], results[1])

    def test_no_credit_can_be_borrowed_from_a_future_success(self):
        c = Contract("task", 50, 10000, {"worker": 0})
        digest = report_commitment("task", 0, 50, "worker", 100, "01" * 32, 100)
        with self.assertRaisesRegex(ValueError, "collateral"):
            c.commit("worker", digest)
        self.assertEqual(c.available["worker"], 0)
        self.assertEqual(c.total(), 10000)

    def test_fresh_identities_cannot_create_more_report_rights(self):
        c = Contract("task", 50, 10000, {"a": 10000, "b": 10000}, slots=1)
        self.add_report(c, "a", 60)
        with self.assertRaisesRegex(ValueError, "report right"):
            c.commit("b", "a" * 64)

    def test_pending_withholding_is_still_a_liveness_gap(self):
        c = Contract("task", 50, 10000, {"a": 10000, "b": 10000})
        c.commit("a", "a" * 64)
        with self.assertRaisesRegex(ValueError, "report right"):
            c.commit("b", "b" * 64)
        c.close()
        self.assertEqual(c.available["a"], 10000)
        self.assertEqual(len(c.updates), 0)

    def test_commitment_cannot_be_transplanted_to_another_task_slot_or_owner(self):
        for task, slot, previous, owner in (
            ("another-task", 0, 50, "a"), ("task", 1, 50, "a"),
            ("task", 0, 49, "a"), ("task", 0, 50, "b"),
        ):
            c = Contract("task", 50, 10000, {"a": 10000})
            digest = report_commitment(task, slot, previous, owner, 60, "01" * 32, 100)
            c.commit("a", digest)
            with self.assertRaisesRegex(ValueError, "does not open"):
                c.reveal(60, "01" * 32)
            self.assertEqual(c.available["a"], 0)
            self.assertEqual(c.total(), 20000)
            c.close()
            self.assertEqual(c.available["a"], 10000)

    def test_closing_the_window_prevents_a_favorable_late_reveal(self):
        c = Contract("task", 50, 10000, {"worker": 20000})
        self.add_report(c, "worker", 60)
        nonce = "ab" * 32
        c.commit("worker", report_commitment("task", 1, 60, "worker", 100, nonce, 100))
        with self.assertRaisesRegex(ValueError, "close reports"):
            c.resolve(1)
        c.close()
        with self.assertRaisesRegex(ValueError, "awaiting reveal"):
            c.reveal(100, nonce)
        self.assertEqual(c.resolve(1).deltas, (900,))
        self.assertEqual(c.available["worker"], 20900)

    def test_unavailable_refunds_without_turning_into_a_wrong_answer(self):
        c = Contract("task", 50, 10000, {"worker": 10000})
        self.add_report(c, "worker", 100)
        c.close()
        result = c.resolve(None)
        self.assertEqual(result.deltas, (0,))
        self.assertEqual(c.available["worker"], 10000)
        self.assertEqual(c.state, "unavailable")

    def test_settlement_is_idempotent_and_cannot_change_the_outcome(self):
        c = Contract("task", 50, 10000, {"worker": 10000})
        self.add_report(c, "worker", 100)
        c.close()
        first = c.resolve(0)
        self.assertEqual(c.resolve(0), first)
        self.assertEqual(c.available["worker"], 2500)
        with self.assertRaisesRegex(ValueError, "cannot be changed"):
            c.resolve(1)

    def test_fractional_and_boolean_probability_fields_are_refused(self):
        for value in (True, 0.5, -1, 101):
            with self.assertRaises(ValueError):
                score_delta(50, value, 1, 100)
        with self.assertRaises(ValueError):
            score_delta(50, 60, True, 100)
        with self.assertRaises(ValueError):
            expected(50, 60, 0.6)
        with self.assertRaises(ValueError):
            expected(50, 60, Fraction(3, 5), loss_cap=1.5)

    def test_no_bond_leaves_a_profitable_default_option(self):
        p = Fraction(1, 2)
        self.assertEqual(expected(50, 100, p), -2500)
        self.assertEqual(expected(50, 100, p, loss_cap=0), 1250)

    def test_committee_calculation_matches_a_small_enumerable_population(self):
        # Select pairs out of four operators; two are corrupt. Exactly one
        # of the six pairs exceeds a bound of one corrupt challenger.
        self.assertEqual(committee_bound_exceeded(4, 2, 2, 1), Fraction(1, 6))
        self.assertEqual(committee_bound_exceeded(4, 0, 2, 0), 0)
        self.assertEqual(committee_bound_exceeded(4, 4, 2, 1), 1)


if __name__ == "__main__":
    unittest.main()
