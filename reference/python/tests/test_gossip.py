"""CRDT laws. If merge is not confluent, gossip silently diverges."""
import random

import pytest

from proofwork.gossip import Candidate, Population, ingest


def cand(score, tag="x", origin="n0", objective="obj"):
    return Candidate(objective_id=objective, artifact={"tag": tag}, score=score, origin=origin)


def pop(*candidates, islands=4, capacity=8):
    return Population(islands=islands, capacity=capacity, candidates=candidates)


def test_merge_is_commutative():
    a = pop(cand(1, "a"), cand(2, "b"))
    b = pop(cand(3, "c"))
    assert a.merge(b) == b.merge(a)


def test_merge_is_associative():
    a, b, c = pop(cand(1, "a")), pop(cand(2, "b")), pop(cand(3, "c"))
    assert a.merge(b).merge(c) == a.merge(b.merge(c))


def test_merge_is_idempotent():
    a = pop(cand(1, "a"), cand(2, "b"))
    assert a.merge(a) == a


def test_pruning_preserves_associativity():
    # The load-bearing property: bounded retention must not make merge order
    # matter. If it did, two nodes seeing the same messages in different orders
    # would end up with different populations and never notice.
    rng = random.Random(1234)
    for _ in range(200):
        groups = [
            [cand(rng.randint(0, 50), f"t{rng.randint(0, 99)}") for _ in range(rng.randint(1, 12))]
            for _ in range(3)
        ]
        a, b, c = (pop(*g, islands=2, capacity=3) for g in groups)
        assert a.merge(b).merge(c) == a.merge(b.merge(c))


def test_gossip_converges_regardless_of_delivery_order():
    rng = random.Random(99)
    messages = [cand(rng.randint(0, 100), f"t{i}") for i in range(40)]
    finals = []
    for _ in range(12):
        shuffled = messages[:]
        rng.shuffle(shuffled)
        node = Population(islands=4, capacity=5)
        for message in shuffled:
            node = node.merge(pop(message, islands=4, capacity=5))
        finals.append(node)
    assert all(f == finals[0] for f in finals)


def test_capacity_is_enforced_per_island():
    population = Population(islands=2, capacity=3)
    for i in range(50):
        population.add(cand(i, f"t{i}"))
    for island in range(2):
        assert len(population.island(island)) <= 3
    assert len(population) <= 6


def test_best_candidates_survive_pruning():
    population = Population(islands=1, capacity=3)
    for i in range(20):
        population.add(cand(i, f"t{i}"))
    assert [c.score for c in population.top(3)] == [19, 18, 17]


def test_islands_preserve_diversity():
    # A run of strong candidates must not evict every weaker island: diversity
    # is what the search depends on, so retention is per island, not global.
    population = Population(islands=4, capacity=2)
    for i in range(200):
        population.add(cand(i, f"t{i}"))
    occupied = [i for i in range(4) if population.island(i)]
    assert len(occupied) > 1


def test_ties_break_deterministically():
    same_score = [cand(7, f"t{i}") for i in range(20)]
    first = Population(islands=2, capacity=3, candidates=same_score)
    for _ in range(10):
        shuffled = same_score[:]
        random.Random(0).shuffle(shuffled)
        assert Population(islands=2, capacity=3, candidates=shuffled) == first


def test_identical_artifact_from_two_peers_converges():
    left = pop(cand(5, "a", origin="alice"))
    right = pop(cand(5, "a", origin="bob"))
    assert left.merge(right) == right.merge(left)
    assert len(left.merge(right)) == 1


def test_digest_detects_equality_cheaply():
    a = pop(cand(1, "a"), cand(2, "b"))
    b = pop(cand(2, "b"), cand(1, "a"))
    assert a.digest() == b.digest()
    assert a.digest() != pop(cand(1, "a")).digest()


def test_round_trips_through_dict():
    population = pop(cand(1, "a"), cand(9, "b"), cand(4, "c"))
    assert Population.from_dict(population.to_dict()) == population


def test_float_score_is_rejected():
    with pytest.raises(ValueError):
        Candidate(objective_id="o", artifact={}, score=1.5, origin="n")


def test_merging_different_island_counts_is_refused():
    with pytest.raises(ValueError):
        pop(cand(1), islands=2).merge(pop(cand(1), islands=4))


def test_same_artifact_at_two_scores_converges():
    # One peer is lying about this artifact's score. Merge must still converge:
    # both entries are representable and every node keeps the same ones.
    honest = cand(5, "a", origin="alice")
    inflated = cand(999, "a", origin="mallory")
    assert honest.artifact_id == inflated.artifact_id
    assert honest.id != inflated.id
    left, right = pop(honest), pop(inflated)
    assert left.merge(right) == right.merge(left)


# -- gossip is untrusted ---------------------------------------------------


def real_score(artifact):
    return len(artifact.get("tag", ""))


def test_ingest_accepts_an_honest_candidate():
    population = Population(islands=2, capacity=4)
    assert ingest(population, cand(3, "abc"), real_score)
    assert len(population) == 1


def test_ingest_rejects_an_inflated_score():
    # Without this, a peer asserts score=10**9 and evicts every genuine
    # candidate from a bounded population -- a cheap DoS on the search itself.
    population = Population(islands=2, capacity=4)
    assert not ingest(population, cand(10**9, "abc"), real_score)
    assert len(population) == 0


def test_ingest_rejects_a_candidate_that_crashes_the_scorer():
    def explode(_):
        raise RuntimeError("boom")

    population = Population(islands=2, capacity=4)
    assert not ingest(population, cand(1, "a"), explode)
    assert len(population) == 0


def test_ingest_rejects_a_non_integer_score():
    population = Population(islands=2, capacity=4)
    assert not ingest(population, cand(3, "abc"), lambda a: 3.0)
    assert len(population) == 0
