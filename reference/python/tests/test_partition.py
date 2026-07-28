"""Coordinator-free work assignment."""
import pytest

from proofwork.partition import assign, assignment_for, beacon, epoch_of


def test_assignment_is_deterministic():
    b = beacon(7, "anchor")
    assert assign("node-a", "obj", b, 16) == assign("node-a", "obj", b, 16)


def test_different_nodes_get_different_partitions():
    b = beacon(7, "anchor")
    seen = {assign(f"node-{i}", "obj", b, 16) for i in range(200)}
    assert len(seen) > 8, "assignment is not spreading nodes across partitions"


def test_assignment_rotates_between_epochs():
    # Without rotation a node owns a region forever, so an adversary grinds one
    # identity into a region and starves it indefinitely.
    moved = sum(
        assign("node-a", "obj", beacon(e, "anchor"), 32)
        != assign("node-a", "obj", beacon(e + 1, "anchor"), 32)
        for e in range(100)
    )
    assert moved > 90


def test_assignment_differs_across_objectives():
    b = beacon(3, "anchor")
    assignments = {assign("node-a", f"obj-{i}", b, 32) for i in range(100)}
    assert len(assignments) > 8


def test_distribution_is_roughly_uniform():
    b = beacon(1, "anchor")
    partitions = 8
    counts = [0] * partitions
    for i in range(8000):
        counts[assign(f"node-{i}", "obj", b, partitions)] += 1
    expected = 8000 / partitions
    assert all(0.85 * expected < c < 1.15 * expected for c in counts), counts


def test_shares_tile_the_space_without_gaps_or_overlap():
    partitions = 7
    spans = [
        assignment_for(f"n{i}", "obj", 1, "anchor", partitions).share for i in range(200)
    ]
    unique = sorted(set(spans))
    assert unique[0][0] == 0
    assert unique[-1][1] == 1 << 32
    for (lo1, hi1), (lo2, _) in zip(unique, unique[1:]):
        assert hi1 == lo2, "partitions must tile the space exactly"


def test_covers_partitions_items_exactly_once():
    partitions = 4
    assignments = [
        assignment_for(f"n{i}", "obj", 1, "anchor", partitions) for i in range(400)
    ]
    by_partition = {a.partition: a for a in assignments}
    assert len(by_partition) == partitions
    for item in (f"item-{i}" for i in range(300)):
        owners = [p for p, a in by_partition.items() if a.covers(item)]
        assert len(owners) == 1, f"{item} owned by {owners}"


def test_beacon_changes_with_anchor():
    assert beacon(1, "a") != beacon(1, "b")


def test_epoch_of_is_monotone():
    assert epoch_of(0, 600) == 0
    assert epoch_of(599, 600) == 0
    assert epoch_of(600, 600) == 1


def test_partitions_must_be_positive():
    with pytest.raises(ValueError):
        assign("n", "o", beacon(1, "a"), 0)
