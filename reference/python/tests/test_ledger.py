import json

import pytest

from proofwork.ledger import Ledger, LedgerError


def test_chain_verifies_when_intact(tmp_path):
    ledger = Ledger(str(tmp_path / "log.jsonl"))
    for i in range(5):
        ledger.append("note", {"i": i}, ts="2026-07-28T00:00:00+00:00")
    assert ledger.verify_chain() == []
    assert len(ledger) == 5


def test_entries_link_to_predecessor(tmp_path):
    ledger = Ledger(str(tmp_path / "log.jsonl"))
    first = ledger.append("note", {"i": 0}, ts="t")
    second = ledger.append("note", {"i": 1}, ts="t")
    assert first.prev is None
    assert second.prev == first.hash


def test_reload_from_disk_preserves_chain(tmp_path):
    path = str(tmp_path / "log.jsonl")
    ledger = Ledger(path)
    ledger.append("note", {"i": 0}, ts="t")
    ledger.append("note", {"i": 1}, ts="t")
    head = ledger.head()

    reloaded = Ledger(path)
    assert reloaded.head() == head
    assert reloaded.verify_chain() == []


def test_tampering_with_payload_is_detected(tmp_path):
    path = tmp_path / "log.jsonl"
    ledger = Ledger(str(path))
    ledger.append("note", {"amount": 1}, ts="t")
    ledger.append("note", {"amount": 2}, ts="t")

    lines = path.read_text().splitlines()
    doctored = json.loads(lines[0])
    doctored["payload"]["amount"] = 1_000_000
    lines[0] = json.dumps(doctored, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    problems = Ledger(str(path)).verify_chain()
    assert any("hash mismatch" in p for p in problems)


def test_deleting_an_entry_breaks_the_chain(tmp_path):
    path = tmp_path / "log.jsonl"
    ledger = Ledger(str(path))
    for i in range(4):
        ledger.append("note", {"i": i}, ts="t")

    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")

    problems = Ledger(str(path)).verify_chain()
    assert problems, "removing an entry must not go unnoticed"


def test_malformed_line_is_an_error(tmp_path):
    path = tmp_path / "log.jsonl"
    path.write_text("{not json}\n")
    with pytest.raises(LedgerError):
        Ledger(str(path))


def test_float_payload_is_refused_before_writing(tmp_path):
    path = tmp_path / "log.jsonl"
    ledger = Ledger(str(path))
    with pytest.raises(Exception):
        ledger.append("note", {"score": 0.5}, ts="t")
    assert not path.exists() or path.read_text() == ""


def test_merkle_root_changes_with_every_append(tmp_path):
    ledger = Ledger(str(tmp_path / "log.jsonl"))
    roots = set()
    for i in range(6):
        ledger.append("note", {"i": i}, ts="t")
        roots.add(ledger.root())
    assert len(roots) == 6
