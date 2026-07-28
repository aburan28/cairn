"""Append-only hash-linked log.

Stage 0 has one sequencer and no consensus. That is deliberate: the property
that actually matters is not "no one is in charge" but **anyone can check**.
A single operator who publishes a hash-linked log plus a re-runnable verifier
gives every reader the ability to independently confirm every claim the network
has settled -- which is most of the value of decentralization, at none of the
cost. Consensus replaces the operator later, and changes nothing below.

Storage is JSONL, one entry per line, each carrying the hash of its predecessor.
Tampering with entry *n* invalidates every hash from *n* onward.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterator

from .canonical import canonical_bytes, digest, merkle_root

GENESIS_PREV = None


@dataclass(frozen=True)
class Entry:
    seq: int
    prev: str | None
    kind: str
    payload: dict[str, Any]
    ts: str
    hash: str

    def body(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "prev": self.prev,
            "kind": self.kind,
            "payload": self.payload,
            "ts": self.ts,
        }

    def recompute_hash(self) -> str:
        return digest(self.body())

    def to_json(self) -> str:
        record = self.body()
        record["hash"] = self.hash
        return json.dumps(record, sort_keys=True, ensure_ascii=False)


class LedgerError(Exception):
    pass


class Ledger:
    """A hash-linked append-only log backed by a JSONL file."""

    def __init__(self, path: str):
        self.path = path
        self._entries: list[Entry] = []
        if os.path.exists(path):
            self._load()

    # -- storage ---------------------------------------------------------
    def _load(self) -> None:
        with open(self.path, encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise LedgerError(f"{self.path}:{lineno}: malformed JSON: {exc}") from exc
                self._entries.append(
                    Entry(
                        seq=data["seq"],
                        prev=data["prev"],
                        kind=data["kind"],
                        payload=data["payload"],
                        ts=data["ts"],
                        hash=data["hash"],
                    )
                )

    def append(self, kind: str, payload: dict[str, Any], ts: str) -> Entry:
        canonical_bytes(payload)  # fail loudly before anything is written
        prev = self._entries[-1].hash if self._entries else GENESIS_PREV
        seq = len(self._entries)
        body = {"seq": seq, "prev": prev, "kind": kind, "payload": payload, "ts": ts}
        entry = Entry(seq=seq, prev=prev, kind=kind, payload=payload, ts=ts, hash=digest(body))
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(entry.to_json() + "\n")
        self._entries.append(entry)
        return entry

    # -- reading ---------------------------------------------------------
    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[Entry]:
        return iter(self._entries)

    def entries(self, kind: str | None = None) -> list[Entry]:
        if kind is None:
            return list(self._entries)
        return [e for e in self._entries if e.kind == kind]

    def head(self) -> str | None:
        return self._entries[-1].hash if self._entries else None

    def root(self) -> str | None:
        """Merkle root over entry hashes -- a single value that pins the log."""
        return merkle_root([e.hash for e in self._entries])

    # -- integrity -------------------------------------------------------
    def verify_chain(self) -> list[str]:
        """Return a list of integrity problems. Empty means the log is intact."""
        problems: list[str] = []
        prev: str | None = GENESIS_PREV
        for i, entry in enumerate(self._entries):
            if entry.seq != i:
                problems.append(f"entry {i}: seq is {entry.seq}")
            if entry.prev != prev:
                problems.append(f"entry {i}: prev is {entry.prev!r}, expected {prev!r}")
            recomputed = entry.recompute_hash()
            if recomputed != entry.hash:
                problems.append(
                    f"entry {i}: hash mismatch -- content was modified after it was written"
                )
            prev = entry.hash
        return problems
