"""proofwork -- a reference implementation of a verified-results research network.

Stage 0: one operator, no token, no consensus. What it does provide is the
property that actually matters -- **anyone can independently re-derive every
result the network has settled**, using nothing but a copy of the log and this
package.

    from proofwork import Ledger, Node, Objective, Claim

See docs/architecture.md for what this is a step toward, and docs/roadmap.md for
what deliberately is not built yet.
"""
from __future__ import annotations

from .attribution import FlowParams, flow, ledger_payouts
from .canonical import canonical_bytes, digest, merkle_root
from .frontier import FrontierEntry, Ratchet
from .gossip import Candidate, Population, ingest
from .partition import Assignment, assign, assignment_for, beacon, epoch_of
from .ledger import Entry, Ledger, LedgerError
from .node import Node, Outcome, RuleViolation, now
from .records import Claim, Commitment, Objective, RecordError, commitment_hash
from .verifiers import Status, Verdict

__version__ = "0.1.0"

__all__ = [
    "Assignment",
    "Candidate",
    "Claim",
    "Commitment",
    "Entry",
    "FrontierEntry",
    "FlowParams",
    "Ledger",
    "LedgerError",
    "Node",
    "Objective",
    "Outcome",
    "Population",
    "Ratchet",
    "RecordError",
    "RuleViolation",
    "Status",
    "Verdict",
    "assign",
    "assignment_for",
    "beacon",
    "canonical_bytes",
    "commitment_hash",
    "digest",
    "epoch_of",
    "flow",
    "ingest",
    "ledger_payouts",
    "merkle_root",
    "now",
]
