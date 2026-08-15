"""Evaluator: qubit × Toffoli product for an ecdsa.fail-shaped cost claim.

Mirrors the launch benchmark's published score
``score = peak_qubits × avg_toffoli`` (lower is better), as a *cheap pinned
fitness function* for the cairn proposer loop.

What this checks
----------------
- ``qubits`` and ``toffoli`` are positive integers (bools refused).
- Optional ``score`` field, when present, must equal ``qubits * toffoli``
  (the ecdsafail ``score.json`` shape carries both; lying about the product
  must not clear).
- Toy feasibility bounds keep garbage from "winning" the demo objective.
  They are **not** a stand-in for the real harness's 9024-shot simulation,
  reversibility, or phase checks — see ``GAP.md``.

Invalid input scores ``INVALID_SCORE`` (worse than any accepted threshold on
a minimize objective) rather than raising. An invalid submission is a bad
artifact; an exception is a broken verifier.

Returns an int. Never a float — see docs/verification.md.
"""

# Above any threshold used by examples/ecdsa-fail/objective.json.
INVALID_SCORE = 10**18

MIN_QUBITS = 8
MAX_QUBITS = 8192
# Toy stand-in for "a point-add circuit needs width and depth": at least one
# Toffoli-class op per qubit of peak width. The real benchmark enforces this
# by construction in its op stream; here it only blocks 1×1 spam.
MIN_TOFFOLI_PER_QUBIT = 1


def _positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def score(artifact: dict) -> int:
    qubits = artifact.get("qubits")
    toffoli = artifact.get("toffoli")
    if not _positive_int(qubits) or not _positive_int(toffoli):
        return INVALID_SCORE
    if not MIN_QUBITS <= qubits <= MAX_QUBITS:
        return INVALID_SCORE
    if toffoli < qubits * MIN_TOFFOLI_PER_QUBIT:
        return INVALID_SCORE

    product = qubits * toffoli
    # i64 ceiling for cairn scores; refuse overflow as invalid rather than
    # wrapping (wrapping would invent a cheap score).
    if product > (2**63 - 1):
        return INVALID_SCORE

    claimed = artifact.get("score")
    if claimed is not None:
        if not _positive_int(claimed) or claimed != product:
            return INVALID_SCORE

    return product
