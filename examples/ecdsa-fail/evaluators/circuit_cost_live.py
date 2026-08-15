"""Evaluator: qubit × Toffoli product for a secp256k1 ECDSA point-add cost claim.

Calibrated to the live ecdsa.fail leaderboard (Aug 2026):

    Litinski published best   24,570,000,000  (8.19M T × 3,000 Q)
    ecdsa.fail challenge start 10,758,874,395  (3.96M T × 2,715 Q)
    Current world best         1,483,649,332  (1.29M T × 1,154 Q)
    Low-qubit record           1,170,012,987  (1.44M T ×   813 Q)
    Low-Toffoli record         1,285,658,000  (1.286M T × 1,154 Q)

Score = qubits × toffoli (minimize).  Lower is better.

What this checks
----------------
The artifact carries *declared* metrics from `ecdsafail run`'s `score.json`.
This evaluator enforces:

1. qubits and toffoli are positive integers (bools refused; floats refused).
2. Optional `score` field, when present, must equal qubits × toffoli exactly
   (a lie about the product must not clear any threshold).
3. Feasibility bounds derived from the known landscape:
   - MIN_QUBITS = 500:  every published secp256k1 circuit uses ≥ 813 Q;
     500 leaves headroom without admitting obviously fake claims.
   - MIN_TOFFOLI = 100_000:  well below the current world-best Toffoli count
     (~1.29M) but high enough to reject trivial non-circuits.
   - MIN_PRODUCT = 500_000_000:  based on known quantum lower bounds for
     256-bit elliptic-curve scalar multiplication; no plausible construction
     is expected below 500M.
4. An upper ceiling to reject overflow exploits.

What this does NOT check
-------------------------
This evaluator does not re-simulate the circuit.  It cannot detect a correct
product that was manufactured without running `ecdsafail run`.  Feasibility
bounds are the only guard here.  The real ecdsafail harness (9024-shot
simulation, reversibility, phase, forward∘reverse) is the authoritative check;
see examples/ecdsa-fail/GAP.md.

Returns an int.  Never a float — see docs/verification.md.
"""

# Above any threshold this objective sets; any invalid artifact lands here.
INVALID_SCORE = 10 ** 18

# ── Feasibility bounds ────────────────────────────────────────────────────────
# Derived from the published landscape as of the ecdsa.fail Aug 2026 leaderboard.
# These are not tight lower bounds — they are sanity guards.

# Lowest promoted qubit count: 813 (low-qubit record).  We allow 500 as
# headroom for future advances while still refusing clearly fake small values.
MIN_QUBITS = 500
MAX_QUBITS = 8_192

# Lowest promoted Toffoli count: ~1.286M.  100K is well below that yet still
# blocks {qubits:1, toffoli:1} spam.
MIN_TOFFOLI = 100_000
MAX_TOFFOLI = 30_000_000   # above Litinski's 8.19M; room for future work

# Lower bound on the qubit × Toffoli product from known quantum complexity
# arguments for 256-bit scalar multiplication.  No published construction
# beats 1.17B; 500M is a conservative floor.
MIN_PRODUCT = 500_000_000


def _pos_int(value) -> bool:
    """True for positive integers; rejects booleans and floats."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def score(artifact: dict) -> int:
    qubits = artifact.get("qubits")
    toffoli = artifact.get("toffoli")

    if not _pos_int(qubits) or not _pos_int(toffoli):
        return INVALID_SCORE

    if not (MIN_QUBITS <= qubits <= MAX_QUBITS):
        return INVALID_SCORE
    if not (MIN_TOFFOLI <= toffoli <= MAX_TOFFOLI):
        return INVALID_SCORE

    product = qubits * toffoli

    # i64 ceiling for proofwork scores.
    if product > (2 ** 63 - 1):
        return INVALID_SCORE

    # Minimum-product guard.
    if product < MIN_PRODUCT:
        return INVALID_SCORE

    # Optional declared score must equal the derived product.
    claimed = artifact.get("score")
    if claimed is not None:
        if not _pos_int(claimed) or claimed != product:
            return INVALID_SCORE

    return product
