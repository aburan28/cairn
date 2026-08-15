"""Evaluator: how few XORs compute AES MixColumns?

MixColumns is GF(2)-linear, so over the bits it is a fixed 32x32 binary matrix
and any implementation of it is a straight-line program of two-input XORs. The
obvious program -- one row at a time, XOR together the input bits that row
selects -- costs 152 XORs. Published implementations reach the low nineties.
Nobody knows the minimum, and finding shortest linear straight-line programs is
NP-hard in general, so this is a search problem with a real floor somewhere
under the best known answer.

It is also the least abstract objective in this family. This exact matrix runs
in every TLS handshake; an XOR removed here is an XOR removed from hardware and
from bitsliced software, and the literature on it exists because that is worth
money to people who ship silicon.

# Why a symbolic check, not 2^32 test vectors

XOR programs are linear, so a value is completely described by *which input
bits it is the parity of* -- a 32-bit mask. Propagating masks through the
program and comparing the 32 output masks against the matrix rows decides
equality over all 2^32 inputs, at a cost of one integer XOR per operation.

Testing on sampled inputs would be both slower and weaker. Linearity is what
lets the checker be complete and nearly free at the same time, which is the
property an objective needs before it is safe to fund.

# The matrix is derived, not pasted

The 32 target rows are computed here from the AES field and the MixColumns
matrix [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]. A pasted table of 32 hex
constants would be unreviewable -- a single wrong bit is an objective that pays
for a program computing something that is not MixColumns, and no reader would
catch it. Deriving it means the reviewable claim is the four lines of field
arithmetic, which anyone can check against the standard.

Returns an int. Never a float -- see `src/verifiers/mod.rs` for why.
"""

BITS = 32
INPUTS = 32

# The artifact is attacker-supplied and billing this node's CPU. The naive
# program is 152 operations; anything past a few hundred is not a near-miss.
MAX_OPERATIONS = 512

# What an invalid artifact scores. A *minimise* objective cannot reject with
# zero: a program with no operations at all would be the best score expressible
# and would take the frontier and the pool with it.
INVALID = MAX_OPERATIONS + 1

# x^8 + x^4 + x^3 + x + 1, the AES reduction polynomial, low 8 bits only.
AES_MODULUS = 0x1B

# MixColumns, as it is written in FIPS-197: a circulant of {02, 03, 01, 01}.
MIXCOLUMNS = (
    (2, 3, 1, 1),
    (1, 2, 3, 1),
    (1, 1, 2, 3),
    (3, 1, 1, 2),
)


def gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) with the AES modulus. Peasant multiplication."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= AES_MODULUS
    return result


def target_rows() -> list[int]:
    """MixColumns as 32 parity masks over the 32 input bits.

    Bit `8 * t + b` of a mask is input byte `t`, bit `b`, with `b = 0` least
    significant. Row `8 * i + b` is bit `b` of output byte `i`.
    """
    rows = []
    for i in range(4):
        for out_bit in range(8):
            mask = 0
            for t, coefficient in enumerate(MIXCOLUMNS[i]):
                for in_bit in range(8):
                    # Multiplying by a constant is linear over the bits, so the
                    # coefficient of input bit `in_bit` in output bit `out_bit`
                    # is read straight off the product of the basis element.
                    if (gf_mul(coefficient, 1 << in_bit) >> out_bit) & 1:
                        mask ^= 1 << (8 * t + in_bit)
            rows.append(mask)
    return rows


def _valid_operation(operation, available: int) -> bool:
    return (
        isinstance(operation, list)
        and len(operation) == 2
        and all(
            isinstance(index, int) and not isinstance(index, bool) and 0 <= index < available
            for index in operation
        )
        # `x ^ x` is zero, which is never a useful intermediate for a matrix with
        # no zero row and is an easy way to pad a program that "computes"
        # something. Refuse it rather than let it be counted as work.
        and operation[0] != operation[1]
    )


def evaluate(operations: list[list[int]]) -> list[int]:
    """Every value in the program, as a parity mask over the inputs."""
    values = [1 << t for t in range(INPUTS)]
    for left, right in operations:
        values.append(values[left] ^ values[right])
    return values


def score(artifact: dict) -> int:
    operations = artifact.get("operations")
    outputs = artifact.get("outputs")
    if not isinstance(operations, list) or not isinstance(outputs, list):
        return INVALID
    if len(operations) > MAX_OPERATIONS:
        return INVALID
    for position, operation in enumerate(operations):
        # An operand may only name a value that already exists: inputs, or the
        # output of an earlier operation. Straight-line means no cycles, and a
        # forward reference is how a submitter would try to write one.
        if not _valid_operation(operation, INPUTS + position):
            return INVALID
    available = INPUTS + len(operations)
    if len(outputs) != BITS:
        return INVALID
    if not all(
        isinstance(index, int) and not isinstance(index, bool) and 0 <= index < available
        for index in outputs
    ):
        return INVALID

    values = evaluate(operations)
    # An output may name an input directly, which is correct for any row of
    # weight one, and two outputs may name the same value. Neither is a trick:
    # both describe a real program that a machine would run as written.
    if [values[index] for index in outputs] != target_rows():
        return INVALID
    return len(operations)
