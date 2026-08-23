"""Exact verifier for the elliptic-curve rank-record portfolio.

The certificate entrypoint requires exactly 31 rational points.  Three score
entrypoints support the rank-32, new-j, and lower-height objectives with up to
64 points.  Every entrypoint takes a general integral Weierstrass equation and
rational points.  Checking that the points lie on the curve is not enough:
copies, negatives, and other integer combinations would all pass that test
without proving rank.  This verifier therefore certifies independence by the
exact quadratic-character method used by Cremona and Brumer.

For a short integral model ``Y^2 = X^3 + A*X + B`` and an odd prime of good
reduction, every root theta of the cubic modulo p gives a homomorphism

    E(Q) / 2 E(Q) -> F_2,
    (u / w^2, Y)  |->  quadratic character of u - theta*w^2 (mod p).

The checker stacks those characters at deterministic good primes.  Full row
rank proves that the submitted point classes are independent modulo 2E(Q).
It separately finds a good prime where the cubic has no root.  That proves the
curve has no rational 2-torsion; consequently its torsion subgroup has odd
order and contributes the zero class modulo 2E(Q).  Full character rank then
proves the points independent modulo torsion, hence rank E(Q) is at least the
number of submitted points.

This is the sufficient, one-way certificate direction.  Failure to reach full
rank does not prove dependence, but an artifact that does not carry a complete
certificate cannot settle this objective.  All decision arithmetic is exact:
Python integers, reduced fractions, and finite-field arithmetic only.

References:

* J. E. Cremona, "On the computation of Mordell-Weil and 2-Selmer groups of
  elliptic curves", section 2 (the method is attributed there to Brumer).
* ICARM's Elliptic Curve Rank Leaderboard verifier, ``src/verify.ts``.  The
  checker deliberately implements only its sound acceptance direction; it
  does not need PARI's torsion or point-halving machinery because absence of
  rational 2-torsion is proved directly.
"""

from fractions import Fraction
from math import gcd, isqrt
import re


TARGET_RANK = 31
MAX_POINTS = 64
MAX_NUMERIC_PART_DIGITS = 256
# Root enumeration is deliberately bounded.  On honest high-rank records the
# character matrix fills at small primes; an unlucky curve remains an
# unaccepted candidate instead of turning verification into unbounded work.
MAX_CERTIFICATE_PRIME = 10_000

# Curve #273 is the public rank-30 baseline.  The three values are exact
# integral-model invariants, not its approximate displayed heights.  Separate
# evaluator entrypoints below use them to define non-copyable successor
# objectives while sharing this one pinned implementation.
BASELINE_C4 = 9684913692500090356012555202915243565710817455750531285486666641
BASELINE_C6 = -994557259417874600793726224085029793887754159405457725835627998281306921883628926505055206421689
BASELINE_DISCRIMINANT = -46714661255308767314567688733841531918983356002159772613256840842851650254036518701100578342601553513579222272710220496887616034526983492843954090554197033638137245037791044053017600000000
BASELINE_INVARIANT_HEIGHT = max(abs(BASELINE_C4) ** 3, BASELINE_C6**2)

_INTEGER = re.compile(r"(?:0|-?[1-9][0-9]*)\Z")
_RATIONAL = re.compile(r"(-?(?:0|[1-9][0-9]*))/([1-9][0-9]*)\Z")


class InvalidArtifact(ValueError):
    """A deterministic defect in the submitted certificate."""


def _parse_integer(raw, label):
    if not isinstance(raw, str) or _INTEGER.fullmatch(raw) is None:
        raise InvalidArtifact(f"{label} must be a canonical decimal integer string")
    if len(raw.removeprefix("-")) > MAX_NUMERIC_PART_DIGITS:
        raise InvalidArtifact(
            f"{label} exceeds the {MAX_NUMERIC_PART_DIGITS}-digit limit"
        )
    return int(raw)


def _parse_rational(raw, label):
    if not isinstance(raw, str):
        raise InvalidArtifact(f"{label} must be a canonical integer or fraction string")
    if _INTEGER.fullmatch(raw) is not None:
        return Fraction(_parse_integer(raw, label), 1)
    match = _RATIONAL.fullmatch(raw)
    if match is None:
        raise InvalidArtifact(f"{label} must be a canonical integer or fraction string")
    numerator_text, denominator_text = match.groups()
    if (
        len(numerator_text.removeprefix("-")) > MAX_NUMERIC_PART_DIGITS
        or len(denominator_text) > MAX_NUMERIC_PART_DIGITS
    ):
        raise InvalidArtifact(
            f"{label} exceeds the {MAX_NUMERIC_PART_DIGITS}-digit limit"
        )
    numerator = int(numerator_text)
    denominator = int(denominator_text)
    if denominator == 1 or gcd(abs(numerator), denominator) != 1:
        raise InvalidArtifact(f"{label} is not in lowest canonical terms")
    return Fraction(numerator, denominator)


def _parse(artifact):
    if not isinstance(artifact, dict):
        raise InvalidArtifact("artifact must be an object")
    if set(artifact) != {"curve", "points"}:
        raise InvalidArtifact("artifact must contain exactly 'curve' and 'points'")

    raw_curve = artifact["curve"]
    if not isinstance(raw_curve, list) or len(raw_curve) != 5:
        raise InvalidArtifact("curve must be [a1, a2, a3, a4, a6]")
    curve = tuple(
        _parse_integer(value, f"curve[{index}]")
        for index, value in enumerate(raw_curve)
    )

    raw_points = artifact["points"]
    if not isinstance(raw_points, list) or not 1 <= len(raw_points) <= MAX_POINTS:
        raise InvalidArtifact(f"points must contain between 1 and {MAX_POINTS} points")
    points = []
    for index, raw_point in enumerate(raw_points):
        if not isinstance(raw_point, list) or len(raw_point) != 2:
            raise InvalidArtifact(f"points[{index}] must be [x, y]")
        points.append(
            (
                _parse_rational(raw_point[0], f"points[{index}][0]"),
                _parse_rational(raw_point[1], f"points[{index}][1]"),
            )
        )
    return curve, points


def _invariants(curve):
    a1, a2, a3, a4, a6 = curve
    b2 = a1 * a1 + 4 * a2
    b4 = 2 * a4 + a1 * a3
    b6 = a3 * a3 + 4 * a6
    b8 = (
        a1 * a1 * a6
        + 4 * a2 * a6
        - a1 * a3 * a4
        + a2 * a3 * a3
        - a4 * a4
    )
    c4 = b2 * b2 - 24 * b4
    c6 = -b2 * b2 * b2 + 36 * b2 * b4 - 216 * b6
    discriminant = (
        -b2 * b2 * b8
        - 8 * b4 * b4 * b4
        - 27 * b6 * b6
        + 9 * b2 * b4 * b6
    )
    if discriminant == 0:
        raise InvalidArtifact("curve is singular (discriminant zero)")
    return b2, c4, c6, discriminant


def _on_general_curve(curve, point):
    a1, a2, a3, a4, a6 = curve
    x, y = point
    return y * y + a1 * x * y + a3 * y == x * x * x + a2 * x * x + a4 * x + a6


def _short_model(curve, points):
    b2, c4, c6, _ = _invariants(curve)
    a1, _, a3, _, _ = curve
    # Classical integral Q-isomorphism:
    #   X = 36x + 3b2, Y = 108(2y + a1*x + a3)
    # sends the general model to Y^2 = X^3 - 27c4*X - 54c6.
    short_a = -27 * c4
    short_b = -54 * c6
    transformed = []
    for index, point in enumerate(points):
        if not _on_general_curve(curve, point):
            raise InvalidArtifact(f"points[{index}] does not lie on the submitted curve")
        x, y = point
        transformed_point = (36 * x + 3 * b2, 108 * (2 * y + a1 * x + a3))
        short_x, short_y = transformed_point
        if (
            short_y * short_y
            != short_x * short_x * short_x + short_a * short_x + short_b
        ):
            raise InvalidArtifact("internal model transformation check failed")
        transformed.append(transformed_point)
    return short_a, short_b, transformed


def _primes_through(limit):
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for candidate in range(2, int(limit**0.5) + 1):
        if sieve[candidate]:
            start = candidate * candidate
            sieve[start : limit + 1 : candidate] = b"\x00" * (
                ((limit - start) // candidate) + 1
            )
    return [value for value in range(5, limit + 1) if sieve[value]]


def _roots_mod_prime(short_a, short_b, prime):
    a = short_a % prime
    b = short_b % prime
    return [x for x in range(prime) if (x * x * x + a * x + b) % prime == 0]


def _quadratic_character_bit(value, prime):
    value %= prime
    if value == 0:
        raise InvalidArtifact("internal zero character at a good prime")
    symbol = pow(value, (prime - 1) // 2, prime)
    if symbol == 1:
        return 0
    if symbol == prime - 1:
        return 1
    raise InvalidArtifact("internal invalid Legendre symbol")


def _f2_rank(rows):
    basis = {}
    for row in rows:
        value = row
        while value:
            pivot = value.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = value
                break
            value ^= basis[pivot]
    return len(basis)


def _certificate_rank(short_a, short_b, points):
    rows = [0] * len(points)
    columns = 0
    used_primes = []
    no_two_torsion_prime = None

    for prime in _primes_through(MAX_CERTIFICATE_PRIME):
        # p > 3 and p not dividing the short discriminant is exactly the good
        # reduction condition needed by the character maps.
        if (4 * pow(short_a, 3, prime) + 27 * pow(short_b, 2, prime)) % prime == 0:
            continue
        roots = _roots_mod_prime(short_a, short_b, prime)
        if not roots:
            # A rational root of the monic integral cubic would be an integer
            # root and would reduce to a root at every good prime.  One
            # root-free reduction therefore proves E(Q)[2] is trivial.
            if no_two_torsion_prime is None:
                no_two_torsion_prime = prime
            continue

        used_primes.append(prime)
        for theta in roots[:2]:
            for index, (x, _) in enumerate(points):
                numerator = x.numerator
                denominator = x.denominator  # a square for a rational point
                root = isqrt(denominator)
                if root * root != denominator:
                    raise InvalidArtifact(
                        "short-model x-coordinate denominator is not a square"
                    )
                value = (numerator - theta * denominator) % prime
                if value == 0:
                    value = (3 * theta * theta + short_a) % prime
                bit = _quadratic_character_bit(value, prime)
                rows[index] |= bit << columns
            columns += 1

        rank = _f2_rank(rows)
        if rank == len(points) and no_two_torsion_prime is not None:
            return rank, columns, used_primes, no_two_torsion_prime

    return _f2_rank(rows), columns, used_primes, no_two_torsion_prime


def _evaluate(artifact):
    curve, points = _parse(artifact)
    _, c4, c6, discriminant = _invariants(curve)
    short_a, short_b, transformed = _short_model(curve, points)
    rank, columns, primes, no_two_torsion_prime = _certificate_rank(
        short_a, short_b, transformed
    )
    return (
        len(points),
        rank,
        columns,
        primes,
        no_two_torsion_prime,
        c4,
        c6,
        discriminant,
    )


def _analyze(artifact):
    """The stable five-field diagnostic used by the adversarial self-test."""
    return _evaluate(artifact)[:5]


def _fully_certified(result):
    point_count, rank, _, _, no_two_torsion_prime, _, _, _ = result
    return no_two_torsion_prime is not None and rank == point_count


def _score_with_policy(artifact, policy):
    try:
        result = _evaluate(artifact)
    except InvalidArtifact:
        return 0
    if not _fully_certified(result):
        return 0

    point_count, _, _, _, _, c4, c6, discriminant = result
    if policy == "rank":
        return point_count
    if policy == "new_j":
        # Equal fractions c4^3/Delta mean equal j-invariants.  Excluding the
        # entire baseline j-class is stricter than merely excluding its bytes:
        # rescaling the known equation or submitting a twist cannot bypass it.
        same_j = (
            c4**3 * BASELINE_DISCRIMINANT
            == BASELINE_C4**3 * discriminant
        )
        return 0 if same_j else point_count
    if policy == "lower_height":
        height = max(abs(c4) ** 3, c6**2)
        return point_count if height < BASELINE_INVARIANT_HEIGHT else 0
    raise ValueError(f"unknown internal policy: {policy}")


def score(artifact: dict) -> int:
    """Exact certified rank score for milestone objectives."""
    return _score_with_policy(artifact, "rank")


def score_new_j(artifact: dict) -> int:
    """Certified rank, but only outside curve #273's entire j-class."""
    return _score_with_policy(artifact, "new_j")


def score_lower_height(artifact: dict) -> int:
    """Certified rank below curve #273's exact invariant-height bound."""
    return _score_with_policy(artifact, "lower_height")


def check(artifact: dict) -> tuple[bool, str]:
    try:
        result = _evaluate(artifact)
    except InvalidArtifact as error:
        return False, str(error)

    point_count, rank, columns, primes, no_two_torsion_prime, _, _, _ = result

    if no_two_torsion_prime is None:
        return False, (
            "could not prove absence of rational 2-torsion within the "
            f"p <= {MAX_CERTIFICATE_PRIME} verification budget"
        )
    if point_count != TARGET_RANK:
        return False, f"artifact has {point_count} points; exactly {TARGET_RANK} are required"
    if rank != TARGET_RANK:
        return False, (
            f"quadratic-character matrix has rank {rank}, not {TARGET_RANK}, "
            f"after {columns} columns at {len(primes)} good primes"
        )
    return True, (
        f"certified {TARGET_RANK} independent rational points: character matrix "
        f"rank {rank} over F_2 using {columns} columns at {len(primes)} good "
        f"primes; root-free good prime {no_two_torsion_prime} proves E(Q)[2] = 0"
    )
