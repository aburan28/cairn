"""Certificate checker: a batch of distinguished points of a shared Pollard rho walk.

The Stage B unit of work in a *piecework* objective (docs/design/rho-piecework.md
section 9): one claim carries up to MAX_BATCH points, each with the walker
index and step count that produced it, and the objective pays `unit_price`
for every point in the batch that is novel across the log. The answer
objective for this instance -- objective-nums-50.json -- pays once, for `k`; this one pays
for the search that finds it, a batch at a time, so that a search at 2^DP_BITS
steps per point ships a claim per hour rather than a claim per point.

# What is checked, exactly

The artifact is exactly `{"dps": [...]}` with 1 to MAX_BATCH elements. Every
element carries exactly the keys `x`, `y`, `a`, `b`, `walker`, `steps`:

- `x`, `y`, `a`, `b` are lowercase hex strings with no prefix and no leading
  zero; `(x, y)` is on the pinned curve, the low DP_BITS bits of `x` are zero,
  `2*y <= p`, `a` and `b` lie in `[0, n)`, and `a*P + b*Q == (x, y)` -- the same
  checks as the single-point checker, per element;
- `walker` is an integer in `[0, 2^64)` and `steps` an integer in
  `[0, MAX_STEPS]`, the walk's step cap: which walker of the pinned job
  produced the point and how far it walked, so that a sampled audit
  (`tools/rho_dp.py audit`) can re-run that walker from its derived start
  and confirm the point is where the shared walk actually leads;
- no two elements share `(x, y, a, b)`: a batch may not list one point
  twice, however it labels the copies.

A batch with one bad element is refused as a whole, naming the element. The
submitter verified every point locally before shipping it, so a bad one is
their mistake and nobody else's; refusing the batch keeps the checker a
yes/no certificate and keeps "which units were valid" out of the rules.

# What this does NOT decide

Whether `walker` and `steps` are true. Checking that costs the 2^DP_BITS steps
of the walk itself, which is why it is sampled by an auditor rather than run
here. The rules key a point's novelty on `x, y, a, b` alone -- the objective's
piecework block says `"key": ["x", "y", "a", "b"]` -- so a public point cannot
be re-minted by relabelling its provenance, and an element's `walker` and
`steps` are exactly as load-bearing as an audit makes them.
"""


def _inv(x, p):
    return pow(x, -1, p)


def _add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % CURVE_P == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + CURVE_A) * _inv(2 * y1, CURVE_P) % CURVE_P
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % CURVE_P, CURVE_P) % CURVE_P
    x3 = (lam * lam - x1 - x2) % CURVE_P
    return (x3, (lam * (x1 - x3) - y1) % CURVE_P)


def _mul(k, P):
    R, A = None, P
    while k:
        if k & 1:
            R = _add(R, A)
        A = _add(A, A)
        k >>= 1
    return R


def _hex_field(element, key):
    value = element.get(key)
    if not isinstance(value, str) or not value:
        return None
    if any(c not in "0123456789abcdef" for c in value):
        return None
    if len(value) > 1 and value[0] == "0":
        return None
    return int(value, 16)


def _check_point(element):
    """One element: the single-point rules, then provenance shape."""
    if not isinstance(element, dict):
        return "must be an object"
    if set(element) != {"x", "y", "a", "b", "walker", "steps"}:
        return "must carry exactly the keys x, y, a, b, walker, steps"
    values = {key: _hex_field(element, key) for key in ("x", "y", "a", "b")}
    for key, value in values.items():
        if value is None:
            return f"{key} must be lowercase hex with no prefix and no leading zero"
    x, y, a, b = values["x"], values["y"], values["a"], values["b"]
    if not (x < CURVE_P and y < CURVE_P):
        return "x and y must be field elements"
    if (y * y - (x * x * x + CURVE_A * x + CURVE_B)) % CURVE_P != 0:
        return "(x, y) is not on the curve"
    if x & ((1 << DP_BITS) - 1):
        return f"x is not distinguished: its low {DP_BITS} bits are not all zero"
    if 2 * y > CURVE_P:
        return "y is not canonical: need 2y <= p"
    if not (a < ORDER_N and b < ORDER_N):
        return "a and b must lie in [0, n)"
    walker, steps = element["walker"], element["steps"]
    if not isinstance(walker, int) or isinstance(walker, bool) or not 0 <= walker < 2**64:
        return "walker must be an integer in [0, 2^64)"
    if not isinstance(steps, int) or isinstance(steps, bool) or not 0 <= steps <= MAX_STEPS:
        return f"steps must be an integer in [0, {MAX_STEPS}]"
    got = _add(_mul(a, (GEN_X, GEN_Y)), _mul(b, (TARGET_X, TARGET_Y)))
    if got != (x, y):
        return "a*P + b*Q does not equal the claimed point"
    return None


def check(artifact: dict) -> tuple[bool, str]:
    if not isinstance(artifact, dict):
        return False, "artifact must be an object"
    if set(artifact) != {"dps"}:
        return False, "artifact must carry exactly the key dps"
    dps = artifact["dps"]
    if not isinstance(dps, list):
        return False, "dps must be a list"
    if not 1 <= len(dps) <= MAX_BATCH:
        return False, f"dps must carry between 1 and {MAX_BATCH} points; got {len(dps)}"
    seen = set()
    for index, element in enumerate(dps):
        why = _check_point(element)
        if why is not None:
            return False, f"dps[{index}]: {why}"
        point = (element["x"], element["y"], element["a"], element["b"])
        if point in seen:
            return False, f"dps[{index}] repeats an earlier point of the batch"
        seen.add(point)
    return True, f"verified: {len(dps)} distinguished points of the nums-50 walk (about 2^{DP_BITS} steps each)"


# -- the pinned instance and walk ----------------------------------------------
#
# Identical to checkers/nums_50_rho_dp.py: the same curve, P, Q, n, DP_BITS
# and the same pinned job document, so a point is a point of the same walk
# whichever objective it was submitted to. MAX_BATCH is the sizing from the
# design note; MAX_STEPS is the job's step cap (20 * 2^DP_BITS, the default
# `max_steps_per_walker` of 0 in the job).
CURVE_P = 1125899906842511
CURVE_A = 210121831610648
CURVE_B = 865344718369497
ORDER_N = 1125899953549127
GEN_X = 61889550517342
GEN_Y = 256352494150688
TARGET_X = 338269902425384
TARGET_Y = 412601840895064
DP_BITS = 16
MAX_BATCH = 64
MAX_STEPS = 20 << DP_BITS
JOB = "examples/certicom-ecdlp/jobs/nums-50-rho.json"
JOB_SHA256 = "feaba85065bf90880d2664ff775c807f69841613c368affb3add8da502012569"
JOB_ID = "bb124c668c79323b856c54372a720339895bcb4fd0599365bd7cf4706a4c855e"
