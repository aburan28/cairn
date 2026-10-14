"""Evaluator: how close to the generic floor is a measured ECDLP bound?

The artifact is a *bound record*: the sealed output of aburan28/crypto's
ecbench harness (its `docs/bounds/README.md`), schema `ecbench.bound/v1`,
saying what a named ECDLP method cost in group-addition equivalents over
several curve sizes, with the per-size counts the figure was fitted from.
This objective is one domain of that frontier -- `ecdlp.single_target` on
prime-field curves with planted targets, one cold target, no precomputation,
at the toy tier (fields of at most 32 bits) -- and the README beside it is
where the rest is argued.

Scored as parts per million of the generic collision floor `sqrt(pi / 2A)
sqrt(r)`, maximised: 1 000 000 at the floor, the committed `rho.negation`
record 682 064, `bsgs.negation` 866 743.  Higher is closer to the bound
nobody beats generically, which is what the ratchet climbs toward.

# What it recomputes, and what it cannot

Everything the record lets it: every size's `S = mean_gae / sqrt(r)` and its
ratio to the floor `sqrt(pi / 2A)`, the pooled ratio as the run-weighted mean
over the sizes, the tier from the field sizes, the domain from its fields, the
unit, admissibility.  A record whose stated figures disagree with its own
counts is refused, as is one that measures time (the unit is counted, never
clocked -- the same rule `TIME_LIKE` enforces on a replay), one outside this
domain or tier, and one that is not admissible by its own account.

It cannot check that the sessions the record names exist and replay: a jailed
evaluator has no filesystem and no `ecbench`.  That is the measuring
repository's CI and an independent replay receipt, both cited by hash inside
the record.  An accept here is a receipt for a well-formed, self-consistent
frontier entry in this domain -- exactly that strong and no stronger.

# Invalid records score zero, never raise

This is a maximise objective, so zero is the worst score expressible and the
objective's `threshold` of 1 makes it a rejection.  A raise would be
`unavailable`, which settles nothing and could be provoked at will by
submitting garbage -- see ../../capset/evaluators/cap_set.py, which made the
same choice first.  Only the exceptions a hostile record can cause are caught;
a bug in this file still propagates, so a broken evaluator reads as an outage
and not as a rejection of every honest record.  The threshold and the
ratchet's `baseline` answer different questions: the threshold says whether an
artifact is a bound record at all, the baseline where paying starts, so a slow
but self-consistent method is accepted, pays nothing and does not take the
frontier.  `check` beside `score` returns the reason, for a submitter; the
node never calls it.

# Floats arrive as decimal strings

cairn's canonical encoding has no float variant, so a bound record as ecbench
writes it is refused at `propose`, `commit` and `score_candidate` before any
verifier runs.  The artifact is the record with every non-integer number
carried as its shortest round-trip decimal string, and `_num` reads both
spellings, so this file gives the same integer for the record as committed and
for the artifact as the node delivers it.

# Zero imports, constants in the text

The jail gives an evaluator its own source and nothing else, and the pinned
hash must cover everything it does.  The domain is bound by the constants
below, not by an argument, so one objective is one domain and one tier;
another domain is a copy with other constants, another hash, another
objective.

The arithmetic is IEEE-754 double precision, as the record's own figures are,
and the score is that arithmetic rounded to an integer.  Two nodes whose libm
differ in the last bit of a square root could in principle round a score one
part per million apart; `min_improvement` is four orders of magnitude above
that, and no accept can turn on it because every genuine record scores far
above the threshold of 1.

Returns an int.  Never a float -- see ../../../docs/verification.md for why.
"""

SCHEMA = "ecbench.bound/v1"
PROBLEM = "ecdlp.single_target"
FAMILY = "prime"
TARGET_KIND = "planted"
UNIT = "ecbench.gae"
TIER = "toy"
MAX_FIELD_BITS = 32
PI = 3.141592653589793
# Relative agreement required between a stated figure and its recomputation:
# the record's floats went through one JSON round trip, nothing more.
TOLERANCE = 1e-9
SCALE = 1_000_000
# What a record this checker refuses scores.  This is a *maximise* objective,
# so zero is the worst score expressible and the objective's threshold of 1
# turns it into a rejection; the sentinel is never a raise, because cairn
# reads a raise as `unavailable` and an outage is not a verdict.
INVALID = 0
# A record claiming to beat the generic floor more than tenfold is capped.  No
# bound in this domain can be there -- the target is the floor itself and the
# ratchet pays nothing past it -- and without a cap a crafted record could
# push the score outside the signed 64-bit range cairn stores, which it
# reports as a broken objective rather than a bad artifact.
SCORE_CAP = 10 * SCALE
# What `_evaluate` raises on a record it refuses.  Everything else -- a bug in
# this file -- propagates, so that a broken checker reads as `unavailable`
# rather than quietly rejecting every honest record.
REFUSALS = (KeyError, TypeError, ValueError, AttributeError, IndexError)


def _decimal(text):
    """A plain decimal literal -- `-12.5`, `596.4583333333334`, `1e-05` -- and
    nothing else `float()` would also take: no `nan`, `inf`, underscores,
    whitespace or Unicode digits, so a string reads as a number only when it
    looks like one.  `None` when it does not."""
    body = text[1:] if text[:1] == "-" else text
    if not body or not all(c in "0123456789.eE+-" for c in body):
        return None
    mantissa, marker, exponent = body.partition("e" if "e" in body else "E")
    whole, _, fraction = mantissa.partition(".")
    if not (whole.isdigit() or fraction.isdigit()):
        return None
    if (whole and not whole.isdigit()) or (fraction and not fraction.isdigit()):
        return None
    if marker:
        digits = exponent[1:] if exponent[:1] in ("+", "-") else exponent
        if not digits.isdigit():
            return None
    return float(text)


def _num(value, name):
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    if isinstance(value, str):
        parsed = _decimal(value)
        if parsed is None:
            raise ValueError(f"{name} must be a number or a decimal string")
        value = parsed
    elif not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError(f"{name} must be finite")
    return float(value)


def _int_like(value, name):
    # `r` is written as a JSON number while it fits 64 bits and as a decimal
    # string above that (ecbench `compat_u128`); the tier bound above keeps it
    # small here, but the reader accepts both forms rather than guessing.
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ValueError(f"{name} must be an integer or a decimal string")


def _close(stated, recomputed, name):
    denom = max(abs(recomputed), 1e-300)
    if abs(stated - recomputed) / denom > TOLERANCE:
        raise ValueError(
            f"{name} is stated as {stated!r} but recomputes to {recomputed!r} from the record's own counts"
        )


def check(artifact):
    """`(ok, detail)`: ok when the record is a self-consistent, admissible
    bound in this domain and tier, with the reason when it is not.  The
    diagnostic half of this file: cairn calls `score`, whose integer carries
    no reason, and this is what a submitter runs to learn why."""
    try:
        score_value, detail = _evaluate(artifact)
    except REFUSALS as exc:
        return False, f"refused: {exc}"
    return True, f"{detail}; score {score_value}"


def score(artifact):
    """The integer cairn reads: parts per million of the generic floor
    achieved, or `INVALID` for a record `check` would refuse.  Never raises
    on hostile input -- see the module docstring for why that is the whole
    difference between a rejection and an outage."""
    try:
        score_value, _ = _evaluate(artifact)
    except REFUSALS:
        return INVALID
    return score_value


def _evaluate(artifact):
    if not isinstance(artifact, dict):
        raise ValueError("artifact must be an object")
    if artifact.get("schema") != SCHEMA:
        raise ValueError(f"schema must be {SCHEMA}")
    bound_id = artifact.get("bound_id")
    if not isinstance(bound_id, str) or not bound_id.startswith("ECBND1h") or len(bound_id) != 19:
        raise ValueError("bound_id must be ECBND1h followed by 12 hex digits")
    domain = artifact["domain"]
    if not isinstance(domain, dict):
        raise ValueError("domain must be an object")
    for key, want in (("problem", PROBLEM), ("family", FAMILY), ("target_kind", TARGET_KIND), ("unit", UNIT), ("tier", TIER)):
        if domain.get(key) != want:
            raise ValueError(f"domain.{key} is {domain.get(key)!r}; this objective is {want!r}")
    envelope = domain.get("envelope")
    if not isinstance(envelope, dict) or envelope.get("targets") != 1 or envelope.get("precomputation") != "none":
        raise ValueError("domain.envelope must be one cold target with no precomputation")
    for word in ("wall", "second", "time", "clock", "ns"):
        if word in str(domain.get("unit")).lower():
            raise ValueError("a bound is never a wall-clock figure")

    admissibility = artifact["admissibility"]
    if not isinstance(admissibility, dict) or admissibility.get("status") != "admissible":
        raise ValueError("the record is not admissible by its own account")

    fit = artifact["fit"]
    if not isinstance(fit, dict) or fit.get("size_parameter") != "r":
        raise ValueError("fit.size_parameter must be r")

    sizes = artifact["sizes"]
    if not isinstance(sizes, list) or not sizes:
        raise ValueError("sizes must be a non-empty list")
    weighted = 0.0
    runs_total = 0
    seen = set()
    for index, row in enumerate(sizes):
        if not isinstance(row, dict):
            raise ValueError(f"sizes[{index}] must be an object")
        slug = row.get("slug")
        if not isinstance(slug, str) or not slug or slug in seen:
            raise ValueError(f"sizes[{index}].slug must be a distinct non-empty string")
        seen.add(slug)
        bits = _int_like(row["field_bits"], f"sizes[{index}].field_bits")
        if bits <= 0 or bits > MAX_FIELD_BITS:
            raise ValueError(f"sizes[{index}] has a {bits}-bit field; the {TIER} tier allows at most {MAX_FIELD_BITS}")
        r = _int_like(row["r"], f"sizes[{index}].r")
        if r < 5:
            raise ValueError(f"sizes[{index}].r is too small to measure")
        automorphisms = _int_like(row["automorphisms_available"], f"sizes[{index}].automorphisms_available")
        if automorphisms < 1:
            raise ValueError(f"sizes[{index}].automorphisms_available must be positive")
        verified = _int_like(row["verified"], f"sizes[{index}].verified")
        runs = _int_like(row["runs"], f"sizes[{index}].runs")
        if verified != runs or verified <= 0:
            raise ValueError(f"sizes[{index}]: {verified} of {runs} runs verified; every measured run must verify")
        floor = (PI / (2.0 * automorphisms)) ** 0.5
        _close(_num(row["floor_s"], f"sizes[{index}].floor_s"), floor, f"sizes[{index}].floor_s")
        mean_gae = _num(row["mean_gae"], f"sizes[{index}].mean_gae")
        if mean_gae <= 0:
            raise ValueError(f"sizes[{index}].mean_gae must be positive")
        mean_s = mean_gae / (r ** 0.5)
        _close(_num(row["mean_s"], f"sizes[{index}].mean_s"), mean_s, f"sizes[{index}].mean_s")
        ratio = mean_s / floor
        _close(_num(row["ratio_to_floor"], f"sizes[{index}].ratio_to_floor"), ratio, f"sizes[{index}].ratio_to_floor")
        weighted += ratio * verified
        runs_total += verified

    pooled = weighted / runs_total
    constant = artifact["constant"]
    stated = _num(constant["ratio_to_floor"]["value"], "constant.ratio_to_floor.value")
    _close(stated, pooled, "constant.ratio_to_floor.value")
    ops = artifact["dimensions"]["ops"]
    if ops.get("known") is not True:
        raise ValueError("dimensions.ops must be known")
    _close(_num(ops["value"], "dimensions.ops.value"), pooled, "dimensions.ops.value")
    provenance = artifact["provenance"]
    if _int_like(provenance["verified"], "provenance.verified") != runs_total:
        raise ValueError("provenance.verified does not equal the sum over sizes")
    if not isinstance(provenance.get("sessions"), list) or not provenance["sessions"]:
        raise ValueError("provenance.sessions must name at least one session")
    for index, session in enumerate(provenance["sessions"]):
        if not isinstance(session, dict):
            raise ValueError(f"provenance.sessions[{index}] must be an object")
        for key in ("session_id", "records_sha256", "dir"):
            if not isinstance(session.get(key), str) or not session[key]:
                raise ValueError(f"provenance.sessions[{index}].{key} is missing")

    if pooled <= 0:
        raise ValueError("the pooled ratio to the floor must be positive")
    value = min(int(round(SCALE / pooled)), SCORE_CAP)
    method = artifact.get("method", {}).get("id") if isinstance(artifact.get("method"), dict) else None
    detail = (
        f"verified: {method or 'method'} at {pooled:.4f} x the generic floor over "
        f"{len(sizes)} size(s) and {runs_total} runs in the {FAMILY} {TIER} domain"
    )
    return value, detail
