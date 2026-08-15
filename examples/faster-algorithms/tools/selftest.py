"""Check the four evaluators against the ways an artifact can cheat them.

Writing this list *is* the work of authoring an objective. A verifier that says
yes to the right artifact and also to a cheap fake is not a verifier, and the
failure is silent: the bounty pays, the frontier moves, and the result is
worthless. `src/verifiers/mod.rs` says the same thing about its own Lean
screens, and the reasoning does not change with the problem.

Three properties get checked for all four, because all four are minimise
objectives and all four die the same way if any of them is wrong:

1. **The sentinel is worse than every honest score.** On a minimise objective
   zero is the *best* score expressible, so an evaluator that returned zero for
   garbage would hand the frontier and the whole pool to the shortest possible
   nonsense -- an empty list.
2. **Padding costs.** Everything a submitter can add to an artifact must make
   their score worse, never better and never free.
3. **The check is real.** Removing a load-bearing piece of a valid artifact has
   to produce the sentinel, or the evaluator is measuring the shape of a
   submission rather than what it computes.

Run: python3 examples/faster-algorithms/tools/selftest.py
"""
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
EVALUATORS = HERE.parent / "evaluators"
ARTIFACTS = HERE.parent / "artifacts"

FAILURES = []


def load(name):
    spec = importlib.util.spec_from_file_location(name, EVALUATORS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def artifact(filename):
    return json.loads((ARTIFACTS / filename).read_text())


def check(label, actual, expected):
    ok = actual == expected
    print(f"  {'ok  ' if ok else 'FAIL'}  {label:<52} {actual}")
    if not ok:
        FAILURES.append(f"{label}: got {actual}, wanted {expected}")


def shared(module, name, valid, valid_score, junk_key):
    """The three properties every minimise evaluator in this family must have."""
    print(f"\n{name}")
    check("baseline verifies", module.score(valid), valid_score)
    # Property 1, in the form an attacker would actually try it.
    check("empty artifact is not zero", module.score({}), module.INVALID)
    check("empty list is not zero", module.score({junk_key: []}), module.INVALID)
    check("wrong type for the whole field", module.score({junk_key: "sort it"}), module.INVALID)
    check("no field at all", module.score({"unrelated": 1}), module.INVALID)
    # The sentinel has to be unreachable by an honest submission, or an honest
    # near-miss would be indistinguishable from garbage.
    assert module.INVALID > valid_score, f"{name}: sentinel is reachable"


# ---------------------------------------------------------------------------
sorting = load("sorting_network_11")
bubble = artifact("sorting-network-11-bubble.json")
shared(sorting, "sorting_network_11", bubble, 55, "comparators")

check(
    "a network missing its last comparator does not sort",
    sorting.score({"comparators": bubble["comparators"][:-1]}),
    sorting.INVALID,
)
check(
    "a duplicated comparator is counted, not ignored",
    sorting.score({"comparators": bubble["comparators"] + [[0, 1]]}),
    56,
)
check(
    "a comparator on one wire is refused",
    sorting.score({"comparators": bubble["comparators"] + [[3, 3]]}),
    sorting.INVALID,
)
check(
    "a wire out of range is refused",
    sorting.score({"comparators": bubble["comparators"] + [[0, 11]]}),
    sorting.INVALID,
)
check(
    "booleans are not wire 0 and wire 1",
    sorting.score({"comparators": [[True, False]] + bubble["comparators"]}),
    sorting.INVALID,
)
check(
    "a network longer than the cap is refused",
    sorting.score({"comparators": [[0, 1]] * (sorting.MAX_COMPARATORS + 1)}),
    sorting.INVALID,
)
# Every comparator kept, every direction flipped: this sorts, but downwards, and
# a network that sorts into the wrong order is not a sorting network.
#
# The obvious test here would have been to *reverse* the bubble network instead.
# It does not work, and finding that out is worth the line: a bubble network
# reversed is an insertion-sort network, which sorts perfectly well. Order does
# matter, but not in a way that survives being probed so bluntly.
check(
    "a network that sorts downwards is refused",
    sorting.score({"comparators": [[hi, lo] for lo, hi in bubble["comparators"]]}),
    sorting.INVALID,
)

# ---------------------------------------------------------------------------
relax = load("relaxation_schedule")
bellman = artifact("relaxation-schedule-bellman-ford.json")
shared(relax, "relaxation_schedule", bellman, 150, "relaxations")

check(
    "the enumeration finds every simple path out of the source",
    relax.TOTAL_PATHS,
    1 + 5 + 20 + 60 + 120 + 120,
)
check(
    "three rounds do not cover every path",
    relax.score({"relaxations": bellman["relaxations"][:90]}),
    relax.INVALID,
)
check(
    "every edge once is not a schedule",
    relax.score({"relaxations": bellman["relaxations"][:30]}),
    relax.INVALID,
)
# Feedback within a single step would let one occurrence of an edge stand in for
# a repeat, which is the bug that makes a wrong schedule look correct.
check(
    "an edge cannot be used before the edge that feeds it",
    relax.score({"relaxations": [[1, 2], [0, 1]]}),
    relax.INVALID,
)
check(
    "a self-loop is refused rather than ignored",
    relax.score({"relaxations": bellman["relaxations"] + [[2, 2]]}),
    relax.INVALID,
)
check(
    "a redundant relaxation is counted, not ignored",
    relax.score({"relaxations": bellman["relaxations"] + [[0, 1]]}),
    151,
)

# An improvement has to verify, or the bounty is unwinnable and nobody finds out
# until they have spent a submission. One relaxation is enough to prove the
# evaluator is not keyed to the baseline -- a *good* schedule is deliberately not
# published here, for the reason `examples/sorting-network/README.md` gives.
shortened = None
for drop in range(len(bellman["relaxations"])):
    candidate = bellman["relaxations"][:drop] + bellman["relaxations"][drop + 1 :]
    if relax.score({"relaxations": candidate}) == len(candidate):
        shortened = candidate
        break
check(
    "a schedule shorter than the baseline verifies",
    relax.score({"relaxations": shortened}) if shortened else None,
    149,
)


# The schedule evaluator decides correctness by matching subsequences and never
# relaxes anything, which is fast and is a *theorem* away from the property the
# objective actually cares about. So: a second implementation that does the
# obvious thing instead -- run the schedule, on the one weighting per simple path
# that the theorem's hard direction is proved with -- and a check that the two
# agree on every schedule tried. `scripts/differential.sh` makes the same
# argument about the two node implementations: agreement on valid input is not
# the interesting part, agreement on the boundary is.
INFINITE = 10**6


def simulate_correct(schedule):
    """Correct by simulation: 0 on the path, 1 everywhere else, one path at a time."""
    for path in relax.simple_paths():
        if len(path) < 2:
            continue
        on_path = {(path[i], path[i + 1]) for i in range(len(path) - 1)}
        distance = [INFINITE] * relax.VERTICES
        distance[relax.SOURCE] = 0
        for u, v in schedule:
            weight = 0 if (u, v) in on_path else 1
            if distance[u] + weight < distance[v]:
                distance[v] = distance[u] + weight
        if distance[path[-1]] != 0:
            return False
    return True


full = [tuple(pair) for pair in bellman["relaxations"]]
battery = [full[:cut] for cut in (0, 30, 60, 90, 100, 120, 150)]
battery += [shortened and [tuple(p) for p in shortened], full[::-1], full[::2], full[1:]]
battery += [sorted(full), sorted(full, reverse=True), full[75:] + full[:75]]
disagreements = [
    schedule
    for schedule in battery
    if schedule is not None
    and simulate_correct(schedule) != relax.covers_every_path(schedule)
]
check("subsequence-matching and simulation agree on 13 schedules", disagreements, [])

# ---------------------------------------------------------------------------
matmul = load("matrix_multiply_3x3")
schoolbook = artifact("matrix-multiply-3x3-schoolbook.json")
shared(matmul, "matrix_multiply_3x3", schoolbook, 27, "products")

zero = {"a": [0] * 9, "b": [0] * 9, "c": [0] * 9}
check(
    "a padding product is counted, not ignored",
    matmul.score({"products": schoolbook["products"] + [zero]}),
    28,
)
check(
    "dropping a product breaks the identity",
    matmul.score({"products": schoolbook["products"][:-1]}),
    matmul.INVALID,
)
perturbed = json.loads(json.dumps(schoolbook))
perturbed["products"][0]["a"][4] = 1
check(
    "one wrong coefficient is caught",
    matmul.score(perturbed),
    matmul.INVALID,
)
# Negating a product's left factor and its output factor together leaves the
# algorithm unchanged, so this must still verify: the check has to be the tensor
# identity and not a comparison against a canonical form.
negated = json.loads(json.dumps(schoolbook))
for product in negated["products"]:
    product["a"] = [-c for c in product["a"]]
    product["c"] = [-c for c in product["c"]]
check("a sign-flipped but equivalent algorithm verifies", matmul.score(negated), 27)
oversized = json.loads(json.dumps(schoolbook))
oversized["products"][0]["a"][0] = matmul.MAX_COEFFICIENT + 1
check("a coefficient out of range is refused", matmul.score(oversized), matmul.INVALID)
short_vector = json.loads(json.dumps(schoolbook))
short_vector["products"][0]["b"] = [0] * 8
check("a factor of the wrong length is refused", matmul.score(short_vector), matmul.INVALID)
check(
    "a float coefficient is refused",
    matmul.score({"products": [{"a": [0.5] * 9, "b": [1] * 9, "c": [1] * 9}]}),
    matmul.INVALID,
)

# ---------------------------------------------------------------------------
slp = load("xor_slp_mixcolumns")
naive = artifact("xor-slp-mixcolumns-naive.json")
shared(slp, "xor_slp_mixcolumns", naive, 152, "operations")

# The matrix is derived rather than pasted, so the derivation is what needs a
# test. MixColumns is an involution up to its inverse, but the property that
# pins it cheaply is this: multiplying by 02 then adding the input is 03.
check("02 * x xor x == 03 * x for every byte",
      all(slp.gf_mul(2, x) ^ x == slp.gf_mul(3, x) for x in range(256)), True)
check("the derived matrix has 32 rows", len(slp.target_rows()), 32)
check(
    "the naive program is one XOR per selected bit, less one per row",
    sum(bin(row).count("1") for row in slp.target_rows()) - 32,
    152,
)

check(
    "an operand naming a value that does not exist yet is refused",
    slp.score({"operations": [[32, 0]] + naive["operations"], "outputs": naive["outputs"]}),
    slp.INVALID,
)
check(
    "x xor x is refused rather than counted",
    slp.score({"operations": naive["operations"] + [[0, 0]], "outputs": naive["outputs"]}),
    slp.INVALID,
)
check(
    "a program with the wrong number of outputs is refused",
    slp.score({"operations": naive["operations"], "outputs": naive["outputs"][:31]}),
    slp.INVALID,
)
check(
    "an output naming the wrong value is refused",
    slp.score({"operations": naive["operations"], "outputs": [0] * 32}),
    slp.INVALID,
)
check(
    "a dead operation is counted, not ignored",
    slp.score({"operations": naive["operations"] + [[0, 1]], "outputs": naive["outputs"]}),
    153,
)

# The same proof-of-life as the schedule: a program shorter than the baseline has
# to verify. Two rows of MixColumns begin with the same pair of input bits, so
# sharing that one operation is a legal one-XOR improvement -- and one is all
# that is published here.
firsts = {}
remap = {}
shared_ops = []
for index, (left, right) in enumerate(naive["operations"]):
    # Only the operation that opens a row is a candidate: both its operands are
    # inputs, so an identical pair in another row is the same value. Chasing the
    # rest of the chain is the actual bounty and is not done here.
    opens_a_row = left < 32 and right < 32
    key = (left, right) if opens_a_row else None
    if key is not None and key in firsts:
        remap[32 + index] = firsts[key]
        continue
    remap[32 + index] = 32 + len(shared_ops)
    if key is not None:
        firsts[key] = 32 + len(shared_ops)
    shared_ops.append([remap.get(left, left), remap.get(right, right)])
shared_outputs = [remap.get(index, index) for index in naive["outputs"]]
check(
    "a program shorter than the baseline verifies",
    slp.score({"operations": shared_ops, "outputs": shared_outputs}),
    len(shared_ops),
)
check(
    "and it is genuinely shorter",
    len(shared_ops) < 152,
    True,
)

# ---------------------------------------------------------------------------
print()
if FAILURES:
    for failure in FAILURES:
        print(f"FAIL: {failure}", file=sys.stderr)
    sys.exit(1)
print("SELFTEST OK: four evaluators, sentinels worse than every honest score")
