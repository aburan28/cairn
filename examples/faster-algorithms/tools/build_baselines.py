"""Emit the four baseline artifacts, and check each one against its evaluator.

Every artifact in `../artifacts/` is the *obvious* algorithm for its objective:
bubble sort, textbook Bellman-Ford, schoolbook matrix multiplication, and a row
at a time for MixColumns. None of them is good. That is the point -- they exist
so the commit-reveal loop can be exercised end to end, and so an improvement has
to beat the textbook rather than beat nothing.

No artifact here is near an optimum. Shipping one that exhausted a pool for the
price of `cat` would make the frontier decorative, which is the reasoning in
`examples/sorting-network/README.md` and it applies to all four.

    build_baselines.py            # rewrite the artifacts
    build_baselines.py --check    # verify the checked-in files match (CI)

The `--check` mode exists because these files are *derived* and an edited copy
would still verify -- it would just no longer be the algorithm the README says
it is. `scripts/derive-first-blood.py` guards its instances the same way and for
a stronger version of the same reason.
"""
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
EVALUATORS = HERE.parent / "evaluators"
ARTIFACTS = HERE.parent / "artifacts"


def load(name):
    """Import an evaluator by path, the way the node's harness does."""
    spec = importlib.util.spec_from_file_location(name, EVALUATORS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# Sorting network on 11 wires: bubble sort, 55 comparators.
# --------------------------------------------------------------------------
def bubble_network(wires=11):
    """Bubble sort with its comparisons fixed in advance, which is a network."""
    return [
        [j, j + 1]
        for i in range(wires - 1)
        for j in range(wires - 1 - i)
    ]


# --------------------------------------------------------------------------
# Relaxation schedule on 6 vertices: Bellman-Ford, minus the wasted edges.
# --------------------------------------------------------------------------
def bellman_ford_schedule(vertices=6):
    """Every edge, |V| - 1 times: Bellman-Ford exactly as it is written down.

    Nothing is trimmed, deliberately. Two easy improvements are sitting on top
    of this and both are left on the table: edges *into* the source can never
    help, because a simple path out of the source never returns to it; and
    whether |V| - 1 rounds are needed at all depends on the order the edges are
    swept in, since a round following a path's own direction picks up more than
    one of its edges. A baseline that had already taken those would be a
    baseline that did the reader's thinking for them.
    """
    edges = [[u, v] for u in range(vertices) for v in range(vertices) if u != v]
    return edges * (vertices - 1)


# --------------------------------------------------------------------------
# Matrix multiplication: schoolbook, 27 products.
# --------------------------------------------------------------------------
def schoolbook_products(n=3):
    """C[i][k] = sum_j A[i][j] * B[j][k], one product per (i, j, k)."""
    products = []
    for i in range(n):
        for j in range(n):
            for k in range(n):
                a = [0] * (n * n)
                b = [0] * (n * n)
                c = [0] * (n * n)
                a[n * i + j] = 1
                b[n * j + k] = 1
                c[n * i + k] = 1
                products.append({"a": a, "b": b, "c": c})
    return products


# --------------------------------------------------------------------------
# MixColumns: one output row at a time, sharing nothing.
# --------------------------------------------------------------------------
def naive_slp(rows):
    """XOR together the inputs each row selects, row by row.

    Shares no subexpression between rows, which is exactly the waste the bounty
    is about: the same parities are recomputed over and over.
    """
    operations = []
    outputs = []
    for row in rows:
        bits = [t for t in range(32) if (row >> t) & 1]
        if not bits:
            raise ValueError("a zero row would need a value this program cannot build")
        current = bits[0]
        for bit in bits[1:]:
            operations.append([current, bit])
            current = 32 + len(operations) - 1
        outputs.append(current)
    return {"operations": operations, "outputs": outputs}


# --------------------------------------------------------------------------
# Writing them out
# --------------------------------------------------------------------------
def render_file(artifact) -> str:
    """JSON with the innermost lists kept on one line.

    `json.dumps(indent=2)` puts every integer of every pair on its own line,
    which turns a 152-operation program into a seven-hundred-line file nobody
    will read. The bytes are what matter to the node and a reviewer is what
    matters here.
    """
    def render(value, depth):
        pad = "  " * depth
        if isinstance(value, list):
            if all(isinstance(item, int) for item in value):
                return "[" + ", ".join(str(item) for item in value) + "]"
            inner = ",\n".join(pad + "  " + render(item, depth + 1) for item in value)
            return "[\n" + inner + "\n" + pad + "]"
        if isinstance(value, dict):
            inner = ",\n".join(
                f'{pad}  "{key}": {render(item, depth + 1)}' for key, item in value.items()
            )
            return "{\n" + inner + "\n" + pad + "}"
        return json.dumps(value)

    text = render(artifact, 0) + "\n"
    # Parse it back before it is returned: a formatter that emits something the
    # node cannot read would fail at submission time, on somebody else's turn.
    json.loads(text)
    return text


def main():
    checking = "--check" in sys.argv[1:]
    ARTIFACTS.mkdir(exist_ok=True)
    failures = []

    def emit(filename, artifact, evaluator_name, expected):
        path = ARTIFACTS / filename
        evaluator = load(evaluator_name)
        actual = evaluator.score(artifact)
        note = "ok" if actual == expected else f"EXPECTED {expected}"
        if actual != expected:
            failures.append(f"{filename} scores {actual}, not {expected}")
        if checking:
            if not path.exists():
                failures.append(f"{filename} is missing")
            elif path.read_text() != render_file(artifact):
                failures.append(f"{filename} differs from its derivation")
                note = "DRIFTED"
        else:
            path.write_text(render_file(artifact))
        print(f"{filename:<40} score {actual:>4}  {note}")

    emit(
        "sorting-network-11-bubble.json",
        {"comparators": bubble_network()},
        "sorting_network_11",
        55,
    )
    emit(
        "relaxation-schedule-bellman-ford.json",
        {"relaxations": bellman_ford_schedule()},
        "relaxation_schedule",
        150,
    )
    emit(
        "matrix-multiply-3x3-schoolbook.json",
        {"products": schoolbook_products()},
        "matrix_multiply_3x3",
        27,
    )
    slp = load("xor_slp_mixcolumns")
    emit(
        "xor-slp-mixcolumns-naive.json",
        naive_slp(slp.target_rows()),
        "xor_slp_mixcolumns",
        152,
    )

    if failures:
        print()
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    if checking:
        print("\n--check: the four checked-in baselines match their derivation")
    else:
        print("\nall four baselines score as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
