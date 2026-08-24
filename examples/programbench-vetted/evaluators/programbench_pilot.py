"""cairn evaluator: behavioural reconstruction of a runnable program.

A pilot in the ProgramBench Vetted shape, small enough to read in full and
faithful in the one way that decides whether the benchmark can live on an
open network at all:

    the grading oracle is the reference *binary*, and the answer is its
    *source*. Publishing the oracle therefore hands a submitter nothing the
    task did not already hand them.

That is why this file may be published while a Terminal Tasks verifier may
not: a Terminal Tasks verifier holds held-out configurations and expected
values, so publishing it burns the task. Here the "binary" is `PROGRAM`
below -- an opcode list for the stack machine in `_run_reference`, exactly
the artefact an agent is given -- and reconstructing readable source that
matches its behaviour over inputs it has never seen is the work.

Contract (cairn `evaluator` kind): `score(artifact) -> int`, in basis
points, 0..10000. Integers only: IEEE-754 does not reproduce bitwise across
hosts, so a float score can compare differently on two honest nodes and
they will disagree about whether the threshold was met.

Purity: this file depends on the artifact and on nothing else. No file is
read, no clock is consulted, no network is touched, and the cases are
derived from `SEED` below, which is inside the file and therefore inside
the objective's id.

Escape hatches, enumerated before the checker runs (verification.md rule 2):

  1. **Ship the emulator.** A submission that embeds `PROGRAM` and
     interprets it reproduces the behaviour without reconstructing
     anything. Screened by `_embeds_reference`.
  2. **Reach outside.** `import`, `open`, `exec`, `eval`, `__import__`,
     dunder attribute walks. Screened by `_FORBIDDEN`; the restricted
     builtins are a second layer and the OS sandbox is the only real one.
  3. **Hang the verifier.** An infinite loop would time the whole run out,
     and a timeout is `UNAVAILABLE` -- an infrastructure fact, which would
     let a submitter deny service to an objective. Bounded by a line
     budget under `sys.settrace`, so a looping artifact scores 0 instead.
  4. **Crash the verifier.** Any exception out of submitted code is scored,
     never raised: an invalid submission is a bad artifact, an exception is
     a broken verifier (verification.md rule 3).
"""

import re
import sys

# -- the pinned instance --------------------------------------------------

SEED = 20260822
CASES = 200
MODULUS = 1000003
STEP_BUDGET = 400
LINE_BUDGET = 200000

# The "binary": machine code for the stack machine below, flat (op, arg)
# pairs. Assembled by tools/assemble.py; see that file for the listing.
PROGRAM = [
    1, 0, 3, 3, 7, 0, 13, 0, 10, 9,
    3, 1, 14, 0, 10, 19, 11, 30, 15, 0,
    0, 0, 3, 7, 5, 0, 1, 0, 4, 0,
    3, 1000003, 7, 0, 9, 0, 12, 0, 0, 0,
    1, 0, 2, 0, 3, 5, 7, 0, 8, 0,
    6, 0, 3, 1000003, 7, 0, 9, 0, 12, 0,
    0, 0, 1, 0, 13, 0, 5, 0, 4, 0,
    3, 1000003, 7, 0, 9, 0, 12, 0,
]

PUSH_ACC, PUSH_X, PUSH_I, PUSH_CONST = 0, 1, 2, 3
ADD, MUL, XOR, MOD, SHL = 4, 5, 6, 7, 8
STORE_ACC, JZ, JMP, HALT, DUP, SUB, POP = 9, 10, 11, 12, 13, 14, 15


# -- the reference machine ------------------------------------------------


def _run_reference(acc, x, i):
    """One step of the reference program: new accumulator from (acc, x, i).

    Bounded by STEP_BUDGET so a malformed PROGRAM cannot hang a node. The
    budget is a step count, never a duration: seconds measure the host, and
    two honest nodes must reach the same verdict.
    """
    stack, pc, steps = [], 0, 0
    while steps < STEP_BUDGET:
        steps += 1
        op, arg = PROGRAM[2 * pc], PROGRAM[2 * pc + 1]
        pc += 1
        if op == PUSH_ACC:
            stack.append(acc)
        elif op == PUSH_X:
            stack.append(x)
        elif op == PUSH_I:
            stack.append(i)
        elif op == PUSH_CONST:
            stack.append(arg)
        elif op == DUP:
            stack.append(stack[-1])
        elif op == POP:
            stack.pop()
        elif op == ADD:
            b, a = stack.pop(), stack.pop()
            stack.append(a + b)
        elif op == SUB:
            b, a = stack.pop(), stack.pop()
            stack.append(a - b)
        elif op == MUL:
            b, a = stack.pop(), stack.pop()
            stack.append(a * b)
        elif op == XOR:
            b, a = stack.pop(), stack.pop()
            stack.append(a ^ b)
        elif op == MOD:
            b, a = stack.pop(), stack.pop()
            stack.append(a % b)
        elif op == SHL:
            b, a = stack.pop(), stack.pop()
            stack.append(a << b)
        elif op == STORE_ACC:
            acc = stack.pop()
        elif op == JZ:
            if stack.pop() == 0:
                pc = arg
        elif op == JMP:
            pc = arg
        elif op == HALT:
            return acc
        else:
            raise AssertionError(f"unknown opcode {op}")
    raise AssertionError("reference exceeded its step budget")


def _reference(xs):
    acc = 0
    for i, x in enumerate(xs):
        acc = _run_reference(acc, x, i)
    return acc


# -- the cases, derived from the pinned seed ------------------------------


def _cases():
    """Deterministic inputs from SEED. A 64-bit LCG, so every node agrees.

    Inputs are non-negative: Python's `%` on a negative left operand differs
    from C's, and a task whose expected output depends on that is a task
    about language choice rather than about the program.
    """
    state = SEED
    out = []
    for _ in range(CASES):
        state = (state * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        length = 1 + state % 12
        xs = []
        for _ in range(length):
            state = (state * 6364136223846793005 + 1442695040888963407) % (1 << 64)
            xs.append(state % 10007)
        out.append(xs)
    return out


# -- screening ------------------------------------------------------------

MAX_SOURCE = 4000

_FORBIDDEN = (
    "import", "open(", "exec", "eval", "compile", "__", "globals", "locals",
    "getattr", "setattr", "delattr", "vars(", "breakpoint", "input(",
)


def _embeds_reference(source):
    """Is the machine code itself in here?

    Hatch 1: a submission that carries PROGRAM and interprets it matches the
    behaviour without reconstructing anything, and a behavioural grader
    cannot tell the difference by looking at outputs. So it is screened by
    looking at the source, which is the only place the difference exists.
    Twelve consecutive opcodes is the window: long enough that no ordinary
    reconstruction hits it by accident, short enough that reordering the
    program's blocks does not evade it.
    """
    literals = [int(n) for n in re.findall(r"\d+", source)]
    window = 12
    if len(literals) < window:
        return False
    pinned = [tuple(PROGRAM[i:i + window]) for i in range(len(PROGRAM) - window + 1)]
    seen = {run for run in pinned}
    return any(
        tuple(literals[i:i + window]) in seen
        for i in range(len(literals) - window + 1)
    )


_SAFE_BUILTINS = {
    "abs": abs, "bool": bool, "divmod": divmod, "enumerate": enumerate,
    "int": int, "len": len, "list": list, "max": max, "min": min,
    "pow": pow, "range": range, "reversed": reversed, "sorted": sorted,
    "sum": sum, "tuple": tuple, "zip": zip,
}


class _Budget(Exception):
    pass


def _load(source):
    """Compile the submission in a namespace with no way out.

    This is a guard rail, not a boundary. The boundary is the OS sandbox the
    node runs this whole file under -- seatbelt or bubblewrap, deny by
    default, no network. A restricted `exec` has been escaped many times and
    claiming otherwise here would be the oversold confinement this project
    warns about.
    """
    namespace = {"__builtins__": dict(_SAFE_BUILTINS)}
    code = compile(source, "<artifact>", "exec")  # noqa: S102 -- see docstring
    exec(code, namespace)  # noqa: S102
    run = namespace.get("run")
    if not callable(run):
        return None
    return run


def _bounded(run, xs, budget):
    """Call `run(xs)` under a line budget, so a loop scores rather than hangs.

    Hatch 3. A timeout would surface as UNAVAILABLE, which settles nothing
    and leaves the objective open -- so an artifact that never returns would
    be a free denial of service against the objective rather than a rejected
    submission.
    """
    remaining = [budget]

    def tracer(frame, event, arg):
        remaining[0] -= 1
        if remaining[0] <= 0:
            raise _Budget()
        return tracer

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        return run(xs)
    finally:
        sys.settrace(previous)


# -- the entrypoint -------------------------------------------------------


def score(artifact):
    """Basis points, 0..10000: the share of pinned cases reproduced exactly.

    Never raises on a bad artifact. Every rejection path returns 0, because
    an exception out of here is a broken evaluator, not a failed submission,
    and the two must not be confused.
    """
    if not isinstance(artifact, dict):
        return 0
    source = artifact.get("source")
    if not isinstance(source, str) or not source or len(source) > MAX_SOURCE:
        return 0
    lowered = source.lower()
    if any(token in lowered for token in _FORBIDDEN):
        return 0
    if _embeds_reference(source):
        return 0
    try:
        run = _load(source)
    except Exception:
        return 0
    if run is None:
        return 0

    cases = _cases()
    budget = LINE_BUDGET
    passed = 0
    for xs in cases:
        expected = _reference(xs)
        try:
            got = _bounded(run, list(xs), budget)
        except _Budget:
            return passed * 10000 // len(cases)
        except Exception:
            continue
        if isinstance(got, bool) or not isinstance(got, int):
            continue
        if got == expected:
            passed += 1
    return passed * 10000 // len(cases)
