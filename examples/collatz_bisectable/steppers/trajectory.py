"""One step of a Collatz trajectory, for interactive fraud proofs.

The same computation `checkers/long_trajectory.py` runs to completion, taken
apart into the smallest unit two parties can disagree about. That is the whole
requirement a stepper has to meet: `checker` answers "is this claim true" in one
expensive call, and `step` answers "what happens next" in one cheap one, and the
two must describe the *same* computation or a dispute settles the wrong way.

Why Collatz is the honest example rather than a flattering one: `n -> n/2 or
3n+1` is already a step function, so nothing had to be invented to make it
bisectable. An objective whose computation has no natural step is not made
bisectable by writing a stepper for it -- it is made bisectable by finding the
step, and if there isn't one, the objective stays on full re-verification. See
`src/challenge/stepper.rs`.

## The obligations, and why each one is here

- **Deterministic.** No clock, no randomness, no environment. A state that two
  honest machines disagree about cannot adjudicate a dispute, so a stepper with
  a nondeterministic step makes its objective unbisectable while looking
  bisectable, which is worse than not having one.
- **Total.** Every input state maps to some output state, including malformed
  ones. A stepper that raises on a state hands the adjudicator an
  `unavailable`, and a dispute that cannot be adjudicated stays open -- which is
  exactly what a liar wants. So a bad state steps to a `halted` state carrying
  the reason, and the liar who submitted it loses on comparison like anyone
  else.
- **Canonically representable.** Integers, never floats. `n // 2` and not
  `n / 2`: the second produces a float, floats have no canonical encoding, and
  the digest of a state nobody can agree on is the digest of nothing.
- **Fixed point at the end.** Once the trajectory reaches 1 it stays there, so
  a trace can be padded to any length without changing what it says. Two traces
  of different lengths cannot be bisected against each other at all, and this
  is what lets both parties commit to the same length.
"""

BOUND = 10_000_000


def step(state: dict) -> dict:
    """Advance one Collatz step. `{"n": int, "i": int}` in, the same out."""
    n = state.get("n")
    i = state.get("i", 0)
    if not isinstance(i, int) or isinstance(i, bool):
        i = 0

    # Bad states halt rather than raise. See the module docstring: an exception
    # here is an `unavailable` verdict, and an unadjudicable dispute is the
    # liar's preferred outcome.
    if isinstance(n, bool) or not isinstance(n, int):
        return {"halted": "n is not an integer", "i": i + 1, "n": 0}
    if not 1 <= n < BOUND:
        return {"halted": f"n outside [1, {BOUND})", "i": i + 1, "n": n}
    if "halted" in state:
        # Halting is absorbing, for the same reason 1 is: a trace must be
        # paddable to a fixed length.
        return dict(state, i=i + 1)
    if n == 1:
        return {"n": 1, "i": i + 1}
    return {"n": n // 2 if n % 2 == 0 else 3 * n + 1, "i": i + 1}
