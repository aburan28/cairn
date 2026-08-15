# Faster algorithms

Four open bounties for finding algorithms that do the same work with fewer
operations: sorting, graph search, matrix multiplication, and the linear step
inside AES.

| objective | problem | baseline | shipped | target |
|---|---|---|---|---|
| [sorting-network-11](objective-sorting-network-11.json) | sort 11 wires, fewest comparators | 58 | 55, bubble | 33 |
| [relaxation-schedule](objective-relaxation-schedule.json) | shortest paths on 6 vertices, fewest relaxations | 160 | 150, Bellman-Ford | 50 |
| [matrix-multiply-3x3](objective-matrix-multiply-3x3.json) | 3×3 matrix product, fewest multiplications | 30 | 27, schoolbook | 19 |
| [xor-slp-mixcolumns](objective-xor-slp-mixcolumns.json) | AES MixColumns, fewest XORs | 160 | 152, one row at a time | 90 |

None of the four has a known optimum, and the shipped artifact in every one is
the textbook algorithm rather than a good one. `python3 tools/selftest.py` and
`python3 tools/build_baselines.py` check the evaluators and rebuild the
artifacts; CI runs both.

## The rule that makes any of this fundable: count, never time

**"Faster" here is always a count of operations under a deterministic abstract
machine, derived by simulating the submitted artifact.** Nothing in this
directory times anything, and nothing may.

That is not fastidiousness, it is the only version of the question that can be
settled. Wall-clock seconds, CPU seconds, cache misses and FLOPS are properties
of the machine that ran the job, so two honest nodes verifying the same artifact
disagree by construction — and a frontier nobody can agree on is not a frontier.
The node already refuses this class of claim: `TIME_LIKE` in
`src/verifiers/mod.rs` denies `time`, `seconds`, `latency`, `throughput`,
`memory` and `flops` in a `replay` spec's reproducible fields, for exactly this
reason. An objective denominated in seconds is a claim about somebody's
hardware.

So each objective fixes a cost model precise enough that the count is a property
of the algorithm alone: comparators, relaxations, multiplications, XORs. Wire
delay, memory traffic and instruction-level parallelism are all outside it. That
is a real loss of fidelity and it is stated rather than hidden — a 35-comparator
network is not automatically the fastest on your machine, it is the smallest
under a model everybody can recompute.

## The rule that makes them safe to fund: simulate, never believe

Every score here is derived by **running the artifact**, not by reading a number
the submitter put in a field. [`../reversible-adder/`](../reversible-adder/) is
where that argument is made most sharply — compare it against `ecdsa-fail`,
which has the same shape and accepts declared numbers — and an evaluator that
trusts a declared metric is paying for a well-formatted assertion.

The consequence worth internalising before you submit: **your own opinion of
your artifact is worth nothing here, and so is a benchmark you ran.** Call
`score_candidate` — it runs the pinned evaluator, records nothing, and is ground
truth.

## The rule that keeps verification cheap: find the structural theorem

Each of these problems is "correct for all inputs", and all four are checked
completely rather than sampled, because in each case a theorem collapses an
infinite question into a small finite one:

| objective | the collapse | cost |
|---|---|---|
| sorting-network-11 | zero-one principle: sorts all 0/1 vectors ⟹ sorts everything | 2048 vectors, run as bitmask columns so one comparator advances all of them at once |
| relaxation-schedule | correct for every weighting ⟺ every simple path out of the source is a subsequence of the schedule | 325 paths, one pass |
| matrix-multiply-3x3 | bilinearity: the Brent equations over 3⁶ index tuples decide every input pair | ~17,000 exact integer multiply-adds |
| xor-slp-mixcolumns | linearity: a value is the parity of a set of input bits, so a 32-bit mask decides all 2³² inputs | one integer XOR per operation |

All four evaluators together score their baselines in under a tenth of a second.
That is the property `docs/consensus.md` says the design rests on — verification
costing about one evaluation is what lets this network skip designing an
incentive-compatible verification game at all. A bounty whose checker is
expensive is a denial-of-service surface aimed at the people doing the work.

**Sampling would have been easier and would have been wrong.** A relaxation
schedule tuned to a fixed set of test weightings passes a sampling checker and
is incorrect; nobody finds out until it ships. Finding the theorem *is* the work
of authoring one of these.

## The trap in every one of them: the sentinel is not zero

All four minimise. On a minimise objective zero is the **best** score
expressible, so an evaluator that returned zero for an invalid artifact would
hand the frontier — and the entire pool behind it — to the shortest possible
garbage: an empty list, which sorts nothing, relaxes nothing and computes
nothing.

All four also set `min_improvement` to 1, where the neighbouring examples use 2
or 3. That is deliberate and it is the one ratchet parameter worth thinking hard
about on an open problem: a 35-comparator sorting network beaten by one
comparator is a world record, and a ratchet with `min_improvement: 2` would
**refuse** it. The cost of 1 is that somebody holding a large improvement can
serve it in single steps — bounded by one epoch each, and cheap next to a
bounty that turns away the result it was funded to buy.

Every evaluator here returns a sentinel larger than any answer it will admit,
and `tools/selftest.py` checks that property first, for all four, in the form an
attacker would actually try it. The same trap is described in
[`../sorting-network/README.md`](../sorting-network/README.md) and
[`../golomb-ruler/`](../golomb-ruler/). It is the first thing to check in any
minimise evaluator, including one you write yourself.

## The four problems

### Sorting: 11 wires

A comparator network is oblivious and branch-free — the same compare-exchanges
run whatever the data — so the count is a property of the network. Eight wires
is settled at 19 and is the tutorial in `../sorting-network/`. Eleven is not:
the best published network has **35** comparators, and the best published lower
bound is **33**, from Van Voorhis applied to the proved S(10) = 29:
S(11) ≥ 29 + ⌈log₂ 11⌉. The pool is exhausted only by closing that gap.

### Graph search: an oblivious relaxation schedule

The graph-search analogue of a sorting network, and the reason to read this
directory if you are judging the design. A schedule is a fixed sequence of edge
relaxations, written before the weights are known, that must compute correct
shortest-path distances for *every* weighting with no negative cycle.

The criterion that makes it checkable is as sharp as the zero-one principle and
proved in the evaluator's docstring in five lines: a schedule is correct for all
weightings **exactly when** the edges of every simple path out of the source
appear in it, in order, as a subsequence. One direction is the path-relaxation
property; the other is one weight function per path — zero on the path, one
everywhere else.

`tools/selftest.py` implements that predicate a second time by *simulation*,
running each schedule against those witness weightings, and requires the two to
agree on thirteen schedules including the ones that fail.
`scripts/differential.sh` makes the same argument about the two node
implementations: agreement on valid input is not the interesting part.

Textbook Bellman-Ford is 150 relaxations and is shipped, untrimmed. Two easy
improvements sit directly on top of it and are deliberately left there: five of
the thirty edges point back at the source and can never be needed, and whether
five rounds are needed at all depends on the order the sweep visits edges in,
since a round running with a path's direction picks up more than one of its
edges.

The floor is not 25 either. For any three non-source vertices the three paths
through them in rotation force `(u,v)` before `(v,x)` before `(x,u)` before
`(u,v)`, so at least one edge of every such triangle appears twice. Where the
real floor is, nobody knows.

### Matrix multiplication: 3×3

The canonical faster-algorithm problem. Strassen did 2×2 in 7 rather than 8;
for 3×3 the best published algorithm is Laderman's **23**, from 1976, and the
best published lower bound is **19**. Half a century, several machine searches,
and a gap of four.

The artifact is the algorithm: R products, each a linear combination of A's
entries times one of B's, plus the combination of those products that forms C.
Verification is the Brent equations in exact integers.

Coefficients are integers in [-2, 2]. This will bite a gradient-descent search
and the constraint is not removable — no float goes anywhere near identity or
money in this network, so "close enough" cannot be expressed here. A numerically
discovered decomposition scores as invalid until it is rounded to exact integers
and re-checked, and rounding a near-solution usually breaks it. Every published
3×3 algorithm fits in {-1, 0, 1}, so the best known result is inside the box.

### The one that is not abstract: MixColumns

AES MixColumns is GF(2)-linear, so it is a fixed 32×32 binary matrix and every
implementation of it is a straight-line program of two-input XORs. The obvious
program costs **152**. Published implementations reach the low nineties. Finding
shortest linear straight-line programs is NP-hard and no optimum is known.

An XOR removed here is an XOR removed from real hardware and from bitsliced
software, which is why the literature on it exists.

The 32 target rows are **derived** in the evaluator from the AES field and the
FIPS-197 circulant, not pasted in as constants. A pasted table is unreviewable,
and one wrong bit would be a bounty that pays for a program computing something
that is not MixColumns.

## Why no good artifact ships

Every artifact in `artifacts/` is the textbook algorithm and none is close to an
optimum. That is the same call `../sorting-network/README.md` makes: these are
funded to be *worked*, and an artifact in the repository that took a large slice
of a pool for the price of `cat` would make the frontier decorative.

The two places where the self-test needs to prove that an *improvement* verifies
— not just the baseline — it uses the smallest improvement that exists: one
relaxation, one XOR. Enough to show the evaluator is not keyed to the baseline,
and not enough to be worth copying.

## Run one

```sh
export CAIRN_EPOCH_SECONDS=1
LOG=/tmp/pw-faster.jsonl

OID=$(./target/release/cairn --log $LOG --root . \
        post examples/faster-algorithms/objective-sorting-network-11.json \
        | head -1 | awk '{print $2}')

./target/release/cairn --log $LOG --root . try "$OID" --submitter you \
  --artifact examples/faster-algorithms/artifacts/sorting-network-11-bubble.json --settle

sleep 3 && ./target/release/cairn --log $LOG --root . settle
```

That accepts at 55 against a baseline of 58 and moves the frontier three steps
of the twenty-five between the baseline and the target. The remaining
twenty-two are the actual problem.

**The second call is not redundant.** `try --settle` waits out the reveal epoch,
but a batch is not eligible until it has been closed for `FINALITY_EPOCHS`
further epochs, so the first call reports `nothing moved for this claim in the
batch that just closed` — which reads like a rejection and is not one. See
[`../../docs/design/settlement-convergence.md`](../../docs/design/settlement-convergence.md).

## If you are writing a fifth one

The pattern these four share, in the order the decisions have to be made:

1. **Fix a cost model that is a property of the algorithm.** If the honest
   answer to "how fast is it" is "depends on the machine", the objective cannot
   be settled and no amount of care downstream fixes that.
2. **Find the theorem that makes the check complete.** Sampling is the failure
   mode, and it is a quiet one.
3. **Derive the score by simulating the artifact.** Never read it off a field.
4. **Make the sentinel worse than every honest answer** — on minimise, larger.
5. **Write down how an artifact could satisfy the checker while missing the
   goal**, and test each one. That list is the real work; `tools/selftest.py`
   is this directory's copy of it.

`cairn scaffold <name> --kind evaluator` writes the skeleton. It posts nothing,
because funding a statement is a decision a person makes after reading it.
