# Index calculus over a prime field as a piecework objective

**Status: proposal.** Nothing here is built. It is the second instance of the
`piecework` primitive (the first is [`rho-piecework.md`](rho-piecework.md), built
in #143–#145),
and it is the one that primitive's own §9 Stage C names next:
[`src/piecework.rs`](../../src/piecework.rs) says at the top that "relation
collection for index calculus" is the same shape as a rho search — many
independent, individually checkable outputs, done when enough of them exist.
This note works out what that shape actually is for the elliptic-curve discrete
log over a prime field, writes the relation checker against the same
`certificate` contract the DP checker uses
([`examples/certicom-ecdlp/checkers/nums_50_rho_dp.py`](../../examples/certicom-ecdlp/checkers/nums_50_rho_dp.py)),
and is honest — §8 — about the fact that for NIST P-224 the resulting search
is astronomically slower than Pollard rho and buys no attack. What it buys is a
paid, verifiable pipeline for the one question that is genuinely open, and a way
for the network to pay per relation that checks while never paying for the
speedup nobody has proven.

Written against [`node.rs::settle_one`](../../src/node.rs),
[`piecework.rs`](../../src/piecework.rs),
[`frontier.rs`](../../src/frontier.rs),
[`examples/certicom-ecdlp/tools/nums.py`](../../examples/certicom-ecdlp/tools/nums.py)
(the nothing-up-my-sleeve curve derivation and the group arithmetic every
checker copies), and the rho piecework note it is a sibling of.

## 1. The gap this closes, and the one it does not

cairn pays for verified outputs, never for claimed effort, so an objective is
only as good as its smallest checkable unit. Pollard rho's unit is a
distinguished point: `2^d` group operations to make, two scalar multiplications
to check, and *also* the shared state the search runs on. That is why rho was
the first search cairn could pay for by the piece.

Index calculus has a unit with the same three properties and a different
internal shape. A **relation** is an equation

```
    a·P + b·Q  =  e_1·F_1 + e_2·F_2 + ... + e_t·F_t
```

where `F_1, ..., F_r` is a fixed **factor base** of points pinned by the
checker, and the right-hand side is a short combination of them. It is expensive
to find (you have to *decompose* a random point over the factor base — §2), it
is trivial to check (two multi-scalar multiplications), and it is the shared
state the search runs on: every relation is one more row of a linear system
whose solution is `k`. So it is proof of work that is also the work, exactly the
property that made a DP payable.

The gap this note does **not** close is the interesting one, and §8 is about it:
for a curve the size of P-224, finding even one relation by any known method
over a prime field costs far more than Pollard rho costs to finish the whole
problem. This note builds the machinery honestly and prices it honestly; it does
not claim a break, and the checker never pays for one.

## 2. The algorithm, devised

Fix `E: y² = x³ + a·x + b` over `F_p`, a point `P` of prime order `n`, and
`Q = k·P`. We want `k`. Baby-step/giant-step and Pollard rho both cost `√n`
group operations and know nothing about the structure of `F_p`. Index calculus
tries to do better by importing the one idea that makes ordinary finite-field
discrete logs subexponential: a **factor base**, **relations**, and **linear
algebra**.

**(a) The factor base.** Choose a set `V ⊆ F_p` and let the factor base be the
points of `E` whose x-coordinate lands in `V`:

```
    F  =  { R ∈ E(F_p) : x(R) ∈ V }.
```

`|F| ≈ 2·|V|` (two y for each x). The discrete logs `ℓ_i = log_P F_i` are
unknown; the whole search is a way to learn them.

**(b) The relation, via Semaev's summation polynomials.** To turn a random
point `R = a·P + b·Q` into a relation we must write `R` as a sum of `m` factor
base points, `R = F_{i_1} + ... + F_{i_m}`. Whether `m` points with
x-coordinates `x_1, ..., x_m` can sum (with some choice of signs on the y's) to
a point with x-coordinate `x_{m+1}` is decided by **Semaev's m+1-th summation
polynomial** `S_{m+1}`:

```
    S_2(x_1, x_2) = x_1 − x_2
    S_3(x_1, x_2, x_3) = (x_1−x_2)²·x_3²
                         − 2·((x_1+x_2)(x_1·x_2 + a) + 2b)·x_3
                         + ((x_1·x_2 − a)² − 4b·(x_1+x_2))
    S_{m}  =  Res_X( S_{m−k}(x_1, ..., x_{m−k−1}, X),
                     S_{k+1}(x_{m−k}, ..., x_m, X) )
```

`S_{m+1}(x_1, ..., x_m, x(R)) = 0` exactly when there exist points on `E` with
those x-coordinates summing to `R`. So a relation is found by solving

```
    S_{m+1}(x_1, ..., x_m, x(R)) = 0     with every x_j ∈ V,
```

then recovering the signs (which F_{i_j}, not its negation) by a scalar check.
That is the whole engine. The cost of the search is the cost of this one step,
repeated until enough relations exist.

**(c) The linear algebra.** Each solved decomposition is a row over `Z/nZ`:

```
    a + b·k  ≡  ℓ_{i_1} + ... + ℓ_{i_m}   (mod n)
```

— linear in the unknowns `{ℓ_i}` and `k`. Collect a little more than `|F|` of
them, solve the sparse system mod `n`, read off `k`. This step is standard
(Wiedemann/Lanczos mod `n`); it is not the bottleneck and, importantly for
cairn, it is a *view* over the log the way rho's collision index is (§7): it
reads accepted relations and moves no money.

The complexity is the product of two knobs pulling against each other. Small `V`
means a small system to solve but a rare decomposition (each `S_{m+1}=0` has a
solution in `V^m` with probability ≈ `|V|^m / p`); large `V` means easy
decompositions but a large system. Balancing them is where the asymptotic story
lives — and where, for prime fields, it falls apart.

## 3. The prime-field problem, and why P-224 is the name on the door

Step 2(b) hides everything. Solving `S_{m+1} = 0` **restricted to `x_j ∈ V`** is
a multivariate polynomial system, solved by a Gröbner basis (F4/F5). Two facts
govern it:

- `S_{m+1}` has degree `2^{m−1}` in each variable. The system's degree, and the
  Gröbner cost, blow up with `m`.
- The restriction `x_j ∈ V` is only cheap if `V` has a **low-degree
  parametrization** — a description as the image of a low-degree map, so
  "`x_j ∈ V`" becomes a few extra low-degree equations rather than a factor of
  `|V|`.

Over an **extension** field `F_{q^n}`, `V` can be a subfield or a vector
subspace, which has exactly that low-degree parametrization; this is the
Gaudry–Diem–FPPR line, and it is where the subexponential results for ECDLP
actually live. Over a **prime** field there is no subfield and no subspace, so
there is no obvious `V` with the property, and index calculus has no foothold.
That is the orthodoxy the 2016 result you pasted pushes on.

**Petit–Kosters–Messeng (2016)** propose the foothold: use the *multiplicative*
structure of `F_p*`. When `p − 1 = r · ∏ p_i` with all `p_i` small, `F_p*` has a
tower of subgroups, and the maps between successive quotients are low degree —
a chain that can play the role the subspace chain plays over `F_{2^n}`, letting
one define a `V` whose membership is expressible as low-degree equations. They
give **no concrete complexity**, and the talk you read reaches the only careful
conclusion available: worked against the criteria a parameter set would have to
meet to beat Pollard rho, the standardized curves **do not meet them**.

P-224 is the standard example because its prime is maximally friendly to the
precondition:

```
    p   = 2²²⁴ − 2⁹⁶ + 1
    p−1 = 2⁹⁶ · (2¹²⁸ − 1)
        = 2⁹⁶ · 3 · 5 · 17 · 257 · 641 · 65537 · 274177 · 6700417 · ...
```

`p − 1` is not just even — it carries a `2⁹⁶` smooth part and then splits into
the Fermat-number factors of `2¹²⁸ − 1`. If any prime field gives PKM its
subgroup tower to build `V` from, this one does. That is the entire reason
P-224's name is attached to the method — and it is a statement about a
*precondition being met*, not about an attack existing. Meeting the precondition
is necessary, not sufficient, and the sufficient part is unproven. §8 is where
that lands for what cairn should pay.

## 4. Concept map

The same table `rho-piecework.md` draws, for the relation search:

| index calculus | cairn | note |
|---|---|---|
| factor base `F = {R : x(R) ∈ V}` | constants pinned in the checker | `V` derived nothing-up-my-sleeve from the objective id, like the rho walk |
| a relation `a·P + b·Q = Σ e_i·F_i` | a claim's artifact | one relation per claim; batches under `items` (§5) |
| relation verification | the `certificate` checker | two multi-scalar mults + factor-base membership; microseconds |
| decomposition attempt (`S_{m+1}=0` over `V`) | the work behind one claim | the expensive step; unpaid until it yields a checkable relation |
| the relation matrix over `Z/nZ` | a derived *view* over the log | reads accepted relations, moves no money (like rho's DP index) |
| "enough relations" → solve → `k` | the answer objective, kind `certificate` | whoever runs the linear algebra first claims `k` |
| balancing `|V|` vs relation cost | the checker's fixed `V`, one number in the job | pinned; not the network's to tune mid-search |
| a linearly *dependent* relation | a novel-but-useless unit | the one place this is not like rho — §6 |

## 5. The relation as a paid unit

**The answer objective** is the existing shape: kind `certificate`, artifact
`{"k": "<hex>"}`, pinned to the same curve, `P`, `Q`, `n` as the demonstration
instances in [`examples/ecdlp/`](../../examples/ecdlp/). Unchanged.

**The work objective** is new: kind `certificate`, `piecework`, with a checker
that pins the curve **plus** the factor base `V` (as a derivation seed, so `V`
is inside the objective id) and the decomposition length `m`. The artifact is a
relation and nothing else:

```json
{
  "a": "…",
  "b": "…",
  "cols": [12, 12, 887, 40311],
  "signs": "+--+"
}
```

`a, b ∈ [0, n)`; `cols` is the sorted multiset of factor-base indices
`i_1 ≤ ... ≤ i_m`; `signs` picks `F_{i_j}` versus `−F_{i_j}`. The checker,
~50 lines on top of the `_add`/`_mul` every checker already carries:

- rejects any artifact whose keys are not exactly `{a, b, cols, signs}`
  (the exact-keys rule from the DP checker — nothing else may travel, or a
  copier re-mints a public relation by relabelling it);
- checks `a, b ∈ [0, n)` and `len(cols) == m`, `cols` sorted, `len(signs) == m`;
- reconstructs each `F_{i_j}` from its index by the pinned derivation of `V`,
  and rejects if any index is out of range or its x is not in `V`;
- computes `L = a·P + b·Q` and `R = Σ (signs_j ? F_{i_j} : −F_{i_j})` and
  requires `L == R` and `L ≠ O`;
- scores every malformed input as a rejection rather than raising, and
  re-derives nothing from the log — pure, integer-only, same contract as
  `nums_dlog.py`.

**Novelty key.** `piecework` keys novelty on the artifact digest by default,
which is wrong here: `(a, b, cols, signs)` and `(a+n, b, cols, signs)` are the
same relation with different bytes, and `a·P + b·Q` has many spellings. The
canonical unit is the relation's **effect**: reduce `(a, b)` mod `n`, and the
row it contributes is `a + b·k ≡ Σ ±ℓ_{i_j}`. Pin the key on the canonical
tuple by requiring the checker to reject non-reduced `a, b` (so `[a, b, cols,
signs]` *is* canonical) and set `"key": ["a", "b", "cols", "signs"]`. Then two
peers who find the same relation pay once, exactly as two peers reaching the
same DP do — and the batch form (`"items": "rels"`, one relation per element,
same key) ships a claim per hour of decomposition instead of a claim per
relation, the way rho batches DPs.

## 6. Piecework, or ratchet? The dependence problem

Here index calculus departs from rho, and the note has to face it. A relation is
novel (new bytes, new canonical tuple) yet **useless** if its row is a linear
combination of rows already in the log: it does not raise the rank of the system
and brings the solve no closer. Rho has no analogue — every distinct DP genuinely
enlarges the searched set. Paying `unit_price` per novel relation therefore pays
for redundancy that piecework's novelty rule cannot see, because novelty is
local (does this unit's bytes appear yet?) and rank is global (is this row in the
span of all the others?).

Two honest ways to price it, and the note picks the first:

- **Pay per relation, accept bounded redundancy (piecework).** Until the log is
  near `|F|` relations, a random relation is almost surely independent — the
  matrix is far from full rank and coincidental dependence is negligible. Only
  the last `O(1)` relations before the solve are likely dependent, so the
  overpayment is a small additive tail, the same shape as rho paying for the
  occasional overlapping trail (`rho-piecework.md` §7: "overlap is wasted
  compute, self-correcting, never an error"). This keeps novelty local and
  changes no consensus rule beyond §5's key. It is the right default.

- **Pay per rank increase (ratchet).** The frontier is the rank of the relation
  matrix mod `n`; a claim pays only if it lifts the rank. This pays for exactly
  the useful work and nothing redundant — but it makes settlement depend on a
  global linear-algebra fact the rules engine must recompute and agree on mod
  `n`, reintroducing exactly the global state piecework was designed to avoid,
  and a rank computation mod a 224-bit `n` over a growing matrix is not the
  microsecond check `certificate` promises. The ratchet primitive exists
  ([`frontier.rs`](../../src/frontier.rs)) and this *could* be built on it, but
  the cost is real and the benefit (that additive tail) is small. Rejected for
  the default; noted as the variant to reach for only if measured redundancy on
  a real instance justifies it.

So: piecework, per relation, with the canonical key. The dependence tail is
priced the way rho prices overlap — honestly named, self-correcting, small.

## 7. Solving for `k`, and who gets paid for it

Every node that verifies the log holds every accepted relation, so every node
can maintain a derived matrix `M` over `Z/nZ` and a target vector — a *view*,
like rho's DP index or `knowledge` over `relations`. When `M` reaches full rank:

- **Finding `k`.** A contributor runs the sparse solve locally
  (Wiedemann/Lanczos mod `n`), recovers `k`, and — the commit–reveal dance from
  `rho-piecework.md` §6 — commits a claim to the **answer** objective in the
  same epoch it commits its last relation, revealing both next epoch. Once the
  relations are public anyone can redo the solve, but the finder's commitment is
  already an epoch old.
- **The rules engine does not solve.** As with rho's `k`, "an agent proposes,
  only the rules engine disposes": the linear algebra is a derivation a node
  ran, not a payment the rules fire on their own. A solvable system nobody has
  claimed stays visible in the view and is claimable by anyone.
- **Progress.** `GET /frontier/{id}` reports `accepted / |F|` relations and pool
  remaining — an honest fraction only under the §6 assumption that accepted
  relations are mostly independent, which the view can spot-check by tracking
  rank lazily and flagging if it lags the count.

## 8. What this pays for, honestly

This is the section that keeps the objective from being a lie, and it is the
same verdict the CryptoPro talk reaches, priced.

**At P-224 this is not an attack.** Pollard rho finishes P-224 in ≈ `√n ≈ 2¹¹²`
group operations. Index calculus over `F_p` has to *find one relation* first,
and the only known way — solve `S_{m+1} = 0` restricted to `V` by Gröbner basis
— has no known parametrization of `V` over a prime field that makes the system
cheap (§3). The PKM subgroup-tower idea is a *candidate* parametrization keyed on
`p−1 = 2⁹⁶·r`; whether it yields decompositions cheaper than `2¹¹²` apiece is
**unproven and generally believed false at this size**. So the network must
never price this objective as though a relation is worth a share of breaking
P-224. It is not. A relation is worth one verified decomposition, and that is
all the checker certifies.

- **Honest decomposition.** One solved `S_{m+1}=0` over `V`, yielding one
  checkable relation. Cost dominated by the Gröbner step; enormous at 224 bits,
  seconds at toy sizes (§9). This is the useful work, and the only thing paid.
- **Random relations.** Pick random `(a,b)`, hope `a·P + b·Q` is *itself* a
  short factor-base combination: probability ≈ `(|F|/p)^m`, worse than honest
  decomposition by the same margin that made a factor base necessary. Irrational,
  self-punishing, never worth `unit_price`.
- **Dependent relations.** Novel bytes, no rank — priced as the redundancy tail
  of §6, not fraud.
- **Forged coefficients.** Impossible without `k`; the checker recomputes
  `a·P + b·Q` and the factor-base sum and compares points.
- **Relabelled copies.** Killed by the exact-keys artifact and the canonical
  §5 key, as relabelled DPs are.
- **Self-dealing.** The factor base `V`, like the rho walk and the `nums.py`
  instances, is derived from the objective id by hash — nobody chose it, so
  nobody planted a relation.

**What is actually open, and worth a paid pipeline anyway.** Whether the
smoothness of `p−1` can be turned into a `V` with a low-degree membership map
that makes decomposition cheap is a concrete, empirical, *unsolved* question.
A piecework relation-collection objective is the right instrument for it
precisely because it separates the two things cleanly: the network pays, per
relation, for decompositions that check — on toy curves where they run, and on
P-224 for anyone who thinks they have a cheaper `V` — and it pays **nothing** for
the conjecture. If the cheap `V` does not exist, the toy pipeline still
demonstrates a full index-calculus solve end to end (which cairn does not have),
the P-224 pool simply never drains, and no false claim was ever minted. If it
does exist, the relations that prove it are on the log, checkable by anyone,
each paid exactly its verified worth. Either way the honest thing gets built and
the unproven thing stays unpaid. That is the objective this note is for.

## 9. Sizing

The knob is `(V, m)`. Toy curves are where the decomposition runs; P-224 is
where it is named and does not.

| instance | `p` | rho cost `√n` | `m` | one honest decomposition | verdict |
|---|---|---|---|---|---|
| nums-30 (demo) | ~2³⁰ | ~2¹⁵ | 3 | Gröbner on `S_4`, milliseconds | runs; teaches the pipeline |
| nums-50 | ~2⁵⁰ | ~2²⁵ | 3–4 | seconds | runs; still far slower than rho |
| nums-60 | ~2⁶⁰ | ~2³⁰ | 4 | seconds–minutes | runs; rho already wins |
| **P-224** | 2²²⁴−2⁹⁶+1 | **~2¹¹²** | ? | **no known feasible `V`** (§3, §8) | named, not run; pool never drains absent a breakthrough |

The point of the toy rungs is the same as `examples/ecdlp/`'s: a full,
end-to-end, verifiable *demonstration* — factor base, relations, solve, `k` —
that a reader runs in seconds and that pins the checker contract. The P-224 row
exists to hold the honest open question and to be the objective a real result
would have to produce relations against. Its reward, like ECCp-131's under Stage
0, is notional: `unit_price × |F|`, claimed for nothing more.

## 10. Staging and concrete change list

**Stage A — the pipeline, on a toy curve, payable today.** No new consensus
rule: this is a second instance of the `piecework` block from
#144/#145.

1. `examples/certicom-ecdlp/tools/index_calculus.py`: derive `V` from a job id,
   the Semaev polynomials `S_2..S_{m+1}` and a Gröbner-based `decompose(R)`, the
   sparse solve mod `n`, and a `selftest` that runs a full solve on nums-30.
   Built on the existing `add`/`mul`/`is_prime` in
   [`nums.py`](../../examples/certicom-ecdlp/tools/nums.py).
2. `examples/certicom-ecdlp/checkers/nums_30_relation.py` (and `nums_50_…`): the
   §5 relation checker — exact keys, factor-base membership from the pinned `V`
   derivation, `a·P + b·Q == Σ ±F_i`. Docstring pins the `V` derivation so a
   second implementation matches, the way the rho checkers pin the walk.
3. `examples/certicom-ecdlp/jobs/nums-30-ic.json` and
   `objective-nums-30-relation.json`: the `piecework` work objective with
   `"key": ["a","b","cols","signs"]`, plus the batch variant `"items": "rels"`.
   The answer objective reuses `examples/ecdlp/`'s shape.
4. `docs/threat-model.md`: a row for the dependent-relation tail (§6, priced as
   redundancy) and one for a mis-derived `V` (rejected by the checker's
   membership test). `docs/coordination.md`: the decomposition search as a second
   worked example of "work split is a pure function" — a lane decomposes the
   random points `R` derived from its `work_assignment` slice.
5. A `cairn arena` scenario: a submitter relabels a public relation; expected
   verdict CLOSED (refused by the exact-keys + canonical key).

**Stage B — measure the tail.** Track matrix rank in the derived view, report
`rank` beside `accepted` on the frontier, and confirm on nums-50/60 that the
dependent-relation tail is the small additive thing §6 claims before any
non-toy pool is funded. Only if it is not does the ratchet variant (§6) earn its
cost.

**Stage C — P-224, if anyone has a `V`.** The P-224 work objective is a checker
that pins the real curve and a candidate factor base, and it is exactly the
place a claimed PKM-style construction proves itself: post the `V`, and if
decompositions against it check and are cheap, the relations are on the log and
paid; if they are not, the pool sits full. No consensus change — Stage C is a
JSON objective and a checker, and the honesty is structural, not editorial.

This mirrors `rho-piecework.md`'s own Stage C, which named this note into
existence. `piecework` is the primitive; the relation is its second instance,
and its most honest one — the objective whose value is in what it refuses to
pay for.
