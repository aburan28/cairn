# Goals and angles

Somebody says "let's solve ECC2K-130". Somebody else already posted an
objective paying for distinguished points from a distributed Pollard rho on
it. A third is funding a faster GPU kernel for the same walk, a fourth wants
index calculus tried instead, and a fifth is paying anyone who can make index
calculus faster. Five objectives, one problem -- and until now five rows in a
list with nothing to say they were the same thing, so the sixth person typed
`GOAL-ecc2k-130` where the first typed `GOAL-certicom-ecc2k130`, and the
network had two names for one goal.

This page is the concept that fixes that, the encoding (which already
existed), the tools that read it, and what it deliberately does not do.

## Three words

| word | what it is | where it lives |
|---|---|---|
| **goal** | the problem: ECC2K-130, the cap-set bound, a theorem | the `goal` handle every objective carries, `GOAL-<key>` |
| **angle** | an approach to it: distributed rho, a faster GPU kernel for rho, index calculus, speeding up index calculus | the path on the handle, `GOAL-<key>/<angle>[/<angle>]` |
| **objective** | one funded, checkable question under a goal and an angle | the record, unchanged |

A goal has many angles; an angle has many objectives (the single-solve
bounty and the per-unit batch on the same walk are two objectives on one
angle). Nothing above the objective is a record. The node reads the grouping
off the objectives on every request, and two readers of one log see the same
goals because they are a pure function of it.

## The encoding

```text
GOAL-<key>[/<angle>[/<angle>...]]

GOAL-certicom-ecc2k130                       the problem, no particular approach
GOAL-certicom-ecc2k130/rho                   Pollard rho on it
GOAL-certicom-ecc2k130/rho/distributed       a divided rho walk, paid per distinguished point
GOAL-certicom-ecc2k130/rho/gpu-kernel        making that walk faster on a GPU
GOAL-certicom-ecc2k130/index-calculus        a different method altogether
GOAL-certicom-ecc2k130/index-calculus/speedup  making that method faster
```

The **key** names the problem. The **angle path** names the approach, and its
segments nest: `rho/gpu-kernel` is a refinement of `rho` without any relation
record saying so, and a page shows it indented under `rho`. An objective
whose goal names no angle -- every objective posted before this convention --
has the empty angle. The reader shows it as *Approach N · tag*: `N` its place
among the goal's angles, `tag` the first characters of the first objective
funded under it, so it can be told apart from the next goal's and matched to
the challenge it came from. Opening any angle says what it is: its method
family when the name is one of the words below, otherwise that its funders
named none, and the statements of what is funded under it.

Why this and not a field: `goal` is a free string the rules never read, so a
convention inside it costs no consensus surface, moves no digest, and needs
no change to the reference implementation or the frozen conformance vectors.
`docs/design/workspace-benchmarks.md` turned down a `category` field for the
same reason, in the same words. A relation record between objectives
("accelerates", "variant of") was the other candidate and was not built: the
path carries the one relation that matters, refinement, and a second record
kind that paid nobody would be ceremony.

### The angle vocabulary

Names worth agreeing on, so that two people funding the same approach land
on the same angle. Lowercase, hyphenated, one or two segments; the first is
the method family.

| angle | what it covers |
|---|---|
| `rho`, `rho/distributed`, `rho/gpu-kernel`, `rho/negation-map`, `rho/tag-tracing` | Pollard rho and its engineering: the divided walk paid per distinguished point, the kernel that walks faster, the group-automorphism and iteration-function tricks |
| `kangaroo`, `bsgs` | the interval and baby-step giant-step methods, for a bounded exponent or a comparison |
| `index-calculus`, `index-calculus/relation-collection`, `index-calculus/linear-algebra`, `index-calculus/speedup` | the factor-base methods and their two halves, and work on making either faster |
| `reduction`, `reduction/weil-descent`, `reduction/cover` | moving the problem to a group where it is easier, and the covering-curve attacks |
| `hardware` | FPGA and ASIC walkers, costed |
| `formal` | a Lean theorem about the problem or an algorithm for it, checked by the kernel |
| `theory` | a bound, a conjecture made precise, a counterexample |

A new approach gets a new word; the list is a convention, not a schema, and
the node accepts any path. What the node will not do is guess: an angle is
what its funder wrote.

## Deduplication: one problem, one key

A goal's key is **normalised**: the `GOAL-` prefix, case, punctuation and
spacing are dropped, so `GOAL-certicom-ecc2k130`, `goal-Certicom_ECC2K-130`
and `Certicom ECC2K-130` are one key, `certicomecc2k130`. That alone does not
join `GOAL-ecc2k130` to it. The **catalog** does: [`launch/goals.json`](../launch/goals.json),
compiled into the binary (`CAIRN_GOALS=<file>` names another), lists the
problems people actually attack with the name they use and the spellings
they type --

```json
{"key": "certicom-ecc2k130", "name": "ECC2K-130",
 "aliases": ["ecc2k-130", "ecc2k130", "certicom ecc2k-130", "koblitz-131"],
 "family": "certicom", "summary": "The Certicom ECC2K-130 challenge: …"}
```

-- and every alias collapses to the catalog's key. So the sixth person's
`GOAL-ecc2k-130` lands under ECC2K-130 beside the first person's
`GOAL-certicom-ecc2k130`, and the page says *also written GOAL-ecc2k-130* so
the join is visible rather than silent. Two goals that are really one and
that no alias joins are shown as two, for a person to notice and add the
alias by pull request. Nothing is rewritten: an objective's goal is what its
funder wrote.

**Before you post** is the other half. A drafting tool asks the node which
goal a phrase names:

```sh
curl -s 'http://127.0.0.1:8080/goals?q=I+want+to+solve+ECC2K-130+with+index+calculus'
# -> {"matches": [{"key": "certicomecc2k130", "name": "ECC2K-130",
#                  "handle": "GOAL-certicom-ecc2k130", "handles": ["GOAL-certicom-ecc2k130", "GOAL-ecc2k-130"],
#                  "match": "alias", "objectives": 4, "open": 3,
#                  "angles": [{"path": "rho/distributed", …}, {"path": "rho/gpu-kernel", "parent": "rho", …}, …]}], …}
```

and posts the new objective as `GOAL-certicom-ecc2k130/index-calculus`
rather than inventing `GOAL-ecc2k130-ic`. A goal the catalog knows that
nobody has funded yet is found too, with nothing under it, so the first
objective on ECCp-131 is posted under the handle everyone will use. A match
is a suggestion from an alias list: it decides nothing, and an agent that
ignores it has merely made the list longer.

## Where it shows

| surface | what |
|---|---|
| `GET /goals` | every goal with its handles, aliases, angles and objectives; `live_workers` from heartbeats, reported and unverified; and `underserved`, below |
| `GET /goals?q=<words>` | the goals a phrase names, best match first, funded or only known |
| `GET /goals/{key}` | one goal by key or alias; a known, unfunded goal answers with nothing funded rather than 404 |
| MCP `list_goals`, `find_goal` | the same two, for an agent; `find_goal` is what [agents.md](agents.md) says to call before `post_objective` |
| the reader's **Goals** page (`/ui/goals`) | the grouping, a *Before you post* box that asks the node as you type, and *Where compute is scarce* |
| Cairn.app, **New Challenge…** | the same question asked of the description as you write it; a match offers to draft the challenge as a new angle on that goal, and the model is told the handle to use |

## Where compute is scarce

A goal page that only lists everything sends workers where workers already
are: to the angle with the famous name and the busy roster. `GET /goals`
therefore also ranks the angles that still have reward open, as
`underserved`, richest per worker first:

```
reward_per_worker = open_reward / (live_workers + 1)
```

`open_reward` is what the angle's open objectives have funded and not yet
paid, and `live_workers` is the heartbeat roster on those objectives. The
`+ 1` is the worker reading the list, and it keeps an angle nobody works from
dividing by zero. Integer arithmetic only, ties broken by open reward, then
fewer workers, then key and path, so two readers of one node rank alike. Each
row names the handle to work or post under and its open objectives, richest
first, and the Goals page shows the top ten with a link to the richest. MCP
`list_goals` has no roster, so it ranks by open reward alone.

It is a ranking, not a payment and not a dispatcher: nothing reads it but
people and agents choosing what to work on. Heartbeats are self-reported, so
a stranger can make an angle look busy, and the worst that buys is that the
list steers fewer workers there.

## What this does not do

- **It is not a record, a rule or a payment.** Nothing in `src/node.rs`
  reads a goal. Duplicate detection for *claims* is per objective and, for
  piecework, per job (`docs/economics.md`); a goal joins objectives for a
  reader, not for the rules engine.
- **It does not merge objectives.** Two objectives on one angle are two
  bounties; the page lists both. Whether to fund a second is the funder's
  call, and the page's job is to make sure it is a call.
- **It does not rename anything.** A misspelt goal stays misspelt in its
  record forever; the catalog joins it to its neighbours and shows the join.
- **It does not know what you meant.** `find` matches aliases and keys, not
  meaning. "the Koblitz curve challenge" finds ECC2K-130 only because
  `koblitz-131` is an alias somebody added; a new problem is found by nobody
  until it is posted once and, if it is worth a name, added to the catalog.
