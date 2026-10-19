# Experimental reasoning information contract

An executable contract model and exact adversarial experiments, using only
Python 3.10+ standard libraries. Local credits have no connection to Cairn
balances. This experiment does not run a model, measure cognitive effort,
verify a physical transfer, or implement a production oracle.

```sh
python3 -m unittest discover -s research/reasoning-contract -p 'test_*.py' -v
python3 research/reasoning-contract/experiment.py --output /tmp/information-report.json
diff -u research/reasoning-contract/experiment.json /tmp/information-report.json
```

The report is deterministic and pins the three experiment source files. These
hashes identify the files used for reproduction; they are not execution proofs.

## The contract

A sponsor freezes an initial forecast `b`, an independently resolved binary
question, and a finite number of report rights. A worker commits a forecast,
then reveals it while the answer remains hidden. For a report `p`, outcome
`y` in `{0,1}`, and probability scale `D`, the signed credit transfer is

```
delta(b, p, y) = (b - D*y)^2 - (p - D*y)^2
```

The next report uses the previous accepted report as its baseline. All accepted
reports close before the answer becomes public and settle together. The sponsor
reserves `D^2` credits and each report locks `D^2` worker credits **before** it is
accepted. A negative score transfers worker collateral to the sponsor; it is
the agreed loss on a forecast, not a misconduct finding. An unavailable outcome
returns the collateral and pays no score. Repeated resolution is idempotent.
An unsealed report cannot be revealed after the report window closes.

For a risk-neutral worker with belief `t/D`, the expected loss from reporting
`p` instead of `t` is exactly `(p-t)^2`. Therefore truthful reporting maximizes
expected score on the probability grid. For a worker acquiring a signal whose
posteriors average back to the prior, expected gross value of the update is
the variance of those posteriors in score units. The worker chooses to acquire
information when its expected score gain exceeds its private cost. This
rewards informative computation; tokens themselves never enter the transfer.
It does not establish that the sponsor's task value has the same shape as the
quadratic score, or that every model use is worth its bill.

The scoring rule and information-acquisition connection are established prior
art: [Gneiting and Raftery](https://doi.org/10.1198/016214506000001437),
[Papireddygari and Waggoner](https://arxiv.org/abs/2204.01773). This experiment
tests a proposed Cairn composition of sealed reports, finite purchased rights,
full collateral, and telescoping updates; it makes no claim of world-first
mechanism design.

## Results and negative controls

At scale 100, the report checks 30,603 belief/report/baseline combinations.
At scale 10, it checks 29,282 three-update paths and outcomes. The tests also
exercise the funded state machine, owner splitting, commitment substitution,
late reveals, missing outcomes, insufficient collateral and duplicate resolution.

| experiment | result in local credits |
|---|---|
| True belief 60%, frozen baseline 50%, full signed score | Best report is 60%; expected gain 100 |
| Same belief, pay only positive score changes | Best report becomes 100%; expected gain 1,500 versus 540 for reporting 60% |
| Reports 50% -> 100% -> 0% -> 100%, outcome 1 | Signed total 2,500; discarding losses pays 12,500 |
| No new information, zero enforceable collateral | Extreme reporting/default offers expected profit 1,250; honest signed score is 0 |
| Let a worker lower the starting baseline from 50% to 0%, final 100%, outcome 1 | Payment grows from 2,500 to 10,000 without a better final forecast |
| One owner versus three owners for the same funded update chain | Same total transfer; splitting labels buys no extra report rights |
| Hypothetical cheap/deeper signals with private costs 50/300 | Expected net gains 50/600; making the deeper signal cost 1,200 makes its net gain -300 |

The effort example uses declared hypothetical signal distributions, not measured
Claude performance. It is evidence about the stated contract model, not about
the deployed network, a population equilibrium, or observed model reasoning.

## What remains open

- The binary outcome must be independently checkable and unaffected by the
  worker after the forecast. A worker-controlled outcome breaks the argument.
  Predicting whether one's own unfinished submission will pass is unsafe;
  freeze its bytes first and enforce an independent resolution path.
- The model's owner labels have no authentication. There is no live deadline,
  external anchor, hidden benchmark service or resolution verifier. Calls to
  `close` and `resolve` are trusted experiment inputs. A sponsor must not be
  able to void a losing invoice by declaring a known outcome unavailable.
- A pending sealed report currently blocks later reports until closure. The
  regression test preserves this liveness gap. A pilot needs timed report
  rights, bounded expiry and measured withholding economics before rollout.
- Full collateral is capital-intensive. A newcomer with no collateral cannot
  use the contract. Relaxing the loss without redesign creates a default
  option; transferring losses to an underfunded public subsidy recreates it.
- Truthfulness here assumes expected-credit maximization. Risk preferences,
  outside bets, coordinated beliefs, task cherry-picking, information theft
  and answer leakage require separate analysis. Proper scoring alone is not
  a proof of coalition resistance.
- There are no fees per identity or update. Adding them can make splitting
  profitable even though the score differences still telescope. The sponsor
  purchases report capacity explicitly rather than paying anyone who arrives.

For a real Cairn result, the original objective checker and settlement rules
still apply. This model is not registered as a verifier and does not satisfy
the prescribed-execution gates in
[`execution-proof-chain.md`](../../docs/design/execution-proof-chain.md).
Network and queue candidates are developed in
[`experimental-mechanisms.md`](../../docs/design/experimental-mechanisms.md).
