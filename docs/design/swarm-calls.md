# Swarm calls: share your compute, and let urgent work take it

**Status: prototype.** `src/swarm_calls.rs` and the `/swarm` routes in
`src/serve.rs` are built and tested. They are node-local memory, like leases
and heartbeats: nothing here is a record, nothing is gossiped, and nothing
moves money. The consensus-level step this would grow into is written down at
the end and is not built.

## What it is for

You install cairn and leave it running. Your machine is a **volunteer**: when
it is idle, it works on whatever the network most wants done that it can
serve, and it is paid as any worker is, by settlement of verified results. An
operator who wants an objective pushed raises a **call**: "I want eight
machines on this for the next six hours". Volunteers that can serve it start
on it. If a call is urgent enough, it can take a machine from work that matters
less. That is **preemption**, and the volunteer has to agree to it.

Three questions have to be answered for this to be safe, and the prototype
answers them in this order:

1. **Who decides what is urgent?** Escrow, not the caller. (§ The bid)
2. **When may a call take a machine that is already busy?** Only by a clear
   margin, only after a minimum stay, only with consent, and not too often.
   (§ Preemption)
3. **Who gets credit for what, and who pays for displaced work?** A
   contribution ledger that records compute given and charges displaced work
   to the call that caused it. It never becomes a balance. (§ Accounting)

## What the words mean

You said the "scoring or cost thing" reads badly and that you weren't sure what
it is called today. Today the code and docs mix five different ideas under two
or three words. Here is what each one is today, and the name this design
proposes:

| idea | today | where | proposed word |
|---|---|---|---|
| what a verified result is paid, from the funder's escrow | `reward`, "bounty", "payout" | records, settlement, `docs/economics.md` | **reward**. Keep it, and only use it for this. |
| what an agent's model calls cost the sponsor | `cost`, `eligible_spend`, "attributed provider expense" | `exploration.rs` (`cost_for_artifact`), `contributor_score.rs` | **spend**. It is a bill, not a score. |
| the compute a volunteer gave to an objective | not tracked before this prototype | `swarm_calls::Ledger` | **contribution**, in core-seconds |
| a reader's summary of how often someone delivers | "contributor score", "delivery score", success rate in ppm | `contributor_score.rs`, the reader | **standing**. "Score" already means the evaluator's frontier score, which is a real number in the record. |
| how urgently an objective wants more machines | "where compute is scarce" on the Goals page | `goals.rs` | **bid** |

The renames are a proposal, not done in this PR: they touch the reader, the
docs and some field names, and `eligible_spend` appears in signed
assignment receipts, so changing it there is a format change. The
prototype's own API already uses the proposed words.

The rule that keeps these straight: **reward and spend are money. Contribution
and standing are records about people. A bid is a ranking.** Nothing in the
second and third groups may ever be added to a balance.

## Calls

A call is `{objective_id, want, until, note}`.

- Only the node's **operator** raises or withdraws one: `POST /swarm/call` and
  `POST /swarm/withdraw` are refused (`403 operator_only`) unless the request
  came from loopback, was not forwarded, and supplied the configured operator
  Bearer token. They are disabled until a token is set. A fleet member key is not enough.
  Calls steer other people's machines, so they belong to whoever runs the
  node.
- The objective must be in this log, open and funded. A call on a settled or
  unfunded objective is `409 nothing_to_pay_for`: a call must never point
  machines at work nobody will pay for.
- `want` is 1 to 100 000 machines. A call lasts 60 seconds to a week, and
  raising it again renews it. A node keeps at most 64 calls.
- A call that has `want` live workers is **full**. A full call attracts
  nobody new, but it keeps the workers it has.

### Operator credential

A reverse proxy can connect from loopback without any forwarding headers.
The socket address therefore cannot establish who controls the node. Generate
a credential, keep it in the named secret store and pass it only to the server:

```sh
python3 -c 'import secrets; print(secrets.token_hex(32))' |
  cairn secret set CAIRN_SWARM_OPERATOR_TOKEN --stdin
cairn secret run --env CAIRN_SWARM_OPERATOR_TOKEN -- \
  cairn --log cairn.jsonl --root . serve --listen 127.0.0.1:8080
```

The value must be 64 lowercase hexadecimal characters. A configured invalid
value refuses server startup. To send a JSON call stored in `call.json`, pass
the credential as a header on stdin so it never enters curl's argument list:

```sh
cairn secret run --env CAIRN_SWARM_OPERATOR_TOKEN -- sh -c '
  printf "Authorization: Bearer %s\n" "$CAIRN_SWARM_OPERATOR_TOKEN" |
    curl --fail-with-body --header @- --header "Content-Type: application/json" \
      --data-binary @call.json http://127.0.0.1:8080/swarm/call
'
```

Use the same header for withdrawal. A missing or incorrect credential is
`403 operator_only`, including on loopback; the credential does not admit a
forwarded or remote request. Rotate it by replacing the secret and restarting
the server. Never expose this header through a public proxy or store it in a
recipe, log or repository. Like the other named secrets, it is readable by
processes running as the same OS user. Public advice and reports keep their
existing permissions and never change balances.

## The bid

```
bid = open_reward / (live_workers + 1)
```

That is the open escrowed reward per worker if one more machine joins. It is
the same figure the Goals page already shows as "where compute is scarce", so
the advice and the page cannot disagree.

The bid comes from escrow and not from anything the caller types. That is
deliberate. If a caller could set a priority, every call would be "urgent".
Here the only way to make a call outrank another is to fund the objective
more, or to have fewer people on it. The call itself only says "I want
machines on this now". Escrow says how much that is worth.

A volunteer only sees calls it can serve: the objective's resource
requirements (`ObjectiveCapabilities`) must match the volunteer's offer
(`scheduling::matches`). A GPU call never steals a laptop.

## Advice

`GET /swarm/advice?host=NAME&current=OBJ&held_for=S&preemptible=1` answers
with one of these:

| action | when |
|---|---|
| `idle` | no call this machine can serve and that isn't full |
| `start` | the machine is idle, or its current objective has closed or is unknown, and a call wants it. Leaving finished work is starting, not yielding. |
| `stay` | the machine is busy and the best call does not clear the preemption rules. `reason` says which rule. |
| `yield` | the machine should checkpoint its current work within `checkpoint_within` seconds and move to `to` |

When the host is registered (`POST /hosts`), its resources come from that
registration. Otherwise they come from `cpus`, `memory_mb` and `gpus` in the
query.

Advice is advice. A volunteer that ignores it loses nothing: settlement pays
verified results exactly as before. The routes never refuse work, and never
take a lease away.

## Preemption

A busy volunteer is told to yield only when all of these hold:

1. **Consent.** It said `preemptible=1`. The default is no.
2. **Margin.** The new call's bid is at least 3/2 of what its current work is
   worth per worker (`open_reward / max(live, 1)`). Small differences do not
   move machines. Without a margin, two calls of nearly equal value would
   bounce volunteers back and forth.
3. **Minimum stay.** It has held its current work for at least
   `max(min_hold, 600 s)`. A volunteer can ask for a longer stay but not a
   shorter one.
4. **Rate limit.** It has yielded fewer than 4 times in the last hour.

A yield carries `checkpoint_within = 120` seconds. That is time to save the
work and report it, not a deadline anyone enforces.

All of these are integer comparisons (`to_bid * 2 >= current * 3`), with no
floats near anything that is denominated in reward.

## Accounting

`POST /swarm/report` (a member route: a fleet member key may sign it, and
reserved names are refused as on heartbeats and leases) records:

```json
{"volunteer": "v1", "objective_id": "sha256:...", "core_seconds": 3600,
 "yielded_to": "sha256:...", "unsaved_core_seconds": 120}
```

- **Contribution** is core-seconds given to an objective. It is what "credit"
  means in this prototype: a record, shown per volunteer and per call on
  `GET /swarm`.
- **Displaced** work is the `unsaved_core_seconds` lost when a volunteer
  yielded. It is charged to the call that took the machine. A call that keeps
  preempting other work shows a growing displaced figure beside its
  contribution, so its cost to everyone else can be seen, not just its
  benefit.
- Reports are capped: one day of 1024 cores per report, 65 536 rows per node.
  Unsaved work can't exceed the work reported. An impossible report is
  refused, not clamped.

### Why contribution is not paid

A report is the volunteer's own word. Paying for core-seconds would pay for
whatever a machine claims to have burned. That is the "time as evidence"
attack, which the threat model already refuses for settlement. So:

- **Reward pays results.** Settlement of verified claims stays the only thing
  that moves balance.
- **Contribution records effort.** It is useful for standing, for thanks, and
  for an operator deciding whose machines to trust, and it is worthless as
  money by construction.

This is the "reasonable cost-accounting mechanism" in its prototype form:
compute is counted honestly where it can be (displaced work charged to
whoever caused it), and paid only where it can be checked.

## What it would take to make this consensus-level

The prototype is advisory and node-local. A version that actually moves value
for preemption would need, in order:

1. **An escrowed preemption premium.** A call becomes a signed record carrying
   an amount drawn from the caller's balance. A yield that the log can
   evidence (the displaced volunteer's lease end, then their claim on the
   calling objective) pays a premium from that escrow to the displaced
   volunteer. Unspent premium returns to the caller when the call expires.
   This is a consensus-surface change (records, settlement rules, the
   reference implementation) and needs its own review.
2. **Verified contribution.** Contribution counted from things the log can
   check (accepted orbit units, verified piecework from
   [orbit-piecework.md](orbit-piecework.md)), not from reported
   core-seconds. Only then could it feed standing that anyone relies on.
3. **Gossiped calls**, so a volunteer on one node sees calls raised on
   another. Each node would keep the operator-only rule for the calls it
   originates and rank calls from elsewhere by their escrow.

None of this changes the prototype's API. What changes is where the numbers
come from.

## What is not built

- `cairn work` acting on the advice by itself. Today a volunteer script polls
  `/swarm/advice` and acts on it. Building it into the worker loop is the next
  step.
- A reader page. `GET /swarm` is JSON.
- Persistence. Calls and the ledger are lost on restart, like leases.
