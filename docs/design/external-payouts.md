# Paying out in Bitcoin or Ethereum

**Status: attribution preview built; payment rails are design only.**
`GET /payouts/{objective_id}` and the reader's External bounties page show
the default-policy contributor split from settled units. An amount entered in
the page is a local illustration, rounded down after aggregating by identity;
it is not a release receipt, since a real release must round separately per
settlement. No receiving address is registered or checked, no external funds
are proved, and nothing here moves Bitcoin, Ether or any other asset. The
remaining Phase 0 receipt and address work, and Phases 1 and 2 (§11), still
need implementation. Phases 0 and 1 change no record, hash or rule; Phase 2
adds one optional record kind and needs both implementations. §12 is the legal
analysis, and it is **not legal advice**: no phase that holds or moves value
should ship before counsel in each jurisdiction it touches has read it.

## 1. The gap

A settlement credits the network's own unit of account to the submitter it
names, and that is all a balance is: a number every node derives from the log
([economics.md](../economics.md)). Units mint only against an escrowed bounty,
are typed by verification tier ([tiers.md](../tiers.md)), and move only by the
rules: settlement, citation flow, bonds, slashes. The one place a wallet
appears is the funding authorization, an Ed25519 signature over an
objective's canonical bytes, which is why a Solana key is a valid funder
([serving.md](../serving.md)). Nothing connects a unit to anything held
outside the log, and [fleet.md](../fleet.md) says so in as many words.

So a funder who wants to pay for an answer in bitcoin has no way to promise
it that a solver can rely on, and a solver who is owed units has nothing to
redeem them for. Closing that gap means answering three questions, and the
answers are the design:

- **Who holds the funds** between the promise and the payment (§4)?
- **How is a unit converted** into an amount of a real asset (§5)?
- **Whom does it pay**, and how is that fixed before anyone knows who will
  win (§6)?

## 2. What it must guarantee

| | property |
|---|---|
| **P1** | **No custodian.** No single party -- not the project, not a node operator, not an attestor -- can move escrowed funds on its own. |
| **P2** | **The pay goes to whoever earned it.** The address a settlement pays was fixed by the earning identity's own key before the result existed; nobody can redirect it after. |
| **P3** | **No price oracle.** The exchange rate is fixed when the funder escrows, in the escrow's own terms. Nothing reads a market. |
| **P4** | **The rules do not read a chain.** Admission and settlement stay what they are, so every node keeps reaching one verdict from the log alone. A chain is downstream of the log, never an input to it. |
| **P5** | **A funder can always get unreleased funds back**, after a deadline, without anyone's cooperation. |
| **P6** | **The project never transmits money.** It publishes software and a design. It operates no wallet, no committee and no endpoint that funds pass through (§12). |

P4 is the one that shapes everything else. Bitcoin and Ethereum each have
their own finality, reorgs and fees. A rule that read either would make
cairn's settlement depend on them. That costs determinism, and it costs the
reference implementation, which would need a chain client to agree with the
primary. So the escrow observes the log, never the other way round.

## 3. The model

```
funder                      the cairn log                     a chain
──────                      ─────────────                     ───────
posts objective O,  ───►    objective O (reward R units)
reward R units
escrows A of asset X ─────────────────────────────────────►  escrow E(O):
  terms: O, X, A, attestors, threshold k, deadline            A of X, k-of-n
                            commitment, claim …
                            settlement S: u units to I  ───►  attestors audit
                            (and citation shares)             the log, and k of
                                                              them sign
payee I bound its address ─────────────────────────────────►  release(E, S):
  (signed by I's key, before S)                               ⌊A·u/R⌋ of X to
                                                              I's bound address
after the deadline, whatever was not released ─────────────►  back to the funder
```

Units stay the accounting. An escrow is a promise denominated in an outside
asset, made against one objective. It pays per settlement, in proportion to
the units that settlement credited. Nothing converts units in general:
**an escrow redeems the units its own objective paid, and nothing else.**
That is what makes conversion a matter of the escrow's terms and not of a
market (§5).

## 4. Who holds the funds

| option | who controls the funds | P1 | verdict |
|---|---|---|---|
| **A. Custodial pool**: an operator or the project holds a hot wallet and pays on settlement | that operator, alone | no | **refused.** It is a money transmitter in most jurisdictions (§12), a honeypot, and the thing P6 forbids |
| **B. The funder pays directly**, off-protocol, against settlement receipts | the funder, alone | n/a (nothing is escrowed) | **Phase 0.** Honest about what it is: a promise backed by the funder's reputation, the way most bug bounties work today |
| **C. EVM escrow contract**, released by a k-of-n attestor quorum chosen by the funder | nobody alone; k attestors together; the funder after the deadline | yes, while fewer than k collude | **Phase 1** |
| **D. Bitcoin taproot output**: key path a FROST k-of-n attestor key, script path a timelocked refund to the funder | the same | the same | **Phase 2** |
| **E. Discreet log contracts**: pre-signed outcome transactions, attested by an oracle | the two parties to the contract | yes | **no**: a DLC needs both parties at setup, and a bounty's payee is unknown until somebody wins |
| **F. Adaptor signatures**: the payment and the answer are one atomic swap | nobody; atomic | yes | **research** (§10): a private sale of one discrete log, which is a different product |
| **G. A cairn token**: an ERC-20 or similar mirroring units | whoever runs the bridge minting it | no | **refused** (§10) |

**C and D are a federation, and this design says so.** Neither chain can
check a cairn log. Ethereum has no Ed25519 precompile, and none for
ML-DSA-65, which signs checkpoints. Bitcoin's script checks neither. So
release rests on a quorum of people who audit the log and sign. The security
is exactly "fewer than k of the n collude", which is the security of most
bridges, and bridges with that shape have been robbed when keys were
concentrated. The design narrows the blast radius rather than pretending it
away:

- **The funder chooses the attestors**, per escrow. A natural set is the
  funder itself, an auditor the funder trusts, and one the solvers'
  community runs. With 2-of-3, the funder alone can neither pay itself back
  early nor refuse a settled claim.
- **One escrow per objective**, capped by what one objective is worth. No
  pooled vault.
- **The refund path needs no attestor** (P5). If the committee disappears,
  the funder still recovers what was never released, by timelock.
- **An attestor's signature is evidence.** A release that does not match the
  log is a signed statement anyone can check against the log. Attestors bond
  units in cairn ([bonded-verification.md](../bonded-verification.md)), and a
  docket can slash that bond. Slashing deters; it does not make the payee
  whole in bitcoin, and §13 says so.

Removing the federation needs the chain to check the settlement itself, by a
succinct proof of the log (§10). That is research, not Phase 1.

## 5. How conversion works

**Fixed at escrow, by the funder, in the escrow's own terms.** An escrow
states: the objective O, the asset X, the amount A in X's base units
(satoshis, wei, or the token's smallest unit), and implicitly O's reward R in
units, read from the log. A settlement S of O that credits u units to an
identity entitles that identity to

```
pay(S, I) = ⌊ A · u / R ⌋   base units of X
```

computed exactly, in integers wide enough for A·u (Solidity's `uint256` on an
EVM chain), and never in floats, as nowhere in cairn is.

- **No market, no oracle** (P3). The funder chose the rate by choosing A
  against R. A funder who wants solvers to bear no price risk escrows a
  stablecoin. A funder who escrows ETH or BTC passes the asset's volatility
  to the payee between escrow and payment, knowingly.
- **Citation flow is included.** A settlement whose claim cites others sends
  δ of its units upstream (`src/attribution.rs`), and each upstream identity
  is owed its proportional share of the same escrow. The payout set of a
  settlement is exactly the attribution's payout set, computed by the same
  deterministic rules, so every attestor reaches the same list.
- **Piecework is included.** An objective that pays per verified unit
  settles many times, and each settlement pays ⌊A·u/R⌋. The sum never
  exceeds A, because Σu ≤ R.
- **Remainders stay in escrow.** The floors leave at most one base unit per
  payee per settlement. They are refunded with everything else at the
  deadline. Nothing is rounded up, so nothing is paid twice.
- **Dust is not paid separately.** On Bitcoin, an output under the relay
  dust limit (a few hundred satoshis, by output type) is unspendable in
  practice. A payee whose share of one settlement falls below a stated floor
  is carried, by a fixed rule, into that settlement's largest output: the
  settling submitter's. On an EVM chain the floor is a stated minimum, chosen
  so that the gas to claim never exceeds the claim.
- **Tiers do not enter.** A tier says where a unit may be *spent* inside
  cairn. An escrow pays out the units its own objective credited, whatever
  their tier, and those units remain in the log, spendable or not, exactly as
  before. **Redeeming does not burn units, and must not:** the log knows
  nothing of chains (P4). An escrow pays at most once per settlement (§7).
- **Several escrows may back one objective.** Anyone can add a bounty by
  escrowing against an objective they did not post. Each escrow pays from its
  own A, and the payee collects from each. A funder who posts an objective
  with a nominal R and escrows A is pricing a unit of that objective at A/R.
  A second escrow prices it again, independently.
- **A settlement fee**, if a log ever declares one (proposed in
  [roles-and-rewards.md](roles-and-rewards.md), not built), takes its share in
  units before the payees'. An escrow then pays the fee's share to the address the
  fee pool binds, by the same formula. Until a log declares a fee there is
  nothing to pay.

## 6. Payout addresses

The address a settlement pays must be one the earning identity chose (P2),
before the result existed, so that nobody racing a solution can substitute
their own. Only key-shaped submitters can bind one: a nickname has no key to
sign with, so nickname submitters are not payable externally, which is right.

A **payout binding** is a statement signed by the identity's Ed25519 key,
under its own domain line, in the style of the fleet strings
([fleet-enrollment.md](fleet-enrollment.md) §4):

```
cairn-payout/1
identity <64 hex: the ed25519 submitter id>
chain <bitcoin | eip155:1 | eip155:8453 | …>
address <the address, in that chain's canonical text form>
seq <decimal, starting at 0>
previous <the address seq-1 bound, or nothing>
```

`eip155:<chainid>` is the CAIP-2 spelling of an EVM chain. A Bitcoin address
is segwit or taproot (bech32 or bech32m), in lowercase, so it has one spelling.

**Where it is published**, so that everyone checks the same order:

- **Phase 0**: handed to the funder with the receipt (§11). Ordering is the
  funder's business, because the funder pays.
- **Phase 1**: in a registry contract on the escrow's chain. Anyone may
  submit a binding with its Ed25519 signature. The contract cannot check
  Ed25519, so it only stores the binding with its block number, and attestors
  check the signature off-chain. The chain's own ordering is the binding's
  timestamp, with no cairn consensus change.
- **Phase 2**: an optional `payout_binding` record in the log, carried by
  both implementations, so bindings travel with the log and need no chain to
  order them.

**Which binding pays.** For a settlement S of an identity I, the binding used
is the latest one for I on that chain published at least D before S's epoch
closed (D is a stated delay, an hour by default). A binding published after a
result exists therefore cannot capture it.

**Rotation needs both keys.** `seq` 0 is signed by I alone. Every later
binding is valid only if it is signed by I **and** by the key of the address
it replaces: a BIP-322 message signature for a Bitcoin address, or EIP-191
for an EVM one. So a stolen cairn key cannot redirect future pay away from an
address its owner still controls. The cost is that losing the address's key
strands payouts until the owner binds again from a new identity, which is the
safer failure.

**Fleets.** A fleet's settlements name its leader
([fleet.md](../fleet.md)), so the leader binds the address and is paid. How
the leader shares with members is between them. The journal says which member
found what, and the pay is not split by protocol.

## 7. Release

An attestor is a person or service running the reference audit. It signs a
release only when every check below passes:

1. **The log is the operator's.** It verifies the log against a checkpoint
   signed by the operator's root key, with the key obtained out of band
   (`cairn verify --from … --root-key … --audit`), and re-runs the pinned
   verifiers it can. A log that does not audit gets no signature.
2. **S is final.** S is a settlement in that log, its epoch has passed the
   finality delay, and the attestor's own audit derives it.
3. **The payout set** is the attribution of S: each identity, with its units.
4. **The bindings.** Each identity's binding is chosen by §6, its signatures
   check, and each address is screened against the sanctions lists the
   attestor is bound by (§12). A listed address is refused, and its share
   stays in escrow.
5. **The amounts** follow §5.
6. **The escrow.** The escrow's terms name O, the escrow has not released S
   before, and the escrow chain's own state is final to the attestor's
   standard (a stated confirmation depth).

The message it signs has its own domain:

- **EVM**: EIP-712 typed data, with domain {name `cairn-escrow`, version 1,
  chainId, the escrow contract} and message `Release {objective, settlement,
  payees[], amounts[], deadline}`. The contract checks k distinct attestor
  signatures with `ecrecover`. A release can be submitted by anyone, since
  the payees are fixed in the signed message and the submitter gains nothing
  but the gas it spent. The contract records `settlement` as released, so
  every settlement pays at most once per escrow.
- **Bitcoin**: a transaction spending the escrow's output to the payees, plus
  change back to a new escrow output carrying the remainder. It is signed on
  the key path by a FROST threshold Schnorr signature (RFC 9591, adapted to
  BIP-340's x-only keys, from a distributed key generation such as the
  ChillDKG draft). On-chain it is one ordinary taproot spend, indistinguishable
  from a single signer's.

**Batching.** Releases can be batched per epoch, one transaction for every
settlement it closed, which matters on Bitcoin where every input and output
costs.

## 8. Ethereum, concretely (Phase 1)

One immutable contract per chain, with no owner, no upgrade path, no pause
and no fee. Sketch:

```
create(objective, asset, amount, attestors[], k, deadline) -> escrowId   // funder deposits
release(escrowId, settlement, payees[], amounts[], signatures[])          // anyone submits
refund(escrowId)                                                          // funder, after deadline
bind(identity, address, seq, ed25519Signature, rotationSignature)         // registry: stored, not checked
```

- **Assets**: ETH, and ERC-20s on an allowlist fixed at deployment (USDC,
  WBTC and the like). A fee-on-transfer or rebasing token would break
  Σpay ≤ A, so it is not allowed.
- **Where**: an L2 (Base, Arbitrum, Optimism) for the cost of a release
  measured in cents, or mainnet for the largest escrows. The design is
  chain-agnostic: the chain is in the escrow's terms and in the binding.
- **Pull, not push**: `release` credits payees, and each payee withdraws, so
  a payee contract that reverts cannot block the others.
- **Audited before any deployment holds real value.** The contract is small
  on purpose, and small contracts are where audits work.

## 9. Bitcoin, concretely (Phase 2)

An escrow is a taproot output with two spend paths:

- **key path**: the FROST aggregate key of the funder's chosen attestors,
  k-of-n;
- **script path**: `<deadline> OP_CHECKLOCKTIMEVERIFY OP_DROP <funder key>
  OP_CHECKSIG`, the refund (P5).

A release spends the escrow output to the payees and re-creates the escrow,
with the same keys and deadline, for the remainder. Piecework objectives,
which settle many times, therefore chain one output through their releases.
The funder's terms (O, A, the attestor set, k, the deadline) are published
with the output's address, so anyone can rebuild the output script and
confirm that the escrow is what it claims.

**Lightning** is a payout rail, not an escrow: an attestor quorum cannot hold
a channel open on a funder's behalf without becoming its custodian. A payee
who prefers Lightning binds an address whose operator swaps on-chain to
Lightning. That is the payee's choice and outside this design.

## 10. Research, and what is refused

**Selling a discrete log atomically.** cairn's flagship objectives are
discrete logarithms. On secp256k1 a bounty for the discrete log x of a point
X = xG can be paid atomically, with no attestor at all, by an adaptor
signature. The funder gives the solver a BIP-340 pre-signature on a
transaction paying the solver, encrypted under X. Only someone who knows x
can complete it. Completing it and broadcasting reveals x to the funder:
s_final − s_pre = x. The payment and the answer are one event, so neither
side can cheat the other. Two limits make it research and not a phase:

- **The curve.** The ECC2K challenges this repository works are on Koblitz
  curves over binary fields, and the ECCp ones on prime fields; none is
  secp256k1. Bridging them needs a cross-group proof that the committed x is
  also the challenge's discrete log, for instance a bitwise
  discrete-log-equality proof across groups (the construction used for
  Monero-Bitcoin atomic swaps, MRL-0010). It is feasible at these sizes and
  costs tens of kilobytes of proof per sale. It is not built anywhere this
  repository depends on.
- **The answer becomes private.** Only the funder sees x. That is a private
  sale, which cuts against cairn's model, where an admitted claim is public
  knowledge that later claims cite. It suits a funder who is paying for a
  secret, not one paying for a result.

**Proving settlement to the chain.** A succinct proof that a log under a
given checkpoint contains settlement S, verified by the escrow contract
itself, would remove the attestor federation. A zkVM can prove signature
checks, hashing and the settlement arithmetic today, at real but bounded
cost. Two limits remain:

- The proof says what the operator's log says. The checkpoint key is still
  the root of trust, as it is for every reader now.
- A proof can re-run a cheap certificate check. It cannot re-run a Lean
  compile, so for heavy verifiers the verdict itself would still be taken
  on trust.

Worth building when Phase 1's federation is the binding constraint.

**Refused: a cairn token.** An ERC-20, or any transferable instrument
mirroring units, would:

- put a bridge's mint key where §4 puts a capped escrow;
- make units an asset that people buy expecting a price to rise from the
  network's efforts, which is the shape the Howey test asks about (§12);
- break tiers, which exist so that cheaply earned units cannot be spent where
  expensive work is priced, and break the demand-gated supply that is
  [economics.md](../economics.md)'s whole argument.

Units stay accounting. Payouts are in assets that already exist and that this
project did not issue.

**Refused: converting units at market rates.** Paying any unit in any asset
at "the current price" needs a price, which means an oracle. It also needs a
market, and making that market is the business of an exchange. Fixing
conversion at escrow needs neither.

## 11. Building it, in phases

| phase | what | custody | consensus change |
|---|---|---|---|
| **0. Receipts** | `cairn payouts` reads the log and prints, for each settlement of an objective, the attribution's payees and their units. Given external terms (asset, A) it adds each payee's ⌊A·u/R⌋ and the binding the payee supplied. The funder pays by hand or by its own tooling. The reader shows a funder's declared external terms, labelled as a promise. | the funder's own wallet | none |
| **1. EVM escrow** | §8's contract, audited; `cairn attest payouts`, an attestor mode that audits, screens and signs releases; the registry; the reader shows escrows read from a chain RPC the operator configured, never consulted by the rules | nobody alone (k-of-n, funder-chosen); refund by deadline | none |
| **2. Bitcoin escrow** | §9's taproot escrow with FROST attestors; batching; the optional `payout_binding` record in both implementations | the same | **yes**: one optional record kind, both implementations, new conformance vectors |
| **R. Research** | adaptor-signature sales of discrete logs; zk settlement proofs | none (atomic), or none (proof-checked) | none, or the escrow contract's |

The attribution preview is the first part of Phase 0 and moves nothing. The
next part needs signed payee bindings that the funder can independently verify,
terms that pin the attribution parameters and rounding rule, and receipts
computed per settlement. Until then the page answers who earned how many
units, and illustrates an amount; it does not tell a wallet what to send.

## 12. The legal side

**Not legal advice.** What follows identifies the regimes a design like this
meets, so that counsel can be asked the right questions. It is written from
the United States, with notes on the EU and UK. Every jurisdiction a funder,
attestor or payee sits in has its own answers.

**Money transmission.** In the US, accepting and transmitting value that
substitutes for currency, convertible virtual currency included, is money
transmission. Under FinCEN's 2019 guidance (FIN-2019-G001) it makes the
transmitter a money services business: registration, an AML program,
suspicious activity reports, and the travel rule. On top of that come state
licenses: New York's BitLicense (23 NYCRR Part 200), California's Digital
Financial Assets Law, and the money transmitter laws of most other states.

- **The project must never be one.** Hence P6: no custodial pool (option A),
  no project-run committee, no hosted release endpoint. Publishing open-source
  software that people run themselves is, under the same guidance, not money
  transmission.
- **What the 2019 guidance says about Phase 1's shape.** A provider of
  unhosted, non-custodial wallet software is not a transmitter. A
  multi-signature arrangement whose participant lacks "total independent
  control" over the value is treated differently from a custodian. And a
  decentralized application's owners or operators can be transmitters when it
  transmits.
- **The open question.** An attestor quorum is the part counsel must look at
  hardest: whether attestors, separately or together, are operators that
  transmit. It is why the funder chooses its own attestors (often the funder
  itself among them), why the contract has no operator, and why the project
  operates no attestor. A funder who pays its own bounty through its own
  escrow is a payer, which is a different position from a service that moves
  others' money.

**Sanctions.** US persons may not pay a sanctioned person or a listed digital
currency address, and OFAC's lists name such addresses. That holds whatever
the custody arrangement and whether or not anyone is a money transmitter.

- **Attestors screen every payout address** at release (§7 check 4) against
  the lists they are bound by, and refuse a listed one. Its share stays in
  escrow and returns to the funder.
- **The contract itself screens nothing.** An immutable contract cannot be
  updated as lists change, and the Fifth Circuit's 2024 decision on immutable
  contracts (Van Loon v. Department of the Treasury) concerned whether such a
  contract can itself be sanctioned. It changes nothing about paying a listed
  person.
- **A funder bears its own sanctions duties** for what it escrows.

**Know your customer and AML.** The protocol identifies no one, and Phase 1
does not change that, because no regulated party sits in the payment path.
Where funders or payees use regulated on-ramps, those do their own checks. A
funder paying large bounties to unidentified payees should take advice on its
own AML exposure. The design leaves room for a funder to require identity
before it lists a payee's binding, and puts no such requirement on the
network.

**Securities.** A bounty paid in an existing asset for verified work is
compensation for work, not an investment. The line this design does not
cross is issuing an instrument people buy expecting profit from the efforts
of others (SEC v. W.J. Howey Co., 328 U.S. 293 (1946)). That is why units
stay non-transferable accounting and a cairn token is refused (§10). In the
EU, the Markets in Crypto-Assets Regulation (MiCA, Regulation (EU) 2023/1114)
governs issuers and service providers. Custody and transfer services are
licensed activities, which Phase 1's non-custodial contract is designed not
to be. The EU Transfer of Funds Regulation ((EU) 2023/1113) brings the travel
rule to crypto-asset transfers made by service providers. In the UK,
cryptoasset businesses register with the FCA under the money laundering
regulations.

**Tax.** In the US, digital assets are property for tax purposes. A payee
generally has ordinary income at the asset's fair market value when it
receives it, and a later sale is a capital transaction. A funder paying
prizes or awards may owe information returns (Form 1099-MISC in the US) above
a reporting threshold, and withholding for payees abroad. That requires
knowing who the payee is, which pushes toward funders collecting tax forms
before they list a payee's binding. These are the funder's obligations as
payer, not the protocol's. Phase 0's receipts are designed to be what a
funder's accountant needs.

**Prize and contest law.** A prize awarded for skill is lawful in most places
where a lottery is not, and the classic test for a lottery is prize, chance
and consideration together.

- **Prize and skill.** A cairn bounty is a prize for a verified result, which
  is skill.
- **Chance.** The settlement order within a batch is drawn from the epoch
  beacon, so when two valid claims land in one epoch, chance decides which is
  paid first ([fleet-enrollment.md](fleet-enrollment.md) §12 describes the
  race).
- **Consideration.** Submitting costs nothing today, so the third element is
  absent.
- **What would change that.** A future fee or bond required to *enter*, as
  opposed to one required to dispute, would add consideration to that
  element of chance. It must be reviewed under lottery and sweepstakes law
  before it ships.
- **Skill contests.** Some states regulate them too, with registration or
  disclosure duties above certain prize values. A funder running large public
  bounties should check them.

**Unclaimed property and consumer law.** A custodial pool would hold other
people's money and inherit escheat and consumer-protection duties. A
non-custodial escrow with a refund path does not, which is one more reason
option A is refused.

**What counsel should be asked, at minimum:**
1. Are attestors, or the deployer of the escrow contract, money transmitters
   in the jurisdictions involved? Does the answer change with who chooses the
   attestors?
2. What sanctions screening is required of attestors, and of funders?
3. What information returns and withholding apply to funders paying bounties
   in digital assets, and to whom?
4. Does any planned fee or bond create a lottery or sweepstakes?
5. Under MiCA and the UK regime: is any party a crypto-asset service provider?

## 13. Threat analysis

| adversary | can | cannot | residual |
|---|---|---|---|
| **k colluding attestors** | release an escrow's funds to addresses they choose, up to that escrow's balance | touch any other escrow, or the refund path's timing | the federation's risk, capped per escrow. Their signatures are evidence, and their cairn bonds are slashable, which deters and does not repay. **Not closed**; §10's proofs would close it |
| **n − k + 1 attestors who stall** | delay releases | keep the funds: the funder's refund needs no attestor | liveness, bounded by the deadline |
| **a dishonest funder** | choose attestors it controls | release early to itself without k signatures; keep funds past a release the quorum signed | a payee should look at who the attestors are before working on an escrow; Phase 1's reader shows them |
| **a thief of a payee's cairn key** | bind an address if the identity has none yet | redirect pay from an address already bound: rotation needs the old address's key too | bind early; an unbound identity's first binding is the race |
| **someone who races a result** | see a claim when it is admitted | bind a payout address in time: a binding must precede the settlement by D | -- |
| **a forked or edited log** | show an attestor a log that pays itself | pass an attestor's audit against the operator's signed checkpoint | an attestor must get the root key out of band, as every reader must |
| **a chain reorg** | undo an escrow's funding, or a release | make an attestor sign twice: the contract records the settlement, and attestors wait for confirmations | stated confirmation depths |
| **a sanctioned payee** | win a bounty | be paid by a screening attestor | the share returns to the funder at the deadline |
| **a fee-on-transfer token** | make Σpay exceed what the escrow holds | be escrowed: the allowlist is fixed at deployment | -- |

## 14. What this does not do

- **Change the rules.** Admission, settlement and balances stay derived from
  the log alone (P4). A unit means what it meant before. An escrow is a
  promise about some units, and their owners can be paid against it.
- **Convert balances in general.** Only units an escrowed objective paid are
  redeemable, and only against that escrow.
- **Remove trust.** Phase 1 and 2 trust a funder-chosen federation, capped
  and refundable, and say so. Removing it is §10's research.
- **Pay nicknames.** Only identities with keys can bind an address.
- **Split a fleet's pay.** The leader is paid and the journal records who
  found what ([fleet.md](../fleet.md)).
- **Settle any legal question.** §12 lists them, for counsel.
