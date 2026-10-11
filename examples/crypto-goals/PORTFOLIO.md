# Cryptographic objective portfolio: 100 slots

This is a curation ledger for growing Cairn's cryptographic objectives. It is
not a claim that every proposed challenge is already an open problem or bounty.
The first 37 entries point to objectives already in the repository; entries
38–100 are candidate additions to investigate and turn into independently
checkable Cairn objectives.

## Admission rule

A candidate becomes an objective only after its maintainer records a fixed
instance and provenance, defines a bounded artifact schema, implements and
pins a deterministic checker, and exercises positive and adversarial cases.
The checker must establish the stated mathematical or computational result
from the submitted artifact. A performance claim needs a reproducible,
matched benchmark protocol; self-reported timings are not a certificate.
Unknown or unavailable verification must remain distinct from rejection.
Repeated parameter thresholds count separately only when they represent
independent, useful instances and do not disclose a known answer as a bounty.

“Candidate” means a research direction, not a promise that a useful public
instance exists. Before posting one, check the source challenge's current
status, solution disclosures, redistribution terms, and whether the proposed
artifact can prove the claim without trusting its submitter.

## Existing objectives (37)

These repository objectives supply the initial 37 of the 100-slot target.
Some are demonstrations or optimization tasks rather than unsolved public
cryptanalysis challenges; their presence here does not imply otherwise.

| # | Existing objective | Family |
|---:|---|---|
| 1 | `examples/aadp-witness-encryption/objective.json` | witness encryption |
| 2 | `examples/bound-frontier/objective-ecdlp-prime-toy.json` | ECDLP measurement record |
| 3–15 | `examples/certicom-ecdlp/objective-*.json` (13 objectives) | Certicom, ECC2K, NUMS and rho batches |
| 16 | `examples/ecdlp/objective.json` | discrete-log demonstration |
| 17–18 | `examples/ecdsa-fail/objective*.json` | ECDSA circuit cost |
| 19–22 | `examples/elliptic-rank/objective*.json` (4 objectives) | rank certificates and record variants |
| 23–27 | `examples/first-blood/objective_*.json` (5 objectives) | prime-field ECDLP instances |
| 28–35 | `examples/hash-differential/objective-*.json` (8 objectives) | hash collisions and differential paths |
| 36 | `examples/faster-algorithms/objective-xor-slp-mixcolumns.json` | AES MixColumns straight-line program |
| 37 | `examples/secp256k1-modadd/objective.json` | secp256k1 modular addition circuit |

## Candidate additions (63)

### Elliptic-curve and group problems

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 38 | ECC2K-130 independent relation-set improvement | Replayable relation records and independently derived rank contribution against the pinned instance |
| 39 | ECC2K-130 alternate orbit decomposition | Exact orbit coverage, no duplicate relations, and rank novelty recomputed from the submitted data |
| 40 | ECC2K-130 sparse linear algebra certificate | A verifiable solution to the pinned linear system plus a reproducible operation and memory profile |
| 41 | ECC2K-130 end-to-end relation yield record | Source, parameters, all accepted relations, and independently recomputed yield |
| 42 | ECC2K-130 memory-reduced solver | Same fixed matrix and result, with a deterministic resource-measurement protocol |
| 43 | Certicom ECCp-131 distinguished-point rho result | A collision path that independently replays to the discrete logarithm |
| 44 | New prime-field ECDLP instance with proof-bound answer | Fixed curve, subgroup, point and target; answer is checked by scalar multiplication |
| 45 | Composite-order elliptic-curve DLP decomposition | Correct factorization of subgroup order and valid logarithm in every prime-power component |
| 46 | Pairing-group discrete logarithm certificate | Fixed pairing parameters and exact verification of the claimed scalar relation |
| 47 | Supersingular isogeny path-shortening record | A checked chain of explicit isogenies with endpoint and degree verified |

### ECDSA and signature analysis

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 48 | ECDSA nonce-reuse key recovery on a fixed corpus | Recovered public key verifies against every signed message and signature |
| 49 | Partial-nonce leakage lattice recovery | Exact lattice input, candidate private key, and full signature verification |
| 50 | Biased-nonce recovery under a pinned leakage model | Model parameters and successful public-key reconstruction from the fixed corpus |
| 51 | Chosen-message ECDSA nonce-bias distinguisher | Reproducible samples, fixed statistical test, and calibrated false-positive bound |
| 52 | Minimal reversible secp256k1 scalar-multiplication circuit | Circuit semantics checked against reference vectors and cost counted from its gate list |

### Factoring and integer groups

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 53 | RSA-100 factorization replay | Two nontrivial factors whose product is the pinned integer |
| 54 | RSA-129 factorization replay | Two nontrivial factors whose product is the pinned integer |
| 55 | RSA-155 factorization replay | Two nontrivial factors whose product is the pinned integer |
| 56 | RSA challenge record with reproducible NFS relations | Relation set and square congruence replayed from the pinned modulus |
| 57 | RSA modulus factorization using a disclosed shared prime | GCD derivation plus primality checks for the factors |
| 58 | Pollard rho factorization of a pinned semiprime | Exact factors and a transcript sufficient to replay the method's state transitions |
| 59 | ECM factorization record for a fixed composite | Valid factor plus a replayable curve and stage transcript |
| 60 | Smallest-factor record for a bounded semiprime family | Factorization and a proof that no smaller factor exists in the declared range |

### Finite-field discrete logarithms

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 61 | Prime-field DLP challenge from a published benchmark set | Scalar multiplication verifies the answer against fixed parameters |
| 62 | Finite-field DLP relation collection | Every relation replays and the target logarithm follows from the pinned linear system |
| 63 | Finite-field DLP linear-algebra certificate | Exact solution of the declared sparse system with residual zero |
| 64 | Pohlig–Hellman decomposition challenge | Correct component logarithms and CRT recombination verified exactly |
| 65 | DLP in a subgroup with a published smooth-order trap | Factorization of the order and independently checked recovered logarithm |

### Symmetric cryptanalysis and implementation

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 66 | Reduced-round AES-128 differential characteristic | Round-by-round state propagation and exact differential probability derivation |
| 67 | Reduced-round AES linear approximation | Exact bias computed from the pinned S-boxes and linear masks |
| 68 | Reduced-round PRESENT differential trail | Exact trail transitions and probability from the pinned permutation and S-box |
| 69 | Reduced-round Speck differential trail | Exact modular-addition differential transitions and round replay |
| 70 | Reduced-round Simon differential trail | Exact bit-vector round propagation and trail probability |
| 71 | AES key-schedule related-key distinguisher | Key schedule and all claimed differential constraints checked from fixed vectors |
| 72 | ChaCha reduced-round distinguishers on a fixed round count | Exact test harness, fixed corpus generation and independently replayed score |
| 73 | Constant-time AES implementation refinement | Equivalence against a reference plus a machine-code timing-leakage audit protocol |

### Hashes and message authentication

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 74 | SHA-256 reduced-round collision | Distinct messages, equal digest under the explicitly reduced-round function |
| 75 | SHA-256 reduced-round preimage | Message whose digest matches the pinned target under the specified reduced-round function |
| 76 | SHA-3 reduced-round differential trail | Exact Keccak state transitions and probability for the declared round subset |
| 77 | BLAKE2 reduced-round collision | Distinct inputs and equal output under the exact reduced-round specification |
| 78 | HMAC truncated-tag forgery in a bounded reduced-key instance | Transcript replay against the exact key, tag length and verification procedure |
| 79 | Chosen-prefix collision for a reduced-round hash | Two chosen prefixes extended to a collision under the pinned function |
| 80 | Chosen-prefix collision cost record for a published hash challenge | Full collision artifact and a reproducible, source-pinned resource ledger |
| 81 | Merkle-tree second-preimage construction in a constrained hash model | Exact tree and leaf witness checked against the declared hash and encoding |

### Lattice and post-quantum cryptography

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 82 | LWE secret recovery on a fixed public sample set | Exact secret reproduces every sample under the pinned modulus and noise vector |
| 83 | LWE distinguisher against a fixed seeded instance | Full sample set, deterministic decision rule and checked distinguishing margin |
| 84 | SIS short-vector solution for a published matrix | Exact modular product and norm bound verified from the artifact |
| 85 | NTRU challenge instance decryption key | Exact polynomial relation and successful encryption/decryption test vectors |
| 86 | Module-LWE secret recovery on a reduced parameter set | Exact module arithmetic and all sample equations checked |
| 87 | Kyber/ML-KEM decapsulation-failure analysis instance | Fixed implementation, seed, trace and independently reproduced failure classification |
| 88 | Dilithium/ML-DSA signing leakage recovery instance | Recovered key verifies the public key and every pinned signature |
| 89 | Concrete lattice reduction record on a public basis | Reduced basis is checked exactly and the cost protocol records full input and resources |

### Protocol, zero knowledge and formal crypto

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 90 | Schnorr protocol transcript forgery under a flawed nonce rule | Forged transcript accepted by the pinned verifier with all equations replayed |
| 91 | Fiat–Shamir transcript malleability counterexample | Minimal counterexample accepted by the pinned flawed verifier and rejected by the corrected one |
| 92 | Zero-knowledge proof circuit constraint reduction | Same relation and soundness assumptions, with constraints counted from canonical circuit bytes |
| 93 | Threshold-signature rogue-key attack reproduction | Fixed protocol transcript accepted by the vulnerable verifier and rejected by the repaired verifier |
| 94 | Certificate-chain parser differential test | Minimal encoded certificate and two pinned parser outcomes with a reproducible divergence |

### Elliptic-curve arithmetic records

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 95 | New independent rank-30 curve with a distinct j-invariant | Exact rational points and independence certificate, plus exact j-invariant comparison |
| 96 | Rank-31 curve with lower invariant height than the current baseline | Exact rank certificate and integer comparison of the declared height invariant |
| 97 | Largest verified consecutive conductor gap in a pinned range | Exhaustive range, complete conductor list and proof/checksum of the enumeration procedure |
| 98 | Largest verified normalized conductor gap in a pinned range | Explicit normalization, exhaustive input range and independently replayable enumeration |

### Reproducibility and cryptographic engineering

| # | Candidate | Evidence a checker should require |
|---:|---|---|
| 99 | Best verified gate-count secp256k1 scalar multiplication | Semantics checked against reference vectors; canonical gate list and deterministic count |
| 100 | Best verified memory-time tradeoff for a pinned ECC2K stage | Same mathematical output and input, with full-charge and reproducible resource accounting |

## Suggested implementation order

Start with exact certificate objectives whose answers can be checked quickly:
RSA factorization, Pohlig–Hellman, SIS, fixed-instance LWE recovery, reduced-
round hash collisions, and replayable signature recovery. Then add research
objectives that need costly computation or statistical controls. Reserve the
two conductor-gap entries and performance records for dedicated enumeration
and measurement designs; their definitions need careful agreement before they
can be compared fairly.

This ledger advances the target to 100 curated slots. It does not add 63 live
objectives: those are deliberately still proposals until they meet the
independence and reproducibility rule above.
