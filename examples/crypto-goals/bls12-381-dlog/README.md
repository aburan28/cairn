# BLS12-381 subgroup discrete logarithms

This suite contains separate full-order discrete-log objectives for G1 and
G2, the prime-order subgroups used by the BLS12-381 pairing curve. BLS12-381
is deployed by pairing-based systems. Its security profile differs from the
NIST prime curves; the current IETF pairing-friendly-curves draft estimates
about 126 bits for BLS12-381.

The checkers use the published field, prime subgroup order, full cofactor,
and base point for their respective groups. Each derives a deterministic
point by trying field elements from SHAKE256 of a public seed and counter,
taking the first point on the curve, and multiplying by the full group
cofactor. G1 uses `y² = x³ + 4` over Fp. G2 uses `y² = x³ + 4(u + 1)` over
Fp2, represented as Fp[u]/(u² + 1). Both checkers verify their target is
nonzero and has order r. The target construction does not choose a discrete
logarithm.

Run the standard-library-only controls with:

```sh
python3 examples/crypto-goals/bls12-381-dlog/selftest.py
python3 examples/crypto-goals/bls12-381-dlog/selftest_g2.py
```

The tests check the published generators and their orders, target derivation,
subgroup membership, controlled positive answers, malformed answers, and the
G2 extension-field square-root arithmetic.

References: [IETF Pairing-Friendly Curves, Section 4.2.1][curve-spec] and
[RFC 9380, BLS12-381 hash-to-curve suites][hash-to-curve].

[curve-spec]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/
[hash-to-curve]: https://www.rfc-editor.org/rfc/rfc9380.html
