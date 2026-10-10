# BLS12-381 G1 discrete logarithm

This objective is a full-order discrete logarithm challenge in G1, the
255-bit prime-order subgroup of the BLS12-381 pairing curve. BLS12-381 is used
by deployed pairing-based systems. Its pairing construction gives it a
security profile distinct from the NIST prime curves; the current IETF
pairing-friendly-curves draft estimates about 126 bits for BLS12-381.

The checker uses the published G1 field, subgroup order, cofactor, and base
point. It derives a deterministic point by trying x-coordinates from SHAKE256
of a public seed and counter, taking the first point on `y² = x³ + 4`, then
multiplying by the full G1 cofactor. It verifies that the target is nonzero
and has order dividing the published prime r. The scalar k is not selected by
the target-generation process.

Run the standard-library-only controls with:

```sh
python3 examples/crypto-goals/bls12-381-dlog/selftest.py
```

The self-test checks the published generator, its order, deterministic target,
subgroup membership, a controlled positive answer, and malformed answers.

References: [IETF Pairing-Friendly Curves, Section 4.2.1][curve-spec] and
[RFC 9380, BLS12-381 hash-to-curve suite][hash-to-curve].

[curve-spec]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/
[hash-to-curve]: https://www.rfc-editor.org/rfc/rfc9380.html
