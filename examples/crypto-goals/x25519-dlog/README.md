# X25519 prime-subgroup discrete logarithm

This is a discrete-log challenge on the Curve25519 prime-order subgroup used
by X25519. RFC 7748 specifies the Montgomery curve, basepoint, subgroup order,
and cofactor. The objective deliberately works with an unclamped subgroup
scalar so it asks a well-defined group DLP, while X25519 key generation uses
clamped scalars.

The checker derives an on-curve point by trying x-coordinates from SHAKE256 of
a public seed and counter, selects the y root by digest parity, then multiplies
by 8 to clear the curve cofactor. It compares only u-coordinates using the
RFC 7748 Montgomery ladder. Since u(P) = u(-P), artifacts use the canonical
scalar in `[1, (ell - 1)/2]`; the range gives exactly one representative for
each non-identity subgroup point.

Run the pure-Python checks with:

```sh
python3 examples/crypto-goals/x25519-dlog/selftest.py
```

The test checks the published basepoint and order, cross-checks the x-only
ladder against full point arithmetic for sample scalars, tests sign
canonicalization, verifies target subgroup membership, and exercises valid and
invalid answer shapes.

Reference: [RFC 7748, Sections 4 and 5][rfc].

[rfc]: https://www.rfc-editor.org/rfc/rfc7748.html
