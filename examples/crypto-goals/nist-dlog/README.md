# NIST prime-curve discrete logarithms

This suite adds full-order DLP objectives for NIST P-256, P-384, and P-521.
Each uses the domain parameters from [NIST SP 800-186, Section 3.2.1][nist].
They are recognizable deployment curves at 128-, 192-, and 256-bit classical
security strengths. They test generic ECDLP solving on three standard sizes,
which complements the repository's Certicom challenge curves and secp256k1.

The public target is generated deterministically from the seed shown in each
objective. Starting at counter zero, the checker hashes `seed || counter` with
SHAKE256, reduces the output to an x-coordinate, and tests whether the curve
right-hand side has a square root. It selects the square root whose parity is
the final digest bit. The first valid point is Q. The objective records Q and
the successful counter, while the pinned checker re-derives both. No secret
scalar is selected as part of target generation.

Run the pure-Python arithmetic and checker controls with:

```sh
python3 examples/crypto-goals/nist-dlog/selftest.py
```

The self-test checks the generator's curve equation and order, re-derives each
target, and exercises valid, wrong, out-of-range, malformed, and extra-field
answers. The checker uses only the Python standard library.

[nist]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
