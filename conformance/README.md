# Conformance vectors

`vectors.json` is the executable contract between implementations.

The whole project rests on one claim: **anyone can independently re-derive every
result the network has settled.** That claim is void if two implementations hash
the same object differently — they would compute different ids for the same
objective, disagree about which artifact was accepted, and never find out. The
disagreement would be silent, because each implementation is internally
consistent.

So the format is pinned, byte for byte, and both implementations are tested
against these vectors rather than against each other's behaviour.

## What is pinned

| section | pins |
|---|---|
| `canonical` | exact UTF-8 bytes and digest for values covering every escaping decision: quotes, backslashes, the five short-form control escapes, generic control characters, DEL, non-ASCII, astral-plane characters, key ordering, integer boundaries |
| `merkle` | roots for leaf counts 0–8, plus the promotion-vs-duplication case |
| `records` | objective / claim / commitment ids, artifact ids, and commitment hashes for concrete records |
| `ratchet` | `progress` and `cumulative` at boundaries for five bounty curves |
| `attribution` | 192 payout maps across amount × delta × depth |
| `partition` | beacon values and partition assignments |
| `gossip` | candidate ids, artifact ids, island assignments |

## The format rules these encode

- Object keys sorted; no insignificant whitespace; UTF-8 output.
- Non-ASCII stays **raw UTF-8**, never `\u`-escaped.
- Escapes: `"` and `\`, the five short forms `\b \t \n \f \r`, and every other
  character below `0x20` as `\u00XX`. `DEL` (`0x7f`) and `/` are **not** escaped.
- **No floats.** IEEE-754 doubles do not round-trip identically through every
  JSON implementation and do not reproduce bitwise across heterogeneous
  hardware. Fractional quantities are carried as scaled integers.
- **Integers are bounded to signed 128 bits.** Python has bignums and Rust does
  not; rather than pull arbitrary precision into a field no record needs, the
  *format* declares the bound and both implementations enforce it. The
  boundaries are pinned so neither drifts.

Key sorting agrees across languages for free: Python sorts `str` by code point,
Rust's `BTreeMap<String, _>` sorts by UTF-8 byte order, and UTF-8 is constructed
so those two orders coincide.

## Regenerating

```sh
python3 scripts/gen_conformance.py
```

Generated from the Python reference implementation in `reference/python/`. CI
regenerates and fails on any diff, so the vectors cannot silently drift from the
implementation that produced them.

**Changing a vector is a breaking change to the network's identity scheme.** If
a change is genuinely needed, every previously computed id changes with it, so
it is a migration, not an edit.
