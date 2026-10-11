# RSA factoring challenge objectives

These three objectives use fixed RSA Laboratories challenge integers at 1024,
1536, and 2048 bits. The moduli are historical public research targets, not
claims about the security of an individual deployed key. RSA Laboratories
ended its original prize contest in 2007; Cairn's displayed rewards are
notional Stage 0 units and do not revive that contest.

The moduli are copied from RSA Inc's challenge statements hosted by
[MysteryTwister: RSA-1024][rsa1024], [RSA-1536][rsa1536], and
[RSA-2048][rsa2048]. Those statements ask for a prime factor. Cairn's checker
uses the weaker, fully explicit certificate claim “a nontrivial divisor”:
from the artifact and pinned integer it verifies `1 < f < N` and `N mod f = 0`
using exact integer arithmetic. It does not test or claim that `f` or `N/f` is
prime. This keeps acceptance within what the submitted artifact proves, while
still requiring discovery of a nontrivial factor of each fixed semiprime.

Each objective pins one entrypoint from the shared checker file. The three
moduli are constants in that same pinned file, so a submission cannot retarget
one objective at an easier integer.

## Reproduce checker validation

```sh
python3 examples/crypto-goals/rsa-factoring/selftest.py
sha256sum examples/crypto-goals/rsa-factoring/checkers/rsa_challenge.py
```

The self-test checks a small positive split, malformed and non-divisor inputs,
canonical decimal spelling, and the documented bit and decimal lengths of all
three pinned moduli. The small split is only a checker fixture; it is not a
solution to any of the RSA objectives.

[rsa1024]: https://mysterytwister.org/media/challenges/pdf/mtc3-rsa-15-en.pdf
[rsa1536]: https://mysterytwister.org/media/challenges/pdf/mtc3-rsa-32-en.pdf
[rsa2048]: https://mysterytwister.org/media/challenges/pdf/mtc3-rsa-38-en.pdf
