---
name: Interop disagreement
about: The two implementations disagree about a digest, a verdict, or a settlement
title: 'interop: '
labels: interop
---

<!--
This is the most valuable bug report this project can receive. The whole
claim is that anyone can independently re-derive every settled result, and a
disagreement between implementations is that claim failing.

Do not worry about diagnosing it. The inputs and the two outputs are enough.
-->

**The input.** The record, artifact, or log that produces the disagreement —
paste it, or attach the `.jsonl`. Exact bytes matter more than a description
of them; a reformatted paste can hide the bug.

**What the primary implementation says.**

```
$ cairn --log … audit        # or the exact command you ran
```

**What the reference implementation says.**

```
$ ./reference/rust/target/release/cairn-reference --log … audit
```

**Versions.** `cairn --version`, the commit hash, and your OS.

**Epoch length.** `CAIRN_EPOCH_SECONDS` if you set it, and whether the log
was *written* under a different value than you are *reading* it under. Epochs
are derived from timestamps and never stored, so a log built with 1-second
epochs audits as broken under the 600-second default. `audit` says so when
every batch faults at once, but it is worth ruling out first.
