# replay-reproduction

The one worked `replay` objective: a claim that is a set of exact figures,
verified by running the pinned command again and comparing what it prints.

```sh
cairn --log /tmp/replay.jsonl --root . try examples/replay-reproduction/objective.json \
  --submitter you --artifact examples/replay-reproduction/artifact.json
```

The verifier runs `python3 replay/reproduce.py` with the example directory
mounted read-only in a jail, parses one JSON object off its stdout, and
compares every field named in `reproducible_fields` with the artifact's
`results`. Identical: `accept`. Different: `reject`, with the claimed and
observed digests of each mismatched field. The command would not start, or
exited non-zero, or timed out: `unavailable`, which blames this node and not
the artifact.

Why it exists: this is the shape an **experiment's run record** takes on the
network. The research program's harness writes a manifest naming a command,
a commit and the integers it produced; a `replay` objective pins the command
and names the integers, and a validator on another machine re-derives them.
`docs/agent.md` and the autoresearcher's `tools/exp_to_objective.py` render
a frozen experiment into exactly this file.

What a replay cannot pin, stated plainly: the command's *code*. `replay` has
no `_sha256` field, so what `reproduce.py` contains at verification time is
whatever the node's `--root` holds; an objective that must bind its code to
a hash uses `certificate` or `workspace` instead, and an experiment bridge
records the commit it ran at beside the objective.
