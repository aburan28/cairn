# CLAUDE.md

See **[AGENTS.md](AGENTS.md)**.

Everything is there: the rules for contributing to this repository, and the
rules for working as a contributor *to* the network via the `cairn` MCP
tools. One file rather than two, because two copies of a rule become two
different rules.

One rule is repeated here because Claude Code loads this file first: the
session that opens a PR keeps watching it until it is merged or closed, but a
top-tier session (Claude Opus, Fable) never does the watching itself. It stays
subscribed (`subscribe_pr_activity`, safety-net check-ins at the harness's
cadence, never a polling loop) and hands every PR wake to a small-model
subagent (`Agent` with `model: "haiku"`, or `"sonnet"` for a real code fix),
which fixes what the PR broke, reports anything larger, and squash-merges once
CI is green -- except a consensus-surface change, which waits for a human.
AGENTS.md, "Watch your PR through a small model".
