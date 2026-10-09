# CLAUDE.md

See **[AGENTS.md](AGENTS.md)**.

Everything is there: the rules for contributing to this repository, and the
rules for working as a contributor *to* the network via the `cairn` MCP
tools. One file rather than two, because two copies of a rule become two
different rules.

One rule is repeated here because Claude Code loads this file first and its
harness defaults to watching the PRs it opens: opening the PR ends your work on
it. Report the link and stop. Claude Opus and Fable never watch CI (no
`subscribe_pr_activity`, no scheduled check-ins, no polling check runs or
logs); a separate automation on Sonnet 5.5 or Haiku 5.5 gets the PR green and
merges it. AGENTS.md, "Stop at the PR: top-tier models never watch CI".
