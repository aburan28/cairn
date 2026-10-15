# Reader UX review

12 October 2026. This pass follows the browser reader's main journeys:
discover a challenge, inspect its current result, join work, monitor a divided
search, post a challenge, and inspect who earned its bounty. The same pages
ship inside Cairn.app; the native bridge contracts were inspected, but Swift
windows and the separate iOS reader need validation on their operating systems.

The review used the running Rust HTTP service and Chromium, first against
the development reader and then its production static export. Test services
read disposable copies of the launch log and a freshly posted piecework
objective. Failure responses, seed discovery and delayed wallet/file responses
were introduced only in isolated browser contexts. No challenge was submitted
and no external payment was attempted.

## Findings and changes

| Journey | Finding | Change |
|---|---|---|
| Choose work | The overview, objectives list and challenge header omitted piecework payouts. An active search could show zero paid and its entire original bounty still available while its own Search panel showed actual payments. | Share payment-summary helpers across the three pages, reading the node's piecework, ratchet or certificate standing. Include piecework in the pool consistency check and remaining-pool fraction. |
| Choose work | “Most left to earn” sorted by percentage rather than amount. The phrase “paid per unit” appeared beside the total paid. | Sort by remaining units and label the cumulative payment “paid out.” |
| Watch a frontier | Objectives, challenge summaries and frontier history were read once. A followed challenge could show new activity beside an old frontier to cite. | Refresh the summary while visible, refresh history less often because it reads the log, and provide a manual Refresh action and last-read time. Preserve the last successful data after failures and label it stale. |
| Recover from filters or an outage | A failed list read removed the previous result. Empty filters had no reset action. | Keep the last read, expose Refresh and Clear filters, and use a connection message a node operator can act on. |
| Open a fresh node | An empty live objective list was replaced by the bundled launch bounties, contradicting that node's empty chain. | Honor a successful empty list. The snapshot remains the fallback when a node cannot be read. |
| Find a node | The shell probed the build-time URL rather than the seed selected by the reader, and accepted any HTTP 200 as “node live.” A stalled probe could prevent every page from finishing discovery. | Share the resolved node with the status indicator, require the health body's `ok`, and bound health and seed-list reads to three seconds. |
| Post from the public site | Posting used the build-time target even after discovery found a seed. The warning described CORS internals without a path forward. | Check the resolved node and same-origin write capability. Link directly to that node's own challenge form and explain what can be composed locally. |
| Complete a challenge form | “Six fields still to fill” did not identify them. A late file or wallet response could restore authorization invalidated by a newer edit. | Link each outstanding problem to its field, lock controls during authorization, and discard responses superseded by a revision. Edits clear both canonical payload and signature. |
| Open a contribution panel | Sheets and the command palette declared themselves modal but keyboard focus escaped; closing a sheet left focus on the body. The phone palette had no close control and arrow navigation could select an invisible row. | Use native modal dialogs with Tab wrapping, focus restoration, background scroll locking, a visible close button, and scrolling of the selected route. |
| Monitor coordination | Slice and coverage facts were only in hover tooltips. Slice ranges displayed an exclusive upper bound as though it were inclusive. Changing task ids or partitions could retain the previous task's answer. | Add keyboard-readable detail tables/lists, display inclusive upper bounds, reset task state when its id changes, and discard superseded partition reads. Leases remain advisory. |
| Inspect bounty attribution | Every real digest lookup returned 404 because the browser encoded `sha256:` while the node matched the raw id. | Keep the digest's colon literal while escaping other path characters. The preview still authorizes no payment. |
| Read a divided search on a phone | A long digest inside the frontier statement widened the document, and the empty result panel spoke about a baseline the search did not have. | Wrap long statement tokens and link divided searches to their task progress; reserve the empty settlement message for objectives that await one result. |

## Repeatable verification

`make ui-check` runs the reader's type check, pure-function tests and static
export. Payment tests cover a mixed certificate/ratchet/piecework list,
exhausted pools and over-accounted piecework. Discovery tests cover a stalled
response body, an HTML host and an empty live node. Attribution tests use the
actual route spelling.

`ui/scripts/ux-smoke.mjs` runs against a local reader and a test node with at
least one objective. It checks routes at 320, 360 and 1280 pixels, modal
keyboard behavior and phone dismissal, failed-read recovery, an actual payout
lookup, field navigation, a file digest delayed across canonicalization,
waiting for a wallet, signature invalidation after an edit, and a real node
reached through a seed alias. With a piecework objective it also checks slice
details and the coverage disclosure. See `ui/README.md` for setup. The only
POST it sends is canonicalization; it never queues a record.

## Follow-through, 15 October 2026

The four follow-up items now have working paths:

| item | implementation |
|---|---|
| Contributor workspace and replay | `/workspace` reads operator-published labs, with authors, causal parents, all conflicts, pinned runs and candidate-to-ledger links. `lab replay` / `lab_replay` materialize original inputs, compare outputs, or explicitly rerun the recipe against current unambiguous files with new lineage and an optional research baseline. Prepare promotion guides the existing verified commit/reveal path; a lab cannot move the frontier. |
| Queue outcome | `/submissions/{queued}` stores admission/refusal metadata durably, recovers an interrupted append from the log and reports unknown when evidence is missing. `/submit` and `/submission` poll it and retain tracking through edits and reloads. |
| Native readers | Shared Swift report types/client, session/network panels, task catalogue, secret fields/validation and navigation policy live in `gui/shared`. All three native readers consume the published observations, retain provenance and distinguish a plain publisher. Cairn.app uses windowed counts and exposes role warnings; the iPhone reader has Network navigation and honors an empty live objective list. See the resolution matrix in the native review. |
| Maintained browser gate | `python3 scripts/reader-ux.py` creates a temporary node, ledger, queue and conflicted lab, and guards test writes with a matching fixture id. CI and release run it against the embedded static export before packaging. It checks 19 routes at three widths, real admission/refusal and receipt recovery, candidate downloads, replay/reapply/promotion panels, outage recovery, focus and authorization races. |

The shared read hook also replaces the remaining duplicated task polling and
centralizes stale-data/cleanup behavior for peers, Network, coordination's
chooser, Log records and workspaces. The chooser's rule has a pure-function
regression test. The earlier strip accessibility and inclusive-range fixes
remain covered by the browser gate.

Input replay is deliberately narrower than inferring how arbitrary algorithm
patches compose. Reapply executes a recipe on a prepared current workspace;
semantic integration and automatic frontier-triggered scheduling remain the
explicit design work in `docs/design/causal-replay.md`.

Portable Swift tests and source syntax checks run on Linux. SwiftUI/AppKit
compilation and native window/worker behavior require macOS and iOS; their
build gates include the shared library. Browser results do not certify native
window behavior.
