# Vuln-Skill Web UI — Bugs & Tweaks

Running list. Workflow: NJ describes something to fix/change, it goes in
here as **pending**. NJ reviews the list and confirms which ones to act on
("do #1 and #3", "deploy all pending", etc.) — nothing gets built or
deployed off this list without that confirmation. Once deployed, an item
moves to **done** with the date.

---

## Pending

Future work on KEV-on-entry (see #12 below): a standalone, more frequent
poll against CISA's KEV feed, independent of when a pipeline run happens —
today it's only checked once per web-UI run, not continuously.

13. **`/demo` capability, like soc-skill-cloud** — needs clarification
    first: no `/demo` route actually exists in soc-skill-cloud's code as
    of 2026-08-01, so confirm what this should do before scoping it.
14. **Rename "New conversation" → "New session"** — copy change only.
15. **Replicate soc-skill-cloud's header buttons/look and feel** — theme
    toggle (manual light/dark override) + About info icon as small
    icon-only buttons, divider separating them from text-labelled
    buttons, move the session button into the header row (currently in
    the chat pane's input toolbar), add Logout (soc-skill-cloud's 401 +
    fresh `WWW-Authenticate` challenge trick forces the browser to drop
    cached Basic Auth). History and Account don't have Vuln-Skill
    equivalents yet — decide build-real-feature vs. skip/stub before
    implementing.
16. **Chat syntax highlighting** — CVE IDs, KEV status, IPs, IoCs,
    domains styled distinctly from surrounding prose in chat replies,
    similar in spirit to soc-skill-cloud's JSON/telemetry token-coloring
    but applied inline within normal text rather than to a structured
    block.
17. **Change login credentials** — username `skills`, password
    `crimson-ember-threat-5836`. This Basic Auth is shared with
    soc-skill-cloud on the same EC2 (Elastic Compute Cloud) instance —
    changing it affects both apps' logins unless split into separate
    credentials first (decide which before acting).

## Done

1. **Run button hard to notice** — moved to its own line with a top border and bolder styling, visually separated from the mode radios. Deployed 2026-07-30.
2. **"KEV Source (added)" column** — added to the candidates table, reuses `orchestrate._format_kev_sources()`. Verified live with real data (e.g. `cisa (2021-12-10), vulncheck (2021-12-06)` for CVE-2021-44228). Deployed 2026-07-30.
3. **Refresh button on the Outputs tab** — `hx-select`/`hx-target` against the same `/outputs` route, no new backend route needed.
4. **Token usage + dollar cost per output** — `ai_caller.py` captures input/output/cache tokens and prices them per model (Opus 5, Sonnet 5, Sonnet 4.6, Haiku 4.5 rates, verified against docs.claude.com 2026-07-30), summed across the self-repair retry when one happens; `output_router.py` threads it into `runs.jsonl`; `/runs` shows Tokens (in/out) and Cost columns, backward-compatible with pre-existing log entries missing these fields. openai_compatible provider gets token counts only, no cost (pricing varies by endpoint).
5. **Surface Claude API errors in the UI** — `produced.html` and `runs.html` now show the actual error text (was only ever in `docker logs` before, e.g. the 2026-07-30 credit-balance failure that had no visible trace on the page).
6. **Sticky header + loading banner while scrolling** — wrapped in `.page-header-sticky` (`position: sticky; top: 0`), matching soc-skill-cloud.
7. **Run/Produce buttons styled with an accent color** — were identical to every other plain button before.
8. **Clear stale candidates immediately on a new run, show what the last run was** — `/run` now empties `_state["enriched_cves"]` before the pipeline call, not after, so a page load mid-run never shows the previous run's data looking current. A "Last run: mode/params — N candidates at TIMESTAMP" line shows above the candidates table ("Running: ..." while one's in progress). Also added a `threading.Lock` around `_state` writes and disabled Run/Produce buttons during their own request, proactively applying the same fix soc-skill-cloud needed for a real bug.
9. **Test mode moved to last** in the Run pipeline options (was second); production-relevant modes now come first.
10. **Hover description on each Run mode option** — a `title` tooltip explaining what each mode actually changes about the run.
11. **Fixed loading-banner/message desync after tabbing away mid-run** — the banner now renders visible server-side whenever `last_run.status == "running"` (new `pipeline_running` context var passed from `index()`), not just via JS tied to the original request. "No results yet — run the pipeline above" no longer shows while a run is genuinely in progress (was contradicting the "Running: ..." line above it and inviting a duplicate run) — replaced with "Pipeline run in progress — please wait" in that state. Added a 4-second auto-reload while running so the page catches up on its own once the run finishes.
12. **KEV-on-entry re-alerting, first cut** — every pipeline run (any mode) now checks each candidate's KEV "added" date directly (`orchestrate.annotate_recent_kev_entries`, `KEV_RECENT_ENTRY_DAYS = 7`), not just whether it's KEV-listed at all. A CVE flagged within the last 7 days gets its own callout card above the candidates table plus a "NEW KEV" badge on its row in the main table, separate from the normal results. Checked once per web-UI run for now, not a standalone frequent poll (see Pending above for that).
