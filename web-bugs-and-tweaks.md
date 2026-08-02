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

37. **Remove the scheduler.** Scope not yet defined — need to confirm what
    this covers before touching it: the daily automated run described in
    `config/vuln-skill.yaml` (currently "disabled by default"), the
    `--scheduled` CLI flag/cron trigger in `orchestrate.py`, or both.
38. **Workflow settings tab: explain every field + the scoring engine, with
    an example** — make the settings page genuinely user-friendly so NJ
    can adjust CVSS/EPSS/age thresholds and weights and understand what
    each one actually does and how the composite score gets computed, not
    just see bare number inputs. Also remove two specific lines once this
    lands: "AI prompts and the output menu are not editable here — SSH in
    and edit `config/vuln-skill.yaml` directly for those" and "(edit
    weights directly in `vuln-skill.yaml` — not exposed here yet)" —
    these should go away once there's a real explanation in their place,
    not before.
39. **Chatbox empty-state/placeholder wording + a real `/help` command** —
    "Ask the assistant to run a workflow..." (`_messages.html`'s empty
    state and `base.html`'s textarea placeholder) → "Ask Vuln-Skill to run
    a workflow...", and mention both `/demo` and `/help` so a new user
    discovers them without having to be told. `/demo` already exists;
    `/help` does not yet — this needs actually building (a slash command
    that explains what the assistant can do, presumably listing the
    supported actions from § 4 of the system prompt / `CHAT_TOOLS`, in the
    same spirit as `/demo`'s client-side-only, no-API-cost menu), not just
    referencing it in copy that would otherwise point at nothing.

    **How it ranks risk** (NJ's draft explanation, verified against
    `config/vuln-skill.yaml`'s actual `scoring.weights` — two real tags
    were missing from the original draft and are included below):
    a composite priority score built from tags, not CVSS alone:
    KEV +50, RCE +40, RCE-KEV +25, Critical CVSS (≥ `cvss_crit_threshold`,
    currently 9.0) +30, High CVSS +20, T1 (MITRE ATT&CK technique match)
    +20, EPSS above `epss_threshold` (currently 0.5) +15, Public PoC +10,
    Newly disclosed (within `new_threshold_days`, currently 3 days) +10,
    Widely deployed product +10. Mapped to tiers via `tier_thresholds`:
    90+ → Tier 0 CRITICAL — ACT NOW, 70–89 → Tier 1 HIGH PRIORITY, 40–69
    → Tier 2 STANDARD, below 40 → Tier 3 MONITOR. Example: a recent
    KEV-listed RCE with critical CVSS and high EPSS clears the "act now"
    threshold quickly — confirmed exploitation and exploit likelihood
    complement severity scoring rather than replacing it. When #38 is
    actually built, pull the live weight/threshold *values* from config at
    render time (not hardcoded into the template) so this explanation
    can't drift from what's actually configured.

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
13. **`/demo` chat shortcut** — typing `/demo` in the chat box expands (client-side) to a real guided request: find a critical, recently disclosed CVE and produce an output. Still subject to the app's existing `produce_output` confirmation gate — a demo doesn't get to skip that. Deployed 2026-08-01.
14. **Rename "New conversation" → "New session"** — done as part of moving it into the header nav group (#15). Deployed 2026-08-01.
15. **Replicate soc-skill-cloud's header buttons/look and feel** — theme toggle (manual light/dark override, persisted via `localStorage`) + About icon dialog (shows the live chat model) as small icon-only buttons, divider-aligned nav group (New session / History / Account / Logout), `/logout` via the 401 + `WWW-Authenticate` challenge trick. History and Account got real Vuln-Skill features rather than stubs: chat sessions now archive on "New session" (mirrors soc-skill-cloud), with a `/chat/history` browser, read-only session view, and resume; `/account` is a real page (not a JS-dialog stub) explaining the shared-login model and the now-split credential (#17). Verified live via Playwright against an isolated test container. Deployed 2026-08-01.
16. **Chat syntax highlighting** — CVE IDs, KEV status, IPs, hashes/IoCs, and domains highlighted inline within chat prose (`web.py`'s `_highlight_entities`), reusing the design system's syntax-highlight color vocabulary. Verified against a real chat reply (CVE-2021-44228 lookup). Deployed 2026-08-01.
17. **Split login credentials from soc-skill-cloud** — both apps used to share one `/etc/nginx/.htpasswd` on the EC2 instance; copied it into a Vuln-Skill-only file and repointed `vulnskill.conf`, so each app's login can be changed independently going forward. The actual credential value is unchanged for now (copied, not reset) — changing it is a separate future step once you actually want a new password. Deployed 2026-08-01.
25. **Long output-type tab labels overflowed the viewport at mobile widths** — `.tab-btn` (`style.css`) had `white-space: nowrap` with no override for narrow screens, so a single long label (e.g. "Threat hunting queries (CrowdStrike + Netflow)") pushed its button past a 375px viewport even though `.tab-strip` itself already wrapped buttons onto new lines. Added a `@media (max-width: 480px)` override letting the label itself wrap onto multiple lines. Pre-existing bug in the shared `_workspace_canvas.html` partial (Pipeline produce results and Outputs page both affected). Verified headlessly at 375px against the exact tab markup (`document.body.scrollWidth` now matches `clientWidth`, was 394px vs 375px before) and confirmed no change to the `nowrap` behavior above the 480px breakpoint.
26. **Unify "produce"/"generate" wording; retire "Pipeline"** — "Generated outputs" → "Produced outputs" (matches the "Produce selected" button and the confirmation-gate wording). "Pipeline" replaced with "Scan" everywhere user-facing: nav link, "Pipeline Workspace" → "Scan Workspace", "Run pipeline" → "Run scan", "Pipeline settings" → "Scan settings", tooltips, the loading banner, chat placeholder text, "Back to Pipeline" links. The internal `produce_output` tool name and Python identifiers are unchanged (not user-facing). Not touched: the AI system prompt's own wording (`vuln_skill_cloud_assistant.md`) — the model may still say "pipeline" in a chat reply since its instructions weren't rewritten, only the static UI text was.
27. **Local time everywhere a timestamp shows, labeled as such** — extended `_highlight_entities` with a `timestamp` entity (matches the app's one actual format, UTC ISO-8601) that wraps matches in a `.local-time[data-utc]` span instead of a colored one; a shared `renderLocalTimestamps()` (base.html, hooked to `DOMContentLoaded` and `htmx:afterSwap`) converts every one of them client-side to `toLocaleString() + ' (local time)'`. Covers a produced doc's own embedded "Generated: ..." line (Preview view only — Raw stays byte-exact, verified: Preview showed "8/1/2026, 4:20:20 PM (local time)", Raw showed the original "2026-08-01T20:20:20.235972Z"), `_pipeline_results.html`'s "Last run ... at" and "started" timestamps, `runs.html`'s Time column, and Chat History's Archived column (unified with the same `.local-time` convention, was already client-side-converted but unlabeled).
28. **`/demo` lets the user pick output type(s)** — two-step, client-side only (no API cost for the menu itself): typing `/demo` shows the six output types as an enumerated list and sets a wait-for-reply flag; the next message is parsed as comma-separated numbers (invalid input re-prompts) and expanded into the real instruction naming the selected output type labels, then proceeds through the normal chat/confirmation flow. Verified live: "/demo" → menu shown, 0 tokens spent; "1,3" → expanded to "...produce Security advisory (management), Suricata signature drafts for it."
29. **Working-bubble wording + "AI Assistant" → "Chatbox"** — `.chat-working` pill now reads "Vuln-Skill working...". Pane heading renamed "AI Assistant" → "Chatbox"; matching About-dialog warning line reworded ("content sent through the Chatbox is sent to the LLM provider").
30. **Tagline → "AI Vulnerability Intelligence Assistant"**.
31. **"Code" → "Raw"; Preview renders meaningfully for every output type** — renamed the toggle button and `content-view-code` → `content-view-raw` (matching `data-view`/JS, no JS change needed since `setContentView` already builds the class name generically). Preview's rendering mode is now config-driven (`config/vuln-skill.yaml`'s `output_menu.*.preview: markdown|highlight`) instead of keyed off file extension — checked each output type's actual AI prompt template before deciding: `advisory`, `technical_findings`, `hunting_queries`, and `patch_recs` (despite its `.yml` extension) are genuinely markdown-structured (headers, bold, fenced code blocks) and now get full `_render_safe_markdown` rendering; `signatures` and `ioc_list` explicitly mandate literal `#`-comment/rule syntax ("no markdown fencing") that full markdown rendering would misparse (a `#` comment read as an H1, a Suricata rule body reflowed into one paragraph) — these keep the existing entity-highlighted `_render_plain_preview`. Verified live: a real Suricata `.rules` file's Preview showed entity highlighting with `#` lines intact as plain text, not H1s.
32. **Workspace Canvas: Outputs page only, not the Scan page** — removed `canvases`/`skipped` from `_pipeline_results_context()` (and the now-dead `_state["last_produced_canvases"]` write/key entirely) so a plain page load or chat-driven OOB refresh no longer threads canvas data into the Scan page at all. `produced.html` (the `/produce` POST's own direct response) now renders a lightweight one-line confirmation + CVE/output-type summary + "View in Outputs →" link instead of the full tabbed canvas. Verified live: `#produce-result` stayed empty after a chat-driven produce; the full canvas only ever appears on `/outputs`.
33. **Header divider misalignment + more spacing** — `.chat-pane` was missing `box-sizing: border-box`, so its border+padding added to the 420px content width instead of being included in it (rendered 445px vs. `.header-nav-group`'s correctly-border-boxed 420px) — a real, measured 25px divider misalignment, not a rendering guess (`getBoundingClientRect()` before: nav-group left 996 vs. chat-pane left 971; after: both 996, both exactly 420px wide). Also increased spacing between the theme/About icon pair and the New session/History/Account/Logout group (`.header-actions` gap 0.5rem → 0.75rem, `.header-nav-group` padding-left 1.5rem → 2rem).
34. **Two more header dividers** — added `.header-divider` spans before and after `<nav>`, splitting the header into three visually distinct clusters: brand+tagline | Workflows/Outputs/History/Products/Workflow settings | theme+About icons — New session/Account/Logout (the third divider, between icons and the session group, is #33 above). `align-self: stretch` overrides the header's own `align-items: baseline` just for the dividers, so each spans the full row height.
35. **"Pipeline"/"Scan" → "Workflow(s)" everywhere; retired Test mode from the web UI; removed the header's chat-History button** — full pass across the web app (nav, headings, tooltips, placeholders, the produce/lookup tool descriptions the model reads, and the literal refusal message shown to a blocked user) and the shared system prompt (`vuln-skill-cloud/prompt/vuln_skill_cloud_assistant.md`) replacing "pipeline" with "workflow". The four remaining Select-workflow options were relabeled to match NJ's exact spec (Daily vulnerability triage / Recent critical-KEV sweep / Product vulnerability search / Run a specific CVE) and mirrored into the system prompt's own § 4.1/4.3/4.4/4.5 rows for consistency between UI and chat self-description. Test mode's radio+count input removed from `index.html` (NJ's list didn't include it) — the backend `_execute_run("test", ...)` and the chat's `run_test_mode` tool are untouched, so it's still chat-reachable, just not a button on the page anymore (`orchestrate.py`'s dead `.test-mode-option`/`.count-input` CSS also removed). **Flagging this one explicitly:** the header's "History" button (linked to `/chat/history`, the archived-conversation browser) was removed and "Run history" (`/runs`, the CVE-workflow run log — a different feature) renamed to plain "History", per NJ's literal instruction that these were duplicates. They aren't the same feature — `/chat/history` still works if navigated to directly, but there's no longer a discoverable link to it anywhere in the UI. If chat-session browsing/resume was still wanted, this needs a follow-up.
36. **Output menu: 6 types → 5, "Technical findings" retired** — matching NJ's exact "Select output type" list (Advisory / Detection Rule Draft / IoC list / Hunting queries / Patch playbook), `technical_findings` was dropped as a distinct producible type (its own prompt template removed too) and everything after it renumbered down by one in `config/vuln-skill.yaml`'s `output_menu`. Propagated the renumbering everywhere it was assumed: `web.py`'s `_OUTPUT_ICONS`, the `produce_output` tool schema (`maximum: 6→5`) and its description, `_expand_output_nums` (now computed from `len(_output_menu())` instead of a hardcoded `range(1, 7)`, so a future resize can't drift out of sync again), the `/demo` menu's `DEMO_OUTPUT_TYPES` JS array, `orchestrate.py`'s CLI wizard prompt/flag help text (Discord's opt-in toggle shifted 7→6 to match), and the shared system prompt's § 4.7/4.8. **Found and fixed a real latent bug while renumbering:** `ai_caller.py` injected its Suricata few-shot example via a hardcoded `output_num == 3` check — after signatures moved to `#2`, that check would have silently fired for the wrong type (or never fired at all). Now keyed off the menu entry's own `"key"` string (`== 'signatures'`), immune to any future renumbering. Verified live end-to-end: selecting "2" (Detection Rule Draft) in chat correctly produced `rules/CVE_2026_42945_signatures.rules` with the few-shot-formatted confidence comment intact, and the Outputs page showed the correct 5-tab strip with matching icons.

Deployed 2026-08-01.
