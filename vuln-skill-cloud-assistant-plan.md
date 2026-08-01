# Vuln-Skill Cloud Assistant — Build Plan

Status tracker for turning `../vuln-skill-cloud/prompt/vuln_skill_cloud_assistant.md`
(the system prompt, drafted 2026-07-31) into a working chat assistant on the
AWS-deployed Vuln-Skill web app, soc-skill-cloud style (chat panel + tabbed
Workspace Canvas). Nothing below has been executed yet except where marked
**done**.

Workflow: same as `web-bugs-and-tweaks.md` — NJ reviews and confirms which
step(s) to act on before anything gets built or deployed.

---

## Decisions already locked in

1. **Vuln-Skill** (this repo, public) and **vuln-skill-cloud** (private,
   Terraform-only) stay two separate repos — no merge. See
   `../Cloud/index.md` §2.2 for why the split exists.
2. **AWS-deployed Vuln-Skill stops publishing CVE outputs to GitHub.**
   Outputs live only in the running app (local `outputs/` dir + web UI) —
   never pushed to any repo. `vuln-skill-cloud`'s "private output buffer"
   role goes away; it reverts to pure Terraform IaC.
3. **Homelab Vuln-Skill deployment (aiserver) is untouched** — keeps
   publishing to the public `Vuln-Skill` repo exactly as it does today.
   This plan only touches the AWS/cloud deployment.
4. The chat assistant's persona/rules/tool-contract/injection-safeguards
   document is written (`../vuln-skill-cloud/prompt/vuln_skill_cloud_assistant.md`)
   but not yet wired into any code.

---

## Pending

### 1. Disable GitHub publishing on the AWS deployment
- Confirmed with NJ (2026-07-31), not yet executed.
- On the EC2 (Elastic Compute Cloud) instance: back up
  `/opt/docker/vuln-skill/config/.env`, blank `GITHUB_TOKEN` and
  `GITHUB_REPO` (both already gate every publish/cleanup call in
  `github_publisher.py` — blank means a safe no-op, not an error).
- Redeploy: `docker compose -f docker/docker-compose.yml up -d
  --force-recreate --env-file /opt/docker/vuln-skill/config/.env` (the
  explicit `--env-file` is required — see `../Cloud/index.md` §1.5).
- Verify: confirm the container has no `GITHUB_TOKEN`/`GITHUB_REPO` set,
  confirm a produce run still saves locally and shows up in `/outputs`,
  confirm `runs.jsonl` still logs the run.
- Update `../Cloud/index.md`, `../references/cloud-inventory.md`, and
  `../references/aws-cloud-migration-plan.md` to drop the "private output
  buffer" description of `vuln-skill-cloud` once this lands.

### 2. Workspace Canvas — tabbed output view
- Rework `src/templates/produced.html` (or add a new template) so a CVE's
  produced outputs render as tabs — one per output type (Advisory,
  Technical Findings, Signatures, IoCs, Hunting Queries, Patch
  Recommendation) — mirroring soc-skill-cloud's canvas
  (`soc-skill-cloud/src/templates`, `src/static/style.css`'s tab-strip
  rules). Reuse `../references/web-design-system.md` wholesale rather than
  re-deriving tab CSS/JS.
- Tab strip needs the same behaviors soc-skill-cloud's checklist already
  verifies: click-to-jump, Back/Next pager, position label, wraps on
  mobile instead of overflowing.
- Only produced output types show a tab; unproduced types show as
  disabled/greyed placeholders, not missing entirely, so the analyst can
  see what's still available to produce.

### 3. Chat backend + tool-calling
- New FastAPI route (mirrors `soc-skill-cloud/src/app.py`'s structure) that
  loads `vuln_skill_cloud_assistant.md` as the system prompt and exposes
  Claude tool-calling for every § 4 action in that document, each backed by
  an existing `orchestrate.py`/`context_assembler.py`/`scorer.py` function
  — no new pipeline logic, purely a tool-call wrapper around what already
  exists.
- Each tool call's structured result (score, tier, tags, KEV status) gets
  handed to the model as data; the model is never the source of truth for
  those values (§ 2.1/§ 8.2 of the prompt document).
- Confirmation gates (§ 7 of the prompt document) implemented as an actual
  pause-and-wait in the chat flow, not just a prompt-level instruction —
  same pattern as SOC_Skill's § 6b gate in soc-skill-cloud.

### 4. Prompt-injection pre-screen
- Port soc-skill-cloud's `_screen_for_attack` pattern
  (`soc-skill-cloud/src/app.py`, Haiku 4.5 classifier, fails open on its
  own errors) to the new Vuln-Skill chat endpoint, using the
  Vuln-Skill-specific classification prompt (distinguish "manipulating the
  assistant itself" from "a CVE description that happens to contain
  injection-like phrasing," matching § 8/§ 9 of the prompt document).

### 5. Documentation pass
- Update `README.md` and `vuln-skill-overview.md` with the new chat
  interface once §§ 1 to 4 above are live.
- Retire this plan file (or move finished items to a "Done" section,
  matching `web-bugs-and-tweaks.md`'s convention) as steps land.
