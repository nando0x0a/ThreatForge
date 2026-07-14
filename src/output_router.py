#!/usr/bin/env python3
import json
import logging
from pathlib import Path
from datetime import datetime

import github_publisher
from config_loader import load_config

log = logging.getLogger("output_router")

_OUTPUT_MENU = {int(k): v for k, v in load_config()["output_menu"].items()}


class OutputRouter:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def clean_remote(self) -> int:
        """Wipe every file under outputs/ in the GitHub repo (single commit) —
        the remote-side counterpart to the local outputs/ folder wipe, so
        GitHub never accumulates files across runs."""
        return github_publisher.clean_outputs()

    def save(self, output_num: int, cve_data: dict, result: dict) -> Path:
        cve_id = cve_data.get("cve_id", "UNKNOWN").replace("-", "_")
        output_type = result.get("output_type", f"output_{output_num}")
        menu_entry = _OUTPUT_MENU.get(output_num, {})
        ext = menu_entry.get("extension", ".txt")
        subdir = menu_entry.get("output_dir", "misc")

        folder = self.base_dir / subdir
        folder.mkdir(parents=True, exist_ok=True)

        # One canonical filename per CVE+output-type — no timestamp. Re-running
        # against the same CVE overwrites this file (locally and, via SHA-based
        # update in github_publisher, on GitHub too) instead of piling up a new
        # timestamped file on every run. The generation time still lives in the
        # header below. review_needed status also stays out of the filename —
        # a REVIEW_NEEDED_ prefix would give the same CVE+type two possible
        # paths, defeating the point of a single canonical file.
        filename = f"{cve_id}_{output_type}{ext}"
        filepath = folder / filename

        header = self._build_header(cve_data, result, output_num, ext)
        footer = self._build_sources_footer(cve_data, ext)
        content = header + "\n\n" + result.get("content", "") + footer

        if result.get("review_needed"):
            content += f"\n\n# REVIEW_NEEDED\n# Error: {result.get('error', 'unknown')}"

        filepath.write_text(content)
        log.info(f"Saved: {filepath}")
        self._log_run(cve_data, output_num, result, filepath)

        repo_path = f"outputs/{subdir}/{filename}"
        commit_msg = f"ThreatForge: {output_type} for {cve_data.get('cve_id', 'UNKNOWN')}"
        github_publisher.publish(str(filepath), repo_path, commit_msg)

        return filepath

    def _build_header(self, cve_data: dict, result: dict, output_num: int, ext: str) -> str:
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))
        fields = [
            f"CVE:       {cve_data.get('cve_id', '')}",
            f"Product:   {cve_data.get('product', '')}",
            f"Tags:      {tags_str}",
            f"Score:     {cve_data.get('composite_score', 0)}",
            f"Tier:      {cve_data.get('tier_label', '')}",
        ]

        disc = cve_data.get("context", {}).get("severity_discrepancy") or {}
        if disc.get("has_discrepancy"):
            fields.append(
                f"SEVERITY DISCREPANCY: NVD/vulnx says {disc['nvd_score']} "
                f"({disc['nvd_severity']}) — CVE.org (CNA, v{disc['cna_version']}) says "
                f"{disc['cna_score']} ({disc['cna_severity']}). See {disc['cna_source_url']}"
            )

        fields += [
            f"Generated: {datetime.utcnow().isoformat()}Z",
            f"Status:    {'REVIEW_NEEDED' if result.get('review_needed') else 'OK'}",
        ]

        title = f"ThreatForge Output — {result.get('output_type', '').upper()}"
        if ext == ".md":
            # '#'-prefixed lines are H1 headings in Markdown, not comments — each
            # would render as its own giant heading. Use a blockquote instead:
            # normal body-text size, still visually set apart from the content below.
            lines = [f"> **{title}**", ">"] + [f"> {f}" for f in fields]
            return "\n".join(lines)

        lines = [f"# {title}"] + [f"# {f}" for f in fields] + ["# ---"]
        return "\n".join(lines)

    def _build_sources_footer(self, cve_data: dict, ext: str) -> str:
        """Deterministic source list, guaranteed present regardless of whether
        the model's own citations (if any) match or are complete."""
        sources = cve_data.get("context", {}).get("sources") or []
        if not sources:
            return ""

        if ext == ".md":
            # Same heading level and plain list style as the AI's own "## Sources"
            # section, so this reads as the same size/font, not a giant heading
            # per '#'-prefixed line.
            lines = ["", "## Sources (ThreatForge-verified)", ""]
            for i, src in enumerate(sources, 1):
                lines.append(f"[{i}] {src['label']} — {src['url']}")
            return "\n".join(lines) + "\n"

        # '#' is a genuine comment character in .txt/.yml/.rules — safe as-is.
        lines = ["", "# --- Sources (ThreatForge-verified) ---"]
        for i, src in enumerate(sources, 1):
            lines.append(f"# [{i}] {src['label']} — {src['url']}")
        return "\n".join(lines) + "\n"

    def _log_run(self, cve_data: dict, output_num: int, result: dict, filepath: Path) -> None:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cve_id": cve_data.get("cve_id"),
            "product": cve_data.get("product"),
            "output_num": output_num,
            "output_type": result.get("output_type"),
            "composite_score": cve_data.get("composite_score"),
            "tags": cve_data.get("tags"),
            "success": result.get("success"),
            "review_needed": result.get("review_needed", False),
            "filepath": str(filepath),
        }
        log_path = Path("/opt/threatforge/logs/runs.jsonl")
        with open(log_path, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
