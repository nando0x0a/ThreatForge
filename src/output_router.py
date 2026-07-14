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

        header = self._build_header(cve_data, result, output_num)
        footer = self._build_sources_footer(cve_data)
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

    def _build_header(self, cve_data: dict, result: dict, output_num: int) -> str:
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))
        lines = [
            f"# ThreatForge Output — {result.get('output_type', '').upper()}",
            f"# CVE:       {cve_data.get('cve_id', '')}",
            f"# Product:   {cve_data.get('product', '')}",
            f"# Tags:      {tags_str}",
            f"# Score:     {cve_data.get('composite_score', 0)}",
            f"# Tier:      {cve_data.get('tier_label', '')}",
        ]

        disc = cve_data.get("context", {}).get("severity_discrepancy") or {}
        if disc.get("has_discrepancy"):
            lines.append(
                f"# SEVERITY DISCREPANCY: NVD/vulnx says {disc['nvd_score']} "
                f"({disc['nvd_severity']}) — CVE.org (CNA, v{disc['cna_version']}) says "
                f"{disc['cna_score']} ({disc['cna_severity']}). See {disc['cna_source_url']}"
            )

        lines += [
            f"# Generated: {datetime.utcnow().isoformat()}Z",
            f"# Status:    {'REVIEW_NEEDED' if result.get('review_needed') else 'OK'}",
            "# ---",
        ]
        return "\n".join(lines)

    def _build_sources_footer(self, cve_data: dict) -> str:
        """Deterministic source list, guaranteed present regardless of whether
        the model's own citations (if any) match or are complete. Uses '#'
        comment lines throughout — safe as a trailing block in .md/.txt, and
        harmless (ignored) if appended to a .rules or .yml file."""
        sources = cve_data.get("context", {}).get("sources") or []
        if not sources:
            return ""
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
