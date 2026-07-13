#!/usr/bin/env python3
import json
import logging
from pathlib import Path
from datetime import datetime

import github_publisher

log = logging.getLogger("output_router")

OUTPUT_DIRS = {
    1: "advisories",
    2: "advisories",
    3: "rules",
    4: "iocs",
    5: "hunting",
    6: "patches",
}

OUTPUT_EXTENSIONS = {
    1: ".md",
    2: ".md",
    3: ".rules",
    4: ".txt",
    5: ".txt",
    6: ".yml",
}


class OutputRouter:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def save(self, output_num: int, cve_data: dict, result: dict) -> Path:
        cve_id = cve_data.get("cve_id", "UNKNOWN").replace("-", "_")
        output_type = result.get("output_type", f"output_{output_num}")
        ext = OUTPUT_EXTENSIONS.get(output_num, ".txt")
        subdir = OUTPUT_DIRS.get(output_num, "misc")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        folder = self.base_dir / subdir
        folder.mkdir(parents=True, exist_ok=True)

        filename = f"{cve_id}_{output_type}_{timestamp}{ext}"
        filepath = folder / filename

        header = self._build_header(cve_data, result, output_num)
        content = header + "\n\n" + result.get("content", "")

        if result.get("review_needed"):
            content += f"\n\n# REVIEW_NEEDED\n# Error: {result.get('error', 'unknown')}"
            filename = "REVIEW_NEEDED_" + filename
            filepath = folder / filename

        filepath.write_text(content)
        log.info(f"Saved: {filepath}")
        self._log_run(cve_data, output_num, result, filepath)

        repo_path = f"outputs/{subdir}/{filename}"
        commit_msg = f"ThreatForge: {output_type} for {cve_data.get('cve_id', 'UNKNOWN')}"
        github_publisher.publish(str(filepath), repo_path, commit_msg)

        return filepath

    def _build_header(self, cve_data: dict, result: dict, output_num: int) -> str:
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))
        return (
            f"# ThreatForge Output — {result.get('output_type', '').upper()}\n"
            f"# CVE:       {cve_data.get('cve_id', '')}\n"
            f"# Product:   {cve_data.get('product', '')}\n"
            f"# Tags:      {tags_str}\n"
            f"# Score:     {cve_data.get('composite_score', 0)}\n"
            f"# Tier:      {cve_data.get('tier_label', '')}\n"
            f"# Generated: {datetime.utcnow().isoformat()}Z\n"
            f"# Status:    {'REVIEW_NEEDED' if result.get('review_needed') else 'OK'}\n"
            f"# ---"
        )

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
