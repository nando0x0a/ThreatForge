#!/usr/bin/env python3
import os
import re
import logging
from pathlib import Path
import anthropic

from context_assembler import ContextAssembler

log = logging.getLogger("claude_caller")

CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")
PROMPTS_DIR = Path("/opt/threatforge/prompts")

OUTPUT_MODULES = {
    1: "advisory",
    2: "technical_findings",
    3: "signatures",
    4: "ioc_list",
    5: "hunting_queries",
    6: "patch_recs",
}


def load_prompt(filename: str) -> str:
    path = PROMPTS_DIR / filename
    if path.exists():
        return path.read_text()
    log.warning(f"Prompt file not found: {path}")
    return ""


class ClaudeCaller:
    def __init__(self):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.assembler = ContextAssembler()
        self.system_prompt = load_prompt("system_prompt.txt")
        self.few_shot = load_prompt("few_shot_rules.txt")

    def produce(self, output_num: int, cve_data: dict) -> dict:
        output_type = OUTPUT_MODULES.get(output_num, "unknown")
        template = load_prompt(f"output_templates/{output_type}.txt")
        context = cve_data.get("context", {})
        context_block = self.assembler.format_for_prompt(context)
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))

        user_message = (
            f"{context_block}\n\n"
            f"Priority Score: {cve_data.get('composite_score', 0)}\n"
            f"Priority Tags: {tags_str}\n"
            f"Priority Tier: {cve_data.get('tier_label', 'UNKNOWN')}\n\n"
            f"{self.few_shot if output_num == 3 else ''}\n\n"
            f"{template}"
        )

        result = self._call(user_message, output_type)

        if not result["success"] and result.get("error"):
            log.info(f"Self-repair retry for {cve_data['cve_id']} output {output_num}")
            retry_msg = user_message + f"\n\nPrevious attempt failed:\n{result['error']}\nPlease fix and try again."
            result = self._call(retry_msg, output_type)
            if not result["success"]:
                result["review_needed"] = True
                log.warning(f"Self-repair failed for {cve_data['cve_id']} output {output_num}")

        result["output_type"] = output_type
        result["cve_id"] = cve_data.get("cve_id", "")
        return result

    def _call(self, user_message: str, output_type: str) -> dict:
        try:
            response = self.client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=2048,
                system=self.system_prompt,
                messages=[{"role": "user", "content": user_message}],
            )
            content = response.content[0].text
            content = re.sub(r"^```[a-z]*\n?", "", content, flags=re.MULTILINE)
            content = re.sub(r"\n?```$", "", content, flags=re.MULTILINE)
            return {"success": True, "content": content.strip(), "error": None}
        except anthropic.APIError as e:
            log.error(f"Claude API error: {e}")
            return {"success": False, "content": "", "error": str(e)}
