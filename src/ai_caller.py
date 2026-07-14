#!/usr/bin/env python3
import os
import re
import logging

from context_assembler import ContextAssembler
from config_loader import load_config

log = logging.getLogger("ai_caller")


class AICaller:
    def __init__(self):
        cfg = load_config()
        ai_cfg = cfg["ai_provider"]
        self.provider = ai_cfg["provider"]
        self.model = ai_cfg["model"]
        self.max_tokens = ai_cfg.get("max_tokens", 2048)
        self.assembler = ContextAssembler()
        self.system_prompt = cfg["prompts"]["system_prompt"]
        self.few_shot = cfg["prompts"]["few_shot_rules"]
        self.templates = cfg["prompts"]["output_templates"]
        self.output_menu = {int(k): v for k, v in cfg["output_menu"].items()}

        if self.provider == "anthropic":
            import anthropic
            api_key = os.getenv(ai_cfg.get("api_key_env", "ANTHROPIC_API_KEY"), "")
            self.client = anthropic.Anthropic(api_key=api_key)
        elif self.provider == "openai_compatible":
            import openai
            api_key = os.getenv(ai_cfg.get("api_key_env", "OPENAI_API_KEY"), "") or "not-needed"
            self.client = openai.OpenAI(api_key=api_key, base_url=ai_cfg.get("base_url"))
        else:
            raise ValueError(f"Unknown ai_provider.provider: {self.provider!r} (expected 'anthropic' or 'openai_compatible')")

    def produce(self, output_num: int, cve_data: dict) -> dict:
        menu_entry = self.output_menu.get(output_num, {})
        output_type = menu_entry.get("key", "unknown")
        template = self.templates.get(output_type, "")
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

        result = self._call(user_message)

        if not result["success"] and result.get("error"):
            log.info(f"Self-repair retry for {cve_data['cve_id']} output {output_num}")
            retry_msg = user_message + f"\n\nPrevious attempt failed:\n{result['error']}\nPlease fix and try again."
            result = self._call(retry_msg)
            if not result["success"]:
                result["review_needed"] = True
                log.warning(f"Self-repair failed for {cve_data['cve_id']} output {output_num}")

        result["output_type"] = output_type
        result["cve_id"] = cve_data.get("cve_id", "")
        return result

    def _call(self, user_message: str) -> dict:
        try:
            if self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=self.system_prompt,
                    messages=[{"role": "user", "content": user_message}],
                )
                content = response.content[0].text
            else:
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                )
                content = response.choices[0].message.content

            content = re.sub(r"^```[a-z]*\n?", "", content, flags=re.MULTILINE)
            content = re.sub(r"\n?```$", "", content, flags=re.MULTILINE)
            return {"success": True, "content": content.strip(), "error": None}
        except Exception as e:
            log.error(f"AI API error ({self.provider}): {e}")
            return {"success": False, "content": "", "error": str(e)}
