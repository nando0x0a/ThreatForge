#!/usr/bin/env python3
import os
import re
import logging

from context_assembler import ContextAssembler
from config_loader import load_config

log = logging.getLogger("ai_caller")

# USD per token, verified against docs.claude.com/en/docs/about-claude/pricing
# on 2026-07-30. cache_write is the 5-minute rate (this app doesn't request
# 1-hour caching). Models not listed here (e.g. a config change to a model
# released after this was last checked) get cost=None rather than a guess —
# re-verify and add a row before trusting a number for a new model.
PRICING = {
    "claude-opus-5":     {"input": 5.00, "cache_write": 6.25, "cache_read": 0.50, "output": 25.00},
    "claude-sonnet-5":   {"input": 3.00, "cache_write": 3.75, "cache_read": 0.30, "output": 15.00},
    "claude-sonnet-4-6": {"input": 3.00, "cache_write": 3.75, "cache_read": 0.30, "output": 15.00},
    "claude-haiku-4-5":  {"input": 1.00, "cache_write": 1.25, "cache_read": 0.10, "output": 5.00},
}


def _extract_usage(model: str, usage) -> dict:
    input_tokens = usage.input_tokens
    output_tokens = usage.output_tokens
    cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
    cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
    rates = PRICING.get(model)
    cost = None
    if rates:
        cost = (
            input_tokens * rates["input"]
            + cache_write * rates["cache_write"]
            + cache_read * rates["cache_read"]
            + output_tokens * rates["output"]
        ) / 1_000_000
    return {"input": input_tokens, "output": output_tokens, "cache_write": cache_write, "cache_read": cache_read, "cost": cost}


def _sum_usage(a: dict | None, b: dict | None) -> dict | None:
    """Combine usage across the initial call and a self-repair retry, if any
    — either side may be None (a call that raised before any usage came
    back)."""
    if not a and not b:
        return None
    a = a or {}
    b = b or {}
    merged = {k: (a.get(k) or 0) + (b.get(k) or 0) for k in ("input", "output", "cache_write", "cache_read")}
    cost_a, cost_b = a.get("cost"), b.get("cost")
    merged["cost"] = (cost_a or 0) + (cost_b or 0) if (cost_a is not None or cost_b is not None) else None
    return merged


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
            # Keyed off the menu entry's own "key" (e.g. "signatures"), not
            # output_num -- a magic-number check here would silently break
            # (fire for the wrong type, or never fire at all) every time
            # config/vuln-skill.yaml's output_menu gets renumbered, exactly
            # what happened when technical_findings was retired and every
            # entry after it shifted down by one.
            f"{self.few_shot if output_type == 'signatures' else ''}\n\n"
            f"{template}"
        )

        result = self._call(user_message)

        if not result["success"] and result.get("error"):
            log.info(f"Self-repair retry for {cve_data['cve_id']} output {output_num}")
            retry_msg = user_message + f"\n\nPrevious attempt failed:\n{result['error']}\nPlease fix and try again."
            retry_result = self._call(retry_msg)
            retry_result["usage"] = _sum_usage(result.get("usage"), retry_result.get("usage"))
            result = retry_result
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
                usage = _extract_usage(self.model, response.usage)
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
                # No verified per-token pricing for arbitrary openai_compatible
                # endpoints — token counts only, no cost estimate.
                u = getattr(response, "usage", None)
                usage = {"input": u.prompt_tokens, "output": u.completion_tokens, "cache_write": 0, "cache_read": 0, "cost": None} if u else None

            content = re.sub(r"^```[a-z]*\n?", "", content, flags=re.MULTILINE)
            content = re.sub(r"\n?```$", "", content, flags=re.MULTILINE)
            return {"success": True, "content": content.strip(), "error": None, "usage": usage}
        except Exception as e:
            log.error(f"AI API error ({self.provider}): {e}")
            return {"success": False, "content": "", "error": str(e), "usage": None}
