"""Shared LLM (Large Language Model) provider abstraction for Cloud web
apps (Vuln-Skill, soc-skill-cloud, and whatever's next). One place to add
a new provider; app code talks to LLMResponse/get_provider() only, never
imports `anthropic`/`openai` directly at the call site.

Provider selection is two env vars, matching the pattern already proven in
Vuln-Skill's ai_caller.py before this scaffold existed:
  LLM_PROVIDER   "anthropic" (default) or "openai_compatible"
  LLM_BASE_URL   only used by openai_compatible -- point it at OpenAI's own
                 API, or a local server's OpenAI-compatible endpoint
                 (LM Studio, Ollama's OpenAI shim, vLLM), same provider
                 code either way. Local vs. "real" OpenAI is a base_url
                 difference only, not a third provider name.

Anthropic-native server tools (web_search, web_fetch) are NOT portable to
openai_compatible -- there is no equivalent tool-call contract on a
generic OpenAI-compatible endpoint. Passing `tools=` to a non-Anthropic
provider raises UnsupportedToolsError rather than silently dropping
enrichment capability. Any app whose analysis workflow depends on live
web_search/web_fetch (soc-skill-cloud's § 5.4 OSINT enrichment, for one)
must stay on the anthropic provider until a provider-specific tool
adapter is written for the alternate backend -- that adapter does not
exist yet and is real work, not a config flip.

This file is the canonical copy. Each app vendors its own copy into its
own src/ (see that app's own llm_provider.py) since apps deploy as
separate containers with no shared filesystem/package registry -- copy
this file wholesale into a new app's src/, don't try to import it across
repos at runtime.
"""
from __future__ import annotations

import os
import logging
from dataclasses import dataclass

log = logging.getLogger("llm_provider")


class UnsupportedToolsError(RuntimeError):
    """Raised when `tools=` is passed to a provider that can't execute them."""


@dataclass
class LLMResponse:
    text: str
    model: str
    input_tokens: int
    output_tokens: int
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    web_search_requests: int = 0
    stop_reason: str | None = None
    raw: object = None  # provider-native response, for callers that need e.g. a pause_turn loop


class LLMProvider:
    name: str

    def create_message(
        self, *, model: str, system: str, messages: list[dict],
        max_tokens: int, tools: list[dict] | None = None,
    ) -> LLMResponse:
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key_env: str = "ANTHROPIC_API_KEY"):
        import anthropic
        self._client = anthropic.Anthropic(api_key=os.getenv(api_key_env) or None)

    def create_message(self, *, model, system, messages, max_tokens, tools=None):
        kwargs = dict(model=model, max_tokens=max_tokens, system=system, messages=messages)
        if tools:
            kwargs["tools"] = tools
        response = self._client.messages.create(**kwargs)
        text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
        usage = response.usage
        server_tool_use = getattr(response, "server_tool_use", None) or getattr(usage, "server_tool_use", None)
        web_searches = getattr(server_tool_use, "web_search_requests", 0) or 0
        return LLMResponse(
            text=text,
            model=model,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_write_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            web_search_requests=web_searches,
            stop_reason=getattr(response, "stop_reason", None),
            raw=response,
        )


class OpenAICompatibleProvider(LLMProvider):
    """Covers both real OpenAI and any OpenAI-compatible local server
    (LM Studio, Ollama's OpenAI shim, vLLM, etc.) -- same code path,
    distinguished only by base_url. Matches the pattern already proven in
    Vuln-Skill's ai_caller.py (its "openai_compatible" provider)."""
    name = "openai_compatible"

    def __init__(self, api_key_env: str = "OPENAI_API_KEY", base_url_env: str = "LLM_BASE_URL"):
        import openai
        api_key = os.getenv(api_key_env) or "not-needed"  # local servers frequently ignore the key entirely
        base_url = os.getenv(base_url_env) or None
        self._client = openai.OpenAI(api_key=api_key, base_url=base_url)

    def create_message(self, *, model, system, messages, max_tokens, tools=None):
        if tools:
            names = [t.get("name", t.get("type")) for t in tools]
            raise UnsupportedToolsError(
                f"{self.name} provider cannot execute Anthropic-native tools {names!r}. "
                "Enrichment features that depend on server-side web_search/web_fetch require "
                "the anthropic provider until a provider-specific tool adapter exists."
            )
        chat_messages = [{"role": "system", "content": system}] + messages
        response = self._client.chat.completions.create(
            model=model, max_tokens=max_tokens, messages=chat_messages
        )
        choice = response.choices[0]
        usage = getattr(response, "usage", None)
        return LLMResponse(
            text=choice.message.content or "",
            model=model,
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage, "completion_tokens", 0) or 0,
            stop_reason=getattr(choice, "finish_reason", None),
            raw=response,
        )


_PROVIDERS = {"anthropic": AnthropicProvider, "openai_compatible": OpenAICompatibleProvider}


def get_provider(name: str | None = None) -> LLMProvider:
    name = name or os.getenv("LLM_PROVIDER", "anthropic")
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ValueError(f"Unknown LLM_PROVIDER {name!r} (expected one of {sorted(_PROVIDERS)})")
    return cls()


# --- Model tier config, shared by both apps -----------------------------
# Sonnet 5 is the default assistant-facing model as of 2026-08-06 -- both
# apps' interactive chat previously defaulted to something else (Haiku for
# Vuln-Skill, Opus for soc-skill-cloud), neither an intentional policy,
# just how each app happened to start. Haiku stays fixed here (not env-
# overridable) for two roles that specifically want the cheapest/fastest
# model: prompt-injection pre-screening (a low-latency classification of
# adversarial input, not the main analysis) and an opt-in test-mode
# override so local iteration doesn't burn Sonnet-rate tokens.
DEFAULT_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-5")
# Dated snapshot ID, not the bare "claude-haiku-4-5" alias -- Vuln-Skill's
# own chat already used this exact dated form successfully in production;
# soc-skill-cloud had independently used the undated form for the same
# model, which this scaffold standardizes on the dated one as the single
# source of truth (2026-08-06). If Anthropic ever adds a stable undated
# alias for this model, update here once rather than in each app.
SCREEN_MODEL = "claude-haiku-4-5-20251001"  # injection pre-screen -- always Haiku
TEST_MODEL = "claude-haiku-4-5-20251001"    # opt-in via LLM_TEST_MODE=1


def get_active_model(default: str = DEFAULT_MODEL) -> str:
    """DEFAULT_MODEL, unless LLM_TEST_MODE=1 forces the cheap Haiku path
    for local iteration/testing -- one place both apps check instead of
    each hand-rolling its own env-var branch."""
    if os.getenv("LLM_TEST_MODE", "").lower() in ("1", "true", "yes"):
        return TEST_MODEL
    return default
