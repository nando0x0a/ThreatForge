"""Shared retry/backoff + structured JSON logging for Cloud web apps.

Neither Vuln-Skill nor soc-skill-cloud had any retry or explicit timeout
on their LLM call sites before the 2026-08-06 production-hardening pass --
a transient timeout/429/5xx from the Anthropic API surfaced straight to
the analyst as a hard error requiring a manual retry click. `with_retry`
fixes that with the 2026 production-standard pattern (3 attempts,
exponential backoff from 1s, retry only on timeout/429/5xx -- never on a
validation error or bad request, which a retry can't fix).

Canonical copy -- vendor into each app's own src/, same rationale as
llm_provider.py's own header note (separate containers, no shared
filesystem/package registry).
"""
from __future__ import annotations

import functools
import json
import logging
import random
import time
import uuid
from contextvars import ContextVar

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")


def new_correlation_id() -> str:
    """Call once per inbound request (e.g. at the top of a /chat handler)
    so every log line emitted while handling it, including across
    retries, carries the same ID."""
    cid = uuid.uuid4().hex[:12]
    _correlation_id.set(cid)
    return cid


def get_correlation_id() -> str:
    return _correlation_id.get()


class JSONFormatter(logging.Formatter):
    """One JSON object per line -- greppable and ingestible by any log
    aggregator (CloudWatch, Datadog, plain `jq`), unlike the plain-text
    `logging.basicConfig` default both apps started with."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "correlation_id": get_correlation_id(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(extra)
        return json.dumps(payload, default=str)


def configure_json_logging(level: int = logging.INFO) -> None:
    """Call once at app startup in place of `logging.basicConfig(...)`."""
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)


def _is_retryable(exc: Exception) -> bool:
    """Classified by exception class NAME, not isinstance -- this module
    has no hard dependency on the anthropic/openai SDKs, so it never
    imports them just to check error types. Both SDKs use these same
    names for the same failure classes."""
    name = type(exc).__name__
    if name in ("APITimeoutError", "RateLimitError", "APIConnectionError"):
        return True
    if name in ("APIStatusError", "InternalServerError"):
        status = getattr(exc, "status_code", None)
        return status is not None and (status == 429 or status >= 500)
    return False


def with_retry(attempts: int = 3, base_delay: float = 1.0, max_delay: float = 8.0):
    """Exponential backoff (base_delay, then doubling, capped at
    max_delay, plus up to 0.25s jitter), retrying ONLY on timeout/429/5xx.
    Never retries a validation error, auth failure, or bad request --
    those can't be fixed by trying again and a retry would just burn
    tokens repeating a doomed call."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            call_log = logging.getLogger(fn.__module__)
            last_exc: Exception | None = None
            for attempt in range(1, attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except Exception as exc:
                    last_exc = exc
                    if attempt == attempts or not _is_retryable(exc):
                        raise
                    delay = min(max_delay, base_delay * (2 ** (attempt - 1))) + random.uniform(0, 0.25)
                    call_log.warning(
                        "retryable error on attempt %d/%d, backing off %.2fs: %s",
                        attempt, attempts, delay, exc,
                        extra={"extra_fields": {
                            "attempt": attempt, "delay_s": round(delay, 2), "error_type": type(exc).__name__,
                        }},
                    )
                    time.sleep(delay)
            raise last_exc  # pragma: no cover -- unreachable, satisfies type checkers
        return wrapper
    return decorator
