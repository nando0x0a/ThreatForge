"""In-process per-IP rate limiting for a single-instance FastAPI app --
no external dependency (Redis, etc.) and no new AWS resource (WAF, API
Gateway), matching the "stay inside the current instance" constraint both
Vuln-Skill and soc-skill-cloud operate under. State lives in a plain dict
in the process's own memory: correct for a single uvicorn worker (which
is what both apps run today -- check your own Dockerfile CMD/compose
`command:` before assuming this still holds if that ever changes to
multiple workers, where each worker would track its own separate counts).

Canonical copy -- vendor into each app's own src/, same rationale as
llm_provider.py's own header note.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class InMemoryRateLimiter:
    def __init__(self, max_requests: int = 20, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)

    def check(self, key: str) -> None:
        """Raises HTTPException(429) if `key` (typically client IP) has
        exceeded max_requests within window_seconds. Call at the top of
        any endpoint that triggers an LLM call -- the expensive/abusable
        path, not every static asset."""
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()
        if len(hits) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - hits[0])) + 1
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please slow down.",
                headers={"Retry-After": str(retry_after)},
            )
        hits.append(now)


def client_ip(request: Request) -> str:
    """Behind nginx (both apps' actual deployment), the real client IP is
    in X-Forwarded-For, not request.client.host (which is nginx's own
    loopback address). Falls back to request.client.host for local/direct
    testing without nginx in front."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# Example wiring in a FastAPI route:
#
#   chat_limiter = InMemoryRateLimiter(max_requests=20, window_seconds=60.0)
#
#   @app.post("/chat")
#   def chat(request: Request, ...):
#       chat_limiter.check(client_ip(request))
#       ...
