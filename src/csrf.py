"""Lightweight CSRF (Cross-Site Request Forgery) protection for a single-
operator FastAPI app sitting behind HTTP Basic Auth + TLS at nginx, no
session cookies of its own.

Why this is needed even with Basic Auth (not just cookie-based sessions):
browsers cache Basic Auth credentials per-origin for the life of the tab/
session and auto-attach them to same-origin requests -- including ones
triggered by a malicious cross-site page the analyst has open in another
tab. Unlike cookies, Basic Auth has no SameSite attribute to opt out of
that behavior, so a state-changing POST endpoint (reset conversation,
retry, chat) is just as forgeable as it would be with a cookie session,
absent some other check.

This uses the Origin-header check pattern (simpler than a double-submit
token: no session state, no hidden form field, no template changes) --
a forged cross-origin request cannot set a custom Origin header the
browser will honor, and modern browsers send Origin on every cross-
origin POST, XHR, and fetch. Falls back to Referer only when Origin is
absent (some older/non-browser clients omit it), and fails CLOSED (403)
when neither header is present on a POST -- a legitimate browser always
sends at least one on a form/fetch POST, so their total absence is
itself a signal of something outside normal browser behavior.

Canonical copy -- vendor into each app's own src/, same rationale as
llm_provider.py's own header note.
"""
from __future__ import annotations

from urllib.parse import urlparse

from fastapi import HTTPException, Request


def verify_same_origin(request: Request) -> None:
    """Call at the top of every state-changing (POST/PUT/DELETE) route.
    Raises HTTPException(403) on a cross-origin or originless request."""
    origin = request.headers.get("origin")
    source = origin
    if not source:
        referer = request.headers.get("referer")
        source = referer

    if not source:
        raise HTTPException(status_code=403, detail="Missing Origin/Referer header on a state-changing request.")

    source_host = urlparse(source).netloc
    request_host = request.headers.get("host", "")
    if source_host != request_host:
        raise HTTPException(
            status_code=403,
            detail=f"Cross-origin request rejected (Origin/Referer host {source_host!r} != {request_host!r}).",
        )


# Example wiring in a FastAPI route:
#
#   @app.post("/chat")
#   def chat(request: Request, ...):
#       verify_same_origin(request)
#       ...
#
# Or, applied to every route in the app at once via middleware instead of
# per-route: only check state-changing methods, GETs are never CSRF targets.
#
#   @app.middleware("http")
#   async def csrf_middleware(request: Request, call_next):
#       if request.method in ("POST", "PUT", "PATCH", "DELETE"):
#           verify_same_origin(request)
#       return await call_next(request)
