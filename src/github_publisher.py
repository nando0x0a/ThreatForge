#!/usr/bin/env python3
import os
import base64
import logging
import requests

log = logging.getLogger("github_publisher")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")
_API = "https://api.github.com"


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _get_sha(path: str) -> str | None:
    """Return the blob SHA of an existing file, or None if it doesn't exist."""
    url = f"{_API}/repos/{GITHUB_REPO}/contents/{path}"
    try:
        resp = requests.get(url, headers=_headers(), params={"ref": GITHUB_BRANCH}, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("sha")
    except Exception as e:
        log.debug(f"SHA lookup failed for {path}: {e}")
    return None


def publish(local_path: str, repo_path: str, commit_message: str) -> bool:
    """Push a local file to the GitHub repo. Creates or updates as needed."""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        log.debug("GitHub publishing skipped — GITHUB_TOKEN or GITHUB_REPO not set")
        return False

    try:
        with open(local_path, "rb") as f:
            content_b64 = base64.b64encode(f.read()).decode()
    except Exception as e:
        log.error(f"Failed to read {local_path} for GitHub publish: {e}")
        return False

    sha = _get_sha(repo_path)
    payload = {
        "message": commit_message,
        "content": content_b64,
        "branch": GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha

    url = f"{_API}/repos/{GITHUB_REPO}/contents/{repo_path}"
    try:
        resp = requests.put(url, headers=_headers(), json=payload, timeout=15)
        resp.raise_for_status()
        action = "updated" if sha else "created"
        log.info(f"GitHub: {action} {repo_path}")
        return True
    except Exception as e:
        log.error(f"GitHub publish failed for {repo_path}: {e}")
        return False
