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


def clean_outputs(prefix: str = "outputs/") -> int:
    """Delete every file under `prefix` in the repo, in a single commit —
    called once before each --produce run so GitHub never accumulates
    outputs across runs, mirroring the local clean_before_run behavior.
    Uses the Git Data API (tree/commit/ref) rather than one DELETE call per
    file, which would create one commit per file instead of one commit total."""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        log.debug("GitHub cleanup skipped — GITHUB_TOKEN or GITHUB_REPO not set")
        return 0

    ref_url = f"{_API}/repos/{GITHUB_REPO}/git/refs/heads/{GITHUB_BRANCH}"
    try:
        resp = requests.get(ref_url, headers=_headers(), timeout=10)
        resp.raise_for_status()
        base_commit_sha = resp.json()["object"]["sha"]

        resp = requests.get(f"{_API}/repos/{GITHUB_REPO}/git/commits/{base_commit_sha}", headers=_headers(), timeout=10)
        resp.raise_for_status()
        base_tree_sha = resp.json()["tree"]["sha"]

        resp = requests.get(f"{_API}/repos/{GITHUB_REPO}/git/trees/{base_tree_sha}?recursive=1", headers=_headers(), timeout=15)
        resp.raise_for_status()
        tree_items = resp.json().get("tree", [])
    except Exception as e:
        log.error(f"GitHub: failed to read tree for cleanup: {e}")
        return 0

    to_delete = [item for item in tree_items if item.get("type") == "blob" and item["path"].startswith(prefix)]
    if not to_delete:
        return 0

    # base_tree + entries with sha=None removes each path from the resulting tree
    new_tree_entries = [{"path": item["path"], "mode": item["mode"], "type": "blob", "sha": None} for item in to_delete]
    try:
        resp = requests.post(
            f"{_API}/repos/{GITHUB_REPO}/git/trees", headers=_headers(),
            json={"base_tree": base_tree_sha, "tree": new_tree_entries}, timeout=15,
        )
        resp.raise_for_status()
        new_tree_sha = resp.json()["sha"]

        resp = requests.post(
            f"{_API}/repos/{GITHUB_REPO}/git/commits", headers=_headers(),
            json={
                "message": f"ThreatForge: clean {len(to_delete)} file(s) under {prefix}",
                "tree": new_tree_sha,
                "parents": [base_commit_sha],
            },
            timeout=15,
        )
        resp.raise_for_status()
        new_commit_sha = resp.json()["sha"]

        resp = requests.patch(ref_url, headers=_headers(), json={"sha": new_commit_sha}, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        log.error(f"GitHub: cleanup commit failed: {e}")
        return 0

    log.info(f"GitHub: cleaned {len(to_delete)} file(s) under {prefix} in one commit")
    return len(to_delete)


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
