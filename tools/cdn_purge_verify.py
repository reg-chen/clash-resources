#!/usr/bin/env python3
"""Purge changed jsDelivr @main files and verify CDN / optional own-domain content.

Shared by the MRS updater and the standalone purge workflow.
"""
import argparse
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
import subprocess
import sys
import time
from urllib.parse import quote


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_path(raw: str) -> str:
    p = PurePosixPath(raw.strip())
    if (not raw or raw.startswith(("/", "-")) or "\\" in raw
            or p.is_absolute()
            or any(part in (".", "..") for part in raw.split("/"))
            or not str(p).strip(".")):
        raise ValueError(f"Invalid repository path: {raw!r}")
    return str(p)


def fetch(url: str, timeout: int = 30) -> tuple[int, bytes]:
    # --write-out is kept separate from the possibly binary response body.
    proc = subprocess.run(
        ["curl", "--location", "--silent", "--show-error",
         "--connect-timeout", "10", "--max-time", str(timeout),
         "--write-out", "\n%{http_code}", url],
        check=False, capture_output=True,
    )
    if proc.returncode:
        raise RuntimeError(
            f"curl rc={proc.returncode} for {url}: "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )
    body, sep, status = proc.stdout.rpartition(b"\n")
    if not sep or not status.isdigit():
        raise RuntimeError(f"Invalid HTTP status for {url}: {status!r}")
    return int(status), body


def refresh_main() -> str:
    local = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True
    ).strip()
    remote = subprocess.check_output(
        ["git", "ls-remote", "origin", "refs/heads/main"], text=True
    ).strip().split()[0]
    if remote != local:
        print(f"::notice::Refresh to main {remote[:12]} from {local[:12]}", flush=True)
        subprocess.run(["git", "fetch", "--quiet", "origin", "main"], check=True)
        subprocess.run(["git", "reset", "--hard", "FETCH_HEAD"], check=True)
    return remote


def purge(repo: str, path: str) -> tuple[bool, int, str]:
    key = f"/gh/{repo}@main/{path}"
    url = f"https://purge.jsdelivr.net/gh/{repo}@main/{quote(path, safe='/')}"
    print(f"Purge: {url}", flush=True)
    try:
        status, body = fetch(url)
        if status != 200:
            return False, 0, f"purge API HTTP {status}"
        payload = json.loads(body)
        entry = (payload.get("paths") or {}).get(key)
        if payload.get("status") != "finished" or not isinstance(entry, dict):
            return False, 0, f"invalid purge response: {payload!r}"
        if entry.get("throttled"):
            reset = int(entry.get("throttlingReset") or 0)
            print(f"::warning::Purge throttled for {path}, reset ~{reset}s", flush=True)
            return False, reset, "purge rate-limited"
        providers = entry.get("providers")
        if not isinstance(providers, dict) or not providers or not all(
            result is True for result in providers.values()
        ):
            return False, 0, f"purge provider failure: {providers!r}"
        return True, 0, "purge finished"
    except (RuntimeError, ValueError) as exc:
        return False, 0, f"purge request failed: {exc}"


def verify(task: tuple[str, str, str | None]) -> tuple[str, str, int, str | None, str | None]:
    path, url, expected = task
    try:
        status, data = fetch(url)
        actual = sha256(data) if status == 200 else None
        matched = (status == 200 and actual == expected) if expected is not None else status in (404, 410)
        return path, url, status, actual, None if matched else "mismatch"
    except RuntimeError as exc:
        return path, url, 0, None, str(exc)


def run(paths: list[str], repo: str, own_domain: bool, attempts: int, interval: float) -> int:
    if not paths:
        print("No paths to purge.")
        return 0
    revision = refresh_main()
    print(f"Verify @main revision {revision[:12]}", flush=True)
    expected: dict[str, str | None] = {}
    for path in paths:
        local = Path(path)
        expected[path] = sha256(local.read_bytes()) if local.is_file() else None
        print(f"Expected {path}: {expected[path] or '<deleted>'}", flush=True)

    # Purge all paths before verifying any: a stale file must not prevent
    # subsequent files in the same MRS batch from being purged.
    outcomes = {path: purge(repo, path) for path in paths}

    endpoints = {}
    for path in paths:
        encoded = quote(path, safe="/")
        urls = [f"https://cdn.jsdelivr.net/gh/{repo}@main/{encoded}"]
        if own_domain and path.startswith("rules/"):
            urls.append(f"https://rules.reginald.win/{quote(path[6:], safe='/')}")
        endpoints[path] = urls

    pending = {(path, url) for path, urls in endpoints.items() for url in urls}
    observed: dict[tuple[str, str], tuple[int, str | None, str | None]] = {}
    for attempt in range(1, attempts + 1):
        if not pending:
            break
        tasks = [(path, url, expected[path]) for path, url in sorted(pending)]
        with ThreadPoolExecutor(max_workers=min(6, len(tasks))) as pool:
            for path, url, status, actual, error in pool.map(verify, tasks):
                observed[(path, url)] = (status, actual, error)
                if error is None:
                    pending.remove((path, url))
                    print(f"OK {path}: {url} HTTP {status} SHA256={actual}", flush=True)
                elif attempt in (1, attempts):
                    print(
                        f"Pending {path} ({attempt}/{attempts}): {url}; "
                        f"HTTP={status}; actual={actual}; error={error}",
                        flush=True,
                    )
        if pending and attempt < attempts:
            time.sleep(interval)

    if pending:
        print(f"::error::CDN verification incomplete for {len(pending)} endpoint(s)", flush=True)
        for path, url in sorted(pending):
            status, actual, issue = observed.get((path, url), (0, None, "not checked"))
            ok, reset, reason = outcomes[path]
            print(
                f"::error::{path}: {url}; purge={reason}; "
                f"reset={reset}s; expected={expected[path]}; "
                f"actual={actual}; HTTP={status}; issue={issue}",
                flush=True,
            )
        return 1
    for path, (ok, reset, reason) in outcomes.items():
        if not ok:
            print(f"::notice::{path}: content converged despite {reason}", flush=True)
    print(f"All {len(paths)} changed paths match current repository content.", flush=True)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--paths-file", required=True)
    p.add_argument("--verify-domain", action="store_true")
    p.add_argument("--attempts", type=int, default=16)
    p.add_argument("--interval", type=float, default=8)
    args = p.parse_args()
    if args.attempts < 1 or args.interval < 0:
        p.error("attempts must be positive; interval must be nonnegative")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        p.error("GITHUB_REPOSITORY missing")
    paths = sorted(set(checked_path(s) for s in Path(args.paths_file).read_text().splitlines() if s.strip()))
    return run(paths, repo, args.verify_domain, args.attempts, args.interval)


if __name__ == "__main__":
    sys.exit(main())
