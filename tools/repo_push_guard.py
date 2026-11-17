"""Local pre-push throttle to avoid accidental CI-triggering push bursts.

This is a local Git hook, NOT a GitHub server-side control. REST/API writes,
web edits, and `git push --no-verify` bypass it. The state is local to .git.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

WINDOW_SECONDS = 10 * 60
MAX_ATTEMPTS = 3
OVERRIDE_VAR = "CLASH_PUSH_GUARD_OVERRIDE"


def recent_attempts(timestamps: object, now: float) -> list[float]:
    if not isinstance(timestamps, list):
        raise ValueError("Invalid push guard state")
    result = []
    for timestamp in timestamps:
        if not isinstance(timestamp, (float, int)) or isinstance(timestamp, bool):
            raise ValueError("Invalid push guard timestamp")
        if 0 <= now - timestamp < WINDOW_SECONDS:
            result.append(float(timestamp))
    return result


def main() -> int:
    try:
        git_path = subprocess.check_output(
            ["git", "rev-parse", "--git-path", "push-guard-attempts.json"],
            text=True, encoding="utf-8", stderr=subprocess.DEVNULL
        ).strip()
        state_file = Path(git_path)
        saved = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else []
        now = time.time()
        recent = recent_attempts(saved, now)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"[push-guard] Cannot verify push frequency: {exc}", file=sys.stderr)
        return 1

    if len(recent) >= MAX_ATTEMPTS and os.getenv(OVERRIDE_VAR) != "1":
        remaining = int(WINDOW_SECONDS - (now - recent[0]) + 0.999)
        print(
            f"[push-guard] Blocked: {len(recent)} push attempts in 10 minutes. "
            f"Combine changes and retry after approximately {remaining} seconds.\n"
            f"To intentionally override: set {OVERRIDE_VAR}=1 for this push.\n"
            "This guard does not cover GitHub API writes.",
            file=sys.stderr,
        )
        return 1

    # Record *attempts*, not successes: pre-push runs before the remote accepts it.
    # The file is inside .git, never committed to the repository.
    recent.append(now)
    try:
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(recent), encoding="utf-8")
        tmp.replace(state_file)
    except OSError as exc:
        print(f"[push-guard] Cannot record push attempt: {exc}", file=sys.stderr)
        return 1
    if len(recent) == MAX_ATTEMPTS:
        print("[push-guard] Third push attempt in 10 minutes; next one will be blocked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
