"""Fast, offline source checks for staged files (no bytecode or rewrites)."""

import json
import subprocess
import sys
from pathlib import Path


def check(path: Path) -> None:
    suffix = path.suffix.lower()
    if suffix == ".py":
        # compile() checks syntax without creating __pycache__ files.
        compile(path.read_bytes(), str(path), "exec")
    elif suffix == ".json":
        json.loads(path.read_text(encoding="utf-8-sig"))
    elif suffix in {".js", ".mjs", ".cjs"}:
        subprocess.run(["node", "--check", str(path)], check=True)


def main(args: list[str]) -> int:
    failed = False
    for name in args:
        path = Path(name)
        if not path.is_file():
            continue  # Removed files should not fail the hook.
        try:
            check(path)
        except (OSError, SyntaxError, ValueError, subprocess.CalledProcessError) as exc:
            print(f"[preflight] {path}: {exc}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
