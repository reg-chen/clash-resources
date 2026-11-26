"""Private Windows MRS build, using the same parser/compiler as public CI."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from mrs_build import build

TASK_NAME = "Clash Local MRS Refresh"
FREQUENCIES = (1, 2, 4, 6, 12, 24)
DEFAULT_ROOT = r"P:\Clash"
PROVIDERS = {
    "combined-security": "rules/security/mrs/combined.mrs",
    "combined-security-ip": "rules/security/mrs/combined-ip.mrs",
    "combined-privacy": "rules/privacy/mrs/combined.mrs",
    "combined-ads": "rules/ads/mrs/combined.mrs",
}
CUSTOM = ("security", "privacy", "ads")


def bundled(name):
    return Path(getattr(sys, "_MEIPASS", Path(__file__).parent)) / name


def catalog():
    return json.loads(bundled("third-party-mrs-sources.json").read_text(encoding="utf-8"))


def profile_path():
    base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    return base / "reg-chen" / "VPN-Network-Toolkit" / "local-mrs.json"


def load_profile():
    path = profile_path()
    if not path.exists():
        return {"sources": [s["name"] for s in catalog() if s.get("distribution", "public") == "public"],
                "directory": DEFAULT_ROOT, "mihomo": shutil.which("mihomo.exe") or "",
                "hours": 2}
    return json.loads(path.read_text(encoding="utf-8"))


def needs_takeover(root):
    root = Path(root).expanduser().resolve()
    return (not (root / ".local-mrs").is_file()
            and any((root / relative).exists() for relative in PROVIDERS.values()))


def validate(profile):
    ids = profile.get("sources")
    if not isinstance(ids, list) or any(not isinstance(v, str) for v in ids):
        raise ValueError("Invalid source selection")
    selected = [s for s in catalog() if s["name"] in ids]
    if len(selected) != len(set(ids)):
        raise ValueError("Unknown source selection; update toolkit")
    for category in CUSTOM:
        if not any(s["name"].startswith(category + "-") and s.get("behavior") != "ipcidr" for s in selected):
            raise ValueError(f"至少選擇一個 {category} 網域來源。")
    if not any(s.get("behavior") in ("ipcidr", "domain-ipcidr") for s in selected):
        raise ValueError("至少選擇一個 IPv4 來源。")
    if profile.get("hours") not in FREQUENCIES:
        raise ValueError("Invalid schedule frequency")
    if not str(profile.get("directory", "")).strip():
        raise ValueError("請選擇本機輸出目錄。")
    root = Path(profile["directory"]).expanduser()
    if not root.is_absolute() or root == Path(root.anchor):
        raise ValueError("請使用獨立的絕對輸出目錄。")
    if not str(profile.get("mihomo", "")).strip():
        raise ValueError("請選擇 Mihomo 執行檔。")
    exe = Path(profile["mihomo"]).expanduser()
    if not exe.is_absolute() or not exe.is_file():
        raise ValueError("找不到 Mihomo 執行檔。")
    root = root.resolve()
    if any((parent / ".git").exists() for parent in (root, *root.parents)):
        raise ValueError("本機輸出不可位於 Git 工作樹內。")
    if needs_takeover(root) and profile.get("takeover_root") != str(root):
        raise ValueError("輸出目錄已有 MRS；須先切換為 file provider 並確認接管。")
    return selected, root, exe.resolve()


def save_profile(profile):
    validate(profile)
    path = profile_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as file:
        tmp = Path(file.name)
        json.dump(profile, file, ensure_ascii=False, indent=2)
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


@contextlib.contextmanager
def build_lock(root):
    # OS-owned lock is released even if a scheduled process crashes.
    with (root / ".build.lock").open("a+b") as handle:
        handle.seek(0)
        if sys.platform == "win32":
            import msvcrt
            if not handle.read(1):
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def override_yaml(root):
    lines = ["# Merge into the PC profile only; keep all existing RULE-SET entries.",
             "rule-providers:"]
    for name, relative in PROVIDERS.items():
        lines.extend([f"  {name}:", "    type: file",
                      f"    behavior: {'ipcidr' if name.endswith('-ip') else 'domain'}",
                      "    format: mrs",
                      "    path: " + json.dumps(str(root / relative), ensure_ascii=False)])
    return "\n".join(lines) + "\n"


def publish(stage, root, paths):
    """Validate all candidates first; replace individually and roll back on errors."""
    with tempfile.TemporaryDirectory(prefix=".rollback-", dir=root) as folder:
        backups = Path(folder)
        completed = []
        for relative in paths:
            source = stage / relative
            target = root / relative
            if not source.is_file():
                raise RuntimeError(f"Missing candidate: {relative}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                backup = backups / relative
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, backup)
        try:
            for relative in paths:
                os.replace(stage / relative, root / relative)
                completed.append(relative)
        except BaseException:
            for relative in reversed(completed):
                backup = backups / relative
                target = root / relative
                if backup.is_file():
                    os.replace(backup, target)
                else:
                    target.unlink(missing_ok=True)
            raise


def run(profile):
    selected, root, exe = validate(profile)
    root.mkdir(parents=True, exist_ok=True)
    with build_lock(root), tempfile.TemporaryDirectory(prefix=".build-", dir=root) as folder:
        stage = Path(folder)
        (stage / "tools").mkdir()
        for category in CUSTOM:
            relative = Path("rules") / category / "custom.txt"
            (stage / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            # Private custom rules may be edited in the output directory.
            source = root / relative
            if not source.is_file():
                source = bundled("mrs-custom-" + category + ".txt")
                if not getattr(sys, "frozen", False) and not source.is_file():
                    source = Path(__file__).resolve().parent.parent / relative
                shutil.copyfile(source, root / relative)
            shutil.copyfile(source, stage / relative)
        # Desktop uses the four combined outputs only, never the iOS artifact.
        entries = [{k: v for k, v in item.items() if k != "target"} for item in selected]
        outputs = build(stage, entries, executable=str(exe), report_dir=stage)
        if {item["path"] for item in outputs} != set(PROVIDERS.values()):
            raise RuntimeError("Unexpected local MRS outputs")
        for item in outputs:
            data = (stage / item["path"]).read_bytes()
            if len(data) != item["size_bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise RuntimeError("Local MRS verification failed")
        (stage / "local-mrs.yaml").write_text(override_yaml(root), encoding="utf-8")
        manifest = json.loads((stage / "tools/third-party-mrs-provenance.json").read_text())
        paths = [i["source_snapshot_path"] for i in manifest["inputs"]]
        paths += ["tools/third-party-mrs-sha256.json", "tools/third-party-mrs-provenance.json",
                  "mrs-overlap.md", "mrs-skipped.md", "local-mrs.yaml"]
        paths += [item["path"] for item in outputs]
        # Do not rewrite unchanged provider files or trigger needless file watchers.
        paths = [p for p in paths if not (root / p).is_file() or
                 (root / p).read_bytes() != (stage / p).read_bytes()]
        publish(stage, root, paths)
        (root / ".local-mrs").touch(exist_ok=True)
        print(f"Local MRS: {len(selected)} sources, {len(paths)} changed files")
        return root


def cli(argv):
    import argparse
    parser = argparse.ArgumentParser(description="Build private local MRS without GUI")
    parser.add_argument("--mrs", action="store_true", required=True)
    parser.parse_args(argv)
    log = profile_path().parent / "local-mrs.log"
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        # One bounded last-run log; task never uploads source or output.
        with log.open("w", encoding="utf-8") as stream, contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            print(datetime.now().astimezone().isoformat())
            try:
                run(load_profile())
                return 0
            except Exception:
                import traceback
                traceback.print_exc()
                return 1
    except OSError:
        return 2
