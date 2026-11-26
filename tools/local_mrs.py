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

from mrs_build import build, fetch_source_bytes
from mrs_provenance import raw_source_parts, verify_source_snapshots
from mrs_ip import FEODO_URL
import mrs_controller
import mrs_compiler

TASK_NAME = "Clash Local MRS Refresh"
MIN_HOURS = 1
MAX_HOURS = 31 * 24
DEFAULT_ROOT = r"P:\Clash"
PROVIDERS = {
    "combined-security": "rules/security/mrs/combined.mrs",
    "combined-security-ip": "rules/security/mrs/combined-ip.mrs",
    "combined-privacy": "rules/privacy/mrs/combined.mrs",
    "combined-ads": "rules/ads/mrs/combined.mrs",
}
CUSTOM = ("security", "privacy", "ads")
BUILD_STATE = "tools/local-mrs-build-state.json"


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
                "directory": DEFAULT_ROOT, "mihomo": "",
                "hours": 2, "notify_mihomo": True, "controller_url": mrs_controller.DEFAULT_URL}
    profile = json.loads(path.read_text(encoding="utf-8"))
    profile.setdefault("notify_mihomo", True)
    profile.setdefault("controller_url", mrs_controller.DEFAULT_URL)
    return profile


def needs_takeover(root):
    root = Path(root).expanduser().resolve()
    return (not (root / ".local-mrs").is_file()
            and any((root / relative).exists() for relative in PROVIDERS.values()))


def validate_hours(hours):
    if type(hours) is not int or not MIN_HOURS <= hours <= MAX_HOURS:
        raise ValueError(f"排程間隔必須為 {MIN_HOURS}–{MAX_HOURS} 的整數小時。")
    return hours


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
    validate_hours(profile.get("hours"))
    if not str(profile.get("directory", "")).strip():
        raise ValueError("請選擇本機輸出目錄。")
    root = Path(profile["directory"]).expanduser()
    if not root.is_absolute() or root == Path(root.anchor):
        raise ValueError("請使用獨立的絕對輸出目錄。")
    manual = str(profile.get("mihomo") or "").strip()
    exe = Path(manual).expanduser() if manual else None
    if exe is not None and not exe.is_absolute():
        raise ValueError("Mihomo 備援路徑必須為絕對路徑。")
    root = root.resolve()
    if any((parent / ".git").exists() for parent in (root, *root.parents)):
        raise ValueError("本機輸出不可位於 Git 工作樹內。")
    if needs_takeover(root) and profile.get("takeover_root") != str(root):
        raise ValueError("輸出目錄已有 MRS；須先切換為 file provider 並確認接管。")
    if profile.get("notify_mihomo", False):
        mrs_controller.normalize_url(profile.get("controller_url", mrs_controller.DEFAULT_URL))
    return selected, root, exe.resolve() if exe is not None else None


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


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def builder_identity():
    # Frozen EXE identity invalidates cache when the toolkit changes, including
    # parser semantics. Source runs use the same relevant Python files.
    if getattr(sys, "frozen", False):
        return file_digest(Path(sys.executable))
    names = ("local_mrs.py", "mrs_build.py", "mrs_merge.py", "mrs_ip.py",
             "mrs_overlap.py", "mrs_provenance.py")
    return {name: file_digest(Path(__file__).parent / name) for name in names}


def fetch_inputs(entries):
    data = {}
    for item in entries:
        url = item["source"]
        if item.get("source_type") == "live":
            if item.get("behavior") != "ipcidr" or url != FEODO_URL:
                raise ValueError("Unsupported live MRS source: " + url)
        else:
            raw_source_parts(url)
        data[item["name"]] = fetch_source_bytes(url, item["name"])
    return data


def current_build(root, fingerprint, entries, source_bytes):
    # Cache is valid only when every selected raw snapshot and all four
    # compiled outputs still match the last successful build.
    try:
        if json.loads((root / BUILD_STATE).read_text(encoding="utf-8")) != fingerprint:
            return False
        manifest = json.loads((root / "tools/third-party-mrs-provenance.json").read_text(encoding="utf-8"))
        inputs = manifest["inputs"]
        if len(inputs) != len(entries) or {i["name"]: i["source_sha256"] for i in inputs} != fingerprint["sources"]:
            return False
        if any(i["source_size_bytes"] != len(source_bytes[i["name"]]) for i in inputs):
            return False
        verify_source_snapshots(root, inputs)
        outputs = manifest["outputs"]
        if len(outputs) != len(PROVIDERS) or {o["path"] for o in outputs} != set(PROVIDERS.values()):
            return False
        for item in outputs:
            path = root / item["path"]
            if path.stat().st_size != item["size_bytes"] or file_digest(path) != item["sha256"]:
                return False
        return ((root / "local-mrs.yaml").read_text(encoding="utf-8") == override_yaml(root)
                and all((root / path).is_file() for path in (
                    ".local-mrs", "mrs-overlap.md", "mrs-skipped.md", "tools/third-party-mrs-sha256.json")))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return False


def run(profile, *, on_notify=None, on_diagnostic=None):
    def notify(root, outputs):
        try:
            pending = mrs_controller.refresh(root, profile, PROVIDERS, outputs, on_diagnostic=on_diagnostic)
        except Exception as exc:
            message = f"Controller refresh pending: {mrs_controller.describe_error(exc)}"
            print(message)
            if on_diagnostic is not None:
                on_diagnostic(message)
            pending = list(PROVIDERS) if profile.get("notify_mihomo", False) else []
        if on_notify is not None:
            on_notify(pending)
    selected, root, _ = validate(profile)
    exe = mrs_compiler.resolve(profile)
    root.mkdir(parents=True, exist_ok=True)
    with build_lock(root):
        # Desktop uses four combined outputs, not the iOS standalone artifact.
        entries = [{k: v for k, v in item.items() if k != "target"} for item in selected]
        raw = fetch_inputs(entries)
        custom = {}
        for category in CUSTOM:
            relative = Path("rules") / category / "custom.txt"
            source = root / relative
            if not source.is_file():
                bundled_source = bundled("mrs-custom-" + category + ".txt")
                if not getattr(sys, "frozen", False) and not bundled_source.is_file():
                    bundled_source = Path(__file__).resolve().parent.parent / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(bundled_source, source)
            custom[relative.as_posix()] = source.read_bytes()
        fingerprint = {
            "schema": 1, "entries": entries, "sources": {name: digest(data) for name, data in raw.items()},
            "custom": {name: digest(data) for name, data in custom.items()},
            "compiler": file_digest(exe), "builder": builder_identity(),
        }
        # A future binary/secondary analysis source must also be fingerprinted
        # before it is safe to skip its build.
        cacheable = not any(i.get("format") == "mrs" for i in entries)
        if cacheable and current_build(root, fingerprint, entries, raw):
            print("Local MRS: unchanged inputs and verified outputs; skipped merge/compile")
            manifest = json.loads((root / "tools/third-party-mrs-provenance.json").read_text(encoding="utf-8"))
            notify(root, manifest["outputs"])
            return root
        with tempfile.TemporaryDirectory(prefix=".build-", dir=root) as folder:
            stage = Path(folder)
            (stage / "tools").mkdir()
            for relative, data in custom.items():
                target = stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            outputs = build(stage, entries, executable=str(exe), report_dir=stage,
                            pin_revisions=False, source_bytes=raw)
            if {item["path"] for item in outputs} != set(PROVIDERS.values()):
                raise RuntimeError("Unexpected local MRS outputs")
            for item in outputs:
                path = stage / item["path"]
                if path.stat().st_size != item["size_bytes"] or file_digest(path) != item["sha256"]:
                    raise RuntimeError("Local MRS verification failed")
            (stage / "local-mrs.yaml").write_text(override_yaml(root), encoding="utf-8")
            (stage / BUILD_STATE).write_text(json.dumps(fingerprint, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            manifest = json.loads((stage / "tools/third-party-mrs-provenance.json").read_text())
            paths = [i["source_snapshot_path"] for i in manifest["inputs"]]
            paths += ["tools/third-party-mrs-sha256.json", "tools/third-party-mrs-provenance.json",
                      "mrs-overlap.md", "mrs-skipped.md", "local-mrs.yaml"]
            paths += [item["path"] for item in outputs]
            # Publish state last; failed builds cannot mark inputs as current.
            paths.append(BUILD_STATE)
            paths = [p for p in paths if not (root / p).is_file() or
                     (root / p).read_bytes() != (stage / p).read_bytes()]
            publish(stage, root, paths)
            (root / ".local-mrs").touch(exist_ok=True)
            print(f"Local MRS: {len(selected)} sources, {len(paths)} changed files")
            notify(root, outputs)
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
                pending = []
                run(load_profile(), on_notify=pending.extend)
                if pending:
                    print("MRS build valid; Controller pending: " + ", ".join(pending))
                    return 3
                return 0
            except Exception:
                import traceback
                traceback.print_exc()
                return 1
    except OSError:
        return 2
