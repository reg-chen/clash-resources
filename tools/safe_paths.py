"""Opt-in machine-level SAFE_PATHS append for generated Mihomo providers."""
from __future__ import annotations

import base64
import ctypes
import ntpath
import os
import subprocess
import sys
from pathlib import Path

ENVIRONMENT_REGISTRY_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"


def provider_directory(output_directory: str | Path) -> str:
    text = str(output_directory).strip()
    if not text:
        raise ValueError("缺少輸出目錄。")
    if sys.platform != "win32":
        # Allows deterministic tests of Windows paths on non-Windows runners.
        return ntpath.normpath(ntpath.join(text, "providers"))
    folder = Path(text).expanduser().resolve()
    if not folder.is_absolute():
        raise ValueError("輸出目錄必須是絕對路徑。")
    return str(folder / "providers")


def _identity(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(path.strip().strip('"')))


def append_value(current: str, directory: str) -> tuple[str, bool]:
    """Preserve order and all existing entries; append only when missing."""
    target = directory.strip()
    if not target or ";" in target:
        raise ValueError("SAFE_PATHS 目錄不得為空或包含分號。")
    items = [item.strip() for item in current.split(";") if item.strip()]
    if _identity(target) in {_identity(item) for item in items}:
        return current, False
    prefix = current.rstrip(";")
    return (prefix + ";" if prefix else "") + target, True


def _machine_registry_value() -> tuple[str, int]:
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ENVIRONMENT_REGISTRY_KEY, 0, winreg.KEY_READ) as key:
        try:
            value, value_type = winreg.QueryValueEx(key, "SAFE_PATHS")
        except FileNotFoundError:
            return "", winreg.REG_EXPAND_SZ
    if value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        raise RuntimeError("SAFE_PATHS 登錄值類型不是字串，拒絕修改。")
    return str(value), value_type


def is_machine_safe_path_present(directory: str) -> bool:
    current, _ = _machine_registry_value()
    return _identity(directory) in {
        _identity(entry) for entry in current.split(";") if entry.strip()
    }


def append_machine_safe_path(directory: str) -> bool:
    """Append an allowlisted directory to HKLM, never replace existing entries."""
    if sys.platform != "win32":
        raise RuntimeError("SAFE_PATHS 登錄更新只支援 Windows。")
    import winreg
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        ENVIRONMENT_REGISTRY_KEY,
        0,
        winreg.KEY_READ | winreg.KEY_SET_VALUE,
    ) as key:
        try:
            current, value_type = winreg.QueryValueEx(key, "SAFE_PATHS")
        except FileNotFoundError:
            current, value_type = "", winreg.REG_EXPAND_SZ
        if value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            raise RuntimeError("SAFE_PATHS 登錄值類型不是字串，拒絕修改。")
        updated, changed = append_value(str(current), directory)
        if changed:
            winreg.SetValueEx(key, "SAFE_PATHS", 0, value_type, updated)
    return changed


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run_elevated(directory: str) -> None:
    # The elevated child re-reads HKLM before writing. This avoids rebuilding
    # SAFE_PATHS from a stale value in the unelevated GUI process.
    if getattr(sys, "frozen", False):
        program = sys.executable
        argv = ["--safe-paths-append", directory]
    else:
        program = sys.executable
        argv = [str(Path(__file__).with_name("vpn-generator-gui.py")), "--safe-paths-append", directory]
    command_line = subprocess.list2cmdline(argv)
    script = (
        f"$proc = Start-Process -FilePath {_ps_literal(program)} "
        f"-ArgumentList {_ps_literal(command_line)} -Verb RunAs -Wait -PassThru; "
        "exit $proc.ExitCode"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, timeout=180,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError("SAFE_PATHS 更新未完成（權限提升被拒絕或執行失敗）。")


def ensure_machine_safe_path(directory: str) -> bool:
    """No-op for existing entries; otherwise append, elevating on permission failure."""
    if sys.platform != "win32":
        raise RuntimeError("只支援 Windows。")
    if is_machine_safe_path_present(directory):
        return False
    try:
        return append_machine_safe_path(directory)
    except PermissionError:
        _run_elevated(directory)
        if not is_machine_safe_path_present(directory):
            raise RuntimeError("更新程序已返回，但 SAFE_PATHS 未包含指定目錄。")
        return True
