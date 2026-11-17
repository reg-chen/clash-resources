"""Backup and selectively restore UWP AppContainer loopback exemptions.

This is NOT a Windows Firewall rule backup. Only AppContainers enabled in
the Windows "UWP Loopback" / WinConfig exemption list are exported.

Read: Windows NetworkIsolationGetAppContainerConfig API.
Apply: CheckNetIsolation.exe LoopbackExempt -a -p=SID, one selected installed
container at a time. Existing exemptions are preserved; -c is never used.
"""
from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

TYPE = "UWP-LoopbackExemptions"
SCHEMA = 1
SID_RE = re.compile(r"^S-1-15-(?:2|7)-(?:\d+-)*\d+$", re.I)
MAX_ITEMS = 10000


class SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class SidCollection(ctypes.Structure):
    _fields_ = [("count", wintypes.DWORD),
                ("entries", ctypes.POINTER(SidAndAttributes))]


class BinaryCollection(ctypes.Structure):
    _fields_ = [("count", wintypes.DWORD),
                ("entries", ctypes.POINTER(ctypes.c_wchar_p))]


class NativeAppContainer(ctypes.Structure):
    _fields_ = [
        ("sid", ctypes.c_void_p),
        ("user_sid", ctypes.c_void_p),
        ("name", ctypes.c_wchar_p),
        ("display_name", ctypes.c_wchar_p),
        ("description", ctypes.c_wchar_p),
        ("capabilities", SidCollection),
        ("binaries", BinaryCollection),
        ("working_directory", ctypes.c_wchar_p),
        ("package_full_name", ctypes.c_wchar_p),
    ]


def require_windows() -> None:
    if sys.platform != "win32":
        raise RuntimeError("UWP Loopback 僅支援 Windows。")


def _winapi():
    require_windows()
    firewall = ctypes.WinDLL("Firewallapi.dll")
    advapi = ctypes.WinDLL("advapi32.dll")
    kernel = ctypes.WinDLL("kernel32.dll")
    firewall.NetworkIsolationGetAppContainerConfig.argtypes = [
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.POINTER(SidAndAttributes)),
    ]
    firewall.NetworkIsolationGetAppContainerConfig.restype = wintypes.DWORD
    firewall.NetworkIsolationEnumAppContainers.argtypes = [
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.POINTER(NativeAppContainer)),
    ]
    firewall.NetworkIsolationEnumAppContainers.restype = wintypes.DWORD
    firewall.NetworkIsolationFreeAppContainers.argtypes = [
        ctypes.POINTER(NativeAppContainer),
    ]
    firewall.NetworkIsolationFreeAppContainers.restype = wintypes.DWORD
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.GetProcessHeap.argtypes = []
    kernel.GetProcessHeap.restype = ctypes.c_void_p
    kernel.HeapFree.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    kernel.HeapFree.restype = wintypes.BOOL
    return firewall, advapi, kernel


def _sid_string(pointer: int, advapi, kernel) -> str:
    if not pointer:
        raise RuntimeError("Windows 回傳了空白 AppContainer SID。")
    output = ctypes.c_void_p()
    if not advapi.ConvertSidToStringSidW(pointer, ctypes.byref(output)):
        raise OSError(ctypes.get_last_error(), "SID 轉換失敗")
    try:
        sid = ctypes.wstring_at(output)
        if not SID_RE.fullmatch(sid):
            raise ValueError(f"非 AppContainer SID：{sid}")
        return sid.upper()
    finally:
        kernel.LocalFree(output)


def enabled_sids() -> set[str]:
    """Read only the checked loopback-exempted AppContainer SIDs."""
    firewall, advapi, kernel = _winapi()
    count = wintypes.DWORD()
    entries = ctypes.POINTER(SidAndAttributes)()
    error = firewall.NetworkIsolationGetAppContainerConfig(
        ctypes.byref(count), ctypes.byref(entries)
    )
    if error:
        raise OSError(error, "NetworkIsolationGetAppContainerConfig 失敗")
    try:
        if count.value > MAX_ITEMS:
            raise ValueError("Loopback 豁免項目數量異常。")
        return {_sid_string(entries[i].sid, advapi, kernel)
                for i in range(count.value)}
    finally:
        # Microsoft requires freeing each SID and the containing allocation.
        heap = kernel.GetProcessHeap()
        if entries:
            for i in range(count.value):
                if entries[i].sid:
                    kernel.HeapFree(heap, 0, entries[i].sid)
            kernel.HeapFree(heap, 0, ctypes.cast(entries, ctypes.c_void_p))


def _installed_package_ids() -> tuple[set[str], set[str]]:
    """Query actually installed AppX packages, not merely created containers.

    Stale AppContainer profiles can persist after an app is uninstalled.
    Requiring a matching Get-AppxPackage record prevents restoring to ghosts.
    """
    require_windows()
    elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    scope = "-AllUsers " if elevated else ""
    script = (
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "
        f"@(Get-AppxPackage {scope}-ErrorAction Stop | "
        "Select-Object PackageFullName,PackageFamilyName) | ConvertTo-Json -Compress"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    process = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, encoding="utf-8", errors="replace", timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if process.returncode:
        raise RuntimeError(
            "無法驗證目前已安裝的 UWP App：" +
            (process.stderr or process.stdout).strip()[-400:]
        )
    payload = json.loads(process.stdout.strip() or "[]")
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        raise RuntimeError("Windows 的 AppX 套件清單格式異常。")
    fullnames: set[str] = set()
    families: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        full = item.get("PackageFullName")
        family = item.get("PackageFamilyName")
        if isinstance(full, str) and full:
            fullnames.add(full.casefold())
        if isinstance(family, str) and family:
            families.add(family.casefold())
    return fullnames, families


def installed_containers() -> dict[str, dict[str, str]]:
    """Verify both native AppContainer presence and an installed AppX package."""
    firewall, advapi, kernel = _winapi()
    installed_full, installed_family = _installed_package_ids()
    count = wintypes.DWORD()
    entries = ctypes.POINTER(NativeAppContainer)()
    error = firewall.NetworkIsolationEnumAppContainers(
        0, ctypes.byref(count), ctypes.byref(entries)
    )
    if error:
        raise OSError(error, "NetworkIsolationEnumAppContainers 失敗")
    result = {}
    try:
        if count.value > 100000:
            raise ValueError("Windows 回傳的 AppContainer 數量異常。")
        for i in range(count.value):
            entry = entries[i]
            if not entry.sid:
                continue
            package_full_name = entry.package_full_name or ""
            container_name = entry.name or ""
            if (package_full_name.casefold() not in installed_full
                    and container_name.casefold() not in installed_family):
                # A registered container is not proof that the app still exists.
                continue
            sid = _sid_string(entry.sid, advapi, kernel)
            result[sid] = {
                "SID": sid,
                "AppContainerName": container_name,
                "DisplayName": entry.display_name or "",
                "PackageFullName": package_full_name,
            }
    finally:
        if entries:
            firewall.NetworkIsolationFreeAppContainers(entries)
    return result


def read_backup(path: Path) -> list[dict[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if (not isinstance(payload, dict) or payload.get("Schema") != SCHEMA
            or payload.get("Type") != TYPE):
        raise ValueError("這不是 UWP Loopback 勾選項目的備份。舊防火牆規則 JSON 不適用。")
    items = payload.get("Exemptions")
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise ValueError("UWP Loopback 備份清單格式無效。")
    results: list[dict[str, str]] = []
    visited: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("UWP Loopback 清單包含無效項目。")
        sid = item.get("SID")
        if not isinstance(sid, str) or not SID_RE.fullmatch(sid):
            raise ValueError("UWP Loopback 清單包含無效 SID。")
        sid = sid.upper()
        if sid in visited:
            raise ValueError("UWP Loopback 備份含重複 SID。")
        visited.add(sid)
        parsed = {"SID": sid}
        for field in ("AppContainerName", "DisplayName", "PackageFullName"):
            value = item.get(field, "")
            if not isinstance(value, str) or len(value) > 2048:
                raise ValueError("UWP Loopback 備份含無效 App 名稱。")
            parsed[field] = value
        results.append(parsed)
    return results


def backup(path: Path) -> dict:
    """Export only currently enabled loopback exemptions; zero is valid."""
    require_windows()
    if path.suffix.lower() != ".json":
        raise ValueError("請選擇 .json 備份檔。")
    active = enabled_sids()
    apps = installed_containers()
    items = [apps.get(sid, {
        "SID": sid, "AppContainerName": "", "DisplayName": "",
        "PackageFullName": "",
    }) for sid in sorted(active)]
    payload = {
        "Schema": SCHEMA, "Type": TYPE,
        "ExportedAt": datetime.now(timezone.utc).isoformat(),
        "Exemptions": items,
    }
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        read_backup(temporary)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return {"Total": len(items),
            "Recognized": sum(item["SID"] in apps for item in items),
            "Unresolved": sum(item["SID"] not in apps for item in items)}


def restore_preview(path: Path) -> list[dict[str, str]]:
    """Read-only preview and exact SID match against installed containers."""
    items = read_backup(path)
    installed = installed_containers()
    active = enabled_sids()
    preview = []
    for original in items:
        sid = original["SID"]
        current = installed.get(sid)
        status = ("missing" if current is None
                  else "existing" if sid in active else "available")
        preview.append({
            **original,
            "DisplayName": (current or {}).get("DisplayName") or original["DisplayName"],
            "AppContainerName": (current or {}).get("AppContainerName")
                                or original["AppContainerName"],
            "Status": status,
        })
    return preview


def apply_selected_sids(sids: list[str]) -> dict:
    """Elevated child process: merge only selected, still-installed SIDs."""
    require_windows()
    if len(sids) > MAX_ITEMS or len(sids) != len(set(sids)):
        raise ValueError("還原清單長度或重複項目異常。")
    if any(not isinstance(s, str) or not SID_RE.fullmatch(s) for s in sids):
        raise ValueError("還原清單包含無效 SID。")
    installed = installed_containers()
    active = enabled_sids()
    outcome = {
        "Total": len(sids), "Added": 0, "Existing": 0,
        "MissingPackage": 0, "Errors": [],
    }
    exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "CheckNetIsolation.exe"
    for sid in sids:
        if sid not in installed:
            outcome["MissingPackage"] += 1
            continue
        if sid in active:
            outcome["Existing"] += 1
            continue
        process = subprocess.run(
            [str(exe), "LoopbackExempt", "-a", f"-p={sid}"],
            capture_output=True, text=True, errors="replace", timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if process.returncode:
            outcome["Errors"].append(
                f"{sid}: {(process.stderr or process.stdout or str(process.returncode)).strip()[:300]}"
            )
            continue
        if sid not in enabled_sids():
            outcome["Errors"].append(f"{sid}: Windows did not retain the exemption.")
            continue
        active.add(sid)
        outcome["Added"] += 1
    return outcome


def elevated_child(selection_file: Path, report_file: Path) -> int:
    """CLI invoked by the same EXE, but elevated and without any Tk window."""
    try:
        data = json.loads(selection_file.read_text(encoding="utf-8"))
        if (not isinstance(data, dict) or data.get("Type") != TYPE
                or not isinstance(data.get("SelectedSids"), list)):
            raise ValueError("無效的 Loopback 勾選項目。")
        outcome = apply_selected_sids(data["SelectedSids"])
    except Exception as exc:
        outcome = {"Total": 0, "Added": 0, "Existing": 0,
                   "MissingPackage": 0, "Errors": [str(exc)]}
    report_file.write_text(
        json.dumps(outcome, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if not outcome["Errors"] else 4


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def restore_selected(path: Path, selected: list[str]) -> dict:
    """Invoke exactly one UAC prompt after the user confirms the checked list."""
    require_windows()
    saved = {item["SID"] for item in read_backup(path)}
    if len(selected) != len(set(selected)) or any(s not in saved for s in selected):
        raise ValueError("選取的豁免項目不屬於這份備份。")
    if not selected:
        return {"Total": 0, "Added": 0, "Existing": 0,
                "MissingPackage": 0, "Errors": []}
    with tempfile.TemporaryDirectory(prefix="regchen-uwp-loopback-") as directory:
        pick = Path(directory) / "selection.json"
        report = Path(directory) / "report.json"
        pick.write_text(json.dumps({"Type": TYPE, "SelectedSids": selected}),
                        encoding="utf-8")
        if getattr(sys, "frozen", False):
            exec_args = [sys.executable]
        else:
            exec_args = [sys.executable, str(Path(__file__).parent / "vpn-generator-gui.py")]
        exec_args += ["--uwp-loopback-apply", str(pick), "--report", str(report)]
        invocation = "& " + " ".join(_ps_literal(x) for x in exec_args) + "; exit $LASTEXITCODE"
        encoded = base64.b64encode(invocation.encode("utf-16-le")).decode("ascii")
        outer = (
            "$p = Start-Process -FilePath 'powershell.exe' "
            "-ArgumentList @('-NoProfile','-NonInteractive',"
            f"'-EncodedCommand','{encoded}') "
            "-Verb RunAs -Wait -PassThru; exit $p.ExitCode"
        )
        command = [
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-EncodedCommand",
            base64.b64encode(outer.encode("utf-16-le")).decode("ascii"),
        ]
        process = subprocess.run(
            command, capture_output=True, text=True, errors="replace",
            timeout=300, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if not report.is_file():
            raise RuntimeError(
                "Loopback 還原未完成，可能取消了管理員授權。"
                f" {(process.stderr or process.stdout).strip()[-250:]}"
            )
        outcome = json.loads(report.read_text(encoding="utf-8-sig"))
        if process.returncode or outcome.get("Errors"):
            raise RuntimeError("Loopback 部分項目還原失敗：" +
                               "; ".join(outcome.get("Errors", []))[:600])
        return outcome
