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
SCHEMA = 2
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


def current_user_context(process_handle=None) -> tuple[str, bool]:
    """Return the running Windows account SID and whether it can self-elevate.

    A split-token administrator is accepted even before UAC consent. A standard
    user who would need another administrator's credentials is not.
    """
    require_windows()
    advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    shell = ctypes.WinDLL("shell32.dll", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    shell.IsUserAnAdmin.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    process = kernel.GetCurrentProcess() if process_handle is None else process_handle
    if not advapi.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        required = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        if required.value < ctypes.sizeof(SidAndAttributes):
            raise RuntimeError("無法取得目前 Windows 帳號的 SID。")
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi.GetTokenInformation(
                token, 1, buffer, required.value, ctypes.byref(required)):
            raise ctypes.WinError(ctypes.get_last_error())
        user_sid = ctypes.cast(buffer, ctypes.POINTER(SidAndAttributes)).contents.sid
        converted = ctypes.c_void_p()
        if not advapi.ConvertSidToStringSidW(user_sid, ctypes.byref(converted)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            sid = ctypes.wstring_at(converted)
        finally:
            kernel.LocalFree(converted)

        elevation_type = wintypes.DWORD()
        if not advapi.GetTokenInformation(
                token, 18, ctypes.byref(elevation_type),
                ctypes.sizeof(elevation_type), ctypes.byref(required)):
            raise ctypes.WinError(ctypes.get_last_error())
        # Default=1, Full=2, Limited=3. Limited is the same admin's
        # filtered token and can elevate with consent rather than credentials.
        is_admin = elevation_type.value in (2, 3) or (
            process_handle is None and bool(shell.IsUserAnAdmin()))
        return sid, is_admin
    finally:
        kernel.CloseHandle(token)


def current_process_is_elevated() -> bool:
    """Check the effective process token, not merely administrator membership."""
    require_windows()
    shell = ctypes.WinDLL("shell32.dll", use_last_error=True)
    shell.IsUserAnAdmin.restype = wintypes.BOOL
    return bool(shell.IsUserAnAdmin())


def current_process_matches_login_shell() -> bool:
    """Reject GUI launched with an alternate administrator's RunAs identity.

    GetShellWindow identifies the Explorer shell on this interactive desktop,
    rather than choosing an arbitrary explorer.exe process from another session.
    """
    require_windows()
    user32 = ctypes.WinDLL("user32.dll", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    user32.GetShellWindow.restype = wintypes.HWND
    user32.GetWindowThreadProcessId.argtypes = [
        wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    # Compare against this desktop's shell, not against an arbitrary admin
    # process whose token might represent a different logged-in account.
    shell_window = user32.GetShellWindow()
    if not shell_window:
        raise RuntimeError("無法確認目前桌面登入帳號（找不到 Windows Shell）。")
    pid = wintypes.DWORD()
    if not user32.GetWindowThreadProcessId(shell_window, ctypes.byref(pid)) or not pid.value:
        raise RuntimeError("無法確認 Windows Shell 的程序身分。")
    process = kernel.OpenProcess(0x1000, False, pid.value)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        shell_sid, _ = current_user_context(process_handle=process)
    finally:
        kernel.CloseHandle(process)
    active_sid, _ = current_user_context()
    return shell_sid.casefold() == active_sid.casefold()


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


def _installed_package_ids() -> tuple[dict[str, str], set[str]]:
    """Map full package versions to stable Package Family Names (PFN).

    Full names include version and architecture; PFNs do not. Never derive a
    package family from a machine/user SID or by splitting package names.
    """
    require_windows()
    # Scope to the *current account*, not -AllUsers. Under an alternate
    # administrator's UAC account, an absent app must be skipped instead of
    # accidentally applying an exemption on behalf of another Windows user.
    script = (
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "
        "@(Get-AppxPackage -ErrorAction Stop | "
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
    full_to_family: dict[str, str] = {}
    families: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        full = item.get("PackageFullName")
        family = item.get("PackageFamilyName")
        if isinstance(family, str) and family:
            families.add(family.casefold())
            if isinstance(full, str) and full:
                full_to_family[full.casefold()] = family
    return full_to_family, families


def installed_containers() -> dict[str, dict[str, str]]:
    """Resolve actual local SIDs with stable monikers and installed PFNs."""
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
            full = entry.package_full_name or ""
            moniker = entry.name or ""
            family = installed_full.get(full.casefold(), "")
            if not family and moniker.casefold() in installed_family:
                family = moniker
            if not family:
                # A stale AppContainer is not evidence that the App is installed.
                continue
            sid = _sid_string(entry.sid, advapi, kernel)
            result[sid] = {
                "SID": sid,
                "PackageFamilyName": family,
                "AppContainerName": moniker,
                "DisplayName": entry.display_name or "",
                "PackageFullName": full,
            }
    finally:
        if entries:
            firewall.NetworkIsolationFreeAppContainers(entries)
    return result


def identity_key(record: dict) -> str:
    """Stable across reinstalls. Source SID is intentionally never a key."""
    moniker = record.get("AppContainerName", "")
    if not isinstance(moniker, str) or not moniker.strip():
        # Cannot safely identify an unlabelled legacy or orphaned container.
        # Make it unselectable; never silently fall back to SourceSID.
        return ""
    return moniker.casefold()


def _local_match(original: dict, installed: dict[str, dict]) -> dict | None:
    """Resolve the current machine's SID, checking PFN when available.

    Reject ambiguous and mismatched identities rather than applying a rule to
    the wrong app. Legacy v1 has only AppContainerName; it must match exactly.
    """
    key = identity_key(original)
    if not key:
        return None
    expected_family = original.get("PackageFamilyName", "").casefold()
    matches = []
    for item in installed.values():
        if identity_key(item) != key:
            continue
        if expected_family and item.get("PackageFamilyName", "").casefold() != expected_family:
            continue
        matches.append(item)
    if len(matches) != 1:
        return None
    return matches[0]


def _validate_rows(items: object, schema: int) -> list[dict[str, str]]:
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise ValueError("UWP Loopback 備份清單格式無效。")
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("UWP Loopback 清單包含無效項目。")
        parsed: dict[str, str] = {}
        for field in ("PackageFamilyName", "AppContainerName",
                      "DisplayName", "PackageFullName"):
            value = item.get(field, "")
            if not isinstance(value, str) or len(value) > 2048:
                raise ValueError("UWP Loopback 備份包含無效 App 身分。")
            parsed[field] = value
        if schema == 1:
            # Prior version backed up machine-local SIDs. Accept its JSON,
            # but NEVER use this SID to match or restore on another machine.
            sid = item.get("SID")
            if not isinstance(sid, str) or not SID_RE.fullmatch(sid):
                raise ValueError("舊版 Loopback 備份包含無效 SID。")
        elif schema == 2:
            if not parsed["PackageFamilyName"] or not parsed["AppContainerName"]:
                raise ValueError("可攜式 Loopback 備份缺少 Package Family Name 或 AppContainer 名稱。")
        elif schema == 0:
            # Elevated selection payload: legacy backups can lack PFN, but
            # must still supply an exact stable AppContainer moniker.
            if not parsed["AppContainerName"]:
                raise ValueError("無法辨識的舊版 AppContainer 不可進行還原。")
        else:
            raise ValueError("不支援的 Loopback 備份版本。")
        key = identity_key(parsed)
        if key:
            if key in seen:
                raise ValueError("UWP Loopback 備份包含重複 AppContainer 身分。")
            seen.add(key)
        results.append(parsed)
    return results


def read_backup(path: Path) -> list[dict[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict) or payload.get("Type") != TYPE:
        raise ValueError("這不是 UWP Loopback 勾選項目的備份。舊防火牆規則 JSON 不適用。")
    schema = payload.get("Schema")
    if schema not in (1, 2):
        raise ValueError("不支援的 UWP Loopback JSON Schema。")
    return _validate_rows(payload.get("Exemptions"), schema)


def backup(path: Path) -> dict:
    """Save checked App identities, NEVER machine-local SIDs in new backups."""
    require_windows()
    if path.suffix.lower() != ".json":
        raise ValueError("請選擇 .json 備份檔。")
    active = enabled_sids()
    apps = installed_containers()
    portable: dict[str, dict[str, str]] = {}
    unresolved = 0
    for sid in sorted(active):
        record = apps.get(sid)
        if not record or not identity_key(record) or not record.get("PackageFamilyName"):
            unresolved += 1
            continue
        key = identity_key(record)
        if key not in portable:
            portable[key] = {
                field: record.get(field, "") for field in (
                    "PackageFamilyName", "AppContainerName",
                    "DisplayName", "PackageFullName",
                )
            }
    # Different user SIDs do not imply distinct application identities.
    items = list(portable.values())
    payload = {
        "Schema": 2, "Type": TYPE,
        "ExportedAt": datetime.now(timezone.utc).isoformat(),
        "UnresolvedCount": unresolved,
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
    return {
        "Total": len(active),
        "Recognized": len(items),
        "Unresolved": unresolved,
        "Duplicates": max(0, len(active) - len(items) - unresolved),
    }


def _privilege_error(exc: OSError) -> bool:
    """Windows ERROR_ACCESS_DENIED / ERROR_PRIVILEGE_NOT_HELD only."""
    return isinstance(exc, PermissionError) or (
        isinstance(exc, OSError) and (
            getattr(exc, "winerror", None) in (5, 1314)
            or exc.errno in (5, 13, 1314)
        )
    )


def backup_with_optional_elevation(path: Path) -> dict:
    """Use normal user access first; request UAC only when enumeration needs it.

    The privileged helper writes into a temporary location. The ordinary GUI
    process owns the final backup file, and file-system errors at the final
    destination cannot spuriously trigger an elevation prompt.
    """
    require_windows()
    if path.suffix.lower() != ".json":
        raise ValueError("請選擇 .json 備份檔。")
    with tempfile.TemporaryDirectory(prefix="regchen-uwp-loopback-") as directory:
        folder = Path(directory)
        stage = folder / "backup.json"
        try:
            result = backup(stage)
        except OSError as exc:
            if not _privilege_error(exc):
                raise
            _, can_self_elevate = current_user_context()
            if not can_self_elevate:
                raise PermissionError(
                    "目前 Windows 標準使用者無法讀取 Loopback 清單；"
                    "不可藉由另一個管理員帳號的 UAC 讀取不同使用者的 App。"
                ) from exc
            if current_process_is_elevated():
                raise
            ticket = folder / "request.json"
            report = folder / "report.json"
            sid, _ = current_user_context()
            ticket.write_text(json.dumps({
                "Type": TYPE, "RequestingUserSID": sid,
            }), encoding="utf-8")
            process = _run_elevated_cli([
                "--uwp-loopback-backup", str(ticket), "--report",
                str(report), "--output", str(stage),
            ])
            if not report.is_file():
                raise RuntimeError(
                    "Loopback 備份未完成，可能取消了管理員授權。"
                    f" {(process.stderr or process.stdout).strip()[-250:]}"
                )
            response = json.loads(report.read_text(encoding="utf-8-sig"))
            if process.returncode or response.get("Errors"):
                raise RuntimeError("提升權限備份失敗：" +
                                   "; ".join(response.get("Errors", []))[:600])
            result = response.get("Result")
            if not isinstance(result, dict) or not stage.is_file():
                raise RuntimeError("提權程序未傳回有效的備份檔案。")

        # Validate the transfer before touching the user-selected destination.
        rows = read_backup(stage)
        if not isinstance(result, dict) or result.get("Recognized") != len(rows):
            raise RuntimeError("Loopback 備份檔案與執行結果不一致。")
        target = path.expanduser().absolute()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".partial")
        try:
            temporary.write_bytes(stage.read_bytes())
            read_backup(temporary)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        return result


def restore_preview(path: Path) -> list[dict[str, str]]:
    """Match by stable moniker and PFN; get target SID from target Windows."""
    items = read_backup(path)
    installed = installed_containers()
    active = enabled_sids()
    preview = []
    for index, original in enumerate(items):
        key = identity_key(original)
        current = _local_match(original, installed)
        sid = (current or {}).get("SID", "")
        status = ("missing" if not current
                  else "existing" if sid in active else "available")
        preview.append({
            **original,
            "Key": key if key else f"unresolved:{index}",
            "DisplayName": (current or {}).get("DisplayName") or original["DisplayName"],
            "AppContainerName": (current or {}).get("AppContainerName")
                                or original["AppContainerName"],
            "PackageFamilyName": (current or {}).get("PackageFamilyName")
                                  or original["PackageFamilyName"],
            "TargetSID": sid,
            "Status": status,
        })
    return preview


def apply_selected_entries(entries: list[dict[str, str]]) -> dict:
    """Elevated child: resolve target SID at apply time and merge exemptions."""
    require_windows()
    if not isinstance(entries, list) or len(entries) > MAX_ITEMS:
        raise ValueError("還原清單長度異常。")
    # Selection always carries stable app identity; no source SID can reach
    # CheckNetIsolation even if a user supplied a legacy v1 backup.
    originals = _validate_rows(entries, 0) if entries else []
    installed = installed_containers()
    active = enabled_sids()
    outcome = {
        "Total": len(originals), "Added": 0, "Existing": 0,
        "MissingPackage": 0, "Errors": [],
    }
    exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "CheckNetIsolation.exe"
    for original in originals:
        current = _local_match(original, installed)
        if current is None:
            outcome["MissingPackage"] += 1
            continue
        target_sid = current["SID"]
        if target_sid in active:
            outcome["Existing"] += 1
            continue
        process = subprocess.run(
            [str(exe), "LoopbackExempt", "-a", f"-p={target_sid}"],
            capture_output=True, text=True, errors="replace", timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if process.returncode:
            outcome["Errors"].append(
                f"{original['AppContainerName']}: "
                f"{(process.stderr or process.stdout or str(process.returncode)).strip()[:300]}"
            )
            continue
        if target_sid not in enabled_sids():
            outcome["Errors"].append(
                f"{original['AppContainerName']}: Windows did not retain the exemption."
            )
            continue
        active.add(target_sid)
        outcome["Added"] += 1
    return outcome


def _validate_requesting_sid(data: dict) -> None:
    expected_sid = data.get("RequestingUserSID")
    if not isinstance(expected_sid, str) or not re.fullmatch(
            r"S-[0-9]+(?:-[0-9]+)+", expected_sid, re.I):
        raise ValueError("缺少有效的來源 Windows 使用者身分。")
    actual_sid, _ = current_user_context()
    if actual_sid.casefold() != expected_sid.casefold():
        raise PermissionError(
            "管理員授權切換了 Windows 使用者帳號；"
            "為避免操作錯誤使用者的 AppContainer，已中止。"
            "請使用目前登入帳號本身的管理員權限。")


def elevated_backup_child(request_file: Path, report_file: Path,
                          output_file: Path) -> int:
    """Headless UAC child: same account, elevated, writes only a staged JSON."""
    try:
        data = json.loads(request_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("Type") != TYPE:
            raise ValueError("無效的 Loopback 備份請求。")
        _validate_requesting_sid(data)
        if not current_process_is_elevated():
            raise PermissionError("備份子程序沒有取得 Windows 管理員權限。")
        result = backup(output_file)
        outcome = {"Result": result, "Errors": []}
    except Exception as exc:
        outcome = {"Result": None, "Errors": [str(exc)]}
    report_file.write_text(
        json.dumps(outcome, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if not outcome["Errors"] else 4


def elevated_child(selection_file: Path, report_file: Path) -> int:
    """CLI invoked by the same EXE, but elevated and without any Tk window."""
    try:
        data = json.loads(selection_file.read_text(encoding="utf-8"))
        if (not isinstance(data, dict) or data.get("Type") != TYPE
                or not isinstance(data.get("SelectedEntries"), list)):
            raise ValueError("無效的 Loopback 勾選項目。")
        _validate_requesting_sid(data)
        outcome = apply_selected_entries(data["SelectedEntries"])
    except Exception as exc:
        outcome = {"Total": 0, "Added": 0, "Existing": 0,
                   "MissingPackage": 0, "Errors": [str(exc)]}
    report_file.write_text(
        json.dumps(outcome, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if not outcome["Errors"] else 4


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run_elevated_cli(arguments: list[str]) -> subprocess.CompletedProcess:
    """Reuse the existing one-prompt UAC path for restore and fallback backup."""
    if getattr(sys, "frozen", False):
        exec_args = [sys.executable]
    else:
        exec_args = [sys.executable, str(Path(__file__).parent / "vpn-generator-gui.py")]
    exec_args += arguments
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
    return subprocess.run(
        command, capture_output=True, text=True, errors="replace",
        timeout=300, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def restore_selected(path: Path, selected: list[str]) -> dict:
    """Invoke exactly one UAC prompt after the user confirms the checked list."""
    require_windows()
    saved = {identity_key(item): item for item in read_backup(path)
             if identity_key(item)}
    if len(selected) != len(set(selected)) or any(key not in saved for key in selected):
        raise ValueError("選取的 App 身分不屬於這份備份。")
    if not selected:
        return {"Total": 0, "Added": 0, "Existing": 0,
                "MissingPackage": 0, "Errors": []}
    # The elevated child will independently resolve these portable identities
    # against Windows' current AppContainers; no source SID crosses UAC.
    selected_entries = [saved[key] for key in selected]
    with tempfile.TemporaryDirectory(prefix="regchen-uwp-loopback-") as directory:
        pick = Path(directory) / "selection.json"
        report = Path(directory) / "report.json"
        requesting_sid, _ = current_user_context()
        pick.write_text(json.dumps({
            "Type": TYPE, "RequestingUserSID": requesting_sid,
            "SelectedEntries": selected_entries,
        }),
                        encoding="utf-8")
        process = _run_elevated_cli([
            "--uwp-loopback-apply", str(pick), "--report", str(report),
        ])
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
