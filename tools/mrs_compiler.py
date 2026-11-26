"""Discover the running Windows Mihomo executable without starting a core."""
from __future__ import annotations

import csv
import ctypes
import ipaddress
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path
from urllib.parse import urlsplit

from mrs_controller import DEFAULT_URL, normalize_url

_CORE = re.compile(r"(?:mihomo|clash-meta)(?:[-_.][a-z0-9_.-]+)?\.exe", re.I)


def _known_name(name):
    return bool(_CORE.fullmatch(name))


def _tcp_listeners(family):
    """Read Windows TCP_TABLE_OWNER_PID_LISTENER (class 3), IPv4 and IPv6."""
    api = ctypes.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                    wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    api.restype = wintypes.DWORD
    size = wintypes.DWORD(0)
    result = api(None, ctypes.byref(size), False, family, 3, 0)
    if result not in (0, 122):
        raise OSError(result, "GetExtendedTcpTable")
    for _ in range(4):
        buf = ctypes.create_string_buffer(max(size.value, 4))
        result = api(buf, ctypes.byref(size), False, family, 3, 0)
        if result == 122:
            continue
        if result:
            raise OSError(result, "GetExtendedTcpTable")
        rows = buf.raw
        count = struct.unpack_from("<I", rows)[0]
        row_size = 24 if family == socket.AF_INET else 56
        if 4 + count * row_size > len(rows):
            raise OSError("Invalid TCP owner table")
        for index in range(count):
            offset = 4 + index * row_size
            if family == socket.AF_INET:
                state, address, port, _, _, pid = struct.unpack_from("<6I", rows, offset)
                address = ipaddress.ip_address(struct.pack("<I", address))
            else:
                address, _, port, _, _, _, state, pid = struct.unpack_from("<16sII16sIIII", rows, offset)
                address = ipaddress.ip_address(address)
            if state == 2 and pid:
                yield address, socket.ntohs(port & 0xffff), pid
        return
    raise OSError("TCP owner table changed repeatedly")


def controller_pids(value):
    url = urlsplit(normalize_url(value))
    answers = socket.getaddrinfo(url.hostname, url.port, type=socket.SOCK_STREAM,
                                 proto=socket.IPPROTO_TCP)
    addresses = {ipaddress.ip_address(row[4][0]) for row in answers}
    if not addresses or not all(a.is_loopback for a in addresses):
        return set()
    pids = set()
    for family, version in ((socket.AF_INET, 4), (socket.AF_INET6, 6)):
        targets = {a for a in addresses if a.version == version}
        if not targets:
            continue
        for address, port, pid in _tcp_listeners(family):
            if port == url.port and (address in targets or address.is_unspecified):
                pids.add(pid)
    return pids


def process_image(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if not kernel.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return None
        return Path(buf.value)
    finally:
        kernel.CloseHandle(handle)


def running_pids():
    # Use the Windows-owned tasklist binary, not a PATH-resolved command.
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "tasklist.exe"
    result = subprocess.run([str(system), "/FO", "CSV", "/NH"], capture_output=True,
                            text=True, errors="replace", timeout=15, check=True,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return {int(row[1]) for row in csv.reader(result.stdout.splitlines())
            if len(row) >= 2 and _known_name(row[0]) and row[1].isdigit()}


def _paths(pids):
    paths = set()
    for pid in pids:
        path = process_image(pid)
        if path is not None and path.is_absolute() and _known_name(path.name) and path.is_file():
            paths.add(path.resolve())
    return paths


def _version_ok(path):
    try:
        result = subprocess.run([str(path), "-v"], capture_output=True, text=True,
                                errors="replace", timeout=10,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.returncode == 0 and bool(re.search(r"\b(?:Mihomo|Clash Meta)\b",
                                                         result.stdout + result.stderr, re.I))
    except (OSError, subprocess.SubprocessError):
        return False


def resolve(profile):
    endpoint = profile.get("controller_url") or DEFAULT_URL
    candidates = []
    ambiguous = False
    if sys.platform == "win32":
        try:
            owners = controller_pids(endpoint)
            paths = _paths(owners)
            if len(paths) == 1 and len(owners) == 1:
                candidates.append(("Controller PID", next(iter(paths))))
            elif len(paths) > 1 or len(owners) > 1:
                ambiguous = True
        except (OSError, ValueError):
            pass
        if not candidates and not ambiguous:
            try:
                paths = _paths(running_pids())
                if len(paths) == 1:
                    candidates.append(("running Mihomo", next(iter(paths))))
                elif len(paths) > 1:
                    ambiguous = True
            except (OSError, subprocess.SubprocessError):
                pass
    manual = str(profile.get("mihomo") or "").strip()
    if manual:
        path = Path(manual).expanduser()
        if path.is_absolute() and path.is_file():
            candidates.append(("manual fallback", path.resolve()))
    # PATH is a fallback only when discovery did not find ambiguous instances.
    if not ambiguous:
        for name in ("mihomo.exe", "mihomo-alpha.exe", "clash-meta.exe", "clash-meta-alpha.exe"):
            path = shutil.which(name)
            if path and Path(path).is_absolute():
                candidates.append(("PATH", Path(path).resolve()))
    seen = set()
    for origin, path in candidates:
        if path in seen:
            continue
        seen.add(path)
        if _version_ok(path):
            print(f"Mihomo compiler ({origin}): {path}")
            return path
    if ambiguous:
        raise RuntimeError("偵測到多個 Mihomo 實例，無法唯一識別；請指定備援執行檔。")
    raise RuntimeError("找不到可用的 Mihomo 執行檔；請啟動核心或設定備援路徑。")
