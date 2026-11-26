"""HTTPS Controller refresh and current-user DPAPI credentials."""
from __future__ import annotations

import base64
import ctypes
import json
import ipaddress
import http.client
import socket
import re
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from ctypes import wintypes
from pathlib import Path
from urllib.parse import quote, urlsplit

DEFAULT_URL = "https://127.0.0.1:9443"
ACK_STATE = "tools/local-mrs-controller-state.json"


def normalize_url(value):
    try:
        value = value.strip()
        if any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in value):
            raise ValueError
        url = urlsplit(value)
        port = url.port
        if (url.scheme != "https" or not url.hostname
                or url.username is not None or url.password is not None
                or url.path not in ("", "/") or "?" in value or "#" in value
                or port == 0 or url.netloc.endswith(":")):
            raise ValueError
        host = url.hostname
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            host = host.rstrip(".").encode("idna").decode("ascii").lower()
            if len(host) > 253 or not all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in host.split(".")):
                raise ValueError
        else:
            if "%" in host:
                raise ValueError
            host = f"[{ip}]" if ip.version == 6 else str(ip)
    except (ValueError, AttributeError):
        raise ValueError("Controller URL 必須是有效的 HTTPS 位址，例如 https://controller.example:9443。") from None
    return f"https://{host}:{port or 443}"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi(data, decrypt=False):
    if sys.platform != "win32":
        raise RuntimeError("Secret 的 DPAPI 保存僅支援 Windows。")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    src_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    src = _Blob(len(data), ctypes.cast(src_buf, ctypes.POINTER(ctypes.c_ubyte)))
    dst = _Blob()
    fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    fn.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    fn.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    try:
        # CRYPTPROTECT_UI_FORBIDDEN; no LOCAL_MACHINE flag (current user only).
        if not fn(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(dst)):
            raise RuntimeError("無法讀寫目前 Windows 使用者的 DPAPI Secret。")
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        ctypes.memset(src_buf, 0, len(data))
        if dst.pbData:
            ctypes.memset(dst.pbData, 0, dst.cbData)
            kernel.LocalFree(ctypes.cast(dst.pbData, ctypes.c_void_p))


def protect_secret(secret):
    if not secret:
        return ""
    if any(not 32 <= ord(c) <= 126 for c in secret):
        raise ValueError("Secret 必須是可列印 ASCII 字元。")
    return base64.b64encode(_dpapi(secret.encode("ascii"))).decode("ascii")


def unprotect_secret(value):
    if not value:
        return ""
    try:
        return _dpapi(base64.b64decode(value, validate=True), decrypt=True).decode("ascii")
    except (ValueError, UnicodeError, RuntimeError):
        raise RuntimeError("無法解密 Controller Secret，請於 MRS 分頁重新輸入。") from None


class NonLoopbackController(OSError):
    """A Controller hostname must resolve exclusively to loopback addresses."""


def _connect_loopback(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    host, port = address
    candidates = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    # Validate the whole result before attempting any connection, including
    # mixed A/AAAA responses. Do not resolve the hostname again at connect().
    if not candidates or any(
            family not in (socket.AF_INET, socket.AF_INET6)
            or not ipaddress.ip_address(sockaddr[0]).is_loopback
            for family, _, _, _, sockaddr in candidates):
        raise NonLoopbackController("Controller must resolve exclusively to loopback")
    last_error = None
    for family, kind, proto, _, sockaddr in candidates:
        sock = socket.socket(family, kind, proto)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            # Verify the established peer as well as the selected address.
            if not ipaddress.ip_address(sock.getpeername()[0]).is_loopback:
                raise NonLoopbackController("Controller peer is not loopback")
            return sock
        except OSError as exc:
            sock.close()
            if isinstance(exc, NonLoopbackController):
                raise
            last_error = exc
        except BaseException:
            sock.close()
            raise
    raise last_error or OSError("No reachable loopback Controller")


class _LoopbackHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect_loopback
        # HTTPSConnection.connect retains the original host for SNI and
        # certificate hostname verification; only TCP connection is pinned.


class _LoopbackHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_LoopbackHTTPSConnection, req, context=self._context)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    context = ssl.create_default_context()
    # Reuse the toolkit's existing CA (including legacy location), not its key.
    if os.environ.get("LOCALAPPDATA"):
        from mihomo_doh import _ca_directory
        ca = _ca_directory() / "root-ca.crt"
        if ca.is_file():
            context.load_verify_locations(cafile=str(ca))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                       _NoRedirect(), _LoopbackHTTPSHandler(context=context))


def _request(opener, url, secret, method):
    headers = {"Accept": "application/json"}
    if secret:
        headers["Authorization"] = "Bearer " + secret
    request = urllib.request.Request(url, headers=headers, method=method)
    with opener.open(request, timeout=10) as response:
        if method == "GET":
            return json.loads(response.read(2 * 1024 * 1024))
        if not 200 <= response.status < 300:
            raise RuntimeError("Controller rejected update")


def _save_state(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        tmp = Path(stream.name)
        json.dump(value, stream, indent=2)
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def describe_error(exc):
    if isinstance(exc, urllib.error.HTTPError):
        hints = {401: "API Secret 驗證失敗", 403: "API 拒絕存取",
                 404: "API 路徑或 Provider 不存在", 503: "Mihomo 無法重新載入 Provider"}
        return f"HTTP {exc.code}: {hints.get(exc.code, 'Controller HTTP 錯誤')}"
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, NonLoopbackController):
        return "主機名稱解析結果或實際連線對端不是純 loopback"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return f"TLS 憑證驗證失敗 ({reason.verify_code}): {reason.verify_message}"
    if isinstance(reason, ssl.SSLError):
        return f"TLS 通訊失敗: {reason.reason or type(reason).__name__}"
    if isinstance(reason, socket.gaierror):
        return f"系統主機名稱解析失敗 ({reason.errno})"
    if isinstance(reason, ConnectionRefusedError):
        return "TCP 連線被拒絕；請確認 Controller HTTPS 監聽位址與埠"
    if isinstance(reason, TimeoutError):
        return "Controller 連線或回應逾時"
    if isinstance(reason, OSError):
        return f"連線或本機檔案錯誤 ({type(reason).__name__}, errno={reason.errno})"
    if isinstance(reason, json.JSONDecodeError):
        return "Controller 回應不是有效 JSON"
    return type(reason).__name__


def refresh(root, profile, providers, outputs, *, on_diagnostic=None):
    """Return names still awaiting successful API refresh; never log secrets."""
    if not profile.get("notify_mihomo", False):
        return []
    expected = {name: next(o["sha256"] for o in outputs if o["path"] == path)
                for name, path in providers.items()}
    pending = list(expected)
    def report(message):
        print(message)
        if on_diagnostic is not None:
            on_diagnostic(message)
    phase = "Controller 設定"
    try:
        endpoint = normalize_url(profile.get("controller_url", DEFAULT_URL))
        state_path = root / ACK_STATE
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            ack = state.get("ack", {}) if state.get("endpoint") == endpoint else {}
            if not isinstance(ack, dict):
                ack = {}
        except (OSError, ValueError, AttributeError):
            ack = {}
        pending = [name for name, sha in expected.items() if ack.get(name) != sha]
        if not pending:
            return []
        phase = "Secret 解密"
        secret = unprotect_secret(profile.get("controller_secret_dpapi", ""))
        phase = "CA 與 TLS 設定"
        opener = _opener()
        phase = "GET /providers/rules"
        active = _request(opener, endpoint + "/providers/rules", secret, "GET")["providers"]
        for name in list(pending):
            provider = active.get(name, {})
            if provider.get("vehicleType") != "File":
                actual = provider.get("vehicleType")
                kind = actual if actual in ("HTTP", "Inline", "Compatible") else "不存在或未知"
                report(f"{name}: 核心 Provider 類型為 {kind}，需要 File")
                continue
            try:
                step = "PUT"
                _request(opener, endpoint + "/providers/rules/" + quote(name, safe=""), secret, "PUT")
                step = "儲存通知狀態"
                ack[name] = expected[name]
                _save_state(state_path, {"endpoint": endpoint, "ack": ack})
                pending.remove(name)
                print(f"Controller {name}: updated")
            except Exception as exc:
                report(f"{name} {step}: {describe_error(exc)}")
    except Exception as exc:
        report(f"{phase}: {describe_error(exc)}")
    return pending
