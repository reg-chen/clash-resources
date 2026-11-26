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


def refresh(root, profile, providers, outputs):
    """Return names still awaiting successful API refresh; never log secrets."""
    if not profile.get("notify_mihomo", False):
        return []
    expected = {name: next(o["sha256"] for o in outputs if o["path"] == path)
                for name, path in providers.items()}
    pending = list(expected)
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
        secret = unprotect_secret(profile.get("controller_secret_dpapi", ""))
        opener = _opener()
        active = _request(opener, endpoint + "/providers/rules", secret, "GET")["providers"]
        for name in list(pending):
            provider = active.get(name, {})
            if provider.get("vehicleType") != "File":
                print(f"Controller {name}: skipped, active provider is not File")
                continue
            try:
                _request(opener, endpoint + "/providers/rules/" + quote(name, safe=""), secret, "PUT")
                ack[name] = expected[name]
                _save_state(state_path, {"endpoint": endpoint, "ack": ack})
                pending.remove(name)
                print(f"Controller {name}: updated")
            except Exception as exc:
                code = f" HTTP {exc.code}" if isinstance(exc, urllib.error.HTTPError) else ""
                print(f"Controller {name}: pending ({type(exc).__name__}{code})")
    except Exception as exc:
        code = f" HTTP {exc.code}" if isinstance(exc, urllib.error.HTTPError) else ""
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        if isinstance(reason, NonLoopbackController):
            print("Controller refresh pending: hostname or peer is not exclusively loopback")
        else:
            print(f"Controller refresh pending ({type(exc).__name__}{code})")
    return pending
