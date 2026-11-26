"""Loopback HTTPS Controller refresh and current-user DPAPI credentials."""
from __future__ import annotations

import base64
import ctypes
import json
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
        url = urlsplit(value.strip())
        port = url.port
        if (url.scheme != "https" or url.hostname not in {"127.0.0.1", "::1", "localhost"}
                or url.username is not None or url.password is not None
                or url.path not in ("", "/") or url.query or url.fragment
                or port == 0):
            raise ValueError
    except (ValueError, AttributeError):
        raise ValueError("Controller URL 必須是本機 HTTPS 位址，例如 https://127.0.0.1:9443。") from None
    host = "[::1]" if url.hostname == "::1" else url.hostname
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
                                       _NoRedirect(), urllib.request.HTTPSHandler(context=context))


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
        print(f"Controller refresh pending ({type(exc).__name__}{code})")
    return pending
