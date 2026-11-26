import sys
import socket
import ssl
import urllib.error
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mrs_controller as controller


class ControllerTests(unittest.TestCase):
    def test_https_controller_hosts(self):
        self.assertEqual(controller.normalize_url("https://127.0.0.1:9443/"), controller.DEFAULT_URL)
        self.assertEqual(controller.normalize_url("https://[::1]:9443"), "https://[::1]:9443")
        self.assertEqual(controller.normalize_url("https://DoH.Example:9443"), "https://doh.example:9443")
        self.assertEqual(controller.normalize_url("https://controller.example"), "https://controller.example:443")
        self.assertEqual(controller.normalize_url("https://192.168.1.20:9443"), "https://192.168.1.20:9443")
        self.assertEqual(controller.normalize_url("https://[fd00::1]:9443"), "https://[fd00::1]:9443")
        for url in ("http://127.0.0.1:9443", "https://127.0.0.1:9443/dns-query",
                    "https://127.0.0.1:9443@evil.example", "https://localhost:0", "https://localhost?x=1",
                    "https://bad host:9443", "https://*.example:9443", "https://host:", "https://host#"):
            with self.assertRaises(ValueError):
                controller.normalize_url(url)

    def test_connect_rejects_mixed_or_nonlocal_answers_before_socket(self):
        local = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 9443))
        remote = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.20", 9443))
        remote6 = (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::1", 9443, 0, 0))
        with mock.patch.object(controller.socket, "getaddrinfo") as resolve, \
             mock.patch.object(controller.socket, "socket") as create:
            for answers in ([], [remote], [local, remote], [local, remote6]):
                resolve.return_value = answers
                with self.assertRaises(controller.NonLoopbackController):
                    controller._connect_loopback(("doh.example", 9443), 10)
                create.assert_not_called()

    def test_connect_pins_loopback_and_preserves_tls_hostname(self):
        local6 = (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 9443, 0, 0))
        local4 = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 9443))
        context = mock.MagicMock()
        context.wrap_socket.return_value = mock.MagicMock()
        with mock.patch.object(controller.socket, "getaddrinfo", return_value=[local6, local4]) as resolve, \
             mock.patch.object(controller.socket, "socket") as create:
            first, second = mock.MagicMock(), mock.MagicMock()
            first.connect.side_effect = ConnectionRefusedError()
            second.getpeername.return_value = local4[4]
            create.side_effect = [first, second]
            conn = controller._LoopbackHTTPSConnection("doh.example", 9443, timeout=10, context=context)
            conn.connect()
            resolve.assert_called_once_with("doh.example", 9443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            first.connect.assert_called_once_with(local6[4])
            first.close.assert_called_once()
            second.connect.assert_called_once_with(local4[4])
            context.wrap_socket.assert_called_once_with(second, server_hostname="doh.example")

    def test_connect_rejects_nonloopback_peer(self):
        local = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 9443))
        with mock.patch.object(controller.socket, "getaddrinfo", return_value=[local]), \
             mock.patch.object(controller.socket, "socket") as create:
            create.return_value.getpeername.return_value = ("192.168.1.20", 9443)
            with self.assertRaises(controller.NonLoopbackController):
                controller._connect_loopback(("doh.example", 9443), 10)
            create.return_value.close.assert_called_once()

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI")
    def test_dpapi_roundtrip(self):
        value = controller.protect_secret("test-secret-32!")
        self.assertNotIn("test-secret-32!", value)
        self.assertEqual(controller.unprotect_secret(value), "test-secret-32!")
        self.assertEqual(controller.protect_secret(""), "")
        self.assertEqual(controller.unprotect_secret(""), "")
        with self.assertRaises(RuntimeError):
            controller.unprotect_secret("invalid")

    def test_refresh_unchanged_retry_and_file_only(self):
        providers = {"a": "a.mrs", "b": "b.mrs"}
        outputs = [{"path": "a.mrs", "sha256": "first"}, {"path": "b.mrs", "sha256": "second"}]
        profile = {"notify_mihomo": True, "controller_url": controller.DEFAULT_URL}
        active = {"a": {"vehicleType": "File"}, "b": {"vehicleType": "HTTP"}}
        calls = []
        def request(opener, url, secret, method):
            calls.append((method, url))
            if method == "GET":
                return {"providers": active}
            if url.endswith("/b") and len(calls) == 4:
                raise OSError("unavailable")
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(controller, "_opener"), \
             mock.patch.object(controller, "_request", side_effect=request):
            root = Path(folder)
            self.assertEqual(controller.refresh(root, profile, providers, outputs), ["b"])
            self.assertEqual([m for m, _ in calls], ["GET", "PUT"])
            active["b"]["vehicleType"] = "File"
            self.assertEqual(controller.refresh(root, profile, providers, outputs), ["b"])
            self.assertEqual(controller.refresh(root, profile, providers, outputs), [])
            count = len(calls)
            self.assertEqual(controller.refresh(root, profile, providers, outputs), [])
            self.assertEqual(len(calls), count)
            outputs[0]["sha256"] = "changed"
            self.assertEqual(controller.refresh(root, profile, providers, outputs), [])
            self.assertEqual(calls[-2:], [("GET", controller.DEFAULT_URL + "/providers/rules"),
                                         ("PUT", controller.DEFAULT_URL + "/providers/rules/a")])
            profile["notify_mihomo"] = False
            outputs[0]["sha256"] = "changed again"
            count = len(calls)
            self.assertEqual(controller.refresh(root, profile, providers, outputs), [])
            self.assertEqual(len(calls), count)

    def test_diagnostics_safe_and_specific(self):
        error = urllib.error.HTTPError(controller.DEFAULT_URL, 401, "secret-not-for-log", {}, None)
        self.assertIn("HTTP 401", controller.describe_error(error))
        self.assertNotIn("secret-not-for-log", controller.describe_error(error))
        self.assertIn("loopback", controller.describe_error(urllib.error.URLError(controller.NonLoopbackController())))
        self.assertIn("解析", controller.describe_error(urllib.error.URLError(socket.gaierror(11001, "ignored"))))
        self.assertIn("TLS", controller.describe_error(urllib.error.URLError(ssl.SSLError("ignored"))))
        profile = {"notify_mihomo": True}
        providers = {"a": "a.mrs"}
        outputs = [{"path": "a.mrs", "sha256": "first"}]
        messages = []
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(controller, "_opener"), \
             mock.patch.object(controller, "_request", side_effect=error):
            self.assertEqual(controller.refresh(Path(folder), profile, providers, outputs,
                                               on_diagnostic=messages.append), ["a"])
        self.assertEqual(len(messages), 1)
        self.assertIn("GET /providers/rules", messages[0])
        self.assertIn("HTTP 401", messages[0])
        self.assertNotIn("secret-not-for-log", messages[0])

    def test_request_bearer_header_and_put(self):
        opener = mock.MagicMock()
        opener.open.return_value.__enter__.return_value.status = 204
        controller._request(opener, controller.DEFAULT_URL + "/providers/rules/a", "sample", "PUT")
        req = opener.open.call_args.args[0]
        self.assertEqual(req.get_method(), "PUT")
        self.assertEqual(req.get_header("Authorization"), "Bearer sample")
