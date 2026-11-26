import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mrs_controller as controller


class ControllerTests(unittest.TestCase):
    def test_loopback_only(self):
        self.assertEqual(controller.normalize_url("https://127.0.0.1:9443/"), controller.DEFAULT_URL)
        self.assertEqual(controller.normalize_url("https://[::1]:9443"), "https://[::1]:9443")
        for url in ("http://127.0.0.1:9443", "https://example.com", "https://127.0.0.1:9443/dns-query",
                    "https://127.0.0.1:9443@evil.example", "https://localhost:0", "https://localhost?x=1"):
            with self.assertRaises(ValueError):
                controller.normalize_url(url)

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

    def test_request_bearer_header_and_put(self):
        opener = mock.MagicMock()
        opener.open.return_value.__enter__.return_value.status = 204
        controller._request(opener, controller.DEFAULT_URL + "/providers/rules/a", "sample", "PUT")
        req = opener.open.call_args.args[0]
        self.assertEqual(req.get_method(), "PUT")
        self.assertEqual(req.get_header("Authorization"), "Bearer sample")
