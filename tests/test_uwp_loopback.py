"""UWP Loopback checked-exemption backups; never mutate firewall in these tests."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import uwp_loopback as loopback

SID_A = "S-1-15-2-1-2-3-4-5-6-7"
SID_B = "S-1-15-7-8-9-10-11-12-13-14-15"
SID_C = "S-1-15-2-100-200-300-400-500-600-700"


def app(sid, name):
    return {"SID": sid, "AppContainerName": name,
            "DisplayName": name, "PackageFullName": name + "_1.0_x64"}


class LoopbackBackupTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.target = Path(self.folder.name) / "loopback.json"
        self.apps = {SID_A: app(SID_A, "Example.A_abc"),
                     SID_B: app(SID_B, "Example.B_xyz")}

    def write(self, rows):
        self.target.write_text(json.dumps({
            "Schema": 1, "Type": loopback.TYPE, "Exemptions": rows,
        }), encoding="utf-8")

    def test_backup_only_exports_checked_sids(self):
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "enabled_sids", return_value={SID_A, SID_C}):
                with mock.patch.object(loopback, "installed_containers",
                                       return_value=self.apps):
                    result = loopback.backup(self.target)
        self.assertEqual(result, {"Total": 2, "Recognized": 1, "Unresolved": 1})
        exported = loopback.read_backup(self.target)
        self.assertEqual({row["SID"] for row in exported}, {SID_A, SID_C})
        self.assertEqual([row for row in exported if row["SID"] == SID_C][0]["DisplayName"], "")
        self.assertEqual(self.target.read_text(encoding="utf-8").count('"SID"'), 2)

    def test_zero_checked_is_valid_not_firewall_rule_count(self):
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "enabled_sids", return_value=set()):
                with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
                    result = loopback.backup(self.target)
        self.assertEqual(result["Total"], 0)
        self.assertEqual(loopback.read_backup(self.target), [])

    def test_preview_skips_uninstalled_and_currently_existing(self):
        self.write([self.apps[SID_A], self.apps[SID_B], app(SID_C, "Deleted.Old_abc")])
        with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
            with mock.patch.object(loopback, "enabled_sids", return_value={SID_B}):
                rows = loopback.restore_preview(self.target)
        self.assertEqual([row["Status"] for row in rows],
                         ["available", "existing", "missing"])

    def test_reject_general_firewall_snapshot(self):
        self.target.write_text(json.dumps({
            "Schema": 2, "Type": "UWP-PackageFirewallRules",
            "Rules": [], "AppIsoRules": [],
        }), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "舊防火牆"):
            loopback.read_backup(self.target)

    def test_reject_duplicate_or_malformed_sid(self):
        self.write([app(SID_A, "Example"), app(SID_A, "Duplicate")])
        with self.assertRaisesRegex(ValueError, "重複"):
            loopback.read_backup(self.target)
        self.write([app("S-1-1-0", "invalid")])
        with self.assertRaisesRegex(ValueError, "無效 SID"):
            loopback.read_backup(self.target)

    def test_selective_restore_keeps_existing_and_skips_missing(self):
        def exec_simulated(command, **kwargs):
            self.assertEqual(command[1:3], ["LoopbackExempt", "-a"])
            self.assertEqual(command[3], f"-p={SID_A}")
            return mock.Mock(returncode=0, stdout="OK", stderr="")
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
                with mock.patch.object(loopback, "enabled_sids",
                                       side_effect=[{SID_B}, {SID_A, SID_B}]):
                    with mock.patch.object(loopback.subprocess, "run",
                                           side_effect=exec_simulated) as add:
                        result = loopback.apply_selected_sids([SID_A, SID_B, SID_C])
        self.assertEqual(result, {
            "Total": 3, "Added": 1, "Existing": 1,
            "MissingPackage": 1, "Errors": [],
        })
        self.assertEqual(add.call_count, 1)

    def test_restore_cannot_apply_sid_outside_backup(self):
        self.write([self.apps[SID_A]])
        with mock.patch.object(loopback, "require_windows"):
            with self.assertRaisesRegex(ValueError, "不屬於"):
                loopback.restore_selected(self.target, [SID_C])

    def test_restore_prompts_for_elevation_only_after_explicit_selection(self):
        import base64
        from types import SimpleNamespace

        self.write([self.apps[SID_A]])
        operations = []

        def fake_process(command, **_kwargs):
            self.assertEqual(command[:3], ["powershell.exe", "-NoProfile", "-NonInteractive"])
            self.assertEqual(command[3], "-EncodedCommand")
            outer = base64.b64decode(command[4]).decode("utf-16-le")
            self.assertIn("-Verb RunAs", outer)
            encoded = outer.split("'-EncodedCommand','", 1)[1].split("'", 1)[0]
            inner = base64.b64decode(encoded).decode("utf-16-le")
            self.assertIn("--uwp-loopback-apply", inner)
            self.assertNotIn("LoopbackExempt -c", inner)
            report = inner.split(" '--report' '", 1)[1].split("'", 1)[0]
            selection = inner.split(" '--uwp-loopback-apply' '", 1)[1].split("'", 1)[0]
            payload = json.loads(Path(selection).read_text(encoding="utf-8"))
            operations.extend(payload["SelectedSids"])
            Path(report).write_text(json.dumps({
                "Total": 1, "Added": 1, "Existing": 0,
                "MissingPackage": 0, "Errors": [],
            }), encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback.subprocess, "run",
                                   side_effect=fake_process) as spawn:
                self.assertEqual(loopback.restore_selected(self.target, []), {
                    "Total": 0, "Added": 0, "Existing": 0,
                    "MissingPackage": 0, "Errors": [],
                })
                spawn.assert_not_called()
                result = loopback.restore_selected(self.target, [SID_A])
                self.assertEqual(result["Added"], 1)
                self.assertEqual(operations, [SID_A])
                self.assertEqual(spawn.call_count, 1)

    def test_unsupported_platform_does_not_call_windows(self):
        with mock.patch.object(loopback.sys, "platform", "linux"):
            with self.assertRaisesRegex(RuntimeError, "Windows"):
                loopback.enabled_sids()


@unittest.skipUnless(sys.platform == "win32", "Windows network isolation API")
class WindowsLoopbackApiTests(unittest.TestCase):
    def test_native_api_enumeration_and_backup_consistency(self):
        import tempfile
        exempted = loopback.enabled_sids()
        apps = loopback.installed_containers()
        self.assertTrue(all(loopback.SID_RE.fullmatch(sid) for sid in exempted))
        self.assertTrue(all(loopback.SID_RE.fullmatch(sid) for sid in apps))
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "loopback.json"
            result = loopback.backup(output)
            self.assertEqual(result["Total"], len(loopback.read_backup(output)))
            self.assertGreaterEqual(result["Total"], 0)


if __name__ == "__main__":
    unittest.main()
