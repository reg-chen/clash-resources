"""UWP backup format validation; no firewall mutations are performed here."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import uwp_firewall


def rule(sid="S-1-15-2-1-2-3-4-5-6-7", action="Allow"):
    return {
        "PackageSID": sid, "PackageFamilyName": "Example.App_abc",
        "Direction": "Inbound", "Action": action, "Enabled": "True",
    }


class UwpFirewallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "fw.json"

    def write(self, rules, schema=1, kind="PersistentStore-UWP-PackageRules"):
        self.path.write_text(json.dumps({"Schema": schema, "Type": kind, "Rules": rules}))

    def test_backup_preview_counts_and_sid_validation(self):
        self.write([rule(), rule(action="Block")])
        self.assertEqual(uwp_firewall.inspect_backup(self.path),
                         {"total": 2, "allow": 1, "block": 1})
        self.write([rule(sid="not-a-package-sid")])
        with self.assertRaisesRegex(ValueError, "Package SID"):
            uwp_firewall.inspect_backup(self.path)

    def test_v2_appiso_snapshot_counts_and_preserves_source_breakdown(self):
        data = {
            "Schema": 2,
            "Type": "UWP-PackageFirewallRules",
            "Rules": [
                {**rule(), "PolicyStore": "PersistentStore"},
                {**rule(action="Block"), "PolicyStore": "ConfigurableServiceStore"},
            ],
            "AppIsoRules": [
                {
                    "Name": "{11111111-2222-3333-4444-555555555555}",
                    "Kind": "String",
                    "Data": "v2.30|Action=Allow|Active=TRUE|Dir=In|"
                            "AppPkgId=S-1-15-2-1-2-3-4-5-6-7|",
                },
                {
                    "Name": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
                    "Kind": "String",
                    "Data": "v2.30|Action=Block|Active=TRUE|Dir=Out|"
                            "AppPkgId=S-1-15-2-1-2-3-4-5-6-7|",
                },
            ],
        }
        self.path.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(
            uwp_firewall.inspect_backup(self.path),
            {"total": 4, "allow": 2, "block": 2,
             "appiso": 2, "netsecurity": 2},
        )

    def test_v2_requires_appiso_field_and_supported_raw_value_types(self):
        payload = {
            "Schema": 2, "Type": "UWP-PackageFirewallRules",
            "Rules": [], "AppIsoRules": None,
        }
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "AppIso"):
            uwp_firewall.inspect_backup(self.path)
        payload["AppIsoRules"] = [{"Name": "bogus", "Kind": "Binary", "Data": "invalid"}]
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "AppIso"):
            uwp_firewall.inspect_backup(self.path)

    def test_zero_rule_backup_is_error_even_if_powershell_reports_success(self):
        from types import SimpleNamespace

        def fake_run(cmd, **kwargs):
            report = Path(cmd[cmd.index("-Report") + 1])
            output = Path(cmd[cmd.index("-Path") + 1])
            output.write_text(
                json.dumps({"Schema": 2, "Type": "UWP-PackageFirewallRules",
                            "Rules": [], "AppIsoRules": []}), encoding="utf-8")
            report.write_text('{"Total":0,"Errors":[]}', encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(uwp_firewall.sys, "platform", "win32"):
            with mock.patch.object(uwp_firewall, "bundled_script",
                                   return_value=Path(__file__)):
                with mock.patch.object(uwp_firewall.subprocess, "run",
                                       side_effect=fake_run):
                    with self.assertRaisesRegex(RuntimeError, "空白檔案"):
                        uwp_firewall.backup(self.path)

    def test_export_uses_appiso_registry_not_only_get_netfirewallrule(self):
        script = (Path(__file__).resolve().parents[1] / "tools" / "uwp_firewall.ps1").read_text(
            encoding="utf-8")
        self.assertIn("AppIso\\\\FirewallRules", script)
        self.assertIn("ConfigurableServiceStore", script)
        self.assertIn("AppIsoRules = $appIsoRules", script)
        self.assertIn("Schema = 2", script)
        self.assertIn("if ($reportData.Total -eq 0 -and -not $AllowEmpty)", script)
        self.assertIn("尚不支援安全自動還原", script)

    def test_reject_unknown_schema_or_action(self):
        self.write([rule()], schema=2)
        with self.assertRaisesRegex(ValueError, "不是支援"):
            uwp_firewall.inspect_backup(self.path)
        self.write([rule(action="PermitAll")])
        with self.assertRaisesRegex(ValueError, "不支援"):
            uwp_firewall.inspect_backup(self.path)

    def test_elevated_restore_encodes_inner_invocation(self):
        import base64
        from types import SimpleNamespace

        self.write([rule()])
        destination = Path(self.temp.name) / "backup's folder" / "rules.json"
        destination.parent.mkdir()
        destination.write_bytes(self.path.read_bytes())

        def fake_run(cmd, **kwargs):
            self.assertEqual(cmd[:3], ["powershell.exe", "-NoProfile", "-NonInteractive"])
            self.assertEqual(cmd[3], "-EncodedCommand")
            outer = base64.b64decode(cmd[4]).decode("utf-16-le")
            self.assertIn("-Verb RunAs", outer)
            self.assertIn("-EncodedCommand", outer)
            encoded = outer.split("'-EncodedCommand','", 1)[1].split("'", 1)[0]
            inner = base64.b64decode(encoded).decode("utf-16-le")
            self.assertIn("backup''s folder", inner)
            self.assertIn("-Mode 'restore'", inner)
            # TemporaryDirectory is a real folder; the report path is in the
            # inner command. Extract it from the quoted PowerShell argument.
            report = inner.split(" -Report '", 1)[1].split("';", 1)[0].replace("''", "'")
            Path(report).write_text('{"Total":1,"Added":1,"Errors":[]}', encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(uwp_firewall.sys, "platform", "win32"):
            with mock.patch.object(uwp_firewall, "bundled_script", return_value=Path(__file__)):
                with mock.patch.object(uwp_firewall.subprocess, "run", side_effect=fake_run):
                    self.assertEqual(uwp_firewall.restore(destination)["Added"], 1)

    def test_failed_restore_cannot_report_success(self):
        from types import SimpleNamespace

        self.write([rule()])

        def fake_run(cmd, **kwargs):
            # Capture report file from the non-elevated invocation.
            report = Path(cmd[cmd.index("-Report") + 1])
            report.write_text(
                '{"Total":1,"Added":0,"Errors":["Access denied"]}', encoding="utf-8"
            )
            return SimpleNamespace(returncode=4, stdout="", stderr="")

        with mock.patch.object(uwp_firewall.sys, "platform", "win32"):
            with mock.patch.object(uwp_firewall, "bundled_script", return_value=Path(__file__)):
                with mock.patch.object(uwp_firewall.subprocess, "run", side_effect=fake_run):
                    with self.assertRaisesRegex(RuntimeError, "Access denied"):
                        uwp_firewall._run("backup", self.path, elevated=False)

    def test_no_execution_without_explicit_restore(self):
        self.write([rule()])
        with mock.patch.object(uwp_firewall, "_run") as invoke:
            with mock.patch.object(uwp_firewall.sys, "platform", "win32"):
                uwp_firewall.inspect_backup(self.path)
                invoke.assert_not_called()
                uwp_firewall.restore(self.path)
                invoke.assert_called_once_with("restore", self.path, elevated=True)


if __name__ == "__main__":
    unittest.main()
