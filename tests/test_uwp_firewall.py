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

    def test_reject_unknown_schema_or_action(self):
        self.write([rule()], schema=2)
        with self.assertRaisesRegex(ValueError, "不是支援"):
            uwp_firewall.inspect_backup(self.path)
        self.write([rule(action="PermitAll")])
        with self.assertRaisesRegex(ValueError, "不支援"):
            uwp_firewall.inspect_backup(self.path)

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
