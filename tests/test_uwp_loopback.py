"""Portable UWP Loopback identities: no source SID may be used for restore."""
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import uwp_loopback as loopback

OLD_SID = "S-1-15-2-1-2-3-4-5-6-7"
NEW_SID = "S-1-15-2-101-202-303-404-505-606-707"
EXISTING_SID = "S-1-15-2-8-9-10-11-12-13-14"
MISSING_SID = "S-1-15-7-8-9-10-11-12-13-14-15"
PFN_A = "Example.App_abcde12345"
PFN_B = "Example.Other_abcde12345"
USER_SID = "S-1-5-21-101-202-303-1001"
OTHER_USER_SID = "S-1-5-21-101-202-303-1002"


def app(sid, moniker=PFN_A, family=PFN_A, name="Example App"):
    return {
        "SID": sid, "PackageFamilyName": family,
        "AppContainerName": moniker, "DisplayName": name,
        "PackageFullName": "Example.App_2.0.0_x64__abcde12345",
    }


def portable(item):
    return {k: v for k, v in item.items() if k != "SID"}


class LoopbackPortableBackupTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.target = Path(self.folder.name) / "loopback.json"
        self.apps = {
            NEW_SID: app(NEW_SID),
            EXISTING_SID: app(EXISTING_SID, PFN_B, PFN_B, "Other App"),
        }

    def write(self, rows, schema=2):
        self.target.write_text(json.dumps({
            "Schema": schema, "Type": loopback.TYPE, "Exemptions": rows,
        }), encoding="utf-8")

    def test_backup_stores_portable_identity_without_original_sid(self):
        source = app(OLD_SID, name="Example App old version")
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "enabled_sids", return_value={OLD_SID}):
                with mock.patch.object(loopback, "installed_containers",
                                       return_value={OLD_SID: source}):
                    result = loopback.backup(self.target)
        self.assertEqual(result["Recognized"], 1)
        self.assertEqual(result["Unresolved"], 0)
        encoded = self.target.read_text(encoding="utf-8")
        self.assertNotIn(OLD_SID, encoded)
        self.assertNotIn('"SID"', encoded)
        self.assertIn('"PackageFamilyName"', encoded)
        self.assertEqual(json.loads(encoded)["Schema"], 2)
        self.assertEqual(loopback.read_backup(self.target), [portable(source)])

    def test_unknown_container_is_marked_unportable_and_not_written_as_sid(self):
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "enabled_sids",
                                   return_value={OLD_SID, MISSING_SID}):
                with mock.patch.object(loopback, "installed_containers",
                                       return_value={OLD_SID: app(OLD_SID)}):
                    result = loopback.backup(self.target)
        self.assertEqual(result["Total"], 2)
        self.assertEqual(result["Recognized"], 1)
        self.assertEqual(result["Unresolved"], 1)
        payload = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertEqual(payload["UnresolvedCount"], 1)
        self.assertNotIn(MISSING_SID, self.target.read_text(encoding="utf-8"))
        self.assertEqual(len(loopback.read_backup(self.target)), 1)

    def test_zero_checked_is_valid(self):
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "enabled_sids", return_value=set()):
                with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
                    result = loopback.backup(self.target)
        self.assertEqual(result["Total"], 0)
        self.assertEqual(loopback.read_backup(self.target), [])

    def test_cross_machine_restore_preview_resolves_new_sid(self):
        self.write([portable(app(OLD_SID))])
        with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
            with mock.patch.object(loopback, "enabled_sids", return_value=set()):
                rows = loopback.restore_preview(self.target)
        self.assertEqual(rows[0]["Status"], "available")
        self.assertEqual(rows[0]["TargetSID"], NEW_SID)
        self.assertEqual(rows[0]["Key"], PFN_A.casefold())

    def test_preview_skips_uninstalled_and_existing(self):
        self.write([
            portable(app(OLD_SID)),
            portable(app(EXISTING_SID, PFN_B, PFN_B)),
            portable(app(MISSING_SID, "Uninstalled.Old_xyz", "Uninstalled.Old_xyz")),
        ])
        with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
            with mock.patch.object(loopback, "enabled_sids",
                                   return_value={EXISTING_SID}):
                rows = loopback.restore_preview(self.target)
        self.assertEqual([r["Status"] for r in rows],
                         ["available", "existing", "missing"])
        self.assertEqual(rows[-1]["TargetSID"], "")

    def test_fails_closed_on_pfn_mismatch_or_ambiguous_moniker(self):
        self.write([portable(app(OLD_SID, family="Other.Publisher_xyz"))])
        with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
            with mock.patch.object(loopback, "enabled_sids", return_value=set()):
                rows = loopback.restore_preview(self.target)
        self.assertEqual(rows[0]["Status"], "missing")
        self.assertEqual(rows[0]["TargetSID"], "")
        original = portable(app(OLD_SID))
        duplicates = {NEW_SID: self.apps[NEW_SID],
                      OLD_SID: app(OLD_SID, name="Duplicate registered container")}
        self.assertIsNone(loopback._local_match(original, duplicates))

    def test_legacy_v1_uses_moniker_not_old_sid(self):
        legacy = app(OLD_SID)
        legacy.pop("PackageFamilyName")
        self.write([legacy], schema=1)
        self.assertNotIn("SID", loopback.read_backup(self.target)[0])
        with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
            with mock.patch.object(loopback, "enabled_sids", return_value=set()):
                rows = loopback.restore_preview(self.target)
        self.assertEqual(rows[0]["TargetSID"], NEW_SID)
        self.assertEqual(rows[0]["Status"], "available")

    def test_legacy_unidentified_sid_is_unselectable(self):
        self.write([{
            "SID": OLD_SID, "AppContainerName": "",
            "PackageFullName": "", "DisplayName": "",
        }], schema=1)
        with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
            with mock.patch.object(loopback, "enabled_sids", return_value=set()):
                rows = loopback.restore_preview(self.target)
        self.assertEqual(rows[0]["Status"], "missing")
        self.assertTrue(rows[0]["Key"].startswith("unresolved:"))

    def test_reject_wrong_type_duplicate_or_invalid_legacy_sid(self):
        self.target.write_text(json.dumps({
            "Schema": 2, "Type": "UWP-PackageFirewallRules",
            "Rules": [], "AppIsoRules": [],
        }), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "舊防火牆"):
            loopback.read_backup(self.target)
        self.write([portable(app(OLD_SID)), portable(app(NEW_SID))])
        with self.assertRaisesRegex(ValueError, "重複"):
            loopback.read_backup(self.target)
        self.write([app("S-1-1-0")], schema=1)
        with self.assertRaisesRegex(ValueError, "無效 SID"):
            loopback.read_backup(self.target)

    def test_elevated_apply_uses_only_new_machine_sid(self):
        rows = [portable(app(OLD_SID)), portable(app(EXISTING_SID, PFN_B, PFN_B)),
                portable(app(MISSING_SID, "Gone_123", "Gone_123"))]
        def fake_add(command, **kwargs):
            self.assertEqual(command[1:3], ["LoopbackExempt", "-a"])
            self.assertEqual(command[3], f"-p={NEW_SID}")
            self.assertNotIn(OLD_SID, str(command))
            return SimpleNamespace(returncode=0, stdout="OK", stderr="")
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
                with mock.patch.object(loopback, "enabled_sids",
                                       side_effect=[{EXISTING_SID}, {NEW_SID, EXISTING_SID}]):
                    with mock.patch.object(loopback.subprocess, "run",
                                           side_effect=fake_add) as call:
                        result = loopback.apply_selected_entries(rows)
        self.assertEqual(result, {
            "Total": 3, "Added": 1, "Existing": 1,
            "MissingPackage": 1, "Errors": [],
        })
        self.assertEqual(call.call_count, 1)

    def test_legacy_migration_never_passes_previous_sid_to_checknetisolation(self):
        legacy = app(OLD_SID)
        legacy.pop("PackageFamilyName")
        self.write([legacy], schema=1)
        entries = loopback.read_backup(self.target)
        self.assertNotIn("SID", entries[0])
        def fake_add(command, **kwargs):
            self.assertEqual(command[3], f"-p={NEW_SID}")
            self.assertNotIn(OLD_SID, str(command))
            return SimpleNamespace(returncode=0, stdout="OK", stderr="")
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
                with mock.patch.object(loopback, "enabled_sids",
                                       side_effect=[set(), {NEW_SID}]):
                    with mock.patch.object(loopback.subprocess, "run",
                                           side_effect=fake_add):
                        applied = loopback.apply_selected_entries(entries)
        self.assertEqual(applied["Added"], 1)

    def test_wrong_publisher_is_not_applied_even_if_container_name_matches(self):
        wrong = portable(app(OLD_SID, family="Another.Publisher_x"))
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "installed_containers", return_value=self.apps):
                with mock.patch.object(loopback, "enabled_sids", return_value=set()):
                    with mock.patch.object(loopback.subprocess, "run") as add:
                        result = loopback.apply_selected_entries([wrong])
        self.assertEqual(result["MissingPackage"], 1)
        self.assertEqual(result["Added"], 0)
        add.assert_not_called()

    def test_reject_selection_not_in_backup(self):
        self.write([portable(app(OLD_SID))])
        with mock.patch.object(loopback, "require_windows"):
            with self.assertRaisesRegex(ValueError, "不屬於"):
                loopback.restore_selected(self.target, [PFN_B.casefold()])

    def test_uac_only_for_explicit_selection_and_no_sid_in_payload(self):
        self.write([portable(app(OLD_SID))])
        captured = []
        def fake_process(command, **kwargs):
            self.assertEqual(command[:4],
                             ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand"])
            outer = base64.b64decode(command[4]).decode("utf-16-le")
            self.assertIn("-Verb RunAs", outer)
            encoded = outer.split("'-EncodedCommand','", 1)[1].split("'", 1)[0]
            inner = base64.b64decode(encoded).decode("utf-16-le")
            report = inner.split(" '--report' '", 1)[1].split("'", 1)[0]
            selection = inner.split(" '--uwp-loopback-apply' '", 1)[1].split("'", 1)[0]
            payload = json.loads(Path(selection).read_text(encoding="utf-8"))
            self.assertNotIn("SelectedSids", payload)
            self.assertEqual(payload["RequestingUserSID"], USER_SID)
            self.assertEqual(payload["SelectedEntries"], [portable(app(OLD_SID))])
            self.assertNotIn(OLD_SID, json.dumps(payload))
            captured.append(payload)
            Path(report).write_text(json.dumps({
                "Total": 1, "Added": 1, "Existing": 0,
                "MissingPackage": 0, "Errors": [],
            }), encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(loopback, "require_windows"):
            with mock.patch.object(loopback, "current_user_context",
                                   return_value=(USER_SID, True)):
                with mock.patch.object(loopback.subprocess, "run",
                                       side_effect=fake_process) as call:
                    self.assertEqual(loopback.restore_selected(self.target, [])["Added"], 0)
                    call.assert_not_called()
                    result = loopback.restore_selected(self.target, [PFN_A.casefold()])
        self.assertEqual(result["Added"], 1)
        self.assertEqual(len(captured), 1)
        self.assertEqual(call.call_count, 1)

    def test_elevated_child_rejects_different_uac_account(self):
        selection = Path(self.folder.name) / "selected.json"
        report = Path(self.folder.name) / "report.json"
        selection.write_text(json.dumps({
            "Type": loopback.TYPE, "RequestingUserSID": USER_SID,
            "SelectedEntries": [portable(app(OLD_SID))],
        }), encoding="utf-8")
        with mock.patch.object(loopback, "current_user_context",
                               return_value=(OTHER_USER_SID, True)):
            with mock.patch.object(loopback, "apply_selected_entries") as apply:
                exit_code = loopback.elevated_child(selection, report)
                apply.assert_not_called()
        self.assertEqual(exit_code, 4)
        self.assertIn("切換了 Windows 使用者帳號",
                      json.loads(report.read_text(encoding="utf-8"))["Errors"][0])

    def test_elevated_child_accepts_same_user_after_consent(self):
        selection = Path(self.folder.name) / "selected.json"
        report = Path(self.folder.name) / "report.json"
        selection.write_text(json.dumps({
            "Type": loopback.TYPE, "RequestingUserSID": USER_SID,
            "SelectedEntries": [portable(app(OLD_SID))],
        }), encoding="utf-8")
        outcome = {"Total": 1, "Added": 1, "Existing": 0,
                   "MissingPackage": 0, "Errors": []}
        with mock.patch.object(loopback, "current_user_context",
                               return_value=(USER_SID, True)):
            with mock.patch.object(loopback, "apply_selected_entries",
                                   return_value=outcome) as apply:
                self.assertEqual(loopback.elevated_child(selection, report), 0)
                apply.assert_called_once()
        self.assertEqual(json.loads(report.read_text(encoding="utf-8")), outcome)

    def test_non_windows_is_unsupported(self):
        with mock.patch.object(loopback.sys, "platform", "linux"):
            with self.assertRaisesRegex(RuntimeError, "Windows"):
                loopback.enabled_sids()


@unittest.skipUnless(sys.platform == "win32", "Windows network isolation API")
class WindowsLoopbackApiTests(unittest.TestCase):
    def test_native_api_enumeration_and_backup_consistency(self):
        exempted = loopback.enabled_sids()
        apps = loopback.installed_containers()
        self.assertTrue(all(loopback.SID_RE.fullmatch(sid) for sid in exempted))
        self.assertTrue(all(loopback.SID_RE.fullmatch(sid) for sid in apps))
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "loopback.json"
            result = loopback.backup(output)
            self.assertEqual(result["Recognized"], len(loopback.read_backup(output)))
            self.assertGreaterEqual(result["Total"], result["Recognized"])
            self.assertNotIn('"SID"', output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
