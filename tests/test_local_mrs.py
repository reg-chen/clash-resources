import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import local_mrs
import mrs_schedule
import toolkit_schedule
import warp_schedule


class LocalMrsTests(unittest.TestCase):
    def test_arbitrary_hour_interval(self):
        for hours in (1, 2, 5, 7, 23, 24, 25, 48, 168, 744):
            self.assertEqual(local_mrs.validate_hours(hours), hours)
        for value in (0, -1, 745, 1.5, True, "5", None):
            with self.assertRaises(ValueError):
                local_mrs.validate_hours(value)
        script = mrs_schedule._SCRIPT
        self.assertIn("Triggers.Create(1)", script)
        self.assertIn("XmlConvert]::ToString([TimeSpan]::FromHours($hours))", script)
        self.assertNotIn("Repetition.Duration =", script)
        self.assertNotIn("DaysInterval", script)

    def test_schedule_install_and_remove(self):
        with mock.patch.object(toolkit_schedule.sys, "platform", "win32"), \
             mock.patch.object(toolkit_schedule.sys, "frozen", True, create=True), \
             mock.patch.object(toolkit_schedule.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "Installed"
            self.assertEqual(mrs_schedule.configure("install", 7), "Installed")
            env = run.call_args.kwargs["env"]
            self.assertEqual(env["MRS_TASK_HOURS"], "7")
            self.assertEqual(Path(env["TOOLKIT_TASK_EXE"]), mrs_schedule.scheduler_executable())
            self.assertEqual(Path(env["TOOLKIT_TASK_SOURCE"]), Path(sys.executable).resolve())
            with self.assertRaises(ValueError):
                mrs_schedule.configure("install", 745)
            self.assertEqual(run.call_count, 1)
            run.return_value.stdout = "Removed"
            self.assertEqual(mrs_schedule.configure("remove"), "Removed")

    def test_schedule_uses_local_appdata_not_roaming(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with mock.patch.dict(toolkit_schedule.os.environ, {"LOCALAPPDATA": str(root / "Local"), "APPDATA": str(root / "Roaming")}):
                self.assertEqual(mrs_schedule.scheduler_executable(), root / "Local" / "reg-chen" / "VPN-Network-Toolkit" / "scheduler" / "VPN-Network-Toolkit.exe")
                self.assertEqual(local_mrs.profile_path().parent, root / "Roaming" / "reg-chen" / "VPN-Network-Toolkit")

    def test_schedule_copy_and_transaction_contract(self):
        script = mrs_schedule._SCRIPT
        self.assertIn("Get-FileHash -LiteralPath $source -Algorithm SHA256", script)
        self.assertIn("[IO.File]::Copy($source, $stage, $false)", script)
        self.assertIn("[IO.File]::Replace($stage, $exe, $backup)", script)
        self.assertIn("[IO.File]::Replace($backup, $exe, $null)", script)
        self.assertIn("$task.GetInstances(0).Count", script)
        self.assertIn("$tasks[$taskName].Enabled = $enabled[$taskName]", script)
        self.assertIn("!$otherExists -and [IO.File]::Exists($exe)", script)
        self.assertIn("if (!$committed -or $taskName -ne $name)", script)
        for name in toolkit_schedule.TASK_NAMES:
            self.assertIn(name, script)
        self.assertIn("$folder.RegisterTaskDefinition($name, $definition, 6", script)
        self.assertNotIn("$previous.Stop(", script)
        self.assertIn("$folder.DeleteTask($name, 0)", script)
        self.assertIn("[IO.Directory]::Delete($directory)", script)
        self.assertNotIn("Remove-Item -Recurse", script)

    def test_warp_and_mrs_share_scheduler_executable(self):
        with mock.patch.object(toolkit_schedule.sys, "platform", "win32"), \
             mock.patch.object(toolkit_schedule.sys, "frozen", True, create=True), \
             mock.patch.object(toolkit_schedule.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "Installed"
            mrs_schedule.configure("install", 7)
            mrs_env = run.call_args.kwargs["env"]
            warp_schedule.configure_schedule(action="install", out_dir=Path("C:/WARP"), mode="interval", interval_days=9)
            warp_env = run.call_args.kwargs["env"]
            self.assertEqual(mrs_env["TOOLKIT_TASK_EXE"], warp_env["TOOLKIT_TASK_EXE"])
            self.assertEqual(mrs_env["TOOLKIT_TASK_NAME"], "Clash Local MRS Refresh")
            self.assertEqual(warp_env["TOOLKIT_TASK_NAME"], "Clash WARP Refresh")
            self.assertEqual(warp_env["WARP_TASK_INTERVAL"], "9")
            self.assertEqual(warp_env["WARP_TASK_MODE"], "interval")
            self.assertTrue(warp_schedule._SCRIPT.startswith(toolkit_schedule._PREFIX))
            self.assertTrue(mrs_schedule._SCRIPT.startswith(toolkit_schedule._PREFIX))
            self.assertTrue(warp_schedule._SCRIPT.endswith(toolkit_schedule._SUFFIX))
            self.assertTrue(mrs_schedule._SCRIPT.endswith(toolkit_schedule._SUFFIX))
            run.return_value.stdout = "Removed"
            self.assertEqual(warp_schedule.configure_schedule(action="remove"), "Removed")
            self.assertEqual(run.call_args.kwargs["env"]["TOOLKIT_TASK_OPERATION"], "remove")

    @unittest.skipUnless(sys.platform == "win32", "Windows PowerShell parser")
    def test_shared_scripts_parse_in_windows_powershell(self):
        import base64
        import subprocess
        import os
        for script in (mrs_schedule._SCRIPT, warp_schedule._SCRIPT):
            env = dict(os.environ, TOOLKIT_TEST_SCRIPT=base64.b64encode(script.encode("utf-8")).decode("ascii"))
            command = (
                "$text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:TOOLKIT_TEST_SCRIPT)); "
                "$tokens = $null; $errors = $null; "
                "$null = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors); "
                "if ($errors.Count) { $errors | Out-String | Write-Output; exit 1 }"
            )
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                    env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_catalog_and_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            exe = root / "mihomo.exe"
            exe.touch()
            profile = {"directory": str(root / "local"), "mihomo": str(exe), "hours": 2,
                       "sources": [s["name"] for s in local_mrs.catalog()]}
            selected, output, compiler = local_mrs.validate(profile)
            self.assertEqual(len(selected), len(profile["sources"]))
            self.assertEqual(output, (root / "local").resolve())
            self.assertEqual(compiler, exe.resolve())
            _, _, auto = local_mrs.validate(dict(profile, mihomo=""))
            self.assertIsNone(auto)
            profile["sources"] = []
            with self.assertRaises(ValueError):
                local_mrs.validate(profile)

    def test_override_preserves_provider_names_and_separate_paths(self):
        text = local_mrs.override_yaml(Path(local_mrs.DEFAULT_ROOT))
        self.assertEqual(local_mrs.DEFAULT_ROOT, r"P:\Clash")
        self.assertEqual(text.count("type: file"), 4)
        self.assertEqual(text.count("behavior: ipcidr"), 1)
        self.assertNotIn("https://", text)
        for name in local_mrs.PROVIDERS:
            self.assertIn("  " + name + ":", text)

    def test_publication_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, stage = base / "local", base / "stage"
            root.mkdir()
            stage.mkdir()
            for path in ("a", "b"):
                (root / path).write_text("old")
                (stage / path).write_text("new")
            real = local_mrs.os.replace
            def replace(src, dst):
                if Path(src) == stage / "b":
                    raise OSError("simulated failure")
                return real(src, dst)
            with mock.patch.object(local_mrs.os, "replace", side_effect=replace):
                with self.assertRaises(OSError):
                    local_mrs.publish(stage, root, ["a", "b"])
            self.assertEqual((root / "a").read_text(), "old")
            self.assertEqual((root / "b").read_text(), "old")

    def test_local_run_stages_before_publish_and_preserves_custom_rules(self):
        import hashlib
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root = base / "local"
            exe = base / "mihomo.exe"
            exe.touch()
            profile = {"directory": str(root), "mihomo": str(exe), "hours": 2,
                       "sources": [s["name"] for s in local_mrs.catalog()]}
            raw = {s["name"]: b"source.example\n" for s in local_mrs.catalog()}
            self.addCleanup(mock.patch.stopall)
            mock.patch.object(local_mrs, "fetch_inputs", side_effect=lambda entries: {s["name"]: raw[s["name"]] for s in entries}).start()
            mock.patch.object(local_mrs.mrs_compiler, "resolve", return_value=exe.resolve()).start()
            def fake_build(stage, entries, executable, report_dir, *, pin_revisions, source_bytes):
                self.assertFalse(pin_revisions)
                self.assertFalse(any("target" in item for item in entries))
                self.assertEqual(Path(executable), exe.resolve())
                self.assertTrue((stage / "rules/security/custom.txt").is_file())
                result = []
                for relative in local_mrs.PROVIDERS.values():
                    path = stage / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    data = b"VALID-MOCK-MRS"
                    path.write_bytes(data)
                    result.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(),
                                   "size_bytes": len(data)})
                inputs = []
                from mrs_provenance import save_source_snapshot
                for item in entries:
                    data = source_bytes[item["name"]]
                    path = save_source_snapshot(stage, item["name"], item["format"], data)
                    inputs.append({"name": item["name"], "format": item["format"],
                                   "source_snapshot_path": path.relative_to(stage).as_posix(),
                                   "source_sha256": hashlib.sha256(data).hexdigest(), "source_size_bytes": len(data)})
                for name, data in (("third-party-mrs-sha256.json", {}),
                                   ("third-party-mrs-provenance.json", {"inputs": inputs, "outputs": result})):
                    (stage / "tools" / name).write_text(json.dumps(data))
                for name in ("mrs-overlap.md", "mrs-skipped.md"):
                    (stage / name).write_text("report")
                return result
            with mock.patch.object(local_mrs, "build", side_effect=fake_build):
                self.assertEqual(local_mrs.run(profile), root.resolve())
            self.assertTrue((root / "local-mrs.yaml").is_file())
            self.assertTrue((root / ".local-mrs").is_file())
            self.assertEqual((root / "rules/security/mrs/combined.mrs").read_bytes(), b"VALID-MOCK-MRS")
            # Unchanged input + intact output: no temporary directory or merge.
            with mock.patch.object(local_mrs, "build", side_effect=AssertionError("unexpected compile")), \
                 mock.patch.object(local_mrs.tempfile, "TemporaryDirectory", side_effect=AssertionError("unexpected staging")):
                self.assertEqual(local_mrs.run(profile), root.resolve())
            # Changed raw data, damaged output, changed selection, or compiler force rebuild.
            raw["security-threat"] = b"changed.example\n"
            with mock.patch.object(local_mrs, "build", side_effect=fake_build) as rebuild:
                local_mrs.run(profile)
                self.assertEqual(rebuild.call_count, 1)
            (root / "rules/security/mrs/combined.mrs").write_bytes(b"corrupted")
            with mock.patch.object(local_mrs, "build", side_effect=fake_build) as rebuild:
                local_mrs.run(profile)
                self.assertEqual(rebuild.call_count, 1)
            profile["sources"].remove("security-fake")
            with mock.patch.object(local_mrs, "build", side_effect=fake_build) as rebuild:
                local_mrs.run(profile)
                self.assertEqual(rebuild.call_count, 1)
            exe.write_bytes(b"new compiler")
            with mock.patch.object(local_mrs, "build", side_effect=fake_build) as rebuild:
                local_mrs.run(profile)
                self.assertEqual(rebuild.call_count, 1)
            custom = root / "rules/security/custom.txt"
            custom.write_text("private.example\n")
            with mock.patch.object(local_mrs, "build", side_effect=RuntimeError("upstream failed")):
                with self.assertRaises(RuntimeError):
                    local_mrs.run(profile)
            self.assertEqual(custom.read_text(), "private.example\n")
            self.assertEqual((root / "rules/security/mrs/combined.mrs").read_bytes(), b"VALID-MOCK-MRS")
            unrelated = base / "unmanaged"
            existing = unrelated / "rules/security/mrs/combined.mrs"
            existing.parent.mkdir(parents=True)
            existing.write_bytes(b"unmanaged")
            with self.assertRaises(ValueError):
                local_mrs.validate(dict(profile, directory=str(unrelated)))

            self.assertTrue(local_mrs.needs_takeover(unrelated))
            selected, output, _ = local_mrs.validate(dict(profile, directory=str(unrelated),
                                                         takeover_root=str(unrelated.resolve())))
            self.assertEqual(output, unrelated.resolve())
            self.assertEqual(existing.read_bytes(), b"unmanaged")
