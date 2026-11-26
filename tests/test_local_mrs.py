import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import local_mrs


class LocalMrsTests(unittest.TestCase):
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
            def fake_build(stage, entries, executable, report_dir):
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
                for name, data in (("third-party-mrs-sha256.json", {}),
                                   ("third-party-mrs-provenance.json", {"inputs": []})):
                    (stage / "tools" / name).write_text(json.dumps(data))
                for name in ("mrs-overlap.md", "mrs-skipped.md"):
                    (stage / name).write_text("report")
                return result
            with mock.patch.object(local_mrs, "build", side_effect=fake_build):
                self.assertEqual(local_mrs.run(profile), root.resolve())
            self.assertTrue((root / "local-mrs.yaml").is_file())
            self.assertTrue((root / ".local-mrs").is_file())
            self.assertEqual((root / "rules/security/mrs/combined.mrs").read_bytes(), b"VALID-MOCK-MRS")
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
