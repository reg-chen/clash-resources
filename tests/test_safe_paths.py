"""SAFE_PATHS additions must be opt-in, additive, and idempotent."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import safe_paths


class SafePathsTests(unittest.TestCase):
    def test_appends_only_provider_subdirectory_and_preserves_existing(self):
        existing = r"P:\Clash\rules;P:\Clash\test;P:\Clash\providers;P:\Clash\certs"
        self.assertEqual(
            safe_paths.provider_directory(r"P:\OtherVPN"),
            r"P:\OtherVPN\providers",
        )
        new, changed = safe_paths.append_value(existing, r"P:\OtherVPN\providers")
        self.assertTrue(changed)
        self.assertEqual(new, existing + r";P:\OtherVPN\providers")
        self.assertNotIn(r";P:\OtherVPN;", new)

    def test_existing_directory_is_not_rewritten(self):
        existing = r"P:\Clash\rules;P:\Clash\test;P:\Clash\providers;P:\Clash\certs"
        new, changed = safe_paths.append_value(existing, r"p:/clash/providers\\")
        self.assertFalse(changed)
        self.assertEqual(new, existing)

    def test_no_paths_are_removed_or_reordered(self):
        raw = r"C:\One;D:\Two;C:\One"
        result, changed = safe_paths.append_value(raw, r"E:\Three")
        self.assertTrue(changed)
        self.assertEqual(result, raw + r";E:\Three")
        with self.assertRaises(ValueError):
            safe_paths.append_value(raw, r"E:\x;y")

    def test_no_elevation_when_entry_already_exists(self):
        with mock.patch.object(safe_paths.sys, "platform", "win32"):
            with mock.patch.object(safe_paths, "is_machine_safe_path_present", return_value=True):
                with mock.patch.object(safe_paths, "append_machine_safe_path") as append:
                    self.assertFalse(safe_paths.ensure_machine_safe_path(r"P:\Clash\providers"))
                    append.assert_not_called()

    def test_elevation_only_on_permission_error_and_verify(self):
        with mock.patch.object(safe_paths.sys, "platform", "win32"):
            with mock.patch.object(safe_paths, "is_machine_safe_path_present", side_effect=[False, True]) as present:
                with mock.patch.object(safe_paths, "append_machine_safe_path", side_effect=PermissionError):
                    with mock.patch.object(safe_paths, "_run_elevated") as elevate:
                        self.assertTrue(safe_paths.ensure_machine_safe_path(r"P:\Clash\providers"))
                        elevate.assert_called_once_with(r"P:\Clash\providers")
                        self.assertEqual(present.call_count, 2)


if __name__ == "__main__":
    unittest.main()
