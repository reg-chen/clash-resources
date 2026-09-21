"""Exercise real Qt provider switches with isolated settings and no network."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication
import vpn_generator_core as core

gui = core.load_sibling("vpn-generator-gui.py", "vpn_gui_under_test")


class ProviderStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.settings = QSettings(
            str(Path(self.directory.name) / "settings.ini"), QSettings.IniFormat
        )
        self.settings.setFallbacksEnabled(False)
        self.patch = mock.patch.object(gui, "QSettings", return_value=self.settings)
        self.patch.start()
        self.window = gui.MainWindow()

    def tearDown(self):
        self.window.close()
        self.patch.stop()
        self.settings.sync()
        self.directory.cleanup()

    def test_credentials_restore_only_for_their_provider(self):
        window = self.window
        window.username_edit.setText("pia-user")
        window.password_edit.setText("pia-password")
        window.surfshark_radio.setChecked(True)
        self.assertEqual(window.username_edit.text(), "")
        self.assertEqual(window.password_edit.text(), "")
        window.username_edit.setText("ss-user")
        window.password_edit.setText("ss-password")
        for _ in range(2):
            window.pia_radio.setChecked(True)
            self.assertEqual(window.username_edit.text(), "pia-user")
            self.assertEqual(window.password_edit.text(), "pia-password")
            window.surfshark_radio.setChecked(True)
            self.assertEqual(window.username_edit.text(), "ss-user")
            self.assertEqual(window.password_edit.text(), "ss-password")
        window.save_settings()
        self.assertFalse(any(
            "username" in key or "password" in key
            for key in self.settings.allKeys()
        ))
        window.close()
        self.window = gui.MainWindow()
        self.assertEqual(self.window.selected_provider(), "surfshark")
        self.assertEqual(self.window.username_edit.text(), "")
        self.assertEqual(self.window.password_edit.text(), "")
        self.window.pia_radio.setChecked(True)
        self.assertEqual(self.window.username_edit.text(), "")
        self.assertEqual(self.window.password_edit.text(), "")

    def test_streaming_preferences_are_independent_and_persist(self):
        window = self.window
        window.exclude_streaming.setChecked(False)
        window.surfshark_radio.setChecked(True)
        self.assertFalse(window.exclude_streaming.isHidden())
        self.assertTrue(window.exclude_streaming.isChecked())
        self.assertEqual(window.credentials_label.text(), "Surfshark 帳號 / 密碼")
        self.assertEqual(window.udp_label.text(), "OpenVPN ZIP")
        window.pia_radio.setChecked(True)
        self.assertFalse(window.exclude_streaming.isChecked())
        window.surfshark_radio.setChecked(True)
        self.assertTrue(window.exclude_streaming.isChecked())
        window.close()
        self.window = gui.MainWindow()
        self.assertEqual(self.window.selected_provider(), "surfshark")
        self.assertTrue(self.window.exclude_streaming.isChecked())
        self.window.pia_radio.setChecked(True)
        self.assertFalse(self.window.exclude_streaming.isChecked())

    def test_worker_passes_surfsharks_own_filter(self):
        for exclude in (True, False):
            with self.subTest(exclude=exclude):
                generator = mock.Mock()
                worker = gui.GenerateWorker(
                    provider="surfshark", generate_openvpn=True,
                    generate_wireguard=False, udp_zip=Path("mock.zip"), tcp_zip=None,
                    username="ss-user", password="ss-password",
                    out_dir=Path(self.directory.name), single_file=True,
                    exclude_streaming=exclude,
                )
                completed = []
                worker.completed.connect(lambda ok, detail: completed.append(ok))
                with mock.patch.object(core, "load_sibling", return_value=generator):
                    worker.run()
                self.assertEqual(completed, [True])
                generator.generate_openvpn.assert_called_once_with(
                    bundle_zip=Path("mock.zip"), username="ss-user", password="ss-password",
                    out_dir=Path(self.directory.name), single_file=True,
                    exclude_streaming=exclude,
                )


if __name__ == "__main__":
    unittest.main()
