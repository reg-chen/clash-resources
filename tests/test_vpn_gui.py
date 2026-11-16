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

from PySide6.QtCore import QPoint, QSettings, Qt
from PySide6.QtWidgets import QApplication, QScrollArea
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

    def test_provider_text_does_not_shift_input_alignment(self):
        window = self.window
        window.show()
        QApplication.processEvents()

        def input_x():
            return window.out_edit.mapTo(window, QPoint(0, 0)).x()

        base_x = input_x()
        window.surfshark_radio.setChecked(True)
        QApplication.processEvents()
        self.assertEqual(input_x(), base_x)
        self.assertEqual(window.exclude_streaming.text(), "排除 Streaming Optimized")
        window.pia_radio.setChecked(True)
        QApplication.processEvents()
        self.assertEqual(input_x(), base_x)
        self.assertEqual(window.credentials_label.width(), window.udp_label.width())

    def test_doh_tab_controls_stay_aligned_on_hostname_changes(self):
        window = self.window
        window.show()
        window.tabs.setCurrentWidget(window.doh_panel)
        QApplication.processEvents()
        panel = window.doh_panel
        scroll = panel.layout().itemAt(0).widget()
        self.assertIsInstance(scroll, QScrollArea)
        self.assertTrue(scroll.widgetResizable())
        self.assertEqual(scroll.horizontalScrollBarPolicy(), Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        before_output = panel.output.mapTo(window, QPoint(0, 0))
        before_snippet = panel.snippet.mapTo(window, QPoint(0, 0))
        panel.host_input.setText("a-very-long-but-valid-localhost-doh-endpoint.test")
        QApplication.processEvents()
        self.assertEqual(panel.output.mapTo(window, QPoint(0, 0)), before_output)
        self.assertEqual(panel.snippet.mapTo(window, QPoint(0, 0)), before_snippet)
        self.assertEqual(panel.endpoint_input.text(),
                         "https://a-very-long-but-valid-localhost-doh-endpoint.test:9443/dns-query")
        self.assertEqual(panel.hosts_input.text(),
                         "'a-very-long-but-valid-localhost-doh-endpoint.test': 127.0.0.1")

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

    def test_safe_paths_checkbox_is_opt_in_and_only_writes_after_success(self):
        window = self.window
        self.assertFalse(window.safe_paths_checkbox.isChecked())
        window.out_edit.setText(r"P:\Clash")

        with mock.patch.object(window, "validate_inputs", return_value=[]):
            with mock.patch.object(gui, "GenerateWorker") as worker:
                with mock.patch.object(gui.safe_paths, "ensure_machine_safe_path", return_value=True) as ensure:
                    with mock.patch.object(gui.QMessageBox, "information") as info:
                        window.start_generation()
                        worker.return_value.start.assert_called_once_with()
                        self.assertIsNone(window._pending_safe_paths)
                        window.generation_finished(True, "done")
                        ensure.assert_not_called()

                        window.safe_paths_checkbox.setChecked(True)
                        window.start_generation()
                        self.assertFalse(window.safe_paths_checkbox.isEnabled())
                        self.assertEqual(window._pending_safe_paths, r"P:\Clash\providers")
                        window.generation_finished(True, "done")
                        ensure.assert_called_once_with(r"P:\Clash\providers")
                        self.assertFalse(window.safe_paths_checkbox.isChecked())
                        self.assertTrue(window.safe_paths_checkbox.isEnabled())
                        self.assertIn("SAFE_PATHS 已加入", info.call_args.args[2])

    def test_safe_paths_not_modified_when_generation_fails(self):
        window = self.window
        window.out_edit.setText(r"P:\Clash")
        window.safe_paths_checkbox.setChecked(True)
        with mock.patch.object(window, "validate_inputs", return_value=[]):
            with mock.patch.object(gui, "GenerateWorker"):
                with mock.patch.object(gui.safe_paths, "ensure_machine_safe_path") as ensure:
                    with mock.patch.object(gui.QMessageBox, "critical"):
                        window.start_generation()
                        window.generation_finished(False, "provider error")
                    ensure.assert_not_called()
        self.assertFalse(window.safe_paths_checkbox.isChecked())

    def test_warp_provider_state_and_worker(self):
        window = self.window
        window.warp_radio.setChecked(True)
        self.assertEqual(window.selected_provider(), "warp")
        self.assertFalse(window.openvpn_checkbox.isEnabled())
        self.assertFalse(window.openvpn_checkbox.isChecked())
        self.assertFalse(window.wireguard_checkbox.isEnabled())
        self.assertTrue(window.wireguard_checkbox.isChecked())
        self.assertTrue(window.udp_row.isHidden())
        self.assertTrue(window.tcp_row.isHidden())
        self.assertTrue(window.credentials_row.isHidden())
        self.assertTrue(window.exclude_streaming.isHidden())
        self.assertEqual(window.validate_inputs(), ["請選擇輸出目錄。"])

        generator = mock.Mock()
        generator.generate_warp.return_value = Path(self.directory.name) / "providers" / "warp.yaml"
        worker = gui.GenerateWorker(
            provider="warp", generate_openvpn=False,
            generate_wireguard=True, udp_zip=None, tcp_zip=None,
            username="", password="",
            out_dir=Path(self.directory.name), single_file=False,
            exclude_streaming=True,
        )
        completed = []
        worker.completed.connect(lambda ok, detail: completed.append(ok))
        with mock.patch.object(core, "load_sibling", return_value=generator):
            worker.run()
        self.assertEqual(completed, [True])
        generator.generate_warp.assert_called_once_with(out_dir=Path(self.directory.name))


    def test_doh_tab_is_global_and_independent_of_selected_provider(self):
        window = self.window
        self.assertEqual(window.tabs.count(), 2)
        self.assertEqual(window.tabs.tabText(0), "VPN Provider")
        self.assertEqual(window.tabs.tabText(1), "Mihomo DNS / TLS")
        panel = window.doh_panel
        self.assertFalse(panel.trust_button.isEnabled())
        self.assertEqual(panel.output.text(), panel._default_cert_root())
        self.assertEqual(panel.host_input.text(), "127.0.0.1")

        panel.output.setText(self.directory.name)
        panel.host_input.setText("dns.mihomo.test")
        with mock.patch.object(gui.mihomo_doh, "generate_certificates") as generate:
            window.surfshark_radio.setChecked(True)
            window.out_edit.setText(str(Path(self.directory.name) / "surfshark"))
            window.warp_radio.setChecked(True)
            window.pia_radio.setChecked(True)
            self.assertEqual(panel.output.text(), self.directory.name)
            generate.assert_not_called()

        files = gui.mihomo_doh.CertificateFiles(
            Path(self.directory.name) / "certs" / "root-ca.crt",
            Path(self.directory.name) / "certs" / "mihomo-localhost.crt",
            Path(self.directory.name) / "certs" / "mihomo-localhost.key",
            True,
        )
        with mock.patch.object(gui.mihomo_doh, "generate_certificates", return_value=files) as generate:
            window.tabs.setCurrentWidget(panel)
            panel.generate()
        generate.assert_called_once_with(Path(self.directory.name), "dns.mihomo.test")
        self.assertTrue(panel.trust_button.isEnabled())
        self.assertIn("external-doh-server: /dns-query", panel.snippet.toPlainText())
        self.assertEqual(self.settings.value("doh/cert_root"), self.directory.name)
        self.assertEqual(self.settings.value("doh/host"), "dns.mihomo.test")
        self.assertEqual(window.tabs.currentWidget(), panel)

        panel.host_input.setText("127.0.0.1")
        self.assertFalse(panel.copy_button.isEnabled())
        self.assertFalse(panel.trust_button.isEnabled())
        self.assertEqual(panel.hosts_input.text(), "")




if __name__ == "__main__":
    unittest.main()
