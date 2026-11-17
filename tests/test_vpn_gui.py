"""Regression tests for the ttkbootstrap frontend and headless Windows entry points."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
GUI = ROOT / "tools" / "vpn-generator-gui.py"
spec = importlib.util.spec_from_file_location("vpn_generator_gui_ttk", GUI)
assert spec and spec.loader
gui = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gui
spec.loader.exec_module(gui)


def options(**kwargs):
    data = {
        "provider": "pia", "openvpn": False, "wireguard": True,
        "udp_zip": "", "tcp_zip": "", "username": "user", "password": "password",
        "out_dir": r"P:\Clash", "single_file": False, "exclude_streaming": True,
    }
    data.update(kwargs)
    return data


class DarkThemeHelpersTests(unittest.TestCase):
    def test_win32_colorref_channels(self):
        self.assertEqual(gui.colorref("#123456"), 0x563412)
        self.assertEqual(gui.colorref("#FFFFFF"), 0xFFFFFF)
        with self.assertRaises(ValueError):
            gui.colorref("not-a-color")

    def test_non_windows_dark_titlebar_is_safe(self):
        if sys.platform == "win32":
            self.skipTest("Only meaningful off Windows")
        self.assertFalse(gui.set_dark_titlebar(None, None))


class ButtonContrastTests(unittest.TestCase):
    @staticmethod
    def contrast(foreground, background):
        def lightness(color):
            rgb = [int(color[i:i + 2], 16) / 255.0 for i in (1, 3, 5)]
            linear = [v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4 for v in rgb]
            return sum(v * weight for v, weight in zip(linear, (.2126, .7152, .0722)))
        a, b = sorted((lightness(foreground), lightness(background)), reverse=True)
        return (a + .05) / (b + .05)

    def test_high_resolution_rounded_surfaces_are_not_flat_bitmaps(self):
        from PIL import Image
        for variant, (base, _hover, _pressed) in gui.BUTTON_PALETTE.items():
            with self.subTest(variant=variant):
                image = gui.render_button_surface(
                    base, gui.BUTTON_BORDERS[variant],
                    size=(112, 44), radius=17)
                self.assertIsInstance(image, Image.Image)
                self.assertEqual(image.size, (112, 44))
                self.assertEqual(image.getpixel((0, 0))[3], 0)
                self.assertEqual(image.getpixel((111, 0))[3], 0)
                self.assertEqual(image.getpixel((56, 20))[3], 255)
                self.assertNotEqual(image.getpixel((56, 8)), image.getpixel((56, 32)))
                # Antialiased edge: intermediate alpha values prove supersampling.
                alphas = image.getchannel("A").getdata()
                self.assertTrue(any(0 < alpha < 255 for alpha in alphas))

    def test_surface_geometry_validation(self):
        with self.assertRaises(ValueError):
            gui.render_button_surface("#355D86", "#6583A1",
                                      size=(20, 18), radius=17)

    def test_white_label_contrast_at_normal_and_hover_is_wcag_aa(self):
        for variant, (base, hover, pressed) in gui.BUTTON_PALETTE.items():
            with self.subTest(variant=variant):
                for color in (base, hover, pressed):
                    self.assertGreaterEqual(
                        self.contrast(gui.BUTTON_FOREGROUND, color), 4.5)


class ConfigAndValidationTests(unittest.TestCase):
    def test_no_qsettings_migration(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "new.json"
            self.assertEqual(gui.load_settings(path), {})
            data = {"provider": "warp", "providers": {"warp": {"out_dir": r"P:\Clash"}}}
            gui.save_settings(data, path)
            self.assertEqual(gui.load_settings(path), data)
            self.assertNotIn("password", path.read_text(encoding="utf-8"))

    def test_corrupt_settings_safe(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.json"
            path.write_text("[broken", encoding="utf-8")
            self.assertEqual(gui.load_settings(path), {})
            path.write_text("[]", encoding="utf-8")
            self.assertEqual(gui.load_settings(path), {})

    def test_warp_requires_no_pia_credentials_or_zips(self):
        self.assertEqual(gui.validate_generation(options(
            provider="warp", openvpn=True, wireguard=False, username="", password="")), [])

    def test_no_unsupported_surfshark_wireguard(self):
        self.assertIn("至少選擇", "".join(gui.validate_generation(options(
            provider="surfshark", openvpn=False, wireguard=True))))

    def test_pia_wireguard_requires_credentials(self):
        self.assertIn("帳號", "".join(gui.validate_generation(options(
            username="", password=""))))

    def test_missing_openvpn_bundles_rejected(self):
        errors = gui.validate_generation(options(openvpn=True, username="u"))
        self.assertGreaterEqual(sum("ZIP" in error for error in errors), 2)

    def test_unknown_provider_rejected(self):
        self.assertTrue(gui.validate_generation(options(provider="invalid")))


class ProviderDispatchTests(unittest.TestCase):
    def test_pia_openvpn_and_wireguard_order_and_parameters(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_ov = SimpleNamespace(generate_openvpn=mock.Mock())
            fake_wg = SimpleNamespace(generate_wireguard=mock.Mock())
            calls = []
            def load(name, module):
                calls.append(name)
                return fake_ov if "openvpn" in name else fake_wg
            with mock.patch.object(gui.core, "load_sibling", side_effect=load):
                gui.generate_provider(options(
                    out_dir=tmp, openvpn=True, wireguard=True,
                    udp_zip="udp.zip", tcp_zip="tcp.zip", single_file=True,
                    exclude_streaming=False))
            self.assertEqual(calls, ["pia-openvpn-generator.py", "pia-wireguard-generator.py"])
            self.assertEqual(fake_ov.generate_openvpn.call_args.kwargs["tcp_zip"], Path("tcp.zip"))
            self.assertFalse(fake_wg.generate_wireguard.call_args.kwargs["exclude_streaming"])

    def test_surfshark_uses_own_filter_and_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = SimpleNamespace(generate_openvpn=mock.Mock())
            with mock.patch.object(gui.core, "load_sibling", return_value=fake) as loader:
                gui.generate_provider(options(
                    provider="surfshark", out_dir=tmp, openvpn=True, wireguard=False,
                    udp_zip="surfshark.zip", exclude_streaming=False))
            loader.assert_called_once_with("surfshark-openvpn-generator.py",
                                           "surfshark_openvpn_generator_gui")
            self.assertEqual(fake.generate_openvpn.call_args.kwargs["bundle_zip"],
                             Path("surfshark.zip"))
            self.assertFalse(fake.generate_openvpn.call_args.kwargs["exclude_streaming"])

    def test_warp_generates_existing_provider_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = SimpleNamespace(generate_warp=mock.Mock(
                return_value=Path(tmp) / "providers" / "warp.yaml"))
            with mock.patch.object(gui.core, "load_sibling", return_value=fake):
                gui.generate_provider(options(provider="warp", out_dir=tmp,
                                              openvpn=False, wireguard=True))
            fake.generate_warp.assert_called_once_with(out_dir=Path(tmp))

    def test_surfshark_wireguard_still_unsupported(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "尚未實作"):
                gui.generate_provider(options(provider="surfshark", out_dir=tmp,
                                              openvpn=False, wireguard=True))


class ScheduledWarpTests(unittest.TestCase):
    def test_task_name_and_invocation_remain_stable(self):
        self.assertEqual(gui.TASK_NAME, "Clash WARP Refresh")
        self.assertIn("'--warp --out-dir \"' + $outDir + '\"'", gui.warp_schedule._SCRIPT)
        self.assertIn("RegisterTaskDefinition($name, $definition, 6", gui.warp_schedule._SCRIPT)
        self.assertEqual(gui.warp_schedule.MODES, {"monthly", "daily", "interval"})

    def test_headless_warp_same_cli_and_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            fake = SimpleNamespace(generate_warp=mock.Mock(
                return_value=out_dir / "providers" / "warp.yaml"))
            with mock.patch.object(gui.core, "load_sibling", return_value=fake):
                code = gui.run_warp_cli(["--warp", "--out-dir", str(out_dir)])
            self.assertEqual(code, 0)
            fake.generate_warp.assert_called_once_with(out_dir=out_dir, timeout=15.0)
            self.assertIn("[OK]", (out_dir / "logs" / "warp-generator.log").read_text(encoding="utf-8"))

    def test_headless_warp_returns_error_when_upstream_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = SimpleNamespace(generate_warp=mock.Mock(side_effect=RuntimeError("network")))
            with mock.patch.object(gui.core, "load_sibling", return_value=fake):
                self.assertEqual(gui.run_warp_cli(["--warp", "--out-dir", tmp]), 1)
            self.assertIn("network", (Path(tmp) / "logs" / "warp-generator.log").read_text(encoding="utf-8"))

    def test_main_handles_cli_before_gui(self):
        with mock.patch.object(gui.sys, "argv", ["VPN-Mihomo-Generator.exe", "--warp",
                                               "--out-dir", r"P:\Clash"]):
            with mock.patch.object(gui, "run_warp_cli", return_value=0) as cli:
                with mock.patch.object(gui, "MainWindow", side_effect=AssertionError("GUI started")):
                    self.assertEqual(gui.main(), 0)
        cli.assert_called_once_with(["--warp", "--out-dir", r"P:\Clash"])

    def test_safe_paths_elevation_cli_remains(self):
        with mock.patch.object(gui.sys, "argv",
                               ["VPN-Mihomo-Generator.exe", "--safe-paths-append", r"P:\Clash\providers"]):
            with mock.patch.object(gui.safe_paths, "append_machine_safe_path") as append:
                self.assertEqual(gui.main(), 0)
            append.assert_called_once_with(r"P:\Clash\providers")


@unittest.skipUnless(sys.platform == "win32", "Tk GUI smoke checks run on Windows")
class WindowsGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.patch = mock.patch.object(gui, "settings_path", return_value=Path(cls.temp.name) / "gui.json")
        cls.patch.start()
        cls.window = gui.MainWindow()
        cls.window.withdraw()
        cls.window.update_idletasks()

    @classmethod
    def tearDownClass(cls):
        cls.window._closing = True
        cls.window.destroy()
        cls.patch.stop()
        cls.temp.cleanup()

    def test_native_text_panes_use_dark_palette_and_ttk_scrollbars(self):
        colors = self.window.style.colors
        for widget in (self.window.log, self.window.doh_yaml):
            self.assertIsInstance(widget, gui.DarkScrolledText)
            self.assertEqual(widget.text.cget("background").lower(), colors.inputbg.lower())
            self.assertEqual(widget.text.cget("foreground").lower(), colors.inputfg.lower())
            self.assertEqual(widget.text.cget("insertbackground").lower(), colors.inputfg.lower())
            self.assertEqual(widget.scrollbar.winfo_class(), "TScrollbar")
        self.assertEqual(self.window.cget("background").lower(), colors.bg.lower())

    def test_button_assets_scale_to_display_and_keep_state_images_alive(self):
        cache = self.window.style._reg_button_assets
        expected_size = tuple(gui.ttk.scale_size(self.window, value)
                              for value in (112, 44))
        self.assertEqual(set(cache), set(gui.BUTTON_PALETTE))
        for variant, assets in cache.items():
            with self.subTest(variant=variant):
                self.assertEqual(assets["images"]["normal"].size, expected_size)
                self.assertEqual(set(assets["photos"]),
                                 {"normal", "hover", "pressed", "focus", "disabled"})
                self.assertNotEqual(assets["images"]["normal"].tobytes(),
                                    assets["images"]["hover"].tobytes())
                self.assertNotEqual(assets["images"]["focus"].tobytes(),
                                    assets["images"]["normal"].tobytes())
                for image in assets["photos"].values():
                    self.assertTrue(self.window.tk.call("image", "type", str(image)))

    def test_actions_use_rounded_muted_styles(self):
        style = self.window.style
        for variant, name in gui.BUTTON_STYLES.items():
            with self.subTest(variant=variant):
                self.assertTrue(style.layout(name))
                self.assertIn(name + ".background", str(style.layout(name)))
        self.assertEqual(self.window.run_button.cget("style"), gui.BUTTON_STYLES["primary"])
        self.assertEqual(self.window.warp_button.cget("style"), gui.BUTTON_STYLES["secondary"])
        self.assertEqual(self.window.trust_button.cget("style"), gui.BUTTON_STYLES["secondary"])

    def test_alert_body_titlebar_and_confirmation_are_dark(self):
        self.window.deiconify()
        self.window.update()
        colors = self.window.style.colors
        try:
            # A closed / cancelled warning is not affirmative.
            dialog = gui.DarkAlertDialog(
                self.window, title="排程確認", message="要移除現有排程嗎？",
                kind="question", confirm=True)
            self.assertEqual(dialog.cget("background").lower(), colors.bg.lower())
            self.assertEqual(dialog.ok_button.cget("style"), gui.BUTTON_STYLES["primary"])
            self.assertEqual(dialog.cancel_button.cget("style"), gui.BUTTON_STYLES["secondary"])
            self.assertTrue(gui.set_dark_titlebar(dialog, colors))
            self.assertTrue(dialog.grab_current() == dialog)
            dialog.after(20, lambda: dialog._finish(False))
            self.assertFalse(dialog.show())

            # Clicking Yes is a genuine bool, not the string "Yes"/"No".
            dialog = gui.DarkAlertDialog(
                self.window, title="CA 信任", message="確定嗎？",
                kind="question", confirm=True)
            dialog.after(20, lambda: dialog._finish(True))
            self.assertIs(dialog.show(), True)
        finally:
            self.window.withdraw()

    def test_three_tabs_and_function_buttons_exist(self):
        self.assertEqual(len(self.window.tabs.tabs()), 3)
        self.assertTrue(self.window.uwp_backup.winfo_exists())
        self.assertTrue(self.window.trust_button.winfo_exists())
        self.assertTrue(self.window.warp_button.winfo_exists())

    def test_provider_session_credentials_remain_separate(self):
        self.window.provider.set("pia")
        self.window.username.set("pia-user")
        self.window.password.set("secret")
        self.window.provider.set("warp")
        self.window.provider.set("pia")
        self.assertEqual(self.window.username.get(), "pia-user")
        self.assertEqual(self.window.password.get(), "secret")
        self.window._save()
        self.assertNotIn("secret", Path(self.temp.name, "gui.json").read_text(encoding="utf-8"))

    def test_warp_forces_wireguard_and_disables_openvpn(self):
        self.window.provider.set("warp")
        self.assertFalse(self.window.openvpn.get())
        self.assertTrue(self.window.wireguard.get())
        self.assertEqual(str(self.window.ov_check.cget("state")), "disabled")

    def test_doh_panel_is_provider_independent(self):
        self.window.provider.set("surfshark")
        self.assertTrue(self.window.doh_endpoint.get())
        self.window.provider.set("warp")
        self.assertTrue(self.window.doh_endpoint.get())

    def test_schedule_shows_exact_original_two_frequency_choices(self):
        dlg = gui.WarpScheduleDialog(self.window, r"P:\Clash", {})
        try:
            values = tuple(dlg.frequency_combo["values"])
            self.assertEqual(values, (
                "每月 5、10、15、20、25、30 日（預設）",
                "每 N 天",
            ))
            self.assertEqual(dlg.mode.get(), "monthly")
            self.assertFalse(bool(dlg.interval_spinbox.grid_info()))
            dlg.frequency_label.set("每 N 天")
            dlg._frequency_selected()
            self.assertEqual(dlg.mode.get(), "interval")
            self.assertTrue(bool(dlg.interval_spinbox.grid_info()))
            dlg.mode.set("monthly")
            self.assertFalse(bool(dlg.interval_spinbox.grid_info()))
            self.assertNotIn("daily", values)
        finally:
            dlg.destroy()

    def test_windows_dwm_sets_outer_caption_and_recomposes(self):
        import ctypes
        from ctypes import wintypes

        self.window.deiconify()
        try:
            self.window.update()
            inner = self.window.winfo_id()
            frame = str(self.window.wm_frame())
            outer = int(frame, 16) if frame.lower().startswith("0x") else int(frame)
            self.assertNotEqual(inner, outer, "Expected the decorated Tk wrapper HWND")
            self.assertTrue(
                gui.set_dark_titlebar(self.window, self.window.style.colors),
                "DWM refused to set the color on Tk's outer HWND")
            gui.show_with_dark_titlebar(self.window, self.window.style.colors)
            self.window.update()
            self.assertTrue(self.window.winfo_ismapped())

            # Screenshot is a diagnostic of the *rendered* caption, unlike
            # DwmGetWindowAttribute(35), which returns E_INVALIDARG for a
            # successfully written caption color.
            from PIL import ImageGrab
            user32 = ctypes.WinDLL("user32")
            class Rect(ctypes.Structure):
                _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                            ("right", ctypes.c_long), ("bottom", ctypes.c_long)]
            rect = Rect()
            user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(Rect)]
            user32.GetWindowRect.restype = wintypes.BOOL
            self.assertTrue(user32.GetWindowRect(outer, ctypes.byref(rect)))
            center_x = (rect.left + rect.right) // 2
            if rect.top < 0:
                self.skipTest("Window titlebar outside capture area")
            box = (center_x - 32, rect.top + 10, center_x + 32, rect.top + 26)
            try:
                image = ImageGrab.grab(bbox=box).convert("RGB")
                rgb = image.getpixel((image.width // 2, image.height // 2))
                print(f"WINDOW_TITLEBAR_CAPTURE outer={outer:#x} rect={tuple((rect.left, rect.top, rect.right, rect.bottom))} center_rgb={rgb} expected={self.window.style.colors.bg}", flush=True)
                expected = self.window.style.colors.bg.lstrip("#")
                expected_rgb = tuple(int(expected[i:i+2], 16) for i in (0, 2, 4))
                self.assertTrue(
                    all(abs(actual - desired) <= 24 for actual, desired in zip(rgb, expected_rgb)),
                    f"Windows titlebar rendered {rgb}, expected near {expected_rgb}",
                )
            except OSError as exc:
                print(f"WINDOW_TITLEBAR_CAPTURE unavailable: {exc}", flush=True)
        finally:
            self.window.withdraw()

    def test_schedule_dialog_uses_same_task_and_updates(self):
        dlg = gui.WarpScheduleDialog(self.window, r"P:\Clash", {})
        dlg.mode.set("interval")
        dlg.interval.set("7")
        dlg.clock.set("03:20")
        with mock.patch.object(gui.warp_schedule, "configure_schedule", return_value="Installed") as run:
            with mock.patch.object(gui.messagebox, "showinfo"):
                dlg.install()
        run.assert_called_once_with(action="install", out_dir=Path(r"P:\Clash"),
                                    mode="interval", interval_days=7, time="03:20")
        dlg.destroy()


if __name__ == "__main__":
    unittest.main()
