#!/usr/bin/env python3
"""Windows VPN/Mihomo utilities with a CustomTkinter 6 GUI.

The command-line entry points run before a Tk root is created.  In particular,
Windows Task Scheduler uses this same executable with --warp.
"""
from __future__ import annotations

import contextlib
import json
import os
import queue
import sys
import threading
import traceback
import tkinter as tk
from tkinter import filedialog
from pathlib import Path

import customtkinter as ctk

import vpn_generator_core as core
import warp_schedule
import mihomo_doh
import safe_paths
import uwp_firewall

APP_NAME = "VPN-Mihomo-Generator"
TASK_NAME = warp_schedule.TASK_NAME
PROVIDERS = ("pia", "surfshark", "warp")


def settings_path() -> Path:
    base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    return base / "reg-chen" / APP_NAME / "settings.json"


def load_settings(path: Path | None = None) -> dict:
    """The new JSON store intentionally does not migrate Qt QSettings."""
    path = path or settings_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(data: dict, path: Path | None = None) -> None:
    path = path or settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def default_cert_root() -> str:
    return str(Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
               / "mihomo-party" / "work")


def validate_generation(options: dict) -> list[str]:
    errors: list[str] = []
    provider = options["provider"]
    ov, wg = bool(options["openvpn"]), bool(options["wireguard"])
    if provider not in PROVIDERS:
        return ["未知 VPN 供應商。"]
    if provider == "warp":
        ov, wg = False, True
    elif provider == "surfshark":
        wg = False
    if not ov and not wg:
        errors.append("請至少選擇一個目前支援的協定。")
    if ov:
        udp = Path(options.get("udp_zip") or "")
        if not udp.is_file() or udp.suffix.lower() != ".zip":
            errors.append("請選擇有效的 OpenVPN ZIP。")
        if provider == "pia":
            tcp = Path(options.get("tcp_zip") or "")
            if not tcp.is_file() or tcp.suffix.lower() != ".zip":
                errors.append("請選擇有效的 OpenVPN TCP ZIP。")
    if (provider == "pia" and wg) or (provider == "surfshark" and ov):
        if not options.get("username", "").strip() or not options.get("password", ""):
            errors.append("請輸入 VPN 帳號與密碼。")
    if not options.get("out_dir", "").strip():
        errors.append("請選擇輸出目錄。")
    return errors


def generate_provider(options: dict) -> Path:
    """Keep provider behavior independent of the GUI toolkit."""
    provider = options["provider"]
    out_dir = Path(options["out_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    single = bool(options["single_file"])
    exclude = bool(options["exclude_streaming"])
    username = options["username"]
    password = options["password"]
    if provider == "pia":
        if options["openvpn"]:
            ov = core.load_sibling("pia-openvpn-generator.py", "pia_openvpn_generator_gui")
            ov.generate_openvpn(
                udp_zip=Path(options["udp_zip"]), tcp_zip=Path(options["tcp_zip"]),
                username=username, password=password, out_dir=out_dir,
                single_file=single, exclude_streaming=exclude,
            )
            print("[OK] PIA OpenVPN 完成。")
        if options["wireguard"]:
            wg = core.load_sibling("pia-wireguard-generator.py", "pia_wireguard_generator_gui")
            wg.generate_wireguard(
                username=username, password=password, out_dir=out_dir,
                single_file=single, exclude_streaming=exclude,
            )
            print("[OK] PIA WireGuard 完成。")
    elif provider == "surfshark":
        if options["wireguard"]:
            raise RuntimeError("Surfshark WireGuard generator 尚未實作。")
        ov = core.load_sibling("surfshark-openvpn-generator.py", "surfshark_openvpn_generator_gui")
        ov.generate_openvpn(
            bundle_zip=Path(options["udp_zip"]), username=username, password=password,
            out_dir=out_dir, single_file=single, exclude_streaming=exclude,
        )
        print("[OK] Surfshark OpenVPN 完成。")
    elif provider == "warp":
        wg = core.load_sibling("warp-wireguard-generator.py", "warp_wireguard_generator_gui")
        target = wg.generate_warp(out_dir=out_dir)
        print(f"[OK] Cloudflare WARP 完成：{target}")
    else:
        raise ValueError(f"未知 provider：{provider}")
    return out_dir


class LogStream:
    def __init__(self, notify):
        self.notify = notify
        self.buffer = ""

    def write(self, value):
        self.buffer += value or ""
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            if line:
                self.notify(line)
        return len(value or "")

    def flush(self):
        if self.buffer:
            self.notify(self.buffer)
            self.buffer = ""


def colorref(value: str) -> int:
    """Convert a theme #RRGGBB color into a Windows COLORREF (0x00BBGGRR)."""
    color = value.lstrip("#")
    if len(color) != 6 or any(character not in "0123456789abcdefABCDEF" for character in color):
        raise ValueError("Expected six-digit RGB color")
    return int(color[4:6] + color[2:4] + color[:2], 16)


def set_dark_titlebar(window: tk.Misc, colors) -> bool:
    """Apply DWM colors to Tk's decorated outer Win32 window."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        window.update_idletasks()
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        user32.GetParent.argtypes = [wintypes.HWND]
        user32.GetParent.restype = wintypes.HWND
        user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.GetWindowLongW.restype = ctypes.c_long
        user32.SetWindowPos.argtypes = [
            wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, ctypes.c_int, wintypes.UINT,
        ]
        user32.SetWindowPos.restype = wintypes.BOOL
        dwmapi.DwmSetWindowAttribute.argtypes = [
            wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ]
        dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long
        # Python/Tk exposes the native top-level frame directly.  The earlier
        # implementation used GetParent(winfo_id) before the frame was mapped.
        frame = str(window.wm_frame()).strip()
        outer = int(frame, 16) if frame.lower().startswith("0x") else int(frame) if frame else 0
        child = window.winfo_id()
        candidates = (outer, user32.GetParent(child))
        target = colorref(colors.bg)
        for hwnd in dict.fromkeys(int(v) for v in candidates if v):
            # WS_CAPTION identifies the window that actually draws the titlebar.
            if not (user32.GetWindowLongW(hwnd, -16) & 0x00C00000):
                continue

            def set_attr(attribute: int, value: int) -> bool:
                data = ctypes.c_uint32(value)
                return dwmapi.DwmSetWindowAttribute(
                    hwnd, attribute, ctypes.byref(data), ctypes.sizeof(data)) == 0

            if not set_attr(20, 1):
                set_attr(19, 1)  # legacy immersive dark mode attribute
            if not set_attr(35, target):
                continue
            set_attr(34, colorref(colors.border))
            set_attr(36, colorref(colors.fg))
            # Caption color is a set-only DWM attribute: requesting it with
            # DwmGetWindowAttribute returns E_INVALIDARG even after a
            # successful DwmSetWindowAttribute call (confirmed on Win CI).
            # SWP_FRAMECHANGED | NOACTIVATE | NOZORDER | NOMOVE | NOSIZE
            user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x0037)
            return True
        return False
    except (AttributeError, OSError, ValueError, tk.TclError):
        return False


def show_with_dark_titlebar(window: tk.Misc, colors) -> None:
    """Force DWM to repaint after mapping a Tk top-level window."""
    if sys.platform != "win32" or not window.winfo_exists():
        return
    window.update_idletasks()
    if not window.winfo_ismapped():
        window.deiconify()
        window.update_idletasks()
    if set_dark_titlebar(window, colors):
        # Tk draws its original light frame on first map. Recomposition is
        # necessary even if DwmSetWindowAttribute returned S_OK.
        window.withdraw()
        window.deiconify()
        window.after(80, lambda: set_dark_titlebar(window, colors)
                     if window.winfo_exists() else None)


BG = "#1E222A"
PANEL = "#252B35"
INPUT = "#2B333E"
BORDER = "#3A4655"
TEXT = "#EBF0F7"
MUTED = "#AAB6C6"
ACCENT = "#47749C"
UI_COLORS = type("Colors", (), {"bg": BG, "fg": TEXT, "border": BORDER})()
BUTTON_PALETTE = {
    "primary": ("#355D86", "#416F98", "#294966"),
    "secondary": ("#334252", "#415368", "#293544"),
    "danger": ("#704650", "#80545F", "#523841"),
}
BUTTON_FOREGROUND = TEXT


def ui_frame(parent, *, padding=0, panel=False):
    return ctk.CTkFrame(parent, width=1, height=1, corner_radius=8 if panel else 0,
                        fg_color=PANEL if panel else "transparent",
                        border_color=BORDER if panel else PANEL,
                        border_width=1 if panel else 0)


def ui_group(parent, *, text: str, padding=0):
    card = ctk.CTkFrame(parent, width=1, height=1, corner_radius=8,
                        fg_color=PANEL, border_color=BORDER, border_width=1)
    ctk.CTkLabel(card, text=text, text_color=MUTED,
                 font=("Segoe UI", 11, "bold"),
                 fg_color="transparent", height=23).place(x=11, y=3)
    return card


def ui_label(parent, *, width=None, foreground=None, **kwargs):
    if width is not None:
        kwargs["width"] = max(1, int(width) * 8)
    kwargs.setdefault("height", 25)
    kwargs.setdefault("anchor", "w")
    kwargs.setdefault("text_color", foreground or TEXT)
    kwargs.setdefault("fg_color", "transparent")
    return ctk.CTkLabel(parent, **kwargs)


def ui_entry(parent, *, width=None, state="normal", **kwargs):
    kwargs["width"] = max(70, int(width) * 8) if width is not None else 160
    if kwargs.get("show") == "":
        kwargs.pop("show")
    return ctk.CTkEntry(
        parent, height=30, corner_radius=6,
        border_width=1, fg_color=INPUT, border_color=BORDER,
        text_color=TEXT, state="disabled" if state == "readonly" else state,
        **kwargs)


def ui_radio(parent, **kwargs):
    return ctk.CTkRadioButton(parent, width=1, height=26,
                              radiobutton_width=18, radiobutton_height=18,
                              border_width_unchecked=2, border_width_checked=5,
                              fg_color=ACCENT, hover_color="#527EA4",
                              border_color="#647386", text_color=TEXT,
                              font=("Segoe UI", 12), **kwargs)


def ui_check(parent, **kwargs):
    return ctk.CTkCheckBox(parent, width=1, height=26,
                           checkbox_width=18, checkbox_height=18,
                           corner_radius=4, border_width=1,
                           fg_color=ACCENT, hover_color="#527EA4",
                           border_color="#647386", checkmark_color=TEXT,
                           text_color=TEXT, font=("Segoe UI", 12), **kwargs)


def styled_button(parent, *, variant: str = "secondary", **kwargs):
    """CTk native rounded canvas: 7px corner on a 30px-high button."""
    fill, hover, _pressed = BUTTON_PALETTE[variant]
    label_text = kwargs.pop("text", "")
    old_width = kwargs.pop("width", None)
    import unicodedata
    estimated = sum(14 if unicodedata.east_asian_width(ch) in ("F", "W") else 7
                    for ch in str(label_text))
    width = max(30 if label_text == "?" else 64, estimated + 24)
    if old_width is not None:
        width = max(width, int(old_width) * 8)
    return ctk.CTkButton(
        parent, text=label_text, width=width, height=30,
        corner_radius=7, border_width=1,
        border_color=BORDER, bg_color="transparent",
        fg_color=fill, hover_color=hover,
        text_color=BUTTON_FOREGROUND, text_color_disabled="#A4AEBA",
        font=("Segoe UI", 12), **kwargs)


class DarkScrolledText(ctk.CTkTextbox):
    """Native CTk scrollable textbox; height argument is legacy line units."""

    def __init__(self, parent, *, height: int, font, wrap: str, state: str):
        super().__init__(
            parent, width=1, height=max(105, height * 20),
            corner_radius=7, border_width=1,
            border_color=BORDER, fg_color=INPUT,
            text_color=TEXT, scrollbar_button_color="#617183",
            scrollbar_button_hover_color="#8394A7",
            font=font, wrap=wrap, state=state)


class DarkAlertDialog(ctk.CTkToplevel):
    """CustomTkinter dark modal with safe Yes/No semantics."""

    def __init__(self, parent, *, title: str, message: str,
                 kind: str = "info", confirm: bool = False):
        super().__init__(parent)
        self.withdraw()
        self.title(title)
        self.transient(parent)
        self.resizable(False, False)
        self.result = False
        self.confirm = confirm
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", lambda: self._finish(False))
        self.bind("<Escape>", lambda _event: self._finish(False))
        self.bind("<Return>", lambda _event: self._finish(True))
        content = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=18, pady=16)
        content.grid_columnconfigure(1, weight=1)
        symbol, color = {
            "info": ("i", "#82B3DF"),
            "warning": ("!", "#C8A66E"),
            "error": ("!", "#CC8C91"),
            "question": ("?", "#82B3DF"),
        }.get(kind, ("i", "#82B3DF"))
        ctk.CTkLabel(content, text=symbol, text_color=color,
                     width=28, height=30, font=("Segoe UI", 20, "bold")).grid(
            row=0, column=0, sticky="n", padx=(0, 12))
        self.message_label = ctk.CTkLabel(
            content, text=message, text_color=TEXT, justify="left",
            wraplength=465, anchor="w", height=30)
        self.message_label.grid(row=0, column=1, sticky="ew", pady=(0, 16))
        actions = ctk.CTkFrame(content, fg_color="transparent", corner_radius=0)
        actions.grid(row=1, column=0, columnspan=2, sticky="e")
        if confirm:
            self.cancel_button = styled_button(
                actions, text="取消", variant="secondary",
                command=lambda: self._finish(False))
            self.cancel_button.pack(side="left", padx=(0, 8))
        self.ok_button = styled_button(
            actions, text="確定", variant="primary",
            command=lambda: self._finish(True))
        self.ok_button.pack(side="left")
        self.update_idletasks()
        # CTkToplevel starts at 200x200 regardless of the form's children.
        # Size explicitly from the wrapped message; keep it readable.
        width = 540
        height = max(168, min(520, self.message_label.winfo_reqheight() + 120))
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - width) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.deiconify()
        self.after(80, lambda: set_dark_titlebar(self, UI_COLORS)
                   if self.winfo_exists() else None)
        self._previous_grab = parent.grab_current()
        self.grab_set()
        self.ok_button.focus_set()

    def _finish(self, result: bool):
        self.result = bool(result)
        try:
            self.grab_release()
            if self._previous_grab is not None and self._previous_grab.winfo_exists():
                self._previous_grab.grab_set()
        finally:
            self.destroy()

    def show(self) -> bool:
        self.wait_window(self)
        return self.result


class ThemedMessagebox:
    """Keep tkinter.messagebox argument semantics and boolean confirmations."""

    @staticmethod
    def _show(title: str, message: str, *, parent, kind: str, confirm=False):
        if parent is None:
            raise ValueError("Dark message boxes require an explicit parent")
        return DarkAlertDialog(
            parent, title=title, message=message, kind=kind, confirm=confirm
        ).show()

    @staticmethod
    def showinfo(title, message, *, parent=None):
        return ThemedMessagebox._show(title, message, parent=parent, kind="info")

    @staticmethod
    def showwarning(title, message, *, parent=None):
        return ThemedMessagebox._show(title, message, parent=parent, kind="warning")

    @staticmethod
    def showerror(title, message, *, parent=None):
        return ThemedMessagebox._show(title, message, parent=parent, kind="error")

    @staticmethod
    def askyesno(title, message, *, parent=None):
        return ThemedMessagebox._show(title, message, parent=parent,
                                     kind="question", confirm=True)


# All existing calls stay compatible; confirm/close still yields bool.
messagebox = ThemedMessagebox


class WarpScheduleDialog(ctk.CTkToplevel):
    """Restore the original two-option WARP schedule interface."""

    FREQUENCIES = {
        "每月 5、10、15、20、25、30 日（預設）": "monthly",
        "每 N 天": "interval",
    }

    def __init__(self, parent, out_dir: str, config: dict):
        super().__init__(parent)
        self.title("WARP 工作排程")
        self.configure(fg_color=BG)
        self.transient(parent)
        self.resizable(False, False)
        # CTkToplevel defaults to a fixed 200x200 geometry; set an explicit
        # dialog size so the original frequency selector is not clipped.
        self.geometry("570x330")
        self.minsize(570, 330)
        self.out = tk.StringVar(value=out_dir or r"P:\Clash")
        selected = config.get("mode", "monthly")
        if selected not in ("monthly", "interval"):
            selected = "monthly"
        self.mode = tk.StringVar(value=selected)
        self.frequency_label = tk.StringVar(
            value=next(label for label, mode in self.FREQUENCIES.items() if mode == selected))
        self.interval = tk.StringVar(value=str(config.get("interval", 5)))
        self.clock = tk.StringVar(value=config.get("time", "03:00"))
        self.config_data = config

        frm = ui_frame(self, padding=16)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)
        ui_label(frm, text="由 Windows 工作排程執行 WARP 更新，不需要開啟 GUI。").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        ui_label(frm, text="執行頻率").grid(row=1, column=0, sticky="w", pady=6)
        self.frequency_combo = ctk.CTkComboBox(
            frm, variable=self.frequency_label, state="readonly",
            values=list(self.FREQUENCIES), command=self._frequency_selected,
            width=300, height=30, corner_radius=6,
            fg_color=INPUT, border_color=BORDER,
            button_color="#3E5064", button_hover_color="#506781",
            dropdown_fg_color=PANEL, dropdown_hover_color="#405470",
            text_color=TEXT)
        self.frequency_combo.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(12, 0))

        self.interval_label = ui_label(frm, text="間隔天數 N")
        self.interval_label.grid(row=2, column=0, sticky="w", pady=6)
        self.interval_spinbox = ui_entry(frm, textvariable=self.interval, width=8)
        self.interval_spinbox.grid(row=2, column=1, sticky="w", padx=(12, 0), pady=6)
        self.interval_unit = ui_label(frm, text="天")
        self.interval_unit.grid(row=2, column=2, sticky="w", pady=6)

        ui_label(frm, text="執行時間").grid(row=3, column=0, sticky="w", pady=6)
        ui_entry(frm, textvariable=self.clock, width=12).grid(
            row=3, column=1, sticky="w", padx=(12, 0), pady=6)
        ui_label(frm, text="HH:mm").grid(row=3, column=2, sticky="w", pady=6)
        ui_label(frm, text="Mihomo 目錄").grid(row=4, column=0, sticky="w", pady=6)
        ui_entry(frm, textvariable=self.out, width=36).grid(
            row=4, column=1, columnspan=2, sticky="ew", padx=(12, 0), pady=6)
        ui_label(frm, text="注意：若使用 P: 映射磁碟，Windows 使用者必須已登入。").grid(
            row=5, column=0, columnspan=3, sticky="w", pady=(8, 14))
        actions = ui_frame(frm)
        actions.grid(row=6, column=0, columnspan=3, sticky="e")
        styled_button(actions, text="安裝／更新排程", command=self.install,
                   variant="primary").pack(side="left", padx=3)
        styled_button(actions, text="移除排程", command=self.remove,
                   variant="danger").pack(side="left", padx=3)
        styled_button(actions, text="關閉", command=self.destroy).pack(side="left", padx=3)

        self.mode.trace_add("write", self._sync_mode)
        self._update_interval_visibility()
        self.update_idletasks()
        self.deiconify()
        self.grab_set()
        self.after(90, lambda: set_dark_titlebar(self, UI_COLORS) if self.winfo_exists() else None)

    def _frequency_selected(self, _event=None):
        self.mode.set(self.FREQUENCIES[self.frequency_label.get()])

    def _sync_mode(self, *_args):
        self.frequency_label.set(next(
            label for label, mode in self.FREQUENCIES.items() if mode == self.mode.get()))
        self._update_interval_visibility()

    def _update_interval_visibility(self):
        action = "grid" if self.mode.get() == "interval" else "grid_remove"
        for widget in (self.interval_label, self.interval_spinbox, self.interval_unit):
            getattr(widget, action)()

    def install(self):
        try:
            mode = self.mode.get()
            days = int(self.interval.get()) if mode == "interval" else 5
            directory = self.out.get().strip()
            if not directory:
                raise ValueError("請設定 Mihomo 輸出目錄。")
            result = warp_schedule.configure_schedule(
                action="install", out_dir=Path(directory), mode=mode,
                interval_days=days, time=self.clock.get().strip())
            self.config_data.update({"mode": mode, "interval": days, "time": self.clock.get()})
            messagebox.showinfo("WARP 排程", f"已安裝／更新：{TASK_NAME}\n{result}", parent=self)
        except Exception as exc:
            messagebox.showerror("排程失敗", str(exc), parent=self)

    def remove(self):
        if not messagebox.askyesno("移除排程", f"確定移除 {TASK_NAME}？", parent=self):
            return
        try:
            result = warp_schedule.configure_schedule(action="remove")
            messagebox.showinfo("完成", result, parent=self)
        except Exception as exc:
            messagebox.showerror("移除失敗", str(exc), parent=self)


class MainWindow(ctk.CTk):
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        super().__init__()
        self.title("VPN / Mihomo Generator")
        self.configure(fg_color=BG)
        self.after(100, lambda: set_dark_titlebar(self, UI_COLORS))
        self.geometry("900x720")
        self.minsize(740, 580)
        self.config_data = load_settings()
        self.provider_data = self.config_data.setdefault("providers", {})
        self.schedule_data = self.config_data.setdefault("warp_schedule", {})
        self.credentials = {}  # Never persisted to disk.
        self._active_provider = self.config_data.get("provider", "pia")
        if self._active_provider not in PROVIDERS:
            self._active_provider = "pia"
        self.events = queue.Queue()
        self.running = False
        self.uwp_running = False
        self.pending_safe_path = None
        self.cert_files = None
        self._closing = False

        self.provider = tk.StringVar(value=self._active_provider)
        self.openvpn = tk.BooleanVar(value=True)
        self.wireguard = tk.BooleanVar(value=True)
        self.single_file = tk.BooleanVar(value=False)
        self.exclude_streaming = tk.BooleanVar(value=True)
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.show_password = tk.BooleanVar()
        self.udp_zip = tk.StringVar()
        self.tcp_zip = tk.StringVar()
        self.out_dir = tk.StringVar()
        self.safe_paths = tk.BooleanVar(value=False)

        self.tabs = ctk.CTkTabview(
            self, corner_radius=8, border_width=0, fg_color=PANEL,
            segmented_button_fg_color="#303947",
            segmented_button_selected_color="#355D86",
            segmented_button_selected_hover_color="#416F98",
            segmented_button_unselected_color="#303947",
            segmented_button_unselected_hover_color="#3B4858",
            text_color=TEXT,
        )
        self.tabs.pack(fill="both", expand=True, padx=12, pady=10)
        self.provider_tab = self.tabs.add("VPN Provider")
        self.doh_tab = self.tabs.add("Mihomo DNS / TLS")
        self.uwp_tab = self.tabs.add("Windows 防火牆")
        self._build_provider()
        self._build_doh()
        self._build_uwp()
        self._restore_provider(self._active_provider)
        self._refresh_provider()
        self.provider.trace_add("write", lambda *_: self._change_provider())
        self.openvpn.trace_add("write", lambda *_: self._refresh_protocols())
        self.show_password.trace_add("write", lambda *_: self.password_entry.configure(
            show="" if self.show_password.get() else "●"))
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(100, self._pump)

    @staticmethod
    def _row(frame, index, title, variable, *, browse=None, secret=False):
        ui_label(frame, text=title, width=21, anchor="w").grid(
            row=index, column=0, sticky="w", pady=5)
        container = ui_frame(frame)
        container.grid(row=index, column=1, sticky="ew", pady=5)
        entry = ui_entry(container, textvariable=variable, show="●" if secret else "")
        entry.pack(side="left", fill="x", expand=True)
        if browse:
            styled_button(container, text="瀏覽", command=browse, width=6).pack(side="left", padx=(6, 0))
        return container, entry

    def _build_provider(self):
        root = self.provider_tab
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)
        form = ui_frame(root)
        form.grid(row=0, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)
        ui_label(form, text="Provider", width=21).grid(row=0, column=0, sticky="w", pady=5)
        choices = ui_frame(form)
        choices.grid(row=0, column=1, sticky="w")
        for value, label in (("pia", "PIA"), ("surfshark", "Surfshark"), ("warp", "Cloudflare WARP")):
            ui_radio(choices, text=label, value=value, variable=self.provider).pack(
                side="left", padx=(0, 14))
        ui_label(form, text="輸出協定", width=21).grid(row=1, column=0, sticky="w", pady=5)
        protocols = ui_frame(form)
        protocols.grid(row=1, column=1, sticky="w")
        self.ov_check = ui_check(protocols, text="OpenVPN", variable=self.openvpn)
        self.ov_check.pack(side="left", padx=(0, 18))
        self.wg_check = ui_check(protocols, text="WireGuard", variable=self.wireguard)
        self.wg_check.pack(side="left")
        self.udp_row, _ = self._row(form, 2, "OpenVPN UDP ZIP", self.udp_zip,
                                    browse=lambda: self._pick_zip(self.udp_zip))
        self.tcp_row, _ = self._row(form, 3, "OpenVPN TCP ZIP", self.tcp_zip,
                                    browse=lambda: self._pick_zip(self.tcp_zip))
        self.tcp_label = form.grid_slaves(row=3, column=0)[0]
        self.udp_label = form.grid_slaves(row=2, column=0)[0]
        credential_row = ui_frame(form)
        credential_row.grid(row=4, column=1, sticky="ew", pady=5)
        credential_row.columnconfigure(0, weight=1)
        credential_row.columnconfigure(1, weight=1)
        ui_label(form, text="帳號 / 密碼", width=21).grid(row=4, column=0, sticky="w")
        self.credential_label = form.grid_slaves(row=4, column=0)[0]
        ui_entry(credential_row, textvariable=self.username).grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.password_entry = ui_entry(credential_row, textvariable=self.password, show="●")
        self.password_entry.grid(row=0, column=1, sticky="ew")
        ui_check(credential_row, text="顯示", variable=self.show_password).grid(row=0, column=2, padx=5)
        self.credential_row = credential_row
        self.output_row, _ = self._row(form, 5, "輸出目錄", self.out_dir, browse=self._pick_output)
        self.safe_check = ui_check(form, text="加入 Provider 目錄至系統 SAFE_PATHS（需管理員權限）",
                                         variable=self.safe_paths)
        self.safe_check.grid(row=6, column=1, sticky="w", pady=4)
        ui_label(form, text="輸出模式", width=21).grid(row=7, column=0, sticky="w", pady=5)
        self.mode_label = form.grid_slaves(row=7, column=0)[0]
        self.mode_row = ui_frame(form)
        self.mode_row.grid(row=7, column=1, sticky="w")
        ui_radio(self.mode_row, text="分節點檔案", variable=self.single_file, value=False).pack(side="left", padx=(0, 12))
        ui_radio(self.mode_row, text="單一檔案", variable=self.single_file, value=True).pack(side="left", padx=(0, 12))
        styled_button(self.mode_row, text="?", width=3, command=self._show_mode_help,
                   variant="secondary").pack(side="left")
        self.filter_label = ui_label(form, text="節點過濾", width=21)
        self.filter_label.grid(row=8, column=0, sticky="w", pady=5)
        self.filter_check = ui_check(form, text="排除 Streaming Optimized", variable=self.exclude_streaming)
        self.filter_check.grid(row=8, column=1, sticky="w", pady=5)
        buttons = ui_frame(root)
        buttons.grid(row=1, column=0, sticky="ew", pady=(12, 6))
        self.run_button = styled_button(buttons, text="執行", command=self._start_generation, variant="primary")
        self.run_button.pack(side="left")
        self.warp_button = styled_button(buttons, text="安裝／管理 WARP 排程",
                                      command=self._open_schedule, variant="secondary")
        self.warp_button.pack(side="left", padx=12)
        logbox = ui_group(root, text="Log", padding=6)
        logbox.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
        self.log = DarkScrolledText(logbox, height=10, state="disabled",
                                            font=("Consolas", 10), wrap="word")
        self.log.pack(fill="both", expand=True, padx=8, pady=(28, 8))

    def _restore_provider(self, provider):
        data = self.provider_data.get(provider, {})
        self.udp_zip.set(data.get("udp_zip", ""))
        self.tcp_zip.set(data.get("tcp_zip", ""))
        self.out_dir.set(data.get("out_dir", ""))
        self.openvpn.set(data.get("openvpn", provider != "warp"))
        self.wireguard.set(data.get("wireguard", provider != "surfshark"))
        self.single_file.set(data.get("single_file", False))
        self.exclude_streaming.set(data.get("exclude_streaming", True))
        username, password = self.credentials.get(provider, ("", ""))
        self.username.set(username)
        self.password.set(password)

    def _store_provider(self, provider):
        self.credentials[provider] = (self.username.get(), self.password.get())
        self.provider_data[provider] = {
            "udp_zip": self.udp_zip.get().strip(), "tcp_zip": self.tcp_zip.get().strip(),
            "out_dir": self.out_dir.get().strip(), "openvpn": self.openvpn.get(),
            "wireguard": self.wireguard.get(), "single_file": self.single_file.get(),
            "exclude_streaming": self.exclude_streaming.get(),
        }

    def _change_provider(self):
        next_provider = self.provider.get()
        if next_provider == self._active_provider:
            return
        self._store_provider(self._active_provider)
        self._active_provider = next_provider
        self._restore_provider(next_provider)
        self._refresh_provider()

    def _refresh_provider(self):
        provider = self.provider.get()
        if provider == "warp":
            self.openvpn.set(False)
            self.wireguard.set(True)
            self.ov_check.configure(state="disabled")
            self.wg_check.configure(state="disabled")
            for widget in (self.udp_row, self.tcp_row, self.udp_label, self.tcp_label,
                           self.credential_row, self.credential_label,
                           self.mode_row, self.mode_label, self.filter_check, self.filter_label):
                widget.grid_remove()
            self.warp_button.configure(state="normal")
        else:
            self.ov_check.configure(state="normal")
            self.wg_check.configure(state="normal" if provider == "pia" else "disabled")
            if provider == "surfshark":
                self.wireguard.set(False)
            for widget in (self.udp_row, self.udp_label, self.credential_row,
                           self.credential_label, self.mode_row, self.mode_label,
                           self.filter_check, self.filter_label):
                widget.grid()
            if provider == "pia":
                self.tcp_row.grid()
                self.tcp_label.grid()
            else:
                self.tcp_row.grid_remove()
                self.tcp_label.grid_remove()
            self.credential_label.configure(text=f"{'PIA' if provider == 'pia' else 'Surfshark'} 帳號 / 密碼")
            self.warp_button.configure(state="disabled")
        self._refresh_protocols()

    def _refresh_protocols(self):
        enabled = self.openvpn.get() and self.provider.get() != "warp"
        for row in (self.udp_row, self.tcp_row):
            for widget in row.winfo_children():
                if isinstance(widget, (ctk.CTkEntry, ctk.CTkButton)):
                    widget.configure(state="normal" if enabled else "disabled")

    def _pick_zip(self, variable):
        path = filedialog.askopenfilename(parent=self, title="選擇 OpenVPN ZIP",
                                          filetypes=[("ZIP", "*.zip"), ("所有檔案", "*.*")])
        if path:
            variable.set(path)

    def _pick_output(self):
        path = filedialog.askdirectory(parent=self, title="選擇輸出目錄",
                                       initialdir=self.out_dir.get() or str(Path.home()))
        if path:
            self.out_dir.set(path)

    def _show_mode_help(self):
        if self.provider.get() == "surfshark":
            text = ("分節點：providers/<endpoint>/surfshark-ov.yaml\n"
                    "單一：providers/surfshark-ov-all.yaml")
        else:
            text = ("分節點：providers/<endpoint>/pia-ov.yaml 及 pia-wg.yaml\n"
                    "單一：providers/pia-ov-all.yaml 及 pia-wg-all.yaml")
        messagebox.showinfo("輸出模式", text, parent=self)

    def _current_options(self):
        return {
            "provider": self.provider.get(), "openvpn": self.openvpn.get(),
            "wireguard": self.wireguard.get(), "udp_zip": self.udp_zip.get().strip(),
            "tcp_zip": self.tcp_zip.get().strip(), "username": self.username.get().strip(),
            "password": self.password.get(), "out_dir": self.out_dir.get().strip(),
            "single_file": self.single_file.get(), "exclude_streaming": self.exclude_streaming.get(),
        }

    def _save(self):
        self._store_provider(self.provider.get())
        self.config_data["provider"] = self.provider.get()
        self.config_data["providers"] = self.provider_data
        save_settings(self.config_data)

    def _open_schedule(self):
        self._save()
        WarpScheduleDialog(self, self.out_dir.get().strip(), self.schedule_data)

    def _append_log(self, value):
        self.log.configure(state="normal")
        self.log.insert("end", value + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _start_generation(self):
        options = self._current_options()
        errors = validate_generation(options)
        if errors:
            messagebox.showwarning("輸入不完整", "\n".join(errors), parent=self)
            return
        self._save()
        self.running = True
        self.run_button.configure(state="disabled")
        self.safe_check.configure(state="disabled")
        self.pending_safe_path = (
            safe_paths.provider_directory(options["out_dir"]) if self.safe_paths.get() else None
        )
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        def worker():
            stream = LogStream(lambda value: self.events.put(("log", value)))
            try:
                with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                    print(f"[INFO] Provider: {options['provider']}")
                    print(f"[INFO] 輸出目錄: {options['out_dir']}")
                    target = generate_provider(options)
                    print("[OK] 全部完成。")
                stream.flush()
                self.events.put(("generate_finished", (True, str(target))))
            except Exception as exc:
                stream.flush()
                self.events.put(("log", traceback.format_exc().rstrip()))
                self.events.put(("generate_finished", (False, str(exc))))
        threading.Thread(target=worker, daemon=True, name="generate-provider").start()

    def _generation_finished(self, ok, detail):
        self.running = False
        self.run_button.configure(state="normal")
        self.safe_check.configure(state="normal")
        path = self.pending_safe_path
        self.pending_safe_path = None
        self.safe_paths.set(False)
        note = ""
        if ok and path:
            try:
                changed = safe_paths.ensure_machine_safe_path(path)
                note = ("\nSAFE_PATHS 已加入；需完整重啟 Clash Party。"
                        if changed else "\nSAFE_PATHS 已包含此目錄。")
            except Exception as exc:
                messagebox.showwarning("SAFE_PATHS 未更新", str(exc), parent=self)
        if ok:
            messagebox.showinfo("完成", f"輸出完成：\n{detail}{note}", parent=self)
        else:
            messagebox.showerror("失敗", detail, parent=self)

    def _build_doh(self):
        frm = self.doh_tab
        frm.columnconfigure(0, weight=1)
        data = self.config_data.get("doh", {})
        self.cert_dir = tk.StringVar(value=data.get("cert_root", default_cert_root()))
        self.doh_host = tk.StringVar(value=data.get("host", "127.0.0.1"))
        self.doh_endpoint = tk.StringVar()
        self.doh_hosts = tk.StringVar()
        self.doh_status = tk.StringVar()
        group = ui_group(frm, text="TLS 憑證", padding=12)
        group.grid(row=0, column=0, sticky="ew")
        group.columnconfigure(1, weight=1)
        group.grid_rowconfigure(0, minsize=28)
        ui_label(group, text="憑證目錄", width=18).grid(row=1, column=0, sticky="w")
        pathrow = ui_frame(group)
        pathrow.grid(row=1, column=1, sticky="ew", pady=5)
        ui_entry(pathrow, textvariable=self.cert_dir).pack(side="left", fill="x", expand=True)
        styled_button(pathrow, text="瀏覽", command=self._pick_cert_root).pack(side="left", padx=6)
        ui_label(group, text="DoH 主機", width=18).grid(row=2, column=0, sticky="w")
        ui_entry(group, textvariable=self.doh_host).grid(row=2, column=1, sticky="ew", pady=5)
        actions = ui_frame(group)
        actions.grid(row=3, column=1, sticky="w", pady=6)
        styled_button(actions, text="產生／更新", command=self._generate_certs,
                   variant="primary").pack(side="left")
        self.trust_button = styled_button(actions, text="信任 CA", command=self._trust_ca, state="disabled")
        self.trust_button.pack(side="left", padx=8)
        ui_label(group, textvariable=self.doh_status).grid(row=4, column=1, sticky="w")
        config = ui_group(frm, text="Mihomo 設定", padding=12)
        config.grid(row=1, column=0, sticky="nsew", pady=12)
        config.columnconfigure(1, weight=1)
        config.grid_rowconfigure(0, minsize=28)
        self.doh_yaml = DarkScrolledText(config, height=7, wrap="word",
                                                 font=("Consolas", 10), state="disabled")
        self.doh_yaml.grid(row=1, column=0, columnspan=3, sticky="ew")
        self.copy_yaml = styled_button(config, text="複製 YAML", command=lambda: self._copy(
            self.doh_yaml.get("1.0", "end-1c")), state="disabled")
        self.copy_yaml.grid(row=2, column=2, sticky="e", pady=7)
        ui_label(config, text="Firefox DoH", width=18).grid(row=3, column=0, sticky="w")
        ui_entry(config, textvariable=self.doh_endpoint, state="readonly").grid(
            row=3, column=1, sticky="ew")
        self.copy_url = styled_button(config, text="複製網址",
                                   command=lambda: self._copy(self.doh_endpoint.get()))
        self.copy_url.grid(row=3, column=2, padx=6)
        ui_label(config, text="Party Hosts", width=18).grid(row=4, column=0, sticky="w", pady=6)
        ui_entry(config, textvariable=self.doh_hosts, state="readonly").grid(
            row=4, column=1, sticky="ew", pady=6)
        frm.rowconfigure(1, weight=1)
        self.doh_host.trace_add("write", lambda *_: self._refresh_doh_endpoint())
        self.cert_dir.trace_add("write", lambda *_: self._refresh_doh_endpoint())
        self._refresh_doh_endpoint()

    def _refresh_doh_endpoint(self):
        self.cert_files = None
        self.trust_button.configure(state="disabled")
        self.copy_yaml.configure(state="disabled")
        self.doh_status.set("")
        self.doh_yaml.configure(state="normal")
        self.doh_yaml.delete("1.0", "end")
        self.doh_yaml.configure(state="disabled")
        try:
            host = mihomo_doh.normalize_host(self.doh_host.get())
            self.doh_endpoint.set(mihomo_doh.doh_url(host))
            self.doh_hosts.set(mihomo_doh.party_hosts_override(host))
            self.copy_url.configure(state="normal")
        except ValueError:
            self.doh_endpoint.set("")
            self.doh_hosts.set("")
            self.copy_url.configure(state="disabled")

    def _pick_cert_root(self):
        path = filedialog.askdirectory(parent=self, initialdir=self.cert_dir.get() or str(Path.home()))
        if path:
            self.cert_dir.set(path)

    def _generate_certs(self):
        try:
            host = mihomo_doh.normalize_host(self.doh_host.get())
            files = mihomo_doh.generate_certificates(Path(self.cert_dir.get().strip()), host)
        except Exception as exc:
            messagebox.showerror("憑證產生失敗", str(exc), parent=self)
            return
        self.cert_files = files
        self.config_data["doh"] = {"cert_root": self.cert_dir.get().strip(), "host": host}
        self._save()
        self.doh_yaml.configure(state="normal")
        self.doh_yaml.insert("1.0", mihomo_doh.mihomo_yaml(files))
        self.doh_yaml.configure(state="disabled")
        self.trust_button.configure(state="normal")
        self.copy_yaml.configure(state="normal")
        self.doh_status.set("已更新" if files.renewed else "憑證有效")

    def _trust_ca(self):
        if self.cert_files is None or not messagebox.askyesno(
                "信任 CA", "將此 CA 加入目前 Windows 使用者的受信任根憑證存放區？", parent=self):
            return
        try:
            mihomo_doh.trust_ca_for_current_user(self.cert_files.ca_certificate)
            self.doh_status.set("CA 已信任")
        except Exception as exc:
            messagebox.showerror("CA 匯入失敗", str(exc), parent=self)

    def _copy(self, value):
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update_idletasks()

    def _build_uwp(self):
        frm = self.uwp_tab
        buttons = ui_group(frm, text="UWP 防火牆規則", padding=14)
        buttons.pack(fill="x")
        self.uwp_backup = styled_button(buttons, text="備份 JSON", command=self._uwp_backup)
        self.uwp_backup.pack(side="left", padx=8, pady=(27, 10))
        self.uwp_restore = styled_button(buttons, text="套用備份", command=self._uwp_restore)
        self.uwp_restore.pack(side="left", padx=8, pady=(27, 10))
        self.uwp_status = tk.StringVar()
        ui_label(frm, textvariable=self.uwp_status).pack(anchor="w", pady=12)

    def _uwp_backup(self):
        path = filedialog.asksaveasfilename(parent=self, title="備份 UWP 防火牆規則",
                                            initialfile="uwp-firewall-rules.json",
                                            defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            self._start_uwp("backup", Path(path))

    def _uwp_restore(self):
        path = filedialog.askopenfilename(parent=self, title="選擇 UWP 防火牆備份",
                                          filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            count = uwp_firewall.inspect_backup(Path(path))
        except Exception as exc:
            messagebox.showerror("備份無效", str(exc), parent=self)
            return
        question = (f"規則 {count['total']} 條（允許 {count['allow']}／封鎖 {count['block']}）。"
                    "\n只建立缺少的規則；未安裝套件或無法完整保留條件的規則會略過。"
                    "\n需要管理員授權。確定套用？")
        if messagebox.askyesno("確認套用 UWP 防火牆規則", question, parent=self):
            self._start_uwp("restore", Path(path))

    def _start_uwp(self, mode, path):
        if self.uwp_running:
            return
        self.uwp_running = True
        self.uwp_status.set("處理中…")
        self.uwp_backup.configure(state="disabled")
        self.uwp_restore.configure(state="disabled")
        def task():
            try:
                handler = uwp_firewall.backup if mode == "backup" else uwp_firewall.restore
                result = handler(path)
                self.events.put(("uwp_finished", (mode, path, True, result)))
            except Exception as exc:
                self.events.put(("uwp_finished", (mode, path, False, str(exc))))
        threading.Thread(target=task, daemon=True, name="uwp-firewall").start()

    def _uwp_finished(self, mode, path, ok, result):
        self.uwp_running = False
        self.uwp_backup.configure(state="normal")
        self.uwp_restore.configure(state="normal")
        if not ok:
            self.uwp_status.set("未完成")
            messagebox.showerror("防火牆操作失敗", str(result), parent=self)
        elif mode == "backup":
            self.uwp_status.set(f"已備份 {result.get('Total', 0)} 條：{path}")
        else:
            self.uwp_status.set(
                f"新增 {result.get('Added', 0)}／已存在 {result.get('Existing', 0)}／"
                f"未安裝 {result.get('MissingPackage', 0)}／略過 {result.get('Unsupported', 0)}")
            if result.get("Errors"):
                messagebox.showwarning("部分套用失敗", "\n".join(result["Errors"][:8]), parent=self)

    def _pump(self):
        try:
            for _ in range(100):
                try:
                    name, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                if name == "log":
                    self._append_log(payload)
                elif name == "generate_finished":
                    self._generation_finished(*payload)
                elif name == "uwp_finished":
                    self._uwp_finished(*payload)
        finally:
            if not self._closing:
                self.after(100, self._pump)

    def _close(self):
        if self.running or self.uwp_running:
            messagebox.showinfo("操作進行中", "請先完成產生器或防火牆操作，再關閉程式。", parent=self)
            return
        try:
            self._save()
        except Exception as exc:
            messagebox.showerror("設定儲存失敗", str(exc), parent=self)
            return
        self._closing = True
        self.destroy()


def run_warp_cli(argv: list[str]) -> int:
    """Unchanged task action: VPN-Mihomo-Generator.exe --warp --out-dir ..."""
    import argparse
    from datetime import datetime
    from contextlib import redirect_stdout, redirect_stderr

    parser = argparse.ArgumentParser(description="Regenerate Cloudflare WARP without GUI.")
    parser.add_argument("--warp", action="store_true")
    parser.add_argument("--out-dir", type=Path, default=Path(r"P:\Clash"))
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--log-file", type=Path)
    args = parser.parse_args(argv)
    if not args.warp:
        parser.error("Specify --warp")
    log_file = args.log_file or args.out_dir / "logs" / "warp-generator.log"
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as log:
            with redirect_stdout(log), redirect_stderr(log):
                print(f"\n===== WARP scheduled run {datetime.now().astimezone().isoformat(timespec='seconds')} =====", flush=True)
                try:
                    warp = core.load_sibling("warp-wireguard-generator.py", "warp_wireguard_generator_cli")
                    result = warp.generate_warp(out_dir=args.out_dir, timeout=args.timeout)
                    print(f"[OK] {result}", flush=True)
                    return 0
                except Exception:
                    traceback.print_exc()
                    print("[ERROR] WARP generation failed; existing provider is preserved.", flush=True)
                    return 1
    except OSError:
        return 2


def main() -> int:
    if len(sys.argv) > 1:
        if sys.argv[1] == "--safe-paths-append":
            if len(sys.argv) != 3:
                return 2
            try:
                safe_paths.append_machine_safe_path(sys.argv[2])
                return 0
            except Exception:
                return 1
        return run_warp_cli(sys.argv[1:])
    window = MainWindow()
    window.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
