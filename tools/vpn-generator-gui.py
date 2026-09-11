#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import sys
import traceback
from pathlib import Path

from PySide6.QtCore import QSettings, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

import pia_generator_core as core

APP_NAME = "PIA Mihomo Generator"  # keep existing QSettings namespace for migration compatibility
ORG_NAME = "reg-chen"


class LogStream:
    def __init__(self, emit_line):
        self._emit_line = emit_line
        self._buffer = ""

    def write(self, text: str) -> int:
        if not text:
            return 0
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if line:
                self._emit_line(line)
        return len(text)

    def flush(self) -> None:
        if self._buffer:
            self._emit_line(self._buffer)
            self._buffer = ""


class GenerateWorker(QThread):
    log = Signal(str)
    completed = Signal(bool, str)

    def __init__(
        self,
        *,
        provider: str,
        generate_openvpn: bool,
        generate_wireguard: bool,
        udp_zip: Path | None,
        tcp_zip: Path | None,
        username: str,
        password: str,
        out_dir: Path,
        single_file: bool,
        exclude_streaming: bool,
    ) -> None:
        super().__init__()
        self.provider = provider
        self.generate_openvpn = generate_openvpn
        self.generate_wireguard = generate_wireguard
        self.udp_zip = udp_zip
        self.tcp_zip = tcp_zip
        self.username = username
        self.password = password
        self.out_dir = out_dir
        self.single_file = single_file
        self.exclude_streaming = exclude_streaming

    def run(self) -> None:
        stream = LogStream(self.log.emit)
        try:
            with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                selected = []
                if self.generate_openvpn:
                    selected.append("OpenVPN")
                if self.generate_wireguard:
                    selected.append("WireGuard")

                provider_name = "PIA" if self.provider == "pia" else "Surfshark"
                print(f"[INFO] Provider: {provider_name}")
                print(f"[INFO] Protocol: {' + '.join(selected)}")
                print(f"[INFO] 輸出目錄: {self.out_dir}")
                print(f"[INFO] 輸出模式: {'單一檔案' if self.single_file else '分節點檔案'}")
                if self.provider == "pia":
                    print(f"[INFO] 排除 Streaming Optimized: {'是' if self.exclude_streaming else '否'}")

                self.out_dir.mkdir(parents=True, exist_ok=True)

                if self.provider == "pia":
                    # OpenVPN runs first when both are selected. WireGuard can then use
                    # pia-ov.yaml endpoint markers to mirror the exact tree and display names.
                    if self.generate_openvpn:
                        assert self.udp_zip is not None
                        assert self.tcp_zip is not None
                        print("\n===== PIA OpenVPN =====")
                        print(f"[INFO] UDP ZIP: {self.udp_zip}")
                        print(f"[INFO] TCP ZIP: {self.tcp_zip}")
                        ov = core.load_sibling(
                            "pia-openvpn-generator.py",
                            "pia_openvpn_generator_gui",
                        )
                        ov.generate_openvpn(
                            udp_zip=self.udp_zip,
                            tcp_zip=self.tcp_zip,
                            username=self.username,
                            password=self.password,
                            out_dir=self.out_dir,
                            single_file=self.single_file,
                            exclude_streaming=self.exclude_streaming,
                        )
                        print("[OK] PIA OpenVPN 完成。")

                    if self.generate_wireguard:
                        print("\n===== PIA WireGuard =====")
                        wg = core.load_sibling(
                            "pia-wireguard-generator.py",
                            "pia_wireguard_generator_gui",
                        )
                        wg.generate_wireguard(
                            username=self.username,
                            password=self.password,
                            out_dir=self.out_dir,
                            single_file=self.single_file,
                            exclude_streaming=self.exclude_streaming,
                        )
                        print("[OK] PIA WireGuard 完成。")

                elif self.provider == "surfshark":
                    if self.generate_wireguard:
                        raise RuntimeError("Surfshark WireGuard generator 尚未實作。")
                    if self.generate_openvpn:
                        assert self.udp_zip is not None
                        print("\n===== Surfshark OpenVPN =====")
                        print(f"[INFO] Configurations ZIP: {self.udp_zip}")
                        ov = core.load_sibling(
                            "surfshark-openvpn-generator.py",
                            "surfshark_openvpn_generator_gui",
                        )
                        ov.generate_openvpn(
                            bundle_zip=self.udp_zip,
                            username=self.username,
                            password=self.password,
                            out_dir=self.out_dir,
                            single_file=self.single_file,
                        )
                        print("[OK] Surfshark OpenVPN 完成。")
                else:
                    raise RuntimeError(f"未知 provider：{self.provider}")

                print("\n[OK] 全部完成。")
                stream.flush()

            self.completed.emit(True, str(self.out_dir))
        except Exception as exc:
            stream.flush()
            self.log.emit(f"[ERROR] {exc}")
            self.log.emit(traceback.format_exc().rstrip())
            self.completed.emit(False, str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.settings = QSettings(ORG_NAME, APP_NAME)
        self.worker: GenerateWorker | None = None
        self._pia_wireguard_preference = True
        self._active_provider = "pia"

        self.setWindowTitle("VPN → Mihomo Provider Generator")
        self.resize(880, 690)

        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        form = QFormLayout()
        root.addLayout(form)

        provider_row = QWidget()
        provider_layout = QHBoxLayout(provider_row)
        provider_layout.setContentsMargins(0, 0, 0, 0)
        self.pia_radio = QRadioButton("PIA")
        self.surfshark_radio = QRadioButton("Surfshark")
        self.pia_radio.setChecked(True)
        provider_group = QButtonGroup(self)
        provider_group.addButton(self.pia_radio)
        provider_group.addButton(self.surfshark_radio)
        provider_layout.addWidget(self.pia_radio)
        provider_layout.addWidget(self.surfshark_radio)
        provider_layout.addStretch(1)
        form.addRow("Provider", provider_row)

        protocol_row = QWidget()
        protocol_layout = QHBoxLayout(protocol_row)
        protocol_layout.setContentsMargins(0, 0, 0, 0)
        self.openvpn_checkbox = QCheckBox("OpenVPN")
        self.wireguard_checkbox = QCheckBox("WireGuard")
        self.openvpn_checkbox.setChecked(True)
        self.wireguard_checkbox.setChecked(True)
        protocol_layout.addWidget(self.openvpn_checkbox)
        protocol_layout.addWidget(self.wireguard_checkbox)
        protocol_layout.addStretch(1)
        form.addRow("輸出協定", protocol_row)

        self.udp_edit = QLineEdit()
        self.udp_row = self._path_row(self.udp_edit, self.pick_udp_zip)
        self.udp_label = QLabel("OpenVPN UDP ZIP")
        form.addRow(self.udp_label, self.udp_row)

        self.tcp_edit = QLineEdit()
        self.tcp_row = self._path_row(self.tcp_edit, self.pick_tcp_zip)
        self.tcp_label = QLabel("OpenVPN TCP ZIP")
        form.addRow(self.tcp_label, self.tcp_row)

        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Username")

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Password")

        credentials_row = QWidget()
        credentials_layout = QHBoxLayout(credentials_row)
        credentials_layout.setContentsMargins(0, 0, 0, 0)
        credentials_layout.addWidget(self.username_edit, 1)
        credentials_layout.addWidget(self.password_edit, 1)

        self.show_password = QCheckBox("顯示密碼")
        self.show_password.toggled.connect(
            lambda checked: self.password_edit.setEchoMode(
                QLineEdit.Normal if checked else QLineEdit.Password
            )
        )
        credentials_layout.addWidget(self.show_password)
        self.credentials_label = QLabel("PIA 帳號 / 密碼")
        form.addRow(self.credentials_label, credentials_row)

        self.out_edit = QLineEdit()
        form.addRow("輸出目錄", self._path_row(self.out_edit, self.pick_output_dir))

        mode_row = QWidget()
        mode_layout = QHBoxLayout(mode_row)
        mode_layout.setContentsMargins(0, 0, 0, 0)
        self.multi_radio = QRadioButton("分節點檔案")
        self.single_radio = QRadioButton("單一檔案")
        self.multi_radio.setChecked(True)

        mode_group = QButtonGroup(self)
        mode_group.addButton(self.multi_radio)
        mode_group.addButton(self.single_radio)
        mode_layout.addWidget(self.multi_radio)
        mode_layout.addWidget(self.single_radio)

        mode_help = QToolButton()
        mode_help.setText("?")
        mode_help.setToolTip("輸出模式說明")
        mode_help.setFixedSize(24, 24)
        mode_help.clicked.connect(self.show_output_mode_help)
        mode_layout.addWidget(mode_help)
        mode_layout.addStretch(1)
        form.addRow("輸出模式", mode_row)

        self.exclude_streaming = QCheckBox("排除 PIA Streaming Optimized")
        self.exclude_streaming.setChecked(True)
        self.exclude_streaming_label = QLabel("節點過濾")
        form.addRow(self.exclude_streaming_label, self.exclude_streaming)

        self.run_button = QPushButton("執行")
        self.run_button.clicked.connect(self.start_generation)
        root.addWidget(self.run_button)

        root.addWidget(QLabel("Log"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        root.addWidget(self.log_view, 1)

        self.openvpn_checkbox.toggled.connect(self.update_protocol_controls)
        self.pia_radio.toggled.connect(self.update_provider_controls)
        self.wireguard_checkbox.toggled.connect(self.remember_pia_wireguard_preference)

        self.restore_settings()
        self.update_provider_controls()
        self.update_protocol_controls()

    def selected_provider(self) -> str:
        return "surfshark" if self.surfshark_radio.isChecked() else "pia"

    def _path_row(self, edit: QLineEdit, callback) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(edit, 1)
        button = QPushButton("瀏覽")
        button.clicked.connect(callback)
        layout.addWidget(button)
        return row

    def remember_pia_wireguard_preference(self, checked: bool) -> None:
        if self.selected_provider() == "pia" and self.wireguard_checkbox.isEnabled():
            self._pia_wireguard_preference = checked

    def update_provider_controls(self, *_args) -> None:
        provider = self.selected_provider()

        if provider != self._active_provider:
            self.save_provider_settings(self._active_provider)
            self.restore_provider_settings(provider)
            self._active_provider = provider

        surfshark = provider == "surfshark"

        if surfshark:
            if self.wireguard_checkbox.isEnabled():
                self._pia_wireguard_preference = self.wireguard_checkbox.isChecked()
            self.wireguard_checkbox.blockSignals(True)
            self.wireguard_checkbox.setChecked(False)
            self.wireguard_checkbox.blockSignals(False)
            self.wireguard_checkbox.setEnabled(False)
            self.wireguard_checkbox.setToolTip("Surfshark WireGuard generator 尚未實作；預留給未來 provisioning/API。")

            self.udp_label.setText("OpenVPN Configurations ZIP")
            self.tcp_label.hide()
            self.tcp_row.hide()
            self.credentials_label.setText("Surfshark service 帳號 / 密碼")
            self.exclude_streaming_label.hide()
            self.exclude_streaming.hide()
        else:
            self.wireguard_checkbox.setEnabled(True)
            self.wireguard_checkbox.setToolTip("")
            self.wireguard_checkbox.blockSignals(True)
            self.wireguard_checkbox.setChecked(self._pia_wireguard_preference)
            self.wireguard_checkbox.blockSignals(False)

            self.udp_label.setText("OpenVPN UDP ZIP")
            self.tcp_label.show()
            self.tcp_row.show()
            self.credentials_label.setText("PIA 帳號 / 密碼")
            self.exclude_streaming_label.show()
            self.exclude_streaming.show()

        self.update_protocol_controls()

    def update_protocol_controls(self, *_args) -> None:
        enabled = self.openvpn_checkbox.isChecked()
        self.udp_row.setEnabled(enabled)
        if self.selected_provider() == "pia":
            self.tcp_row.setEnabled(enabled)

    def show_output_mode_help(self) -> None:
        if self.selected_provider() == "surfshark":
            text = (
                "分節點檔案\n"
                "OpenVPN：providers/<endpoint>/surfshark-ov.yaml\n\n"
                "單一檔案\n"
                "OpenVPN：providers/surfshark-ov-all.yaml"
            )
        else:
            text = (
                "分節點檔案\n"
                "OpenVPN：providers/<endpoint>/pia-ov.yaml\n"
                "WireGuard：providers/<endpoint>/pia-wg.yaml\n"
                "兩者同時輸出時會放在相同 endpoint 目錄。\n\n"
                "單一檔案\n"
                "OpenVPN：providers/pia-ov-all.yaml\n"
                "WireGuard：providers/pia-wg-all.yaml\n"
                "兩者同時輸出時仍維持兩份獨立 provider payload。"
            )
        QMessageBox.information(self, "輸出模式說明", text)

    def pick_udp_zip(self) -> None:
        provider = self.selected_provider()
        title = "選擇 Surfshark OpenVPN Configurations ZIP" if provider == "surfshark" else "選擇 PIA OpenVPN UDP ZIP"
        path, _ = QFileDialog.getOpenFileName(
            self,
            title,
            self._dialog_start(self.udp_edit.text()),
            "ZIP files (*.zip);;All files (*)",
        )
        if path:
            self.udp_edit.setText(path)

    def pick_tcp_zip(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "選擇 PIA OpenVPN TCP ZIP",
            self._dialog_start(self.tcp_edit.text()),
            "ZIP files (*.zip);;All files (*)",
        )
        if path:
            self.tcp_edit.setText(path)

    def pick_output_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self,
            "選擇輸出目錄",
            self._dialog_start(self.out_edit.text()),
        )
        if path:
            self.out_edit.setText(path)

    @staticmethod
    def _dialog_start(value: str) -> str:
        if value:
            path = Path(value)
            return str(path if path.is_dir() else path.parent)
        return str(Path.home())

    def append_log(self, text: str) -> None:
        self.log_view.appendPlainText(text)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def validate_inputs(self) -> list[str]:
        problems: list[str] = []
        provider = self.selected_provider()
        ov_enabled = self.openvpn_checkbox.isChecked()
        wg_enabled = self.wireguard_checkbox.isChecked() and provider == "pia"

        if not ov_enabled and not wg_enabled:
            problems.append("請至少選擇一個目前支援的協定。")

        if ov_enabled:
            udp = Path(self.udp_edit.text().strip())
            if not udp.is_file() or udp.suffix.lower() != ".zip":
                if provider == "surfshark":
                    problems.append("請選擇有效的 Surfshark OpenVPN Configurations ZIP。")
                else:
                    problems.append("請選擇有效的 OpenVPN UDP ZIP。")

            if provider == "pia":
                tcp = Path(self.tcp_edit.text().strip())
                if not tcp.is_file() or tcp.suffix.lower() != ".zip":
                    problems.append("請選擇有效的 OpenVPN TCP ZIP。")

        credentials_required = wg_enabled or (provider == "surfshark" and ov_enabled)
        if credentials_required and (
            not self.username_edit.text().strip()
            or not self.password_edit.text()
        ):
            if provider == "surfshark":
                problems.append("Surfshark OpenVPN 需要 service username / password。")
            else:
                problems.append("WireGuard provisioning 需要 PIA 帳號與密碼。")

        if not self.out_edit.text().strip():
            problems.append("請選擇輸出目錄。")

        return problems

    def start_generation(self) -> None:
        problems = self.validate_inputs()
        if problems:
            QMessageBox.warning(self, "輸入不完整", "\n".join(problems))
            return

        self.save_settings()
        self.log_view.clear()
        self.run_button.setEnabled(False)

        provider = self.selected_provider()
        ov_enabled = self.openvpn_checkbox.isChecked()
        wg_enabled = self.wireguard_checkbox.isChecked() and provider == "pia"
        self.worker = GenerateWorker(
            provider=provider,
            generate_openvpn=ov_enabled,
            generate_wireguard=wg_enabled,
            udp_zip=Path(self.udp_edit.text().strip()) if ov_enabled else None,
            tcp_zip=(Path(self.tcp_edit.text().strip()) if ov_enabled and provider == "pia" else None),
            username=self.username_edit.text().strip(),
            password=self.password_edit.text(),
            out_dir=Path(self.out_edit.text().strip()),
            single_file=self.single_radio.isChecked(),
            exclude_streaming=self.exclude_streaming.isChecked(),
        )
        self.worker.log.connect(self.append_log)
        self.worker.completed.connect(self.generation_finished)
        self.worker.start()

    def generation_finished(self, ok: bool, detail: str) -> None:
        self.run_button.setEnabled(True)
        if ok:
            QMessageBox.information(self, "完成", f"輸出完成：\n{detail}")
        else:
            QMessageBox.critical(self, "失敗", detail)
        self.worker = None

    def provider_setting_key(self, provider: str, name: str) -> str:
        return f"{provider}/{name}"

    def restore_provider_settings(self, provider: str) -> None:
        self.udp_edit.setText(
            self.settings.value(self.provider_setting_key(provider, "udp_zip"), "", str)
        )
        self.tcp_edit.setText(
            self.settings.value(self.provider_setting_key(provider, "tcp_zip"), "", str)
        )
        self.out_edit.setText(
            self.settings.value(self.provider_setting_key(provider, "out_dir"), "", str)
        )
        self.openvpn_checkbox.setChecked(
            self.settings.value(self.provider_setting_key(provider, "generate_openvpn"), True, bool)
        )

        if provider == "pia":
            self._pia_wireguard_preference = self.settings.value(
                self.provider_setting_key(provider, "generate_wireguard"), True, bool
            )
            self.exclude_streaming.setChecked(
                self.settings.value(
                    self.provider_setting_key(provider, "exclude_streaming"), True, bool
                )
            )

        single = self.settings.value(
            self.provider_setting_key(provider, "single_file"), False, bool
        )
        self.single_radio.setChecked(single)
        self.multi_radio.setChecked(not single)

    def save_provider_settings(self, provider: str) -> None:
        self.settings.setValue(
            self.provider_setting_key(provider, "udp_zip"), self.udp_edit.text().strip()
        )
        self.settings.setValue(
            self.provider_setting_key(provider, "tcp_zip"), self.tcp_edit.text().strip()
        )
        self.settings.setValue(
            self.provider_setting_key(provider, "out_dir"), self.out_edit.text().strip()
        )
        self.settings.setValue(
            self.provider_setting_key(provider, "generate_openvpn"),
            self.openvpn_checkbox.isChecked(),
        )
        self.settings.setValue(
            self.provider_setting_key(provider, "single_file"),
            self.single_radio.isChecked(),
        )

        if provider == "pia":
            self.settings.setValue(
                self.provider_setting_key(provider, "generate_wireguard"),
                self._pia_wireguard_preference,
            )
            self.settings.setValue(
                self.provider_setting_key(provider, "exclude_streaming"),
                self.exclude_streaming.isChecked(),
            )

    def restore_settings(self) -> None:
        provider = self.settings.value("provider", "pia", str)
        self.pia_radio.blockSignals(True)
        self.surfshark_radio.blockSignals(True)
        self.surfshark_radio.setChecked(provider == "surfshark")
        self.pia_radio.setChecked(provider != "surfshark")
        self.pia_radio.blockSignals(False)
        self.surfshark_radio.blockSignals(False)

        self._active_provider = self.selected_provider()
        self.restore_provider_settings(self._active_provider)

    def save_settings(self) -> None:
        # Credentials are deliberately never persisted.
        provider = self.selected_provider()
        self.save_provider_settings(provider)
        self.settings.setValue("provider", provider)

    def closeEvent(self, event) -> None:
        self.save_settings()
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    app.setOrganizationName(ORG_NAME)
    app.setApplicationName(APP_NAME)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
