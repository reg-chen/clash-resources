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

APP_NAME = "PIA Mihomo Generator"
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

                print(f"[INFO] Protocol: {' + '.join(selected)}")
                print(f"[INFO] 輸出目錄: {self.out_dir}")
                print(f"[INFO] 輸出模式: {'單一檔案' if self.single_file else '分節點檔案'}")
                print(f"[INFO] 排除 Streaming Optimized: {'是' if self.exclude_streaming else '否'}")

                self.out_dir.mkdir(parents=True, exist_ok=True)

                # OpenVPN runs first when both are selected. WireGuard can then use
                # pia-ov.yaml endpoint markers to mirror the exact tree and display names.
                if self.generate_openvpn:
                    assert self.udp_zip is not None
                    assert self.tcp_zip is not None
                    print("\n===== OpenVPN =====")
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
                    print("[OK] OpenVPN 完成。")

                if self.generate_wireguard:
                    print("\n===== WireGuard =====")
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
                    print("[OK] WireGuard 完成。")

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

        self.setWindowTitle("PIA → Mihomo Provider Generator")
        self.resize(880, 650)

        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        form = QFormLayout()
        root.addLayout(form)

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
        form.addRow("OpenVPN UDP ZIP", self.udp_row)

        self.tcp_edit = QLineEdit()
        self.tcp_row = self._path_row(self.tcp_edit, self.pick_tcp_zip)
        form.addRow("OpenVPN TCP ZIP", self.tcp_row)

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
        form.addRow("PIA 帳號 / 密碼", credentials_row)

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
        form.addRow("節點過濾", self.exclude_streaming)

        self.run_button = QPushButton("執行")
        self.run_button.clicked.connect(self.start_generation)
        root.addWidget(self.run_button)

        root.addWidget(QLabel("Log"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        root.addWidget(self.log_view, 1)

        self.openvpn_checkbox.toggled.connect(self.update_protocol_controls)
        self.restore_settings()
        self.update_protocol_controls()

    def _path_row(self, edit: QLineEdit, callback) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(edit, 1)
        button = QPushButton("瀏覽")
        button.clicked.connect(callback)
        layout.addWidget(button)
        return row

    def update_protocol_controls(self) -> None:
        enabled = self.openvpn_checkbox.isChecked()
        self.udp_row.setEnabled(enabled)
        self.tcp_row.setEnabled(enabled)

    def show_output_mode_help(self) -> None:
        QMessageBox.information(
            self,
            "輸出模式說明",
            "分節點檔案\n"
            "OpenVPN：providers/<endpoint>/pia-ov.yaml\n"
            "WireGuard：providers/<endpoint>/pia-wg.yaml\n"
            "兩者同時輸出時會放在相同 endpoint 目錄。\n\n"
            "單一檔案\n"
            "OpenVPN：providers/pia-ov-all.yaml\n"
            "WireGuard：providers/pia-wg-all.yaml\n"
            "兩者同時輸出時仍維持兩份獨立 provider payload。",
        )

    def pick_udp_zip(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "選擇 PIA OpenVPN UDP ZIP",
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
        ov_enabled = self.openvpn_checkbox.isChecked()
        wg_enabled = self.wireguard_checkbox.isChecked()

        if not ov_enabled and not wg_enabled:
            problems.append("請至少選擇 OpenVPN 或 WireGuard。")

        if ov_enabled:
            udp = Path(self.udp_edit.text().strip())
            tcp = Path(self.tcp_edit.text().strip())
            if not udp.is_file() or udp.suffix.lower() != ".zip":
                problems.append("請選擇有效的 OpenVPN UDP ZIP。")
            if not tcp.is_file() or tcp.suffix.lower() != ".zip":
                problems.append("請選擇有效的 OpenVPN TCP ZIP。")

        if wg_enabled and (
            not self.username_edit.text().strip()
            or not self.password_edit.text()
        ):
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

        ov_enabled = self.openvpn_checkbox.isChecked()
        self.worker = GenerateWorker(
            generate_openvpn=ov_enabled,
            generate_wireguard=self.wireguard_checkbox.isChecked(),
            udp_zip=Path(self.udp_edit.text().strip()) if ov_enabled else None,
            tcp_zip=Path(self.tcp_edit.text().strip()) if ov_enabled else None,
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

    def restore_settings(self) -> None:
        self.udp_edit.setText(self.settings.value("udp_zip", "", str))
        self.tcp_edit.setText(self.settings.value("tcp_zip", "", str))
        self.out_edit.setText(self.settings.value("out_dir", "", str))
        self.openvpn_checkbox.setChecked(
            self.settings.value("generate_openvpn", True, bool)
        )
        self.wireguard_checkbox.setChecked(
            self.settings.value("generate_wireguard", True, bool)
        )
        self.exclude_streaming.setChecked(
            self.settings.value("exclude_streaming", True, bool)
        )
        single = self.settings.value("single_file", False, bool)
        self.single_radio.setChecked(single)
        self.multi_radio.setChecked(not single)

    def save_settings(self) -> None:
        # Credentials are deliberately never persisted.
        self.settings.setValue("udp_zip", self.udp_edit.text().strip())
        self.settings.setValue("tcp_zip", self.tcp_edit.text().strip())
        self.settings.setValue("out_dir", self.out_edit.text().strip())
        self.settings.setValue("generate_openvpn", self.openvpn_checkbox.isChecked())
        self.settings.setValue("generate_wireguard", self.wireguard_checkbox.isChecked())
        self.settings.setValue("exclude_streaming", self.exclude_streaming.isChecked())
        self.settings.setValue("single_file", self.single_radio.isChecked())

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
