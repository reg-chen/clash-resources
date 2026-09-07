#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
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

APP_NAME = "PIA Mihomo Generator"
ORG_NAME = "reg-chen"


def bundled_core_path() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "pia-openvpn-generator.py"
    return Path(__file__).resolve().with_name("pia-openvpn-generator.py")


def load_core():
    path = bundled_core_path()
    if not path.is_file():
        raise FileNotFoundError(f"找不到核心產生器：{path}")

    spec = importlib.util.spec_from_file_location("pia_openvpn_generator_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"無法載入核心產生器：{path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
        udp_zip: Path,
        tcp_zip: Path,
        username: str,
        password: str,
        out_dir: Path,
        single_file: bool,
        exclude_streaming: bool,
    ) -> None:
        super().__init__()
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
                core = load_core()
                core.COMPRESS_MAP_VALUE = "yes"

                print(f"[INFO] UDP ZIP: {self.udp_zip}")
                print(f"[INFO] TCP ZIP: {self.tcp_zip}")
                print(f"[INFO] 輸出目錄: {self.out_dir}")
                print(f"[INFO] 輸出模式: {'單一檔案' if self.single_file else '分節點檔案'}")
                print(f"[INFO] 排除 Streaming Optimized: {'是' if self.exclude_streaming else '否'}")
                if not self.username or not self.password:
                    print("[WARN] PIA username/password 有空值；輸出的 YAML 也會保留空值。")

                ovpn_inputs = core.collect_ovpn_inputs([self.udp_zip, self.tcp_zip])
                print(f"[INFO] ZIP 內共找到 {len(ovpn_inputs)} 個 .ovpn。")

                if self.exclude_streaming:
                    streaming = [
                        item for item in ovpn_inputs
                        if core.is_streaming_optimized_source(item.name)
                    ]
                    if streaming:
                        print(f"[INFO] 已排除 {len(streaming)} 個 PIA Streaming Optimized profile。")
                    ovpn_inputs = [
                        item for item in ovpn_inputs
                        if not core.is_streaming_optimized_source(item.name)
                    ]

                nodes = []
                for ovpn_file in ovpn_inputs:
                    try:
                        nodes.append(core.parse_ovpn(ovpn_file))
                    except Exception as exc:
                        raise RuntimeError(f"解析失敗：{ovpn_file.name}") from exc

                nodes = core.dedupe_nodes(nodes)
                core.apply_node_names(nodes, city_mode="multi")

                if not nodes:
                    raise RuntimeError("沒有任何節點可輸出。")

                self.out_dir.mkdir(parents=True, exist_ok=True)

                if self.single_file:
                    target = self.out_dir / "providers" / "pia-all.yaml"
                    core.write_single_yaml(
                        path=target,
                        nodes=nodes,
                        username=self.username,
                        password=self.password,
                        hot_ping=20,
                        hot_ping_restart=60,
                    )
                else:
                    core.write_endpoint_tree(
                        out_dir=self.out_dir,
                        nodes=nodes,
                        username=self.username,
                        password=self.password,
                        hot_ping=20,
                        hot_ping_restart=60,
                    )

                print(f"OVPN 檔案數：{len(ovpn_inputs)}")
                core.print_summary(nodes)

                has_tls_auth = any(node.tls_auth for node in nodes)
                has_tls_crypt = any(node.tls_crypt for node in nodes)
                has_comp_lzo = any(node.comp_lzo is not None for node in nodes)

                if has_tls_auth:
                    print("[WARN] 偵測到 tls-auth；請確認目前 Mihomo OpenVPN outbound 支援狀況。")
                else:
                    print("[OK] 未偵測到 tls-auth/key-direction。")

                if has_tls_crypt:
                    print("[INFO] 偵測到 tls-crypt。")
                else:
                    print("[INFO] 未偵測到 tls-crypt。")

                if has_comp_lzo:
                    print(f"[OK] OpenVPN compress/comp-lzo 已映射為 comp-lzo: {core.COMPRESS_MAP_VALUE}。")

                print("[OK] 完成。")
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

        self.setWindowTitle("PIA OpenVPN → Mihomo Provider Generator")
        self.resize(860, 620)

        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        form = QFormLayout()
        root.addLayout(form)

        self.udp_edit = QLineEdit()
        form.addRow("UDP ZIP", self._path_row(self.udp_edit, self.pick_udp_zip))

        self.tcp_edit = QLineEdit()
        form.addRow("TCP ZIP", self._path_row(self.tcp_edit, self.pick_tcp_zip))

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

        self.restore_settings()

    def _path_row(self, edit: QLineEdit, callback) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(edit, 1)
        button = QPushButton("瀏覽")
        button.clicked.connect(callback)
        layout.addWidget(button)
        return row

    def show_output_mode_help(self) -> None:
        QMessageBox.information(
            self,
            "輸出模式說明",
            "分節點檔案\n"
            "每個 PIA endpoint 各產生一份 providers/<endpoint>/pia.yaml，"
            "同一檔案內包含 UDP 與 TCP 節點。\n\n"
            "單一檔案\n"
            "將全部 endpoint 與 transport 合併輸出為 providers/pia-all.yaml。",
        )

    def pick_udp_zip(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "選擇 PIA UDP ZIP",
            self._dialog_start(self.udp_edit.text()),
            "ZIP files (*.zip);;All files (*)",
        )
        if path:
            self.udp_edit.setText(path)

    def pick_tcp_zip(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "選擇 PIA TCP ZIP",
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

    def start_generation(self) -> None:
        udp = Path(self.udp_edit.text().strip())
        tcp = Path(self.tcp_edit.text().strip())
        out = Path(self.out_edit.text().strip())

        problems = []
        if not udp.is_file() or udp.suffix.lower() != ".zip":
            problems.append("請選擇有效的 UDP ZIP。")
        if not tcp.is_file() or tcp.suffix.lower() != ".zip":
            problems.append("請選擇有效的 TCP ZIP。")
        if not self.out_edit.text().strip():
            problems.append("請選擇輸出目錄。")

        if problems:
            QMessageBox.warning(self, "輸入不完整", "\n".join(problems))
            return

        self.save_settings()
        self.log_view.clear()
        self.run_button.setEnabled(False)

        self.worker = GenerateWorker(
            udp_zip=udp,
            tcp_zip=tcp,
            username=self.username_edit.text(),
            password=self.password_edit.text(),
            out_dir=out,
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
        self.exclude_streaming.setChecked(
            self.settings.value("exclude_streaming", True, bool)
        )
        single = self.settings.value("single_file", False, bool)
        self.single_radio.setChecked(single)
        self.multi_radio.setChecked(not single)

    def save_settings(self) -> None:
        # Intentionally do not persist username/password.
        self.settings.setValue("udp_zip", self.udp_edit.text().strip())
        self.settings.setValue("tcp_zip", self.tcp_edit.text().strip())
        self.settings.setValue("out_dir", self.out_edit.text().strip())
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
