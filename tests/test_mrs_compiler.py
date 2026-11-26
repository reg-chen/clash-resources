import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mrs_compiler as compiler


class CompilerTests(unittest.TestCase):
    def test_controller_priority_and_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            active = root / "mihomo-alpha.exe"
            manual = root / "mihomo.exe"
            active.touch()
            manual.touch()
            with mock.patch.object(compiler.sys, "platform", "win32"), \
                 mock.patch.object(compiler, "controller_pids", return_value={42}) as owners, \
                 mock.patch.object(compiler, "process_image", return_value=active), \
                 mock.patch.object(compiler, "running_pids") as running, \
                 mock.patch.object(compiler, "_version_ok", return_value=True), \
                 mock.patch.object(compiler.shutil, "which", return_value=None):
                self.assertEqual(compiler.resolve({"mihomo": str(manual)}), active.resolve())
                running.assert_not_called()
                owners.return_value = set()
                running.return_value = {42}
                self.assertEqual(compiler.resolve({"mihomo": ""}), active.resolve())
                running.return_value = set()
                self.assertEqual(compiler.resolve({"mihomo": str(manual)}), manual.resolve())
                with self.assertRaises(RuntimeError):
                    compiler.resolve({"mihomo": ""})

    def test_multiple_instances_not_arbitrarily_selected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            a, b = root / "mihomo.exe", root / "mihomo-alpha.exe"
            a.touch()
            b.touch()
            with mock.patch.object(compiler.sys, "platform", "win32"), \
                 mock.patch.object(compiler, "controller_pids", return_value={1, 2}), \
                 mock.patch.object(compiler, "process_image", side_effect=lambda pid: {1: a, 2: b}[pid]), \
                 mock.patch.object(compiler, "_version_ok", return_value=True):
                with self.assertRaisesRegex(RuntimeError, "多個"):
                    compiler.resolve({})
                self.assertEqual(compiler.resolve({"mihomo": str(b)}), b.resolve())

    @unittest.skipUnless(sys.platform == "win32", "Windows TCP/PID APIs")
    def test_real_listener_and_process_image(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            self.assertIn(os.getpid(), compiler.controller_pids(f"https://127.0.0.1:{port}"))
            self.assertEqual(compiler.process_image(os.getpid()).resolve(), Path(sys.executable).resolve())

    def test_version_probe(self):
        with mock.patch.object(compiler.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "Mihomo Meta v1.19.34"
            run.return_value.stderr = ""
            self.assertTrue(compiler._version_ok(Path("mihomo.exe")))
            self.assertEqual(run.call_args.args[0][-1], "-v")
            run.return_value.stdout = "unrelated"
            self.assertFalse(compiler._version_ok(Path("mihomo.exe")))
