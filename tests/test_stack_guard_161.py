# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Offline tests for 1.6.1: a stable Python for the daily watch, a self-refreshing script copy, and the depth option.
Run: python3 -m unittest discover -s tests -v"""
import os
import subprocess
import sys
import unittest
from unittest import mock

from test_stack_guard import Base, POSIX_ONLY
import stack_guard as sg


class StablePython(Base):
    def test_versioned_paths_fall_back_to_a_system_python(self):
        cellar = "/opt/homebrew/Cellar/python@3.13/3.13.1/bin/python3.13"
        framework = "/opt/homebrew/Cellar/python@3.13/3.13.1/Frameworks/Python.framework/Versions/3.13/bin/python3"
        for exe in (cellar, framework):
            with mock.patch.object(sys, "executable", exe), mock.patch.object(os.path, "exists", lambda p: p == "/usr/local/bin/python3"):
                self.assertEqual(sg.stable_python(), "/usr/local/bin/python3")

    def test_unversioned_path_is_kept(self):
        real = os.path.join(self.home, "py", "python3")
        os.makedirs(os.path.dirname(real))
        open(real, "w").close()
        with mock.patch.object(sys, "executable", real):
            self.assertEqual(sg.stable_python(), os.path.realpath(real))

    def test_windows_keeps_the_running_python(self):
        with mock.patch.object(sg, "platform_name", lambda: "windows"), mock.patch.object(sys, "executable", "C:\\Py\\Cellar\\python.exe"):
            self.assertEqual(sg.stable_python(), os.path.realpath("C:\\Py\\Cellar\\python.exe"))

    @POSIX_ONLY
    def test_scheduled_wrapper_logs_and_fails_when_python_or_copy_is_missing(self):
        gone = os.path.join(self.tmp, "no-such-python")
        script = os.path.join(self.tmp, "s.py")
        open(script, "w").close()
        r = subprocess.run(["/bin/sh", "-c", sg.WATCH_GUARD_SH, "sh", gone, script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 127)
        self.assertIn("the Python at", r.stdout)
        r = subprocess.run(["/bin/sh", "-c", sg.WATCH_GUARD_SH, "sh", sys.executable, os.path.join(self.tmp, "gone.py")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 127)
        self.assertIn("script copy", r.stdout)
        r = subprocess.run(["/bin/sh", "-c", sg.WATCH_GUARD_SH, "sh", sys.executable, script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


class ScriptCopyRefresh(Base):
    def make_plugin(self, version):
        d = os.path.join(self.tmp, "cache", "stack-guard", version, "scripts")
        os.makedirs(d)
        path = os.path.join(d, "stack_guard.py")
        with open(path, "w") as fh:
            fh.write('VERSION = "%s"\n' % version)
        return path

    def test_newer_plugin_script_replaces_the_copy_and_logs_one_line(self):
        old = self.make_plugin("1.6.1")
        newer = self.make_plugin("1.6.2")
        copy = sg.stable_script_path()
        os.makedirs(os.path.dirname(copy), exist_ok=True)
        with open(copy, "w") as fh:
            fh.write('VERSION = "1.6.1"\n')
        sg.write_file(os.path.join(os.path.dirname(copy), sg.SOURCE_NOTE), old)  # the path recorded at watch-install
        # the refresh mechanics are tested here; which folders may supply the script is tested in 1.6.2
        with mock.patch.object(sg, "__file__", copy), mock.patch.object(sg, "VERSION", "1.6.1"), \
                mock.patch.object(sg, "trusted_plugin_script", lambda p: True), mock.patch("builtins.print") as pr:
            self.assertTrue(sg.refresh_script_copy())
        self.assertEqual(sg.script_version(copy), "1.6.2")
        self.assertEqual(pr.call_count, 1)

    def test_same_version_or_not_the_copy_changes_nothing(self):
        plug = self.make_plugin("1.6.1")
        copy = sg.stable_script_path()
        os.makedirs(os.path.dirname(copy), exist_ok=True)
        with open(copy, "w") as fh:
            fh.write('VERSION = "1.6.1"\n')
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_ROOT": os.path.dirname(os.path.dirname(plug))}):
            with mock.patch.object(sg, "__file__", copy):
                self.assertFalse(sg.refresh_script_copy())
            self.make_plugin("1.6.3")
            with mock.patch.object(sg, "__file__", plug):  # run from the plugin itself, not the scheduled copy
                self.assertFalse(sg.refresh_script_copy())
        self.assertEqual(sg.script_version(copy), "1.6.1")


class DepthOption(Base):
    def test_depth_option_reaches_a_deeper_folder(self):
        deep = os.path.join(self.folder, *["d"] * 7)
        os.makedirs(deep)
        with open(os.path.join(deep, "package-lock.json"), "w") as fh:
            fh.write('{"packages": {}}')
        inv = sg.build_inventory(self.folder)
        self.assertTrue(inv["too_deep"])
        with mock.patch.object(sg, "MAX_DEPTH", 10):
            self.assertFalse(sg.build_inventory(self.folder)["too_deep"])


if __name__ == "__main__":
    unittest.main()
