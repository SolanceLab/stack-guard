# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Offline tests for 1.5.4: the three user settings (secret_guard, reply_check, update_check).
Run: python3 -m unittest discover -s tests -v"""
import importlib.util
import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from test_stack_guard import Base, HERE
import stack_guard as sg

ROOT = os.path.abspath(os.path.join(HERE, ".."))
PLUGIN = os.path.join(ROOT, "plugins", "stack-guard")
SECRET_VALUE = "SETTINGS-CANARY-4d3c2b1a"
HOOKS = os.path.join(PLUGIN, "hooks")


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HOOKS, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE_PLUGIN_OPTION_") and k != "PLUGIN_UPDATE_CHECK"}
    env.update(extra)
    return env


class OptionValues(Base):
    def test_off_words_any_case_and_spacing(self):
        for v in ("False", " 0 ", "OFF", "no", "false"):
            self.assertTrue(sg.option_off("update_check", {"CLAUDE_PLUGIN_OPTION_UPDATE_CHECK": v}), v)
        for v in ("true", "True", "1", "", "yes"):
            self.assertFalse(sg.option_off("update_check", {"CLAUDE_PLUGIN_OPTION_UPDATE_CHECK": v}), v)
        self.assertFalse(sg.option_off("update_check", {}))
        guard = load("secret_guard")
        for v in ("False", " 0 ", "OFF"):
            with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_OPTION_SECRET_GUARD": v}):
                self.assertTrue(guard.option_off("secret_guard"), v)
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_OPTION_SECRET_GUARD": "true"}):
            self.assertFalse(guard.option_off("secret_guard"))

    def test_plugin_json_user_config_shape(self):
        with open(os.path.join(PLUGIN, ".claude-plugin", "plugin.json"), encoding="utf-8") as fh:
            uc = json.load(fh)["userConfig"]
        self.assertEqual(sorted(uc), ["reply_check", "secret_guard", "update_check"])
        for key, opt in uc.items():
            self.assertEqual(opt["type"], "boolean", key)
            self.assertIs(opt["default"], True, key)
            self.assertFalse(opt.get("required", False), key)
            self.assertTrue(opt["title"] and opt["description"], key)
            self.assertLessEqual(set(opt), {"type", "title", "description", "default", "required"}, key)


class HookSettings(unittest.TestCase):
    def run_hook(self, argv, env_opts):
        guard = load("secret_guard")
        reader = mock.Mock(return_value=False)
        payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/p/.env"}, "transcript_path": "/nope"})
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, clean_env(**env_opts), clear=True), mock.patch.object(sys, "argv", ["secret_guard.py"] + argv), \
                mock.patch.object(sys, "stdin", io.StringIO(payload)), mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err), \
                mock.patch.object(guard, "stack_guard_in_use", reader), mock.patch.object(guard, "marker_in_file", reader), \
                mock.patch.object(guard, "transcript_lines", reader):
            try:
                guard.main()
                code = 0
            except SystemExit as e:
                code = e.code or 0
        return code, out.getvalue(), err.getvalue(), reader

    def test_secret_guard_off_silences_all_three_hooks_and_reads_nothing(self):
        for argv in ([], ["--post"], ["--stop"]):
            code, out, err, reader = self.run_hook(argv, {"CLAUDE_PLUGIN_OPTION_SECRET_GUARD": "false"})
            self.assertEqual((code, out, err), (0, "", ""), argv)
            reader.assert_not_called()

    def test_reply_check_off_silences_only_stop(self):
        code, out, err, reader = self.run_hook(["--stop"], {"CLAUDE_PLUGIN_OPTION_REPLY_CHECK": "OFF"})
        self.assertEqual((code, out, err), (0, "", ""))
        reader.assert_not_called()

    def test_reply_check_off_leaves_pre_and_post_working(self):
        env = dict(STACK_GUARD_ACTIVE="1", CLAUDE_PLUGIN_OPTION_REPLY_CHECK="false")
        pre = subprocess.run([sys.executable, os.path.join(HOOKS, "secret_guard.py")], capture_output=True, text=True, env=clean_env(**env),
                             input=json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/p/.env"}}))
        self.assertEqual(pre.returncode, 2)
        self.assertIn("stack-guard secret guard", pre.stderr)
        token = "ghp_" + "a" * 30
        post = subprocess.run([sys.executable, os.path.join(HOOKS, "secret_guard.py"), "--post"], capture_output=True, text=True, env=clean_env(**env),
                              input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": {"stdout": "k=" + token}}))
        self.assertNotIn(token, post.stdout)
        self.assertIn("REDACTED", post.stdout)

    def test_options_on_or_missing_keep_the_hook_running(self):
        for opts in ({}, {"CLAUDE_PLUGIN_OPTION_SECRET_GUARD": "true", "CLAUDE_PLUGIN_OPTION_REPLY_CHECK": "true"}):
            _, _, _, reader = self.run_hook([], opts)
            reader.assert_called()

    def test_update_check_hook_off_makes_no_request(self):
        upd = load("update_check")
        for env in ({"PLUGIN_UPDATE_CHECK": "0"}, {"CLAUDE_PLUGIN_OPTION_UPDATE_CHECK": " False "}):
            out = io.StringIO()
            with mock.patch.object(upd, "fetch", side_effect=AssertionError("network")):
                upd.run(["https://example.invalid/p.json", "m"], env, os.path.join(HOOKS, "update_check.py"), out)
            self.assertEqual(out.getvalue(), "")


class ScriptUpdateSettings(Base):
    def setUp(self):
        super().setUp()
        self.net.latest = "9.9.9"
        p = mock.patch.dict(os.environ, clean_env(), clear=True)
        p.start()
        self.addCleanup(p.stop)

    def save(self, text):
        os.makedirs(os.path.join(self.home, ".claude"), exist_ok=True)
        with open(os.path.join(self.home, ".claude", "settings.json"), "w", encoding="utf-8") as fh:
            fh.write(text)

    def assert_no_fetch(self):
        self.assertIsNone(sg.latest_version())
        self.assertIsNone(sg.update_line())
        code, out = self.run_main("version-check")
        self.assertEqual((code, out.strip()), (0, "Update check is turned off."))
        self.run_main("check", self.folder)
        self.assertEqual(self.net.calls.count(sg.LATEST_URL), 0)

    def test_on_by_default_and_with_unreadable_settings(self):
        self.assertEqual(sg.latest_version(), "9.9.9")
        os.remove(sg.config_dir("latest.json"))
        self.save("{not json")
        self.assertEqual(sg.latest_version(), "9.9.9")

    def test_env_plugin_option_off_means_no_fetch(self):
        os.environ["CLAUDE_PLUGIN_OPTION_UPDATE_CHECK"] = "false"
        self.assert_no_fetch()

    def test_env_kill_switch_still_works(self):
        os.environ["PLUGIN_UPDATE_CHECK"] = "0"
        self.assert_no_fetch()

    def test_saved_setting_off_means_no_fetch(self):
        self.save(json.dumps({"pluginConfigs": {"stack-guard@stack-guard": {"options": {"update_check": False}}}}))
        self.assert_no_fetch()

    def test_saved_setting_on_or_other_plugin_stays_on(self):
        self.save(json.dumps({"pluginConfigs": {"stack-guard@stack-guard": {"options": {"update_check": True}},
                                                "other@x": {"options": {"update_check": False}}}}))
        self.assertEqual(sg.latest_version(), "9.9.9")

    def test_other_settings_never_appear_in_output(self):
        self.save(json.dumps({"env": {"MY_KEY": SECRET_VALUE}, "apiKeyHelper": SECRET_VALUE,
                              "pluginConfigs": {"stack-guard@stack-guard": {"options": {"update_check": "off", "reply_check": SECRET_VALUE}}}}))
        seen = [self.run_main("version-check")[1], self.run_main("check", self.folder)[1]]
        for dirpath, _, files in os.walk(self.folder):
            for fn in files:
                with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as fh:
                    seen.append(fh.read())
        self.assertNotIn(SECRET_VALUE, "\n".join(seen))
        self.assertEqual(self.net.calls.count(sg.LATEST_URL), 0)


if __name__ == "__main__":
    unittest.main()
