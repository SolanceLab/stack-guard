# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.9.0: the secret guard no longer blocks commands; it still hides secret-shaped values in tool output and checks the final reply."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GUARD = os.path.join(ROOT, "plugin", "hooks", "secret_guard.py")
sys.path.insert(0, os.path.join(ROOT, "plugin", "scripts"))
import stack_guard as sg  # noqa: E402

j = lambda *parts: "".join(parts)  # build fakes in pieces so no real-looking literal sits in this file
FAKES = {
    "github token": j("ghp_", "Zq7" * 12),
    "AWS access key id": j("AKIA", "QZ7X" * 4),
    "OpenAI-style key": j("sk-", "proj-", "aB3d" * 10),
    "Slack bot token": j("xoxb-", "1234567890-", "abcdefABCDEF" * 2),
    "JWT": j("eyJ", "a" * 16, ".", "b" * 16, ".", "c" * 16),
}
NAMED = {"dotenv line under a secret name": ("API_KEY=", j("v4lue", "Q9" * 10)),
         "password under a secret name": ("DB_PASSWORD=", j("pa55", "Wz" * 9))}


def run(payload, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE_PLUGIN_OPTION_")}
    env["STACK_GUARD_ACTIVE"] = "1"
    return subprocess.run([sys.executable, GUARD, *args], input=json.dumps(payload), capture_output=True, text=True,
                          env=env, timeout=30)


class NoCommandCheck190(unittest.TestCase):
    def test_pre_tool_use_input_is_never_blocked(self):
        for tool, inp in (("Bash", {"command": "cat .env"}), ("Read", {"file_path": "/p/.env"}),
                          ("Grep", {"pattern": "TOKEN", "path": ".", "output_mode": "content"}),
                          ("Bash", {"command": "printenv"})):
            r = run({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp})
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""), (tool, inp))

    def test_hooks_json_has_no_pre_tool_use_secret_guard(self):
        with open(os.path.join(ROOT, "plugin", "hooks", "hooks.json"), encoding="utf-8") as fh:
            hooks = json.load(fh)["hooks"]
        cmds = lambda ev: [h.get("command", "") for e in hooks.get(ev, []) for h in e.get("hooks", [])]
        self.assertFalse(any("secret_guard.py" in c for c in cmds("PreToolUse")))
        self.assertEqual(len([c for c in cmds("PostToolUse") if "secret_guard.py" in c and "--post" in c]), 1)
        self.assertEqual(len([c for c in cmds("Stop") if "secret_guard.py" in c and "--stop" in c]), 1)
        self.assertEqual(len([c for c in cmds("SessionStart") if "update_check.py" in c]), 1)

    def test_command_check_code_is_gone(self):
        sys.path.insert(0, os.path.join(ROOT, "plugin", "hooks"))
        import secret_guard as g
        for n in ("pre_tool", "bash_violation", "bash_violation_pass", "is_secret_path", "unrestricted_content_search"):
            self.assertFalse(hasattr(g, n), n)
        for n in ("redact", "post_tool", "stop", "stack_guard_in_use", "option_off", "hide_named", "segments_sep"):
            self.assertTrue(callable(getattr(g, n, None)), n)


class OutputFilter190(unittest.TestCase):
    def post(self, text):
        return run({"tool_name": "Bash", "tool_input": {"command": "cat notes.txt"}, "tool_response": {"stdout": text}},
                   "--post")

    def test_fake_tokens_are_removed(self):
        for name, val in FAKES.items():
            with self.subTest(name=name):
                r = self.post("config line: " + val + "\n")
                self.assertEqual(r.returncode, 0)
                self.assertTrue(r.stdout)
                self.assertNotIn(val, r.stdout)
                self.assertIn("REDACTED", r.stdout)

    def test_named_values_are_removed(self):
        for name, (k, val) in NAMED.items():
            with self.subTest(name=name):
                r = self.post(k + val + "\n")
                self.assertEqual(r.returncode, 0)
                self.assertTrue(r.stdout)
                self.assertNotIn(val, r.stdout)
                self.assertIn("REDACTED", r.stdout)

    def test_clean_output_is_silent(self):
        r = self.post("all good\n")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))


class ReplyCheck190(unittest.TestCase):
    def stop(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        self.addCleanup(os.unlink, f.name)
        f.write(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}) + "\n")
        f.close()
        return run({"transcript_path": f.name}, "--stop")

    def test_fake_token_in_final_reply_is_flagged(self):
        token = FAKES["github token"]
        r = self.stop("your token is " + token)
        self.assertIn('"block"', r.stdout)
        self.assertNotIn(token, r.stdout)

    def test_clean_reply_is_silent(self):
        self.assertEqual(self.stop("all done").stdout, "")


class Version190(unittest.TestCase):
    def load(self, *rel):
        with open(os.path.join(ROOT, *rel), encoding="utf-8") as fh:
            return json.load(fh)

    def test_versions(self):
        self.assertEqual(sg.VERSION, "1.9.0")
        for rel in (("plugin", ".claude-plugin", "plugin.json"), ("plugin", ".codex-plugin", "plugin.json"),
                    ("plugins", "stack-guard", ".claude-plugin", "plugin.json")):
            self.assertEqual(self.load(*rel)["version"], sg.VERSION, rel)
        mk = self.load(".claude-plugin", "marketplace.json")
        self.assertEqual(mk["metadata"]["version"], sg.VERSION)
        for p in mk["plugins"]:
            if p["name"] == "stack-guard":
                self.assertEqual(p["version"], sg.VERSION)

    def test_changelog(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
            text = fh.read()
        heads = list(re.finditer(r"^## .*$", text, re.M))
        self.assertEqual(heads[0].group(), "## 1.9.0")
        self.assertEqual(heads[1].group(), "## 1.8.3")
        section = text[heads[0].end():heads[1].start()]
        self.assertEqual(len([l for l in section.splitlines() if l.startswith("- ")]), 2)

    def test_readme_points_to_deny_rules(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
            text = fh.read()
        for needle in ("Read(./.env)", "Read(./.env.*)", "https://code.claude.com/docs/en/settings"):
            self.assertIn(needle, text)
        self.assertIn("cover the Read tool only", text)
        for name in ("README.md", os.path.join("docs", "secret-guard.md"), "SECURITY.md", "CHANGELOG.md"):
            with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
                doc = fh.read()
            self.assertNotIn("secret files outright", doc, name + " must not promise a block it cannot give")


if __name__ == "__main__":
    unittest.main()
