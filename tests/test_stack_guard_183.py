# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.8.3: the update notice names the store you installed from."""
import importlib.util
import io
import json
import ntpath
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "plugin", "scripts"))
import stack_guard as sg  # noqa: E402

WIN_CLAUDE = r"C:\Users\a\.claude\plugins\cache\solancelab\stack-guard\1.8.3\scripts\stack_guard.py"
WIN_CODEX = r"C:\Users\a\.codex\plugins\cache\mystore\stack-guard\1.8.3\scripts\stack_guard.py"


class UpdateNotice183(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for p in (mock.patch.object(sg, "config_dir", lambda *p: os.path.join(self.tmp, *p)),
                  mock.patch.object(sg, "latest_version", return_value="9.9.9")):
            p.start()
            self.addCleanup(p.stop)

    def at(self, path):
        return mock.patch.object(sg, "__file__", path)

    def test_claude_cache(self):
        with self.at("/h/.claude/plugins/cache/solancelab/stack-guard/1.8.3/scripts/stack_guard.py"):
            self.assertEqual(sg.install_marketplace(), "solancelab")
            long_line, short = sg.update_line(), sg.update_line(short=True)
        for s in ("claude plugin marketplace update solancelab", "claude plugin update stack-guard@solancelab",
                  "codex plugin marketplace upgrade solancelab", "codex plugin add stack-guard@solancelab"):
            self.assertIn(s, long_line)
        self.assertNotIn("stack-guard@stack-guard", long_line)
        self.assertTrue(short.endswith("claude plugin update stack-guard@solancelab"))

    def test_old_store(self):
        with self.at("/h/.claude/plugins/cache/stack-guard/stack-guard/1.8.3/scripts/stack_guard.py"):
            self.assertIn("stack-guard@stack-guard", sg.update_line(short=True))

    def test_codex_cache(self):
        with self.at("/h/.codex/plugins/cache/mystore/stack-guard/1.8.3/scripts/stack_guard.py"):
            self.assertEqual(sg.install_marketplace(), "mystore")

    def test_windows_paths(self):
        self.assertEqual(sg.CACHE_MARKETPLACE.search(WIN_CLAUDE).group(1), "solancelab")
        self.assertEqual(sg.CACHE_MARKETPLACE.search(WIN_CODEX).group(1), "mystore")
        with mock.patch.object(sg.os.path, "abspath", ntpath.abspath), mock.patch.object(sg.os.path, "realpath", ntpath.abspath):
            with self.at(WIN_CLAUDE):
                self.assertEqual(sg.install_marketplace(), "solancelab")
            with self.at(WIN_CODEX):
                self.assertEqual(sg.install_marketplace(), "mystore")

    def test_non_cache_falls_back(self):
        with self.at("/x/repo/plugin/scripts/stack_guard.py"):
            self.assertEqual(sg.install_marketplace(), "solancelab")

    def test_watch_note(self):
        os.makedirs(os.path.join(self.tmp, "bin"))
        with open(os.path.join(self.tmp, "bin", sg.SOURCE_NOTE), "w", encoding="utf-8") as fh:
            fh.write("/h/.claude/plugins/cache/otherstore/stack-guard/1.8.3/scripts/stack_guard.py")
        with self.at("/x/repo/plugin/scripts/stack_guard.py"):
            self.assertEqual(sg.install_marketplace(), "otherstore")

    def test_symlink(self):
        real = os.path.join(self.tmp, ".claude", "plugins", "cache", "linkstore", "stack-guard", "1.8.3")
        os.makedirs(os.path.join(real, "scripts"))
        open(os.path.join(real, "scripts", "stack_guard.py"), "w").close()
        link = os.path.join(self.tmp, "link")
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            self.skipTest("no symlinks here")
        with self.at(os.path.join(link, "scripts", "stack_guard.py")):
            self.assertEqual(sg.install_marketplace(), "linkstore")

    def test_name_length(self):
        tpl = "/h/.claude/plugins/cache/%s/stack-guard/1.8.3/scripts/stack_guard.py"
        with self.at(tpl % ("a" * 31)):
            self.assertEqual(sg.install_marketplace(), "solancelab")
        with self.at(tpl % ("a" * 30)):
            self.assertEqual(sg.install_marketplace(), "a" * 30)
            self.assertLess(len(sg.update_line(short=True)), 120)

    def test_shell_characters(self):
        for name in ("a;b", "a b", "$x", "a`b"):
            with self.subTest(name=name), self.at("/h/.claude/plugins/cache/%s/stack-guard/1.8.3/scripts/stack_guard.py" % name):
                self.assertEqual(sg.install_marketplace(), "solancelab")

    def test_ascii_and_watch_sentence(self):
        long_line, short = sg.update_line(), sg.update_line(short=True)
        long_line.encode("ascii")
        short.encode("ascii")
        self.assertIn("Using the daily watch? Run /stack-guard:watch again afterwards", long_line)


class UpdateCheckHook183(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        spec = importlib.util.spec_from_file_location("update_check_183", os.path.join(ROOT, "plugin", "hooks", "update_check.py"))
        self.upd = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.upd)
        p = mock.patch.object(self.upd, "fetch", return_value={"name": "stack-guard", "version": "9.9.9"})
        p.start()
        self.addCleanup(p.stop)

    def make(self, *base):
        root = os.path.join(self.tmp, *base)
        os.makedirs(os.path.join(root, ".claude-plugin"))
        os.makedirs(os.path.join(root, "hooks"))
        with open(os.path.join(root, ".claude-plugin", "plugin.json"), "w", encoding="utf-8") as fh:
            json.dump({"name": "stack-guard", "version": "1.0.0"}, fh)
        return os.path.join(root, "hooks", "update_check.py")

    def message(self, script, data):
        out = io.StringIO()
        self.upd.run(["https://example.invalid/p.json", "solancelab"], {"CLAUDE_PLUGIN_DATA": os.path.join(self.tmp, data)}, script, out)
        return json.loads(out.getvalue())["systemMessage"]

    def test_cache_install(self):
        msg = self.message(self.make(".claude", "plugins", "cache", "mystore", "stack-guard", "1.0.0"), "d1")
        self.assertIn("claude plugin update stack-guard@mystore", msg)
        self.assertIn("Marketplaces > mystore > Enable auto-update", msg)

    def test_plain_directory(self):
        msg = self.message(self.make("plain", "stack-guard"), "d2")
        self.assertIn("stack-guard@solancelab", msg)

    def test_windows_path(self):
        with mock.patch.object(self.upd.os.path, "abspath", ntpath.abspath), mock.patch.object(self.upd.os.path, "realpath", ntpath.abspath):
            got = self.upd.installed_marketplace(
                r"C:\Users\a\.claude\plugins\cache\mystore\stack-guard\1.0.0\hooks\update_check.py", "stack-guard", "solancelab")
        self.assertEqual(got, "mystore")

    def test_hooks_json(self):
        with open(os.path.join(ROOT, "plugin", "hooks", "hooks.json"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("plugin.json solancelab || true", text)
        self.assertNotIn("plugin.json stack-guard ||", text)


class NoRetiredStoreText(unittest.TestCase):
    def test_no_old_store_name(self):
        files = []
        for base, dirs, names in os.walk(os.path.join(ROOT, "plugin")):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            files += [os.path.join(base, n) for n in names if not n.endswith(".pyc")]
        docs = os.path.join(ROOT, "docs")
        if os.path.isdir(docs):
            files += [os.path.join(docs, n) for n in os.listdir(docs) if n.endswith(".md")]
        files.append(os.path.join(ROOT, "README.md"))
        for path in files:
            try:
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            self.assertNotIn("stack-guard@stack-guard", text, path)


class Version183(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
