"""1.6.2: the daily watch refreshes its script copy only from the user's own plugin folders."""
import os
import tempfile
import unittest
from unittest import mock

import stack_guard as sg


class TrustedRefreshSource(unittest.TestCase):
    def setUp(self):
        self.home = os.path.realpath(tempfile.mkdtemp())
        os.chmod(self.home, 0o755)
        real_expand = os.path.expanduser
        self.patch = mock.patch.object(sg.os.path, "expanduser",
                                       lambda p: p.replace("~", self.home, 1) if p.startswith("~") else real_expand(p))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def script(self, *parts, mode=0o644, dirmode=0o755):
        d = os.path.join(self.home, *parts)
        os.makedirs(d, exist_ok=True)
        cur = d
        while cur != self.home:
            os.chmod(cur, dirmode)
            cur = os.path.dirname(cur)
        f = os.path.join(d, "stack_guard.py")
        with open(f, "w") as fh:
            fh.write('VERSION = "9.9.9"\n')
        os.chmod(f, mode)
        return f

    def test_plugin_folder_is_trusted(self):
        f = self.script(".claude", "plugins", "cache", "stack-guard", "stack-guard", "9.9.9", "scripts")
        self.assertTrue(sg.trusted_plugin_script(f))

    def test_codex_plugin_folder_is_trusted(self):
        self.assertTrue(sg.trusted_plugin_script(self.script(".codex", "plugins", "stack-guard", "scripts")))

    def test_a_project_folder_is_not_trusted(self):
        self.assertFalse(sg.trusted_plugin_script(self.script("work", "some-project", "scripts")))

    def test_a_link_out_of_the_plugin_folder_is_not_trusted(self):
        outside = self.script("work", "evil", "scripts")
        d = os.path.join(self.home, ".claude", "plugins", "cache", "x", "1", "scripts")
        os.makedirs(d, exist_ok=True)
        link = os.path.join(d, "stack_guard.py")
        os.symlink(outside, link)
        self.assertFalse(sg.trusted_plugin_script(link))

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_writable_by_others_is_not_trusted(self):
        f = self.script(".claude", "plugins", "cache", "sg", "1", "scripts", mode=0o666)
        self.assertFalse(sg.trusted_plugin_script(f))
        g = self.script(".claude", "plugins", "cache", "sg2", "1", "scripts", dirmode=0o777)
        self.assertFalse(sg.trusted_plugin_script(g))

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_writable_folder_above_the_plugins_root_is_not_trusted(self):
        f = self.script(".claude", "plugins", "cache", "sg3", "1", "scripts")
        os.chmod(os.path.join(self.home, ".claude"), 0o777)
        try:
            self.assertFalse(sg.trusted_plugin_script(f))
        finally:
            os.chmod(os.path.join(self.home, ".claude"), 0o755)
        os.chmod(self.home, 0o777)
        try:
            self.assertFalse(sg.trusted_plugin_script(f))
        finally:
            os.chmod(self.home, 0o755)

    def test_newest_plugin_script_ignores_untrusted_candidates(self):
        evil = self.script("work", "evil", "scripts")
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_ROOT": os.path.dirname(os.path.dirname(evil))}):
            with mock.patch.object(sg, "config_dir", lambda *a: os.path.join(self.home, "nowhere", *a)):
                self.assertIsNone(sg.newest_plugin_script())


if __name__ == "__main__":
    unittest.main()
