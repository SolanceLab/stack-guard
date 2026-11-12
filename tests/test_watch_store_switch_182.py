# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.8.2: the daily watch finds newer versions in any marketplace's cache folder."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugin", "scripts"))
import stack_guard as sg


class StoreSwitch(unittest.TestCase):
    def setUp(self):
        self.home = os.path.realpath(tempfile.mkdtemp())
        os.chmod(self.home, 0o755)
        real_expand = os.path.expanduser
        p = mock.patch.object(sg.os.path, "expanduser",
                              lambda x: x.replace("~", self.home, 1) if x.startswith("~") else real_expand(x))
        p.start()
        self.addCleanup(p.stop)
        q = mock.patch.dict(os.environ, {}, clear=False)
        q.start()
        self.addCleanup(q.stop)
        os.environ.pop("CLAUDE_PLUGIN_ROOT", None)

    def script(self, *parts, version="1.8.2"):
        d = os.path.join(self.home, *parts, "scripts")
        os.makedirs(d, exist_ok=True)
        cur = d
        while cur != self.home:
            os.chmod(cur, 0o755)
            cur = os.path.dirname(cur)
        f = os.path.join(d, "stack_guard.py")
        with open(f, "w") as fh:
            fh.write('VERSION = "%s"\n' % version)
        os.chmod(f, 0o644)
        return f

    def trust(self, root, name, repo):
        if root == ".codex":  # Codex records marketplaces in ~/.codex/config.toml
            d = os.path.join(self.home, ".codex")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "config.toml"), "a") as fh:
                fh.write('[marketplaces.%s]\nsource_type = "git"\nsource = "https://github.com/%s.git"\n\n' % (name, repo))
            return
        d = os.path.join(self.home, root, "plugins")
        os.makedirs(d, exist_ok=True)
        f = os.path.join(d, "known_marketplaces.json")
        try:
            with open(f) as fh:
                data = json.load(fh)
        except OSError:
            data = {}
        data[name] = {"source": {"source": "github", "repo": repo}}
        with open(f, "w") as fh:
            json.dump(data, fh)

    def run_with_record(self, recorded):
        cfg = lambda *a: os.path.join(self.home, "cfg", *a)
        if recorded:
            os.makedirs(cfg("bin"), exist_ok=True)
            with open(cfg("bin", sg.SOURCE_NOTE), "w") as fh:
                fh.write(recorded)
        with mock.patch.object(sg, "config_dir", cfg):
            return sg.newest_plugin_script()

    def test_claude_other_marketplace_newer_wins(self):
        old = self.script(".claude", "plugins", "cache", "stack-guard", "stack-guard", "1.8.1", version="1.8.1")
        new = self.script(".claude", "plugins", "cache", "solancelab", "stack-guard", "1.8.2")
        self.trust(".claude", "solancelab", "SolanceLab/plugins")
        self.assertEqual(self.run_with_record(old), new)

    def test_codex_other_marketplace_newer_wins(self):
        old = self.script(".codex", "plugins", "cache", "stack-guard", "stack-guard", "1.8.1", version="1.8.1")
        new = self.script(".codex", "plugins", "cache", "solancelab", "stack-guard", "1.8.2")
        self.trust(".codex", "solancelab", "SolanceLab/plugins")
        self.assertEqual(self.run_with_record(old), new)

    def test_codex_foreign_config_marketplace_ignored(self):
        self.script(".codex", "plugins", "cache", "evil", "stack-guard", "99.0.0", version="99.0.0")
        self.trust(".codex", "evil", "someone/else")
        self.assertIsNone(self.run_with_record(None))

    def test_found_with_no_recorded_source(self):
        new = self.script(".claude", "plugins", "cache", "solancelab", "stack-guard", "1.8.2")
        self.trust(".claude", "solancelab", "SolanceLab/plugins")
        self.assertEqual(self.run_with_record(None), new)

    def test_foreign_marketplace_with_higher_version_ignored(self):
        old = self.script(".claude", "plugins", "cache", "stack-guard", "stack-guard", "1.8.1", version="1.8.1")
        self.script(".claude", "plugins", "cache", "evil", "stack-guard", "99.0.0", version="99.0.0")
        self.trust(".claude", "evil", "someone/else")
        self.assertEqual(self.run_with_record(old), old)

    def test_unlisted_marketplace_ignored(self):
        self.script(".claude", "plugins", "cache", "evil", "stack-guard", "99.0.0", version="99.0.0")
        self.assertIsNone(self.run_with_record(None))

    def test_untrusted_marketplace_copies_ignored(self):
        elsewhere = self.script("work", "evil", version="9.9.9")
        link_dir = os.path.join(self.home, ".claude", "plugins", "cache", "evil", "stack-guard", "9.9.9")
        os.makedirs(os.path.join(link_dir, "scripts"))
        os.symlink(elsewhere, os.path.join(link_dir, "scripts", "stack_guard.py"))
        self.trust(".claude", "evil", "SolanceLab/plugins")
        self.trust(".claude", "wide", "SolanceLab/plugins")
        wide = self.script(".claude", "plugins", "cache", "wide", "stack-guard", "9.9.8", version="9.9.8")
        os.chmod(os.path.dirname(wide), 0o777)
        self.assertIsNone(self.run_with_record(None))


if __name__ == "__main__":
    unittest.main()
