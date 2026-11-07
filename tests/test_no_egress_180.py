# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.8.0: the egress guard is gone; the other hooks stay wired."""
import json
import os
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PLUGIN = os.path.join(ROOT, "plugin")


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


class NoEgress180Test(unittest.TestCase):
    def test_no_egress_in_manifests_or_hooks(self):
        for parts in (("plugin", "hooks", "hooks.json"), ("plugin", ".claude-plugin", "plugin.json"),
                      ("plugin", ".codex-plugin", "plugin.json"), (".claude-plugin", "marketplace.json")):
            self.assertNotIn("egress", read(*parts).lower(), parts)
        self.assertFalse(os.path.exists(os.path.join(PLUGIN, "hooks", "egress_guard.py")))

    def test_other_hooks_still_wired(self):
        text = read("plugin", "hooks", "hooks.json")
        self.assertEqual(text.count("secret_guard.py"), 3)
        self.assertEqual(text.count("update_check.py"), 1)
        json.loads(text)


if __name__ == "__main__":
    unittest.main()
