# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.9.1: when OSV cannot be reached, the report and the notification never print a false all-clear."""
import os
import sys
import tempfile
import contextlib
import io
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "plugin", "scripts"))
import stack_guard as sg  # noqa: E402

NOT_CHECKED = "Not checked: OSV could not be reached"


def section(text, head):
    """The lines under a '## ' heading, up to the next one."""
    out, on = [], False
    for ln in text.splitlines():
        if ln.startswith("## "):
            on = ln.startswith(head)
            continue
        if on:
            out.append(ln)
    return out


class OsvUnreachable191(unittest.TestCase):
    def render(self, osv_ok):
        with tempfile.TemporaryDirectory() as folder:
            inv = sg.build_inventory(folder)
            rep = sg.make_report(inv, [], [], osv_ok)
            rep["runtimes"] = []  # no host runtime lookups in this test
            return rep, sg.render_report(rep, sg.diff_reports(None, rep, None))

    def test_unreachable_says_not_checked_in_both_sections(self):
        _, text = self.render(False)
        for head in ("## \U0001F534 Fix first", "## \U0001F7E0 Also worth fixing"):
            lines = section(text, head)
            self.assertTrue(any(l.startswith(NOT_CHECKED) for l in lines), head)
            self.assertNotIn("None.", lines, head)

    def test_reachable_still_says_none(self):
        _, text = self.render(True)
        self.assertNotIn(NOT_CHECKED, text)
        self.assertIn("None.", section(text, "## \U0001F534 Fix first"))
        self.assertIn("None.", section(text, "## \U0001F7E0 Also worth fixing"))

    def test_notify_text_says_packages_not_checked(self):
        rep, _ = self.render(False)
        diff = {"first": True, "new": [], "fixed": [], "runtimes": [], "mcp": []}
        head, body = sg.notify_text(rep, diff)
        self.assertIn("packages NOT checked (OSV unreachable)", head)
        rep, _ = self.render(True)
        self.assertNotIn("OSV unreachable", sg.notify_text(rep, diff)[0])

    def test_tools_section_not_an_all_clear(self):
        rep, _ = self.render(False)
        rep["tools"] = [{"name": "npm", "version": "10.0.0", "path": "/x/npm"}]
        text = sg.render_report(rep, sg.diff_reports(None, rep, None))
        self.assertNotIn("No known problems in these tools.", text)
        self.assertIn("these tools were not looked up", text)

    def test_repeat_check_does_not_say_nothing_new(self):
        prev, _ = self.render(True)
        rep, _ = self.render(False)
        lines = sg.diff_lines(sg.diff_reports(prev, rep, None), True)
        self.assertNotIn("Nothing new since the last check.", lines)
        self.assertTrue(any(l.startswith("Nothing to compare") for l in lines))
        lines_ok = sg.diff_lines(sg.diff_reports(prev, prev, None), True)
        self.assertIn("Nothing new since the last check.", lines_ok)

    def test_notify_body_says_packages_not_checked(self):
        rep, _ = self.render(False)
        diff = {"first": True, "new": [], "fixed": [], "runtimes": [], "mcp": []}
        _, body = sg.notify_text(rep, diff)
        self.assertIn("packages NOT checked (OSV unreachable)", body)

    def test_terminal_summary_says_packages_not_checked(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(sg, "osv_check", return_value=None), \
                mock.patch.object(sg, "fallback_check", return_value=None), \
                mock.patch.object(sg, "eol_check", side_effect=lambda rts, errs: [r.update(status="unknown", update=False, latest=None) for r in rts]), \
                mock.patch.object(sg, "update_line", return_value=""):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                sg.cmd_check(folder, notify=False)
        text = out.getvalue()
        self.assertIn("packages NOT checked, OSV could not be reached", text)
        self.assertIn("among what could be checked", text)

    def test_version(self):
        self.assertEqual(sg.VERSION, "1.10.1")


if __name__ == "__main__":
    unittest.main()
