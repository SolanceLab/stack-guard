# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Offline tests for 1.5.6: fixes wait for a safe release age, and known malicious releases come first.
Run: python3 -m unittest discover -s tests -v"""
import datetime
import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from test_stack_guard import Base
import stack_guard as sg

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def npm_doc(version, stamp):
    return {"time": {"created": "2020-01-01T00:00:00.000Z", version: stamp}}


def pypi_doc(*stamps):
    return {"urls": [{"upload_time_iso_8601": s} for s in stamps]}


class ReleaseAge(unittest.TestCase):
    def test_old_enough_npm(self):
        code, line = sg.release_age("npm", "lodash", "4.17.21", lambda url: npm_doc("4.17.21", "2026-10-20T12:00:00.000Z"), NOW)
        self.assertEqual(code, 0)
        self.assertEqual(line, "lodash 4.17.21: published 2026-10-20T12:00:00Z, 216 hours ago — OK")

    def test_too_new_says_when_to_come_back(self):
        code, line = sg.release_age("npm", "@types/node", "9.9.9", lambda url: npm_doc("9.9.9", "2026-10-29T06:00:00.000Z"), NOW)
        self.assertEqual(code, 3)
        self.assertIn("TOO NEW, wait until 2026-10-31T06:00:00Z", line)

    def test_npm_scoped_name_is_url_encoded(self):
        seen = []
        sg.release_age("npm", "@types/node", "1.0.0", lambda url: seen.append(url) or npm_doc("1.0.0", "2026-01-01T00:00:00Z"), NOW)
        self.assertEqual(seen, ["https://registry.npmjs.org/%40types%2Fnode"])

    def test_pypi_uses_latest_upload(self):
        code, line = sg.release_age("PyPI", "requests", "2.32.0",
                                    lambda url: pypi_doc("2026-10-29T10:00:00.000000Z", "2026-10-01T00:00:00.000000Z"), NOW)
        self.assertEqual(code, 3, line)
        self.assertIn("published 2026-10-29T10:00:00Z", line)

    def test_unknown_version_and_fetch_error_are_not_proven(self):
        self.assertEqual(sg.release_age("npm", "lodash", "1.0.0", lambda url: npm_doc("2.0.0", "2026-01-01T00:00:00Z"), NOW)[0], 2)
        self.assertEqual(sg.release_age("PyPI", "requests", "1.0.0", lambda url: pypi_doc(), NOW)[0], 2)

        def boom(url):
            raise OSError("offline")
        code, line = sg.release_age("npm", "lodash", "1.0.0", boom, NOW)
        self.assertEqual(code, 2)
        self.assertTrue(line.startswith("unknown:"))
        code, _ = sg.release_age("npm", "lodash", "1.0.0", lambda url: npm_doc("1.0.0", "not a date"), NOW)
        self.assertEqual(code, 2)

    def test_bad_input_never_reaches_the_registry(self):
        fetch = mock.Mock()
        self.assertEqual(sg.release_age("npm", "bad name;", "1.0.0", fetch, NOW)[0], 2)
        self.assertEqual(sg.release_age("gem", "rails", "1.0.0", fetch, NOW)[0], 2)
        fetch.assert_not_called()

    def test_min_hours_override_order(self):
        with mock.patch.dict(os.environ, {"STACK_GUARD_MIN_RELEASE_HOURS": "6"}), mock.patch.object(sg, "saved_option", lambda n: None):
            self.assertEqual(sg.min_release_hours(), 6)
            self.assertEqual(sg.min_release_hours("1"), 1)
            self.assertEqual(sg.min_release_hours("junk"), 6)
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(sg, "saved_option", lambda n: None):
            self.assertEqual(sg.min_release_hours(), 48)
        stamp = "2026-10-29T06:00:00Z"
        self.assertEqual(sg.release_age("npm", "a", "1.0.0", lambda u: npm_doc("1.0.0", stamp), NOW, min_hours=48)[0], 3)
        self.assertEqual(sg.release_age("npm", "a", "1.0.0", lambda u: npm_doc("1.0.0", stamp), NOW, min_hours=2)[0], 0)


class ReleaseAgeBounds(unittest.TestCase):
    def test_non_finite_or_huge_hours_never_crash(self):
        fetch = lambda url: npm_doc("1.0.0", "2026-10-20T12:00:00Z")
        for bad in (float("inf"), float("nan"), 1e309, 1e18):
            code, line = sg.release_age("npm", "lodash", "1.0.0", fetch, NOW, bad)
            self.assertEqual(code, 2)
            self.assertTrue(line.startswith("unknown:"))

    def test_setting_falls_back_to_default_for_inf_and_huge(self):
        for bad in ("inf", "1e309", "nan", "1e18"):
            self.assertEqual(sg.min_release_hours(bad), sg.DEFAULT_MIN_RELEASE_HOURS)


class StackFixPinsCheckedVersion(unittest.TestCase):
    def test_skill_pins_instead_of_ranges(self):
        text = open(os.path.join(os.path.dirname(__file__), "..", "plugins", "stack-guard", "skills", "stack-fix", "SKILL.md")).read()
        self.assertIn("--save-exact", text)
        self.assertNotIn('"^7.3.7"', text)


class ReleaseAgeCli(Base):
    def run_cli(self, *args, now_stamp="2026-10-01T00:00:00Z"):
        net = mock.Mock(side_effect=lambda url, *a, **k: npm_doc("1.0.0", now_stamp) if "npmjs" in url else pypi_doc(now_stamp))
        out = io.StringIO()
        with mock.patch.object(sg, "http_json", net), redirect_stdout(out), mock.patch.dict(os.environ, {}, clear=False):
            code = sg.main(["release-age", *args])
        return code, out.getvalue().strip(), net

    def test_exit_codes(self):
        code, out, _ = self.run_cli("npm", "lodash", "1.0.0")
        self.assertEqual((code, out.endswith("OK")), (0, True), out)
        code, out, _ = self.run_cli("npm", "lodash", "1.0.0", "--min-hours", "100000")
        self.assertEqual(code, 3, out)
        code, out, _ = self.run_cli("npm", "lodash", "2.0.0")
        self.assertEqual(code, 2, out)

    def test_private_npm_name_is_not_looked_up(self):
        code, out, net = self.run_cli("npm", "@scope/pkg", "1.0.0")
        self.assertEqual((code, out), (2, "unknown: private package, release date not looked up"))
        net.assert_not_called()
        code, out, net = self.run_cli("npm", "@scope/pkg", "1.0.0", "--folder", os.path.join(self.folder, "app"))
        self.assertEqual(code, 2)
        net.assert_not_called()

    def test_unknown_scope_stays_unlooked_even_with_registry_lockfile(self):
        # npm private packages are scoped and resolve from registry.npmjs.org too, so a lockfile cannot prove a
        # scoped name outside the known open-source scopes is public; the name must not leave the machine.
        import json
        proj = os.path.join(self.tmp, "pub")
        os.makedirs(proj)
        with open(os.path.join(proj, "package.json"), "w", encoding="utf-8") as fh:
            json.dump({"dependencies": {"@acme/js": "1.0.0"}}, fh)
        with open(os.path.join(proj, "package-lock.json"), "w", encoding="utf-8") as fh:
            json.dump({"lockfileVersion": 3, "packages": {"node_modules/@acme/js": {
                "version": "1.0.0", "resolved": "https://registry.npmjs.org/@acme/js/-/js-1.0.0.tgz"}}}, fh)
        code, out, net = self.run_cli("npm", "@acme/js", "1.0.0", "--folder", proj)
        self.assertEqual(code, 2, out)
        net.assert_not_called()

    def test_private_pypi_name_is_not_looked_up(self):
        proj = os.path.join(self.tmp, "priv")
        os.makedirs(proj)
        with open(os.path.join(proj, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("secretlib @ git+https://git.example/secretlib.git\nrequests==1.0.0\n")
        code, out, net = self.run_cli("PyPI", "secretlib", "1.0.0", "--folder", proj)
        self.assertEqual((code, out), (2, "unknown: private package, release date not looked up"))
        net.assert_not_called()
        code, out, net = self.run_cli("PyPI", "requests", "1.0.0", "--folder", proj)
        self.assertEqual(code, 0, out)
        code, out, net = self.run_cli("PyPI", "flask", "1.0.0", "--folder", proj)   # not one of this project's packages
        self.assertEqual(code, 2, out)
        net.assert_not_called()

    def test_private_index_for_the_computer_keeps_pypi_names_home(self):
        with mock.patch.dict(os.environ, {"PIP_INDEX_URL": "https://corp-mirror.example/simple"}):
            sg._global_index = None
            code, _, net = self.run_cli("PyPI", "requests", "1.0.0")
        self.assertEqual(code, 2)
        net.assert_not_called()


class MaliciousReleases(Base):
    def test_id_and_alias_make_malicious(self):
        self.assertEqual(sg.vuln_severity({"id": "MAL-2026-1234"}), "MALICIOUS")
        self.assertEqual(sg.vuln_severity({"id": "GHSA-x", "aliases": ["MAL-2026-9"]}), "MALICIOUS")
        self.assertEqual(sg.vuln_severity({}, "MAL-2026-5"), "MALICIOUS")
        self.assertEqual(sg.vuln_severity({"id": "GHSA-x", "aliases": ["CVE-2026-1"]}), "UNKNOWN")
        self.assertGreater(sg.SEV_ORDER["MALICIOUS"], sg.SEV_ORDER["CRITICAL"])

    def test_report_shows_malicious_first_and_counts_it(self):
        sg.http_json.vulns = {"lodash": ["MAL-2026-1234"], "requests": ["GHSA-dddd-eeee-ffff"]}
        inv = sg.build_inventory(self.folder)
        errors = []
        findings = sg.osv_check(sg.collect_targets(inv), os.path.join(self.tmp, "cache"), errors)
        mal = [f for f in findings if f["id"] == "MAL-2026-1234"]
        self.assertTrue(mal and all(f["severity"] == "MALICIOUS" for f in mal))
        sg.eol_check(inv["runtimes"], errors)
        rep = sg.make_report(inv, findings, errors, True)
        self.assertTrue(any(c["MALICIOUS"] for c in rep["counts"].values()))
        diff = sg.diff_reports(None, rep, None)
        text = sg.render_report(rep, diff)
        self.assertIn("## Known malicious releases", text)
        self.assertLess(text.index("Known malicious releases"), text.index("New since last check"))
        self.assertEqual(text.count("MAL-2026-1234"), 1)

    def test_malicious_notifies_even_in_dev_packages(self):
        f = {"key": "k", "id": "MAL-1", "severity": "MALICIOUS", "dev": True, "deploy": False, "package": "x", "version": "1", "project": "p",
             "ecosystem": "npm", "fixed": [], "summary": "s"}
        rep = {"date": "2026-10-29", "not_checked": [], "findings": [f]}
        diff = {"first": False, "new": [{"key": "k", "text": "x"}], "fixed": [], "runtimes": [], "mcp": []}
        self.assertIn("Run /stack-guard", sg.notify_text(rep, diff)[1])


if __name__ == "__main__":
    unittest.main()


class PypiLookupFailsClosed(unittest.TestCase):
    """A PyPI name leaves the computer only for a scanned project that lists it from a public index."""

    def setUp(self):
        self.real = (sg.build_inventory, sg.global_private_index)
        sg.global_private_index = lambda: False

    def tearDown(self):
        sg.build_inventory, sg.global_private_index = self.real

    def inv(self, packages, private_py=(), private_index=False):
        return {"projects": [{"packages": [{"ecosystem": "PyPI", "name": n, "version": "1.0"} for n in packages],
                              "private_npm": [], "private_py": list(private_py), "private_index": private_index}]}

    def test_no_folder_is_not_proven(self):
        self.assertFalse(sg.may_look_up_name("PyPI", "requests", None))

    def test_name_from_the_project_is_looked_up(self):
        sg.build_inventory = lambda f: self.inv(["requests"])
        self.assertTrue(sg.may_look_up_name("PyPI", "Requests", "/p"))

    def test_name_not_in_the_project_is_not_looked_up(self):
        sg.build_inventory = lambda f: self.inv(["requests"])
        self.assertFalse(sg.may_look_up_name("PyPI", "acme-internal", "/p"))

    def test_private_name_or_private_index_is_not_looked_up(self):
        sg.build_inventory = lambda f: self.inv(["acme-internal"], private_py=["acme-internal"])
        self.assertFalse(sg.may_look_up_name("PyPI", "acme-internal", "/p"))
        sg.build_inventory = lambda f: self.inv(["requests"], private_index=True)
        self.assertFalse(sg.may_look_up_name("PyPI", "requests", "/p"))
