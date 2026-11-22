# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.10.0: a second advisory source (npm registry, PyPI, GitHub malware records) when OSV cannot be reached. No network."""
import contextlib
import datetime
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "plugin", "scripts"))
import stack_guard as sg  # noqa: E402


def target(eco, name, version):
    return {"ecosystem": eco, "name": name, "version": version, "project": "p", "dev": False, "deploy": True}


def http_404():
    return urllib.error.HTTPError("u", 404, "nf", {}, None)


class FallbackCheck(unittest.TestCase):
    def run_fb(self, targets, fake):
        errors = []
        with mock.patch.object(sg, "http_json", fake):
            return sg.fallback_check(targets, errors), errors

    def test_npm_mapping_severity_ghsa_and_bad_id(self):
        def fake(url, body=None, timeout=30, headers=None):
            self.assertEqual(url, sg.NPM_BULK)
            return {"next": [
                {"url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "title": "Bad <b>thing</b>", "severity": "moderate"},
                {"url": "https://github.com/advisories/GHSA-dddd-eeee-ffff", "title": "Malware in next", "severity": "critical"},
                {"url": "https://github.com/advisories/GHSA-gggg-hhhh-iiii", "title": "Contains malicious code", "severity": "low"},
                {"url": "https://example.com/not an id", "title": "x", "severity": "high"}]}
        found, errors = self.run_fb([target("npm", "next", "16.4.1")], fake)
        self.assertEqual([(f["id"], f["severity"]) for f in found],
                         [("GHSA-aaaa-bbbb-cccc", "MEDIUM"), ("GHSA-dddd-eeee-ffff", "MALICIOUS"), ("GHSA-gggg-hhhh-iiii", "MALICIOUS")])
        self.assertNotIn("<", found[0]["summary"])
        self.assertEqual(found[0]["fixed"], [])
        self.assertTrue(any("not allowed" in e for e in errors))

    def test_npm_severity_map(self):
        self.assertEqual(sg.NPM_SEVERITY, {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW"})

    def test_npm_two_versions_of_one_name_go_in_separate_requests(self):
        bodies = []
        def fake(url, body=None, timeout=30, headers=None):
            bodies.append(body)
            return {}
        self.run_fb([target("npm", "a", "1.0.0"), target("npm", "a", "2.0.0")], fake)
        self.assertEqual(bodies, [{"a": ["1.0.0"]}, {"a": ["2.0.0"]}])

    def test_npm_chunks_of_500(self):
        sizes = []
        def fake(url, body=None, timeout=30, headers=None):
            sizes.append(len(body))
            return {}
        self.run_fb([target("npm", "p%d" % i, "1.0.0") for i in range(1001)], fake)
        self.assertEqual(sizes, [500, 500, 1])

    def test_pypi_ghsa_alias_preferred_and_404_is_a_note(self):
        def fake(url, body=None, timeout=30, headers=None):
            if "/ok/1.0/" in url:
                return {"vulnerabilities": [{"id": "PYSEC-1", "aliases": ["CVE-1", "GHSA-xxxx-yyyy-zzzz"], "details": "First line\nmore", "fixed_in": ["1.1"]}]}
            if "/mal/1.0/" in url:
                return {"vulnerabilities": [{"id": "MAL-2026-1", "aliases": [], "summary": "evil"}]}
            raise http_404()
        found, errors = self.run_fb([target("PyPI", "ok", "1.0"), target("PyPI", "mal", "1.0"), target("PyPI", "gone", "9.9")], fake)
        a, b = found
        self.assertEqual((a["id"], a["summary"], a["severity"], a["fixed"]), ("GHSA-xxxx-yyyy-zzzz", "First line", "UNKNOWN", ["1.1"]))
        self.assertEqual((b["id"], b["severity"]), ("MAL-2026-1", "MALICIOUS"))
        self.assertTrue(any("not found on PyPI" in e for e in errors))

    def test_pypi_withdrawn_advisory_is_skipped(self):
        def fake(url, body=None, timeout=30, headers=None):
            return {"vulnerabilities": [
                {"id": "PYSEC-1", "aliases": [], "summary": "gone", "withdrawn": "2026-01-01T00:00:00Z"},
                {"id": "PYSEC-2", "aliases": [], "summary": "live", "withdrawn": None}]}
        found, _ = self.run_fb([target("PyPI", "w", "1.0")], fake)
        self.assertEqual([f["id"] for f in found], ["PYSEC-2"])

    def test_pypi_cap_and_other_ecosystems_are_named(self):
        calls = []
        def fake(url, body=None, timeout=30, headers=None):
            calls.append(url)
            return {"vulnerabilities": []}
        targets = [target("PyPI", "p%d" % i, "1.0") for i in range(sg.PYPI_LOOKUP_CAP + 5)] + [target("Go", "g", "1.0")]
        found, errors = self.run_fb(targets, fake)
        self.assertEqual(len(calls), sg.PYPI_LOOKUP_CAP)
        self.assertTrue(any("5 Python package versions beyond" in e for e in errors))
        self.assertTrue(any("1 package version(s) of other kinds" in e for e in errors))

    def test_partial_answer_returns_findings_and_names_the_gap(self):
        def fake(url, body=None, timeout=30, headers=None):
            if url == sg.NPM_BULK:
                raise OSError("offline")
            return {"vulnerabilities": []}
        found, errors = self.run_fb([target("npm", "a", "1.0.0"), target("PyPI", "b", "1.0")], fake)
        self.assertEqual(found, [])
        self.assertTrue(any("npm registry could not be reached" in e for e in errors))

    def test_nothing_answered_is_none(self):
        def fake(*a, **k):
            raise OSError("offline")
        found, errors = self.run_fb([target("npm", "a", "1.0.0"), target("PyPI", "b", "1.0")], fake)
        self.assertIsNone(found)


class FallbackWiring(unittest.TestCase):
    def check(self, osv, fb):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(sg, "osv_check", return_value=osv) as o, \
                mock.patch.object(sg, "fallback_check", return_value=fb) as f, \
                mock.patch.object(sg, "eol_check", side_effect=lambda rts, errs: [r.update(status="unknown", update=False, latest=None) for r in rts]), \
                mock.patch.object(sg, "update_line", return_value=""):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                sg.cmd_check(folder, notify=False)
            report = ""
            rdir = os.path.join(folder, sg.STATE_DIR, "reports")
            for n in os.listdir(rdir):
                if n.endswith(".md"):
                    report = open(os.path.join(rdir, n), encoding="utf-8").read()
            return o, f, out.getvalue(), report

    def test_fallback_not_called_when_osv_answers(self):
        _, f, _, _ = self.check([], [])
        f.assert_not_called()

    def test_fallback_answered_reads_as_checked(self):
        _, f, out, report = self.check(None, [])
        f.assert_called_once()
        self.assertNotIn("packages NOT checked", out)
        self.assertIn("checked with the npm registry and PyPI instead", out)
        self.assertIn(sg.FALLBACK_NOTE, report)
        self.assertNotIn("Not checked: OSV could not be reached, so no package", report)

    def test_nothing_answered_is_as_before(self):
        _, _, out, report = self.check(None, None)
        self.assertIn("packages NOT checked, OSV could not be reached", out)
        self.assertNotIn(sg.FALLBACK_NOTE, report)

    def test_make_report_source(self):
        with tempfile.TemporaryDirectory() as folder:
            inv = sg.build_inventory(folder)
            self.assertEqual(sg.make_report(inv, [], [], True)["source"], "OSV")
            self.assertNotIn(sg.FALLBACK_NOTE, sg.make_report(inv, [], [], True)["not_checked"])
            self.assertNotIn(sg.FALLBACK_NOTE, sg.make_report(inv, [], [], True, None, sg.FALLBACK_SOURCE)["not_checked"])


class LockMalwareFallback(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.published = {("left-pad", "1.3.0"): (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=500)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.gh = []           # what GitHub answers (a list, or an exception)
        self.seen_headers = []
        for k in ("GITHUB_TOKEN", "GH_TOKEN"):
            p = mock.patch.dict(os.environ)
            p.start()
            self.addCleanup(p.stop)
            os.environ.pop(k, None)
        p = mock.patch.object(sg, "http_json", self.fetch)
        p.start()
        self.addCleanup(p.stop)

    def fetch(self, url, body=None, timeout=30, headers=None):
        if url == sg.OSV_BATCH:
            raise OSError("osv down")
        if url.startswith(sg.GH_ADVISORIES):
            self.seen_headers.append(headers)
            if isinstance(self.gh, Exception):
                raise self.gh
            return self.gh
        if url.startswith("https://registry.npmjs.org/"):
            return {"time": {v: t for (n, v), t in self.published.items()}}
        raise AssertionError(url)

    def lock(self, name, packages):
        path = os.path.join(self.dir, name)
        data = {"lockfileVersion": 3, "packages": {"": {"name": "x"}}}
        for pkg, ver in packages.items():
            data["packages"]["node_modules/" + pkg] = {"version": ver, "resolved": "https://registry.npmjs.org/%s/-/%s-%s.tgz" % (pkg, pkg, ver)}
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(data, fh)
        return path

    def run_check(self):
        a, b = self.lock("before/package-lock.json", {"left-pad": "1.2.0"}), self.lock("after/package-lock.json", {"left-pad": "1.3.0"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sg.main(["lock-check", a, b])
        return code, out.getvalue()

    def test_malware_found_exits_4(self):
        self.gh = [{"ghsa_id": "GHSA-aaaa-bbbb-cccc"}]
        code, out = self.run_check()
        self.assertEqual(code, 4, out)
        self.assertIn("MALICIOUS (GHSA-aaaa-bbbb-cccc)", out)

    def test_all_clean_exits_0(self):
        self.gh = []
        code, out = self.run_check()
        self.assertEqual(code, 0, out)
        self.assertIn("no malware record (GitHub advisory database; OSV unreachable)", out)

    def test_rate_limited_exits_2(self):
        self.gh = urllib.error.HTTPError("u", 403, "rate limit", {}, None)
        code, out = self.run_check()
        self.assertEqual(code, 2, out)
        self.assertIn("malware check not done", out)

    def test_token_sent_only_when_set_and_never_printed(self):
        self.run_check()
        self.assertEqual(self.seen_headers, [None])
        os.environ["GH_TOKEN"] = "tok-123-secret"
        self.seen_headers.clear()
        code, out = self.run_check()
        self.assertEqual(self.seen_headers, [{"Authorization": "Bearer tok-123-secret"}])
        self.assertNotIn("tok-123-secret", out)


class FallbackCoverage(unittest.TestCase):
    def test_all_404_is_not_an_answer(self):
        def fake(url, body=None, **kw):
            raise http_404()
        errors = []
        with mock.patch.object(sg, "http_json", fake):
            self.assertIsNone(sg.fallback_check([target("PyPI", "requests", "2.0.0")], errors))

    def test_checked_lists_only_answered_versions(self):
        def fake(url, body=None, **kw):
            if "pypi.org" in url:
                raise http_404()
            return {}
        checked = set()
        with mock.patch.object(sg, "http_json", fake):
            sg.fallback_check([target("npm", "a", "1.0.0"), target("PyPI", "b", "1.0.0"), target("Go", "c", "v1")], [], checked)
        self.assertEqual(checked, {("npm", "a", "1.0.0")})

    def test_unchecked_ecosystem_is_not_shown_as_fixed(self):
        def f(eco, name):
            return {"key": "p|%s|%s|1|X" % (eco, name), "id": "GHSA-aaaa-bbbb-cccc", "summary": "s", "severity": "HIGH", "fixed": [],
                    "package": name, "version": "1", "ecosystem": eco, "project": "p", "dev": False, "deploy": True}
        prev = {"osv_ok": True, "findings": [f("npm", "a"), f("Go", "g")], "runtimes": [], "mcp": []}
        cur = {"osv_ok": True, "findings": [], "runtimes": [], "mcp": [], "source": sg.FALLBACK_SOURCE, "checked": [["npm", "a", "1"]]}
        d = sg.diff_reports(prev, cur)
        self.assertEqual(len(d["fixed"]), 1)
        self.assertIn("a 1", d["fixed"][0]["text"])

    def test_osv_error_superseded_by_successful_fallback(self):
        def osv(targets, cache, errors):
            errors.append("OSV (known security problems) could not be reached: timeout. No package was checked.")
            return None
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(sg, "osv_check", osv), \
                mock.patch.object(sg, "fallback_check", return_value=[]), \
                mock.patch.object(sg, "eol_check", side_effect=lambda rts, errs: [r.update(status="unknown", update=False, latest=None) for r in rts]), \
                mock.patch.object(sg, "update_line", return_value=""):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = sg.cmd_check(folder, notify=False)
        self.assertEqual(code, 0)
        self.assertNotIn("No package was checked", out.getvalue())
        self.assertNotIn("OSV (known security problems) could not be reached", out.getvalue())


class PartialCoverageWording(unittest.TestCase):
    def render(self, uncovered):
        with tempfile.TemporaryDirectory() as folder:
            inv = sg.build_inventory(folder)
            inv["runtimes"] = []
            inv["tools"] = [{"name": "t", "version": "1", "path": "/x"}]
            rep = sg.make_report(inv, [], [], True, None, sg.FALLBACK_SOURCE)
            if uncovered is not None:
                rep["uncovered"] = uncovered
            return sg.render_report(rep, {"first": True, "new": [], "fixed": [], "runtimes": [], "notes": [], "not_compared": False})

    def test_partial_coverage_gives_no_all_clear(self):
        text = self.render({"all": 3, "main": 2, "tool": 1})
        self.assertNotIn("\nNone.\n", text)
        self.assertNotIn("No known problems in these tools.", text)
        self.assertNotIn("No known problems found.", text)
        self.assertIn("None among what was checked; 2 package version(s) were not checked", text)
        self.assertIn("1 tool package(s) were not checked", text)

    def test_full_coverage_keeps_the_all_clear(self):
        text = self.render({"all": 0, "main": 0, "tool": 0})
        self.assertIn("\nNone.\n", text)
        self.assertIn("No known problems in these tools.", text)


class CoverageScopes(unittest.TestCase):
    """Review fixes: services are their own coverage scope; the fallback note is a 'not checked' item only when a source answered and something was left uncovered."""
    def run_check(self, targets, covered, answered=True):
        def fb(tg, errors, checked=None):
            if not answered:
                errors.append("fallback unreachable")
                return None
            for t in tg:
                k = (t["ecosystem"], t["name"], t["version"])
                if k in covered:
                    checked.add(k)
            return []
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(sg, "collect_targets", return_value=targets), \
                mock.patch.object(sg, "osv_check", return_value=None), \
                mock.patch.object(sg, "fallback_check", side_effect=fb), \
                mock.patch.object(sg, "eol_check", side_effect=lambda rts, errs: [r.update(status="unknown", update=False, latest=None) for r in rts]), \
                mock.patch.object(sg, "update_line", return_value=""):
            with contextlib.redirect_stdout(io.StringIO()):
                sg.cmd_check(folder, notify=False)
            rdir = os.path.join(folder, sg.STATE_DIR, "reports")
            js = [n for n in os.listdir(rdir) if n.endswith(".json")][0]
            with open(os.path.join(rdir, js), encoding="utf-8") as fh:
                rep = json.load(fh)
            with open(os.path.join(rdir, js[:-5] + ".md"), encoding="utf-8") as fh:
                md = fh.read()
            return rep, md

    def test_service_targets_counted_in_their_own_scope(self):
        main = target("npm", "a", "1.0.0")
        tool = dict(target("npm", "npm", "10.0.0"), tool=True)
        svc = dict(target("Go", "stdlib", "1.22.0"), tool=True, service=True)
        rep, _ = self.run_check([main, tool, svc], {("npm", "a", "1.0.0")})
        self.assertEqual(rep["uncovered"], {"all": 2, "main": 0, "tool": 1, "service": 1})

    def test_full_coverage_fallback_note_is_not_a_not_checked_item(self):
        rep, md = self.run_check([target("npm", "a", "1.0.0")], {("npm", "a", "1.0.0")})
        self.assertEqual(rep["source"], sg.FALLBACK_SOURCE)
        self.assertNotIn(sg.FALLBACK_NOTE, rep["not_checked"])
        self.assertIn(sg.FALLBACK_NOTE, md)  # the report still names which source answered
        self.assertNotIn("- " + sg.FALLBACK_NOTE, md)  # but not as a Not checked bullet

    def test_partial_coverage_keeps_fallback_note_in_not_checked(self):
        rep, md = self.run_check([target("npm", "a", "1.0.0"), target("Go", "g", "v1.0.0")], {("npm", "a", "1.0.0")})
        self.assertIn(sg.FALLBACK_NOTE, rep["not_checked"])
        self.assertIn("- " + sg.FALLBACK_NOTE, md)

    def test_nothing_answered_with_targets_never_claims_fallback(self):
        # every source failed while targets exist: miss is non-empty, but nothing was checked, so no fallback claim
        svc = dict(target("npm", "s", "1.0.0"), tool=True, service=True)
        rep, md = self.run_check([target("npm", "a", "1.0.0"), svc], set(), answered=False)
        self.assertFalse(rep["osv_ok"])
        self.assertNotIn(sg.FALLBACK_NOTE, rep["not_checked"])
        self.assertNotIn(sg.FALLBACK_NOTE, md)

    def render_services(self, unc, osv_ok=True):
        with tempfile.TemporaryDirectory() as folder:
            inv = sg.build_inventory(folder)
            inv["runtimes"] = []
            rep = sg.make_report(inv, [], [], osv_ok, None, sg.FALLBACK_SOURCE)
            rep["services"] = [{"label": "svc", "flags": [], "program": "/bin/x", "status": "running"}]
            rep["uncovered"] = unc
            return sg.render_report(rep, {"first": True, "new": [], "fixed": [], "runtimes": [], "notes": [], "not_compared": False})

    def test_services_partial_coverage_says_not_checked(self):
        text = self.render_services({"all": 1, "main": 0, "tool": 0, "service": 1})
        section = text.split("## \U0001F7E0 Services")[1].split("## Tools on this computer")[0]
        self.assertNotIn("None need a look.", section)
        self.assertIn("Not checked: 1 service package(s) were not looked up (see Not checked below).", section)
        self.assertNotIn("svc", section)  # counts only, no service name added

    def test_services_full_coverage_keeps_none_need_a_look(self):
        text = self.render_services({"all": 0, "main": 0, "tool": 0, "service": 0})
        self.assertIn("None need a look.", text)
        self.assertNotIn("service package(s) were not looked up", text)

    def test_services_every_source_down_never_reads_all_clear(self):
        text = self.render_services({"all": 0, "main": 0, "tool": 0, "service": 0}, osv_ok=False)
        section = text.split("## \U0001F7E0 Services")[1].split("## Tools on this computer")[0]
        self.assertNotIn("None need a look.", section)
        self.assertIn("Not checked: OSV could not be reached, so no service package was looked up.", section)


if __name__ == "__main__":
    unittest.main()
