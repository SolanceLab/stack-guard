# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.10.0: a name outside the known scopes is asked about only at the registry that served it. No network: every fetch is recorded."""
import contextlib
import datetime
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "plugin", "scripts"))
sys.path.insert(0, HERE)
import stack_guard as sg  # noqa: E402
from test_stack_guard import symlink  # noqa: E402

NPMJS = "https://registry.npmjs.org/"


def stamp(hours_ago):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Base(unittest.TestCase):
    age = 500

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.calls = []
        self.mocks = {n: mock.Mock(return_value=None) for n in ("osv_check", "malware_fallback", "fallback_check")}
        self.real_osv = mock.patch.object(sg, "osv_check", sg.osv_check)
        patches = [mock.patch.object(sg, "http_json", self.net), mock.patch.object(sg, "global_private_index", return_value=False)]
        patches += [mock.patch.object(sg, n, m) for n, m in self.mocks.items()]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def net(self, url, body=None, *a, **k):
        self.calls.append((url, body))
        if url.startswith(NPMJS):
            return {"time": {self.ver: stamp(self.age)}}
        if url.startswith("https://pypi.org/"):
            return {"urls": [{"upload_time_iso_8601": stamp(self.age)}]}
        if url == sg.OSV_BATCH:
            return {"results": [{} for _ in body["queries"]]}
        raise AssertionError("unexpected fetch " + url)

    ver = "2.1.8"

    def cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sg.main(list(args))
        return code, out.getvalue()

    def npm_project(self, name, resolved, dirname="proj"):
        d = os.path.join(self.tmp, dirname)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "package.json"), "w") as fh:
            json.dump({"dependencies": {name: "1.0.0"}}, fh)
        entry = {"version": self.ver, "integrity": "sha512-x"}
        if resolved:
            entry["resolved"] = resolved
        with open(os.path.join(d, "package-lock.json"), "w") as fh:
            json.dump({"lockfileVersion": 3, "packages": {"node_modules/" + name: entry}}, fh)
        return d

    def lockfile(self, name, version, resolved, fname):
        p = os.path.join(self.tmp, fname)
        with open(p, "w") as fh:
            json.dump({"lockfileVersion": 3, "packages": {"node_modules/" + name: {"version": version, "resolved": resolved, "integrity": "sha512-x"}}}, fh)
        return p

    def empty_lock(self, fname):
        p = os.path.join(self.tmp, fname)
        with open(p, "w") as fh:
            json.dump({"lockfileVersion": 3, "packages": {}}, fh)
        return p

    def assert_no_second_party(self):
        for m in self.mocks.values():
            m.assert_not_called()


VURL = NPMJS + "@vitest/expect/-/expect-2.1.8.tgz"
VITEST = "@vitest/expect"


class SourceOnlyReleaseAge(Base):
    def test_served_by_npmjs_gets_an_age_verdict_there_only(self):
        d = self.npm_project(VITEST, VURL)
        code, out = self.cli("release-age", "npm", VITEST, "2.1.8", "--folder", d)
        self.assertEqual(code, 0, out)
        self.assertIn("(registry.npmjs.org only)", out)
        self.assertTrue(out.strip().endswith("OK"))
        self.assertTrue(self.calls)
        self.assertTrue(all(u.startswith(NPMJS) for u, _ in self.calls))
        self.assert_no_second_party()

    def test_too_new(self):
        self.age = 2
        d = self.npm_project(VITEST, VURL)
        code, out = self.cli("release-age", "npm", VITEST, "2.1.8", "--folder", d)
        self.assertEqual(code, 3, out)
        self.assert_no_second_party()

    def test_other_registry_stays_unproven(self):
        d = self.npm_project(VITEST, "https://npm.corp.example/@vitest/expect/-/expect-2.1.8.tgz")
        code, out = self.cli("release-age", "npm", VITEST, "2.1.8", "--folder", d)
        self.assertEqual(code, 2)
        self.assertIn("unknown: private package, release date not looked up", out)
        self.assertEqual(self.calls, [])

    def test_no_resolved_stays_unproven(self):
        d = self.npm_project(VITEST, None)
        self.assertEqual(self.cli("release-age", "npm", VITEST, "2.1.8", "--folder", d)[0], 2)
        self.assertEqual(self.calls, [])

    def test_one_project_elsewhere_vetoes(self):
        a = self.npm_project(VITEST, VURL, "a")
        self.npm_project(VITEST, "https://npm.corp.example/x.tgz", "b")
        self.assertEqual(self.cli("release-age", "npm", VITEST, "2.1.8", "--folder", self.tmp)[0], 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.cli("release-age", "npm", VITEST, "2.1.8", "--folder", a)[0], 0)

    def test_no_folder_stays_unproven(self):
        self.assertEqual(self.cli("release-age", "npm", VITEST, "2.1.8")[0], 2)
        self.assertEqual(self.calls, [])

    def test_fetch_guard_refuses_other_hosts(self):
        with self.assertRaises(ValueError):
            sg.npmjs_only_fetch("https://example.com/x")
        self.assertEqual(self.calls, [])


class SourceOnlyLockCheck(Base):
    def test_unlisted_name_is_counted_not_looked_up(self):
        after = self.lockfile(VITEST, "2.1.8", VURL, "package-lock.json")
        before = self.empty_lock("before.json")
        code, out = self.cli("lock-check", before, after)
        self.assertEqual(code, 2, out)
        self.assertIn("1 private", out)
        self.assertIn("came from registry.npmjs.org", out)
        self.assertEqual(self.calls, [])
        self.assert_no_second_party()

    def test_invalid_version_is_not_counted_as_source_only(self):
        after = self.lockfile(VITEST, "2.1.8 bad", VURL, "package-lock.json")
        code, out = self.cli("lock-check", self.empty_lock("before.json"), after)
        self.assertEqual(code, 2, out)
        self.assertNotIn("came from registry.npmjs.org", out)

    def test_listed_babel_keeps_the_usual_path(self):
        self.ver = "7.26.0"
        code, out = self.cli("release-age", "npm", "@babel/core", "7.26.0")
        self.assertEqual(code, 0, out)
        self.assertNotIn("registry.npmjs.org only", out)


class SourceOnlyGuards(Base):
    def test_missing_source_entry_fails_closed(self):
        self.assertFalse(sg.npm_source_only(VITEST, [{"npm_from_npmjs": [VITEST]}], ()))
        self.assertTrue(sg.npm_source_only(VITEST, [{"npm_from_npmjs": [VITEST]}], (VURL,)))

    def test_source_only_name_is_not_shareable(self):
        d = self.npm_project(VITEST, VURL)
        inv = sg.build_inventory(d)
        self.assertEqual(sg.lookup_source("npm", VITEST, d), "registry.npmjs.org only")
        self.assertFalse(sg.shareable({"ecosystem": "npm", "package": VITEST}, inv))

    def test_tarball_for_another_name_is_not_source_only(self):
        d = self.npm_project(VITEST, NPMJS + "other/-/other-2.1.8.tgz")
        self.assertIsNone(sg.lookup_source("npm", VITEST, d))

    def test_pypi_fetch_guard_refuses_other_hosts(self):
        with self.assertRaises(ValueError):
            sg.pypi_only_fetch("https://example.com/x")
        self.assertEqual(self.calls, [])

    def test_venv_names_are_not_cut_at_the_cap(self):
        d = os.path.join(self.tmp, "py")
        v = os.path.join(d, ".venv")
        sp = os.path.join(v, "lib", "python3.12", "site-packages")
        for i in range(sg.SERVICE_VENV_CAP + 5):
            os.makedirs(os.path.join(sp, "pkg%04d-1.0.dist-info" % i))
        with open(os.path.join(d, "requirements.txt"), "w") as fh:
            fh.write("requests==1.0.0\n")
        with open(os.path.join(v, "pyvenv.cfg"), "w") as fh:
            fh.write("version = 3.12.0\n")
        names = sg.venv_pypi_names(sg.build_inventory(d), os.path.abspath(d))
        self.assertEqual(len(names), sg.SERVICE_VENV_CAP + 5)
        self.assertEqual(len(sg.venv_packages(v)), sg.SERVICE_VENV_CAP)


class BabelLockCheck(Base):
    ver = "7.26.0"

    def test_babel_goes_through_osv(self):
        after = self.lockfile("@babel/core", "7.26.0", NPMJS + "@babel/core/-/core-7.26.0.tgz", "package-lock.json")
        before = self.lockfile("@babel/core", "7.25.0", NPMJS + "@babel/core/-/core-7.25.0.tgz", "before.json")
        self.real_osv.start()  # undo the Mock from setUp: the real osv_check posts to OSV_BATCH through the recorder
        self.addCleanup(self.real_osv.stop)
        code, out = self.cli("lock-check", before, after)
        self.assertEqual(code, 0, out)
        self.assertIn("no malware record", out)
        osv = [b for u, b in self.calls if u == sg.OSV_BATCH]
        self.assertTrue(osv)
        self.assertIn("@babel/core", json.dumps(osv))


class PypiVenv(Base):
    ver = "2026.10.18"

    def project(self, direct_url=False, pip_conf=False, index=False, link_cfg=False):
        d = os.path.join(self.tmp, "py")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "requirements.txt"), "w") as fh:
            fh.write(("--index-url https://corp.example/simple\n" if index else "") + "requests==1.0.0\n")
        v = os.path.join(d, ".venv")
        di = os.path.join(v, "lib", "python3.12", "site-packages", "certifi-2026.10.18.dist-info")
        os.makedirs(di, exist_ok=True)
        if direct_url:
            with open(os.path.join(di, "direct_url.json"), "w") as fh:
                fh.write("{}")
        if pip_conf:
            with open(os.path.join(v, "pip.conf"), "w") as fh:
                fh.write("")
        cfg = os.path.join(v, "pyvenv.cfg")
        if link_cfg:
            real = os.path.join(self.tmp, "real.cfg")
            with open(real, "w") as fh:
                fh.write("version = 3.12.0\n")
            symlink(real, cfg)
        else:
            with open(cfg, "w") as fh:
                fh.write("version = 3.12.0\n")
        return d

    def test_no_folder_stays_unproven(self):
        self.assertEqual(self.cli("release-age", "PyPI", "certifi", "2026.10.18")[0], 2)
        self.assertEqual(self.calls, [])

    def test_venv_name_goes_to_pypi_only(self):
        d = self.project()
        for name in ("certifi", "Certifi"):
            code, out = self.cli("release-age", "PyPI", name, "2026.10.18", "--folder", d)
            self.assertEqual(code, 0, out)
            self.assertIn("(pypi.org only)", out)
        self.assertTrue(all(u.startswith("https://pypi.org/") for u, _ in self.calls))
        self.assert_no_second_party()

    def test_each_veto_keeps_it_unproven(self):
        for kw in ({"direct_url": True}, {"pip_conf": True}, {"index": True}, {"link_cfg": True}):
            __import__("shutil").rmtree(os.path.join(self.tmp, "py"), True)
            d = self.project(**kw)
            self.assertEqual(self.cli("release-age", "PyPI", "certifi", "2026.10.18", "--folder", d)[0], 2, kw)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
