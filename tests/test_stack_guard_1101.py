# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.10.1: an npm name registry.npmjs.org serves to anyone (no login, no redirect) is public at install time. No outside network."""
import contextlib
import datetime
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "plugin", "scripts"))
sys.path.insert(0, HERE)
import stack_guard as sg  # noqa: E402

CORP = "@corp/secret"
NPMJS = "https://registry.npmjs.org/"
VITEST = "@vitest/expect"
VER = "2.1.8"
VURL = NPMJS + "@vitest/expect/-/expect-2.1.8.tgz"
CURL = "https://npm.corp.example/@corp/secret/-/secret-1.0.0.tgz"


def stamp(hours_ago):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class LocalServer(unittest.TestCase):
    def setUp(self):
        self.seen = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.seen.append((self.path, dict(self.headers)))
                if self.path == "/redir":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:%d/target" % self.server.server_port)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps({"t": 1} if self.path == "/target" else {"ok": 1}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                return None

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = "http://127.0.0.1:%d" % self.server.server_port
        p = mock.patch.dict(os.environ, {"no_proxy": "*", "NO_PROXY": "*", "GITHUB_TOKEN": "tok-should-not-leave"})
        p.start()
        self.addCleanup(p.stop)

    def test_anonymous_request_sends_no_login(self):
        self.assertEqual(sg.http_json(self.base + "/ok", no_redirect=True), {"ok": 1})
        headers = {k.lower(): v for k, v in self.seen[0][1].items()}
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertFalse(any("tok-should-not-leave" in v for v in headers.values()))

    def test_redirect_is_refused_and_target_never_asked(self):
        with self.assertRaises(urllib.error.HTTPError):
            sg.http_json(self.base + "/redir", no_redirect=True)
        paths = [p for p, _ in self.seen]
        self.assertIn("/redir", paths)
        self.assertNotIn("/target", paths)

    def test_default_path_still_follows_redirects(self):
        self.assertEqual(sg.http_json(self.base + "/redir"), {"t": 1})

    def test_body_or_headers_refused_before_asking(self):
        with self.assertRaises(ValueError):
            sg.http_json(self.base + "/ok", body={}, no_redirect=True)
        with self.assertRaises(ValueError):
            sg.http_json(self.base + "/ok", headers={"X": "1"}, no_redirect=True)
        self.assertEqual(self.seen, [])


class Guards(unittest.TestCase):
    def test_npmjs_only_fetch_is_anonymous(self):
        m = mock.Mock(return_value={})
        with mock.patch.object(sg, "http_json", m):
            sg.npmjs_only_fetch(NPMJS + "x")
            m.assert_called_once_with(NPMJS + "x", no_redirect=True)
            with self.assertRaises(ValueError):
                sg.npmjs_only_fetch("https://example.com/x")
            with self.assertRaises(ValueError):
                sg.npmjs_only_fetch(NPMJS + "x", headers={"Authorization": "y"})
            self.assertEqual(m.call_count, 1)

    def test_proof_needs_the_version_in_versions(self):
        for ans in ({"time": {VER: stamp(500)}}, {"versions": {}, "time": {VER: stamp(500)}}, []):
            with mock.patch.object(sg, "http_json", mock.Mock(return_value=ans)):
                self.assertIsNone(sg.npm_anonymous_proof(VITEST, VER), ans)
        good = {"versions": {VER: {}}, "time": {VER: stamp(500)}}
        with mock.patch.object(sg, "http_json", mock.Mock(return_value=good)):
            self.assertEqual(sg.npm_anonymous_proof(VITEST, VER), good)
        with mock.patch.object(sg, "http_json", mock.Mock(side_effect=urllib.error.URLError("down"))):
            self.assertIsNone(sg.npm_anonymous_proof(VITEST, VER))


class LockCheck1101(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.calls = []
        self.answer = {"versions": {VER: {"name": VITEST}}, "time": {VER: stamp(500)}}
        self.osv = mock.Mock(return_value=[])
        self.fb = mock.Mock(return_value=({}, set()))
        for p in (mock.patch.object(sg, "http_json", self.net),
                  mock.patch.object(sg, "global_private_index", return_value=False),
                  mock.patch.object(sg, "osv_check", self.osv),
                  mock.patch.object(sg, "malware_fallback", self.fb)):
            p.start()
            self.addCleanup(p.stop)

    def net(self, url, body=None, *a, **k):
        self.calls.append((url, body, k))
        if url.startswith(NPMJS):
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
        raise AssertionError("unexpected fetch " + url)

    def lock(self, fname, entries):
        path = os.path.join(self.tmp, fname)
        pk = {"node_modules/" + n: {"version": v, "resolved": r, "integrity": "sha512-x"} for n, v, r in entries}
        with open(path, "w") as f:
            json.dump({"lockfileVersion": 3, "packages": pk}, f)
        return path

    def run_check(self, entries):
        before = self.lock("before.json", [])
        after = self.lock("package-lock.json", entries)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = sg.main(["lock-check", before, after])
        return code, buf.getvalue()

    def osv_names(self):
        return [t["name"] for c in self.osv.call_args_list for t in c[0][0]]

    def test_asks_npmjs_only_anonymously(self):
        self.run_check([(VITEST, VER, VURL)])
        self.assertTrue(self.calls)
        for url, body, k in self.calls:
            self.assertTrue(url.startswith(NPMJS))
            self.assertIsNone(body)
            self.assertEqual(k, {"no_redirect": True})

    def test_not_served_is_not_proven(self):
        errs = [urllib.error.HTTPError(NPMJS, c, "x", {}, None) for c in (404, 401, 403)] + [urllib.error.URLError("down")]
        for err in errs:
            self.osv.reset_mock()
            self.fb.reset_mock()
            self.answer = err
            code, out = self.run_check([(VITEST, VER, VURL)])
            self.assertEqual(code, 2, out)
            self.assertIn("1 private", out)
            self.assertNotIn(VITEST, out)
            self.assertNotIn("vitest", out)
            self.osv.assert_not_called()
            self.fb.assert_not_called()

    def test_time_only_is_not_proven(self):
        self.answer = {"time": {VER: stamp(500)}}
        code, out = self.run_check([(VITEST, VER, VURL)])
        self.assertEqual(code, 2, out)
        self.osv.assert_not_called()
        self.fb.assert_not_called()
        self.assertNotIn(VITEST, out)

    def test_no_publish_time_still_gets_malware_check(self):
        # the version is served (in versions) but npm gave no time entry: age is not proven (2), malware still screened
        self.answer = {"versions": {VER: {"name": VITEST}}}
        code, out = self.run_check([(VITEST, VER, VURL)])
        self.assertEqual(code, 2, out)
        self.osv.assert_called_once()
        self.assertEqual(self.osv.call_args[0][0][0]["name"], VITEST)
        self.osv.return_value = [{"id": "MAL-2026-1", "severity": "MALICIOUS", "ecosystem": "npm", "package": VITEST, "version": VER}]
        code, out = self.run_check([(VITEST, VER, VURL)])
        self.assertEqual(code, 4, out)

    def test_clean_exits_0_with_proof_line(self):
        code, out = self.run_check([(VITEST, VER, VURL)])
        self.assertEqual(code, 0, out)
        self.assertIn(sg.NPMJS_PUBLIC_PROOF, out)
        self.assertIn("no malware record", out)
        self.osv.assert_called_once()
        self.assertIn(VITEST, self.osv_names())

    def test_malware_exits_4(self):
        self.osv.return_value = [{"id": "MAL-2026-1", "severity": "MALICIOUS", "ecosystem": "npm", "package": VITEST, "version": VER}]
        code, out = self.run_check([(VITEST, VER, VURL)])
        self.assertEqual(code, 4, out)
        self.assertIn("MALICIOUS (MAL-2026-1)", out)

    def test_osv_down_asks_github(self):
        self.osv.return_value = None
        self.fb.return_value = ({}, {("npm", VITEST, VER)})
        code, out = self.run_check([(VITEST, VER, VURL)])
        self.assertEqual(code, 0, out)
        self.assertIn(VITEST, [t["name"] for t in self.fb.call_args[0][0]])
        self.assertIn("GitHub advisory database", out)
        self.fb.return_value = ({("npm", VITEST, VER): ["GHSA-aaaa-bbbb-cccc"]}, set())
        code, out = self.run_check([(VITEST, VER, VURL)])
        self.assertEqual(code, 4, out)

    def test_too_new_exits_3(self):
        self.answer["time"][VER] = stamp(2)
        code, out = self.run_check([(VITEST, VER, VURL)])
        self.assertEqual(code, 3, out)
        self.assertIn("TOO NEW", out)
        self.assertIn(sg.NPMJS_PUBLIC_PROOF, out)

    def test_other_registry_name_is_never_asked(self):
        code, out = self.run_check([(VITEST, VER, VURL), (CORP, "1.0.0", CURL)])
        self.assertEqual(code, 2, out)
        self.assertFalse(any("corp" in u.lower() for u, _, _ in self.calls))
        self.assertNotIn(CORP, self.osv_names())
        self.assertNotIn("corp", out)
        self.assertIn("1 private", out)


if __name__ == "__main__":
    unittest.main()
