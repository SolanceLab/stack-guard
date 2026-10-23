"""Offline tests for stack_guard.py. Run: python3 -m unittest discover -s tests -v"""
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "plugins", "stack-guard", "scripts"))
import stack_guard as sg  # noqa: E402

REAL_NOTIFY = sg.notify_desktop  # Base replaces sg.notify_desktop with a Mock
FIX = os.path.join(HERE, "fixtures")
SECRET = "SECRET-VALUE-123"
VULNS = {"lodash": ["GHSA-aaaa-bbbb-cccc"], "requests": ["GHSA-dddd-eeee-ffff"]}


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


class FakeNet:
    """Stands in for http_json: no real network. vulns maps package name to advisory ids."""

    def __init__(self, vulns=None, fail=False):
        self.vulns, self.fail, self.calls = dict(VULNS if vulns is None else vulns), fail, []

    def __call__(self, url, body=None, timeout=30):
        self.calls.append(url)
        if self.fail:
            raise OSError("offline")
        if url == sg.OSV_BATCH:
            return {"results": [{"vulns": [{"id": i} for i in self.vulns.get(q["package"]["name"], [])]}
                                for q in body["queries"]]}
        if url.startswith(sg.OSV_VULN):
            return fixture("osv_vuln_%s.json" % url.rsplit("/", 1)[1])
        if url == sg.EOL_URL % "nodejs":
            return fixture("eol_nodejs.json")
        if url == sg.EOL_URL % "python":
            return fixture("eol_python.json")
        raise AssertionError("unexpected url " + url)


def fake_run(args, input_text=None, timeout=30, cwd=None):
    exe = os.path.basename(str(args[0]))
    if exe == "node":
        return 0, "v18.20.1"
    if exe in ("python3", "python"):
        return 0, "Python 3.13.1"
    return 127, ""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.folder = os.path.join(self.tmp, "work")
        shutil.copytree(os.path.join(FIX, "sample"), self.folder)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.date = ["2026-10-23"]
        for target, new in (("http_json", FakeNet()), ("run_cmd", fake_run), ("which", lambda n: "/usr/local/bin/" + n), ("home_dir", lambda: self.home),
                            ("today", lambda: self.date[0]), ("notify_desktop", mock.Mock()),
                            ("platform_name", lambda: "darwin")):
            p = mock.patch.object(sg, target, new)
            p.start()
            self.addCleanup(p.stop)
        self.net = sg.http_json

    def run_main(self, *args):
        with mock.patch("sys.stdout") as out:
            code = sg.main(list(args))
        return code, "".join(c.args[0] + "\n" if c.args[0] != "\n" else "" for c in out.write.call_args_list)

    def report(self, date=None):
        with open(os.path.join(self.folder, ".stack-guard", "reports", (date or self.date[0]) + ".md"), encoding="utf-8") as fh:
            return fh.read()


class InventoryTests(Base):
    def test_finds_projects_packages_and_deploy_configs(self):
        os.makedirs(os.path.join(self.folder, "app", "node_modules", "x"))
        shutil.copy(os.path.join(self.folder, "app", "package-lock.json"), os.path.join(self.folder, "app", "node_modules", "x"))
        inv = sg.build_inventory(self.folder)
        by = {p["path"]: p for p in inv["projects"]}
        self.assertEqual(sorted(by), ["api", "app", "pnpmapp"])  # node_modules copy was skipped
        npm = {(p["name"], p["version"]): p["dev"] for p in by["app"]["packages"]}
        self.assertEqual(npm, {("lodash", "4.17.20"): False, ("left-pad", "1.3.0"): True, ("@scope/pkg", "2.0.0"): False})
        py = {p["name"]: p["dev"] for p in by["api"]["packages"]}
        self.assertEqual(py, {"requests": False, "flask": False, "pytest": True})  # unpinned line ignored
        self.assertTrue(any("my-worker" in d for d in by["app"]["deploy"]))
        self.assertTrue(any("my-site" in d for d in by["app"]["deploy"]))
        self.assertTrue(any("my-api" in d for d in by["api"]["deploy"]))
        self.assertEqual(by["app"]["engines_node"], ">=18")
        self.assertEqual([(r["name"], r["version"]) for r in by["api"]["runtimes"]], [("python", "3.9"), ("node", "18")])
        self.assertIn("packages not parsed", by["pnpmapp"]["not_parsed"][0])

    def test_mcp_never_leaks_secrets_and_flags_floating_versions(self):
        self.run_main("inventory", self.folder)
        for path in ("STACK-INVENTORY.md", ".stack-guard/inventory.json"):
            with open(os.path.join(self.folder, path), encoding="utf-8") as fh:
                self.assertNotIn(SECRET, fh.read())
        m = {x["name"]: x for x in sg.build_inventory(self.folder)["mcp"]}
        self.assertTrue(m["floating"]["unpinned"])
        self.assertTrue(m["latest"]["unpinned"])
        self.assertFalse(m["pinned"]["unpinned"])
        self.assertEqual(m["pinned"]["package"], {"ecosystem": "PyPI", "name": "tool-mcp", "version": "1.2.3", "pinned": True})
        self.assertIsNone(m["plain"]["package"])
        self.assertEqual(m["plain"]["command"], "node")

    def test_unreadable_file_is_reported(self):
        with open(os.path.join(self.folder, "app", "package-lock.json"), "w") as fh:
            fh.write("{broken")
        code, out = self.run_main("inventory", self.folder)
        self.assertIn("Could not read: app/package-lock.json", out)

    def test_writes_only_inside_state_dir_and_inventory(self):
        before = set(os.listdir(self.folder))
        self.run_main("inventory", self.folder)
        self.assertEqual(set(os.listdir(self.folder)) - before, {".stack-guard", "STACK-INVENTORY.md"})


class SeverityTests(unittest.TestCase):
    def test_cvss_bands(self):
        self.assertEqual(sg.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(sg.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), 7.5)
        self.assertIsNone(sg.cvss3_score("CVSS:4.0/AV:N"))
        self.assertEqual(sg.vuln_severity({"database_specific": {"severity": "MODERATE"}}), "MEDIUM")
        self.assertEqual(sg.vuln_severity({"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}), "HIGH")
        self.assertEqual(sg.vuln_severity({}), "UNKNOWN")

    def test_mcp_package_parsing(self):
        self.assertEqual(sg.mcp_package("npx", ["-y", "@a/b@1.0.0"])["pinned"], True)
        self.assertEqual(sg.mcp_package("npx", ["@a/b@^1.0"])["pinned"], False)
        self.assertEqual(sg.mcp_package("pipx", ["run", "tool"])["name"], "tool")
        self.assertIsNone(sg.mcp_package("node", ["x.js"]))


class CheckTests(Base):
    def test_check_report_and_diff_between_days(self):
        code, out = self.run_main("check", self.folder)
        self.assertEqual(code, 0)
        self.assertIn("First check", out)
        rep = self.report()
        self.assertIn("## 🔴 Fix first", rep)
        red = rep.split("## 🔴 Fix first")[1].split("## 🟠")[0]
        self.assertIn("lodash 4.17.20", red)
        self.assertIn("Fixed in: 4.17.21", red)
        self.assertIn("requests 2.25.0", red)  # CVSS 7.5 = HIGH, live code, api has fly.toml
        self.assertIn("node 18.20.1 (this computer): NO LONGER SUPPORTED", rep)
        self.assertIn("auto-updates on every start", rep)

        self.date[0] = "2026-10-24"
        sg.http_json.vulns = {"requests": ["GHSA-dddd-eeee-ffff"]}  # lodash fixed
        code, out = self.run_main("check", self.folder)
        self.assertEqual(code, 0)
        self.assertIn("Fixed since last time", out)
        self.assertIn("lodash 4.17.20", out)
        self.assertNotIn("New problems", out)
        self.assertNotIn("no longer supported", out)  # was already unsupported yesterday

    def test_source_failure_exits_2_and_is_named(self):
        sg.http_json.fail = True
        code, out = self.run_main("check", self.folder)
        self.assertEqual(code, 2)
        self.assertIn("OSV (known security problems) could not be reached", out)
        self.assertIn("## Not checked", self.report())
        # a later good run must not call the missing problems "fixed"
        self.date[0] = "2026-10-24"
        sg.http_json.fail = False
        _, out = self.run_main("check", self.folder)
        self.assertNotIn("Fixed since last time", out)
        self.assertIn("could not be compared", out)

    def test_vuln_details_are_cached(self):
        self.run_main("check", self.folder)
        first = sum(1 for u in self.net.calls if u.startswith(sg.OSV_VULN))
        self.date[0] = "2026-10-24"
        self.run_main("check", self.folder)
        self.assertEqual(sum(1 for u in self.net.calls if u.startswith(sg.OSV_VULN)), first)

    def test_nothing_new_message(self):
        self.run_main("check", self.folder)
        self.date[0] = "2026-10-24"
        _, out = self.run_main("check", self.folder)
        self.assertIn("Nothing new since the last check.", out)


HOOK = "https://discord.com/api/webhooks/123/TOPSECRET"


class WebhookTests(Base):
    def store(self, url=HOOK, mode=0o600):
        sg.store_webhook(self.folder, url)
        os.chmod(sg.webhook_file(self.folder), mode)

    def test_allowlist(self):
        self.assertEqual(sg.webhook_kind(HOOK), "discord")
        self.assertEqual(sg.webhook_kind("https://hooks.slack.com/services/T/B/x"), "slack")
        for bad in ("https://evil.example/api/webhooks/1/x", "http://discord.com/api/webhooks/1/x",
                    "https://discord.com.evil.example/api/webhooks/1/x", "https://u:p@discord.com/api/webhooks/1/x",
                    "https://discord.com/other"):
            self.assertIsNone(sg.webhook_kind(bad), bad)

    def test_secret_lives_outside_the_project_with_mode_600(self):
        self.store()
        path = sg.webhook_file(self.folder)
        self.assertTrue(path.startswith(self.home))
        self.assertFalse(path.startswith(self.folder))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_webhook_set_reads_stdin_and_rejects_other_hosts(self):
        with mock.patch("sys.stdin") as stdin, mock.patch("sys.stdout"):
            stdin.readline.return_value = "https://evil.example/x\n"
            self.assertEqual(sg.main(["webhook-set", self.folder]), 1)
            self.assertFalse(os.path.exists(sg.webhook_file(self.folder)))
            stdin.readline.return_value = HOOK + "\n"
            self.assertEqual(sg.main(["webhook-set", self.folder]), 0)
        self.assertEqual(sg.read_text(sg.webhook_file(self.folder)), HOOK)
        with mock.patch("sys.stdout"):
            sg.main(["webhook-remove", self.folder])
        self.assertFalse(os.path.exists(sg.webhook_file(self.folder)))

    def test_repo_webhook_file_is_ignored(self):
        os.makedirs(os.path.join(self.folder, ".stack-guard"))
        with open(os.path.join(self.folder, ".stack-guard", "webhook"), "w") as fh:
            fh.write("https://evil.example/x")
        with mock.patch.object(sg, "http_post_webhook") as post:
            self.assertIsNone(sg.send_webhook(self.folder, "hi"))
            post.assert_not_called()

    def test_refuses_loose_permissions_and_tampered_address(self):
        with mock.patch.object(sg, "http_post_webhook") as post:
            self.store(mode=0o644)
            self.assertIn("not private", sg.send_webhook(self.folder, "hi"))
            self.store("https://evil.example/x")
            self.assertIn("not a Discord or Slack", sg.send_webhook(self.folder, "hi"))
            post.assert_not_called()

    def test_sends_without_printing_url(self):
        self.store()
        with mock.patch.object(sg, "http_post_webhook") as post:
            code, out = self.run_main("check", self.folder, "--notify")
        self.assertEqual(post.call_args.args[0], HOOK)
        payload = post.call_args.args[1]
        self.assertEqual(list(payload), ["content"])
        self.assertLessEqual(len(payload["content"]), 1900)
        self.assertNotIn(self.tmp, payload["content"])  # no local paths
        self.assertNotIn("TOPSECRET", out)
        self.assertIn("Webhook sent.", out)
        sg.notify_desktop.assert_called_once()

    def test_slack_payload_uses_text_key(self):
        self.store("https://hooks.slack.com/services/T/B/x")
        with mock.patch.object(sg, "http_post_webhook") as post:
            sg.send_webhook(self.folder, "hi")
        self.assertEqual(post.call_args.args[1], {"text": "hi"})

    def test_failed_webhook_is_reported(self):
        self.store()
        with mock.patch.object(sg, "http_post_webhook", side_effect=OSError("boom")):
            _, out = self.run_main("check", self.folder, "--notify")
        self.assertIn("Webhook failed: OSError", out)
        self.assertNotIn("TOPSECRET", out)


class AgentTests(Base):
    def setUp(self):
        super().setUp()
        self.calls = []
        self.cwds = []

        def run(args, input_text=None, timeout=30, cwd=None):
            if os.path.basename(str(args[0])) in ("claude", "codex"):
                self.calls.append((args, input_text, timeout))
                self.cwds.append((cwd, os.listdir(cwd) if cwd else None))
                kind = "news" if "WebSearch,WebFetch" in args or "--search" in args else "explain"
                return self.agent_result[kind]
            return fake_run(args, input_text, timeout)
        self.agent_result = {"news": (0, "- Story about lodash"), "explain": (0, "lodash is old; update it.")}
        for target, new in (("run_cmd", run), ("which", lambda n: "/opt/x/bin/" + n if n == "claude" else None)):
            p = mock.patch.object(sg, target, new)
            p.start()
            self.addCleanup(p.stop)

    def test_off_by_default_and_with_no_agents(self):
        self.run_main("check", self.folder)
        self.run_main("check", self.folder, "--agents", "--no-agents")
        self.assertEqual(self.calls, [])

    def test_agents_run_from_an_empty_folder_outside_the_repo(self):
        self.run_main("check", self.folder, "--agents")
        self.assertEqual(len(self.cwds), 2)
        for cwd, listing in self.cwds:
            self.assertIsNotNone(cwd)
            self.assertEqual(listing, [])
            self.assertFalse(os.path.abspath(cwd).startswith(os.path.abspath(self.folder)))
            self.assertFalse(os.path.exists(cwd))  # cleaned up afterwards

    def test_agents_run_locked_and_land_in_report(self):
        code, out = self.run_main("check", self.folder, "--agents", "--notify")
        self.assertEqual(code, 0)
        news, explain = self.calls
        self.assertEqual([os.path.basename(news[0][0])] + news[0][1:6], ["claude", "-p", "--model", "sonnet", "--allowedTools", "WebSearch,WebFetch"])
        self.assertIn("Bash", news[0][news[0].index("--disallowedTools") + 1])
        self.assertEqual(explain[0][explain[0].index("--allowedTools") + 1], "")
        self.assertEqual(news[2], sg.AGENT_TIMEOUT)
        # public names and versions only: no paths, no env value, no dev package
        self.assertIn("lodash 4.17.20", news[1])
        self.assertNotIn(self.tmp, news[1] + explain[1])
        self.assertNotIn(SECRET, news[1] + explain[1])
        self.assertNotIn("left-pad", news[1])
        self.assertIn("lodash 4.17.20", explain[1])
        rep = self.report()
        self.assertIn("## 📰 In the news", rep)
        self.assertIn("- Story about lodash", rep)
        self.assertIn("## What this means", rep)
        self.assertIn("lodash is old", rep)

    def test_codex_command_when_only_codex_is_installed(self):
        with mock.patch.object(sg, "which", lambda n: "/x/codex" if n == "codex" else None):
            self.run_main("check", self.folder, "--agents")
        self.assertEqual([os.path.basename(self.calls[0][0][0])] + self.calls[0][0][1:], ["codex", "--search", "exec", "--skip-git-repo-check", "--sandbox", "read-only"])
        self.assertEqual([os.path.basename(self.calls[1][0][0])] + self.calls[1][0][1:], ["codex", "exec", "--skip-git-repo-check", "--sandbox", "read-only"])

    def test_failed_agent_is_named_and_findings_still_report(self):
        self.agent_result["news"] = (127, "")
        self.agent_result["explain"] = (1, "")
        code, out = self.run_main("check", self.folder, "--agents")
        self.assertEqual(code, 2)
        rep = self.report()
        self.assertIn("agent step failed: claude could not run", rep)
        self.assertIn("agent step failed: claude exited with code 1", rep)
        self.assertIn("lodash 4.17.20", rep)

    def test_no_cli_is_said_plainly(self):
        with mock.patch.object(sg, "which", lambda n: None):
            code, _ = self.run_main("check", self.folder, "--agents")
        self.assertEqual(code, 0)
        self.assertIn("Agent step skipped", self.report())

    def test_agent_text_reaches_notification_text(self):
        self.run_main("check", self.folder, "--agents", "--notify")
        with open(os.path.join(self.folder, ".stack-guard", "reports", "2026-10-23.json")) as fh:
            rep_json = json.load(fh)
        _, body = sg.notify_text(rep_json, {"first": False, "new": [], "fixed": [], "runtimes": [], "mcp": []})
        self.assertIn("- Story about lodash", body)

    def test_private_and_transitive_packages_stay_out_of_the_prompt(self):
        inv = {"runtimes": [], "mcp": [], "projects": [{
            "deploy": [], "direct_npm": ["pub", "priv"], "private_npm": ["priv"],
            "packages": [{"ecosystem": "npm", "name": "pub", "version": "1.0.0", "dev": False},
                         {"ecosystem": "npm", "name": "priv", "version": "1.0.0", "dev": False},
                         {"ecosystem": "npm", "name": "transitive", "version": "1.0.0", "dev": False},
                         {"ecosystem": "PyPI", "name": "internal-pkg", "version": "2.0", "dev": False}]}]}
        self.assertEqual(sg.public_components(inv), ["pub 1.0.0 (npm)"])


class HygieneTests(Base):
    def test_state_dir_goes_into_root_gitignore_of_a_repo(self):
        os.makedirs(os.path.join(self.folder, ".git"))
        with open(os.path.join(self.folder, ".gitignore"), "w") as fh:
            fh.write("node_modules")
        _, out = self.run_main("inventory", self.folder)
        self.assertIn("Added .stack-guard/ to .gitignore", out)
        with open(os.path.join(self.folder, ".gitignore")) as fh:
            self.assertEqual(fh.read(), "node_modules\n.stack-guard/\n")
        self.assertFalse(os.path.exists(os.path.join(self.folder, ".stack-guard", ".gitignore")))
        _, out = self.run_main("check", self.folder)  # already there: no second line, no message
        self.assertNotIn("Added", out)
        with open(os.path.join(self.folder, ".gitignore")) as fh:
            self.assertEqual(fh.read().count(".stack-guard"), 1)

    def test_no_gitignore_written_outside_a_repo(self):
        self.run_main("inventory", self.folder)
        self.assertFalse(os.path.exists(os.path.join(self.folder, ".gitignore")))

    def test_inventory_first_line_warns(self):
        self.run_main("inventory", self.folder)
        with open(os.path.join(self.folder, "STACK-INVENTORY.md"), encoding="utf-8") as fh:
            self.assertIn("review before committing", fh.readline())

    def test_secret_bearing_mcp_args_never_become_a_package_name(self):
        pkg = sg.mcp_package("npx", ["-y", "--api-key", SECRET, "actual-package"])
        self.assertEqual(pkg["name"], "actual-package")
        self.assertEqual(sg.mcp_package("npx", ["--token=" + SECRET, "actual-package@1.0.0"])["version"], "1.0.0")
        self.assertEqual(sg.mcp_package("npx", ["https://u:" + SECRET + "@host/x"])["name"], "<redacted>")
        self.assertIsNone(sg.mcp_package("npx", ["--api-key", SECRET]))

    def test_secret_in_args_is_absent_from_every_output(self):
        with open(os.path.join(self.folder, ".mcp.json"), "w") as fh:
            json.dump({"mcpServers": {"s": {"command": "npx", "args": ["--api-key", SECRET, "actual-package"]}}}, fh)
        self.run_main("inventory", self.folder)
        for path in ("STACK-INVENTORY.md", ".stack-guard/inventory.json"):
            with open(os.path.join(self.folder, path), encoding="utf-8") as fh:
                self.assertNotIn(SECRET, fh.read())


class SymlinkTests(Base):
    def setUp(self):
        super().setUp()
        self.outside = os.path.join(self.tmp, "outside")
        os.makedirs(self.outside)

    def test_symlinked_files_are_replaced_not_followed(self):
        os.makedirs(os.path.join(self.folder, ".git"), exist_ok=True)
        targets = {}
        for name in ("STACK-INVENTORY.md", ".gitignore"):
            t = os.path.join(self.outside, name)
            with open(t, "w") as fh:
                fh.write("original\n")
            os.symlink(t, os.path.join(self.folder, name))
            targets[name] = t
        self.run_main("check", self.folder)
        for t in targets.values():
            with open(t) as fh:
                self.assertEqual(fh.read(), "original\n")

    def test_symlinked_state_folder_is_refused(self):
        os.symlink(self.outside, os.path.join(self.folder, ".stack-guard"))
        code, out = self.run_main("check", self.folder)
        self.assertEqual(code, 1)
        self.assertIn("symbolic link", out)
        self.assertEqual(os.listdir(self.outside), [])

    def test_symlinked_reports_folder_is_refused(self):
        os.makedirs(os.path.join(self.folder, ".stack-guard"))
        os.symlink(self.outside, os.path.join(self.folder, ".stack-guard", "reports"))
        code, out = self.run_main("check", self.folder)
        self.assertEqual(code, 1)
        self.assertEqual(os.listdir(self.outside), [])


class WatchTests(Base):
    def test_plans_per_platform(self):
        mac = sg.watch_plan("darwin", self.folder, "07:30")
        self.assertTrue(mac["file"].endswith("dev.stack-guard.watch.plist"))
        self.assertIn(b"<integer>30</integer>", mac["content"])
        self.assertIn("--notify", mac["show"])
        lin = sg.watch_plan("linux", self.folder, "07:30")
        self.assertTrue(lin["line"].startswith("30 7 * * * "))
        win = sg.watch_plan("windows", self.folder, "07:30")
        self.assertIn("/ST", win["install"][0])
        with self.assertRaises(ValueError):
            sg.watch_plan("linux", self.folder, "25:00")

    def test_scheduler_path_has_discovered_tool_folders(self):
        found = {"node": "/opt/n/bin/node", "claude": "/home/u/.local/bin/claude", "codex": None, "python3": "/usr/bin/python3"}
        with mock.patch.object(sg, "which", lambda n: found.get(n)):
            mac = sg.watch_plan("darwin", self.folder, "07:30")
            lin = sg.watch_plan("linux", self.folder, "07:30")
        for part in ("/opt/n/bin", "/home/u/.local/bin", "/usr/bin"):
            self.assertIn(part.encode(), mac["content"])
            self.assertIn(part, lin["line"])
        self.assertIn(" PATH=", lin["line"])
        self.assertIn("--agents", lin["line"])  # claude was found
        with mock.patch.object(sg, "which", lambda n: None):
            self.assertNotIn("--agents", sg.watch_plan("linux", self.folder, "07:30")["line"])

    def test_no_agents_flag_leaves_agents_out_of_the_entry(self):
        with mock.patch.object(sg, "which", lambda n: "/opt/x/bin/" + n if n == "claude" else None):
            self.assertIn("--agents", sg.watch_plan("linux", self.folder, "07:30")["line"])
            self.assertNotIn("--agents", sg.watch_plan("linux", self.folder, "07:30", agents=False)["line"])
            code, out = self.run_main("watch-install", self.folder, "--no-agents")
        self.assertEqual(code, 0)
        self.assertNotIn("--agents", out)
        self.assertIn("Agents: off", out)

    def test_watch_remove_accepts_the_folder_watch_md_passes(self):
        with mock.patch.object(sg, "run_cmd", lambda a, **k: (0, "")):
            code, out = self.run_main("watch-remove", self.folder)
        self.assertEqual(code, 0)
        self.assertIn("Removed", out)

    def test_install_needs_yes(self):
        code, out = self.run_main("watch-install", self.folder)
        self.assertIn("Nothing installed", out)
        self.assertFalse(os.path.exists(os.path.join(self.home, "Library")))

    def test_install_and_remove_on_mac(self):
        calls = []
        with mock.patch.object(sg, "run_cmd", lambda a, **k: calls.append(a) or (0, "")):
            self.run_main("watch-install", self.folder, "--yes")
            plist = os.path.join(self.home, "Library", "LaunchAgents", "dev.stack-guard.watch.plist")
            self.assertTrue(os.path.exists(plist))
            self.run_main("watch-remove")
        self.assertFalse(os.path.exists(plist))
        self.assertTrue(any([os.path.basename(c[0]), c[1]] == ["launchctl", "bootstrap"] for c in calls))

    def test_cron_install_replaces_old_line(self):
        sent = []

        def run(args, input_text=None, timeout=30, cwd=None):
            if [os.path.basename(args[0])] + list(args[1:]) == ["crontab", "-l"]:
                return 0, "0 1 * * * other\n5 5 * * * old # dev.stack-guard.watch"
            sent.append(input_text)
            return 0, ""
        with mock.patch.object(sg, "platform_name", lambda: "linux"), mock.patch.object(sg, "run_cmd", run):
            self.run_main("watch-install", self.folder, "--yes")
        self.assertIn("other", sent[0])
        self.assertNotIn("5 5 * * *", sent[0])
        self.assertEqual(sent[0].count("dev.stack-guard.watch"), 1)



class HandFixes23Oct(Base):
    """Fixes made by hand after tag-team hit its cycle cap (23 Oct): no execution from the scanned tree,
    public npm names need positive proof, unchanged news is not resent."""

    def test_venv_python_is_read_never_executed(self):
        venv = os.path.join(self.folder, "app", ".venv")
        os.makedirs(os.path.join(venv, "bin"))
        marker = os.path.join(self.tmp, "EXECUTED")
        py = os.path.join(venv, "bin", "python")
        with open(py, "w") as f:
            f.write("#!/bin/sh\ntouch %s\necho Python 9.9.9\n" % marker)
        os.chmod(py, 0o755)
        with open(os.path.join(venv, "pyvenv.cfg"), "w") as f:
            f.write("home = /usr/bin\nversion = 3.12.4\n")
        with mock.patch.object(sg, "run_cmd", sg.run_cmd):
            inv = sg.build_inventory(self.folder)
        self.assertFalse(os.path.exists(marker), "a binary inside the scanned folder was executed")
        versions = [r["version"] for r in inv["runtimes"] if r.get("source") == ".venv virtualenv"]
        self.assertIn("3.12.4", versions)

    def test_tool_inside_scanned_folder_is_not_used(self):
        inside = os.path.join(self.folder, "bin", "node")
        with mock.patch.object(sg, "which", lambda n: inside):
            self.assertIsNone(sg.outside_tool("node", self.folder))
        with mock.patch.object(sg, "which", lambda n: "/usr/local/bin/node"):
            self.assertEqual(sg.outside_tool("node", self.folder), "/usr/local/bin/node")

    def test_public_npm_needs_positive_proof(self):
        reg = "https://registry.npmjs.org/x/-/x-1.0.0.tgz"
        self.assertTrue(sg.npm_provably_public("lodash", reg))
        self.assertTrue(sg.npm_provably_public("@types/node", reg))
        self.assertFalse(sg.npm_provably_public("@acme-private/secret-sdk", reg))
        self.assertFalse(sg.npm_provably_public("lodash", ""))
        self.assertFalse(sg.npm_provably_public("lodash", "https://npm.acme.internal/lodash.tgz"))

    def test_unchanged_news_is_not_resent(self):
        rep = {"date": "2026-10-24", "not_checked": [], "news": "- story A", "explain": "- meaning A"}
        diff = {"first": False, "new": [], "fixed": [], "runtimes": [], "mcp": []}
        _, body = sg.notify_text(rep, diff, {"news": "- story A", "explain": "- meaning A"})
        self.assertNotIn("story A", body)
        _, body = sg.notify_text(rep, diff, {"news": "- older story", "explain": "- meaning A"})
        self.assertIn("story A", body)
        self.assertNotIn("meaning A", body)


class PrivacyFixes23Oct(Base):
    """Codex round on the hand fixes (23 Oct 11:17): every exit path keeps private names and planted tools out."""

    def test_agent_cli_inside_scanned_folder_is_refused(self):
        planted = os.path.join(self.folder, "node_modules", ".bin", "claude")
        with mock.patch.object(sg, "which", lambda n: planted if n == "claude" else None):
            self.assertIsNone(sg.find_agent_cli(self.folder))
        with mock.patch.object(sg, "which", lambda n: "/usr/local/bin/claude" if n == "claude" else None):
            self.assertEqual(sg.find_agent_cli(self.folder), "/usr/local/bin/claude")

    def test_private_scoped_mcp_and_pypi_mcp_stay_out_of_news(self):
        inv = {"runtimes": [], "projects": [{"direct_npm": [], "private_npm": [], "deploy": [], "packages": [
            {"ecosystem": "npm", "name": "@modelcontextprotocol/server-x", "version": "1.2.0", "dev": False}]}], "mcp": [
            {"package": {"ecosystem": "npm", "name": "@acme-private/mcp", "version": "1.0.0"}, "unpinned": False, "unpinned_package": None, "command": "npx"},
            {"package": {"ecosystem": "PyPI", "name": "acme-internal-mcp", "version": "2.0"}, "unpinned": False, "unpinned_package": None, "command": "uvx"},
            {"package": {"ecosystem": "npm", "name": "@modelcontextprotocol/server-x", "version": "1.2.0"}, "unpinned": False, "unpinned_package": None, "command": "npx"},
            {"package": None, "unpinned": True, "unpinned_package": "@acme-private/other", "command": "npx"}]}
        text = "\n".join(sg.public_components(inv))
        self.assertNotIn("acme", text)
        self.assertIn("@modelcontextprotocol/server-x 1.2.0", text)

    def test_private_npm_finding_not_shared_with_explainer_or_webhook(self):
        inv = {"projects": [{"private_npm": ["internal-lib"]}]}
        self.assertFalse(sg.shareable({"ecosystem": "npm", "package": "internal-lib"}, inv))
        self.assertFalse(sg.shareable({"ecosystem": "npm", "package": "@acme-private/x"}, {"projects": []}))
        self.assertTrue(sg.shareable({"ecosystem": "npm", "package": "lodash"}, {"projects": []}))
        rep = {"date": "2026-10-24", "not_checked": []}
        diff = {"first": False, "new": [{"text": "internal-lib 1.0: HIGH", "key": "k1"}, {"text": "lodash 4: HIGH", "key": "k2"}],
                "fixed": [], "runtimes": [], "mcp": []}
        _, body = sg.notify_text(rep, diff, None, frozenset({"k1"}))
        self.assertNotIn("internal-lib", body)
        self.assertIn("lodash", body)

    def test_same_day_rerun_does_not_resend_news(self):
        rep = {"date": "2026-10-23", "not_checked": [], "news": "- story A", "explain": ""}
        diff = {"first": False, "new": [], "fixed": [], "runtimes": [], "mcp": []}
        _, body = sg.notify_text(rep, diff, {"news": "- story A", "explain": ""})
        self.assertNotIn("story A", body)


class Round3Fixes(Base):
    """Codex round 3 (23 Oct): stable script copy, run log, nothing from the scanned folder runs, MCP proof."""

    def plist(self):
        calls = []
        with mock.patch.object(sg, "run_cmd", lambda a, **k: calls.append(a) or (0, "")):
            code, out = self.run_main("watch-install", self.folder, "--yes")
        path = os.path.join(self.home, "Library", "LaunchAgents", "dev.stack-guard.watch.plist")
        with open(path, "rb") as fh:
            return sg.plistlib.loads(fh.read()), out

    def test_schedule_runs_the_stable_copy(self):
        stable = os.path.join(self.home, ".config", "stack-guard", "bin", "stack_guard.py")
        pl, out = self.plist()
        self.assertEqual(pl["ProgramArguments"][1], stable)
        self.assertTrue(os.path.isfile(stable))
        self.assertEqual(stat.S_IMODE(os.stat(stable).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(stable)).st_mode), 0o700)
        self.assertIn(stable, sg.watch_plan("linux", self.folder, "07:30")["line"])
        with mock.patch.object(sg, "run_cmd", lambda a, **k: (0, "")):
            self.run_main("watch-remove", self.folder)
        self.assertTrue(os.path.isfile(stable))  # remove leaves the copy

    def test_scheduled_run_is_logged(self):
        log = sg.watch_log_path(self.folder)
        self.assertTrue(log.startswith(os.path.join(self.home, ".config", "stack-guard", "logs")))
        self.assertFalse(sg.is_inside(log, self.folder))
        pl, _ = self.plist()
        self.assertTrue(os.path.isdir(os.path.dirname(log)))
        self.assertEqual(pl["StandardOutPath"], log)
        self.assertEqual(pl["StandardErrorPath"], log)
        self.assertTrue(sg.watch_plan("linux", self.folder, "07:30")["line"].split(" # ")[0].endswith(">> %s 2>&1" % log))
        self.assertIn("2>&1", sg.watch_plan("windows", self.folder, "07:30")["show"])

    def test_symlinked_python_schedules_its_resolved_target(self):
        real = os.path.join(self.home, "realpy", "python3")
        os.makedirs(os.path.dirname(real))
        open(real, "w").close()
        link = os.path.join(self.folder, "link-python")
        os.symlink(real, link)
        with mock.patch.object(sys, "executable", link):
            plan = sg.watch_plan("linux", self.folder, "07:30")
        self.assertIn(os.path.realpath(real), plan["line"])
        self.assertNotIn(link, plan["line"])

    def test_windows_metacharacters_stay_quoted_or_refuse(self):
        evil = os.path.join(self.home, "demo&calc&rem")
        tr = sg.watch_plan("windows", evil, "07:30")["install"][0][7]  # the /TR value cmd.exe receives
        self.assertIn('"%s"' % evil, tr)
        for bad in ("a%PATH%b", 'a"b'):
            with self.assertRaises(ValueError):
                sg.watch_plan("windows", os.path.join(self.home, bad), "07:30")

    def test_nothing_inside_the_folder_is_scheduled(self):
        mine = os.path.join(self.folder, "venv", "bin", "python3")
        with mock.patch.object(sys, "executable", mine):
            with self.assertRaises(ValueError):
                sg.watch_plan("darwin", self.folder, "07:30")
        planted = os.path.join(self.folder, "node_modules", ".bin")
        with mock.patch.object(sg, "which", lambda n: os.path.join(planted, n) if n == "node" else "/opt/n/bin/" + n):
            path = sg.schedule_path(self.folder)
        self.assertNotIn(planted, path)
        self.assertIn("/opt/n/bin", path)

    def test_stable_script_inside_the_folder_refuses_install(self):
        home_in_folder = os.path.join(self.folder, "fakehome")
        calls = []
        with mock.patch.object(sg, "home_dir", lambda: home_in_folder), \
                mock.patch.object(sg, "run_cmd", lambda a, **k: calls.append(a) or (0, "")):
            with self.assertRaises(ValueError):
                sg.watch_plan("darwin", self.folder, "07:30")
            code, out = self.run_main("watch-install", self.folder, "--yes")
        self.assertEqual(code, 1)
        self.assertIn("Refusing", out)
        self.assertEqual(calls, [])
        self.assertFalse(os.path.exists(os.path.join(home_in_folder, ".config")))

    def test_is_inside_is_case_blind_and_whole_part(self):
        self.assertTrue(sg.is_inside("/a/b/c", "/a/b"))
        self.assertTrue(sg.is_inside("/a/b", "/a/b"))
        self.assertFalse(sg.is_inside("/a/bc", "/a/b"))
        self.assertTrue(sg.is_inside("/A/B/c", "/a/b"))  # darwin in these tests
        with mock.patch.object(sg, "platform_name", lambda: "linux"):
            self.assertFalse(sg.is_inside("/A/B/c", "/a/b"))

    def test_system_tools_are_resolved_outside_the_folder(self):
        seen = []
        with mock.patch.object(sg, "run_cmd", lambda a, **k: seen.append(a) or (0, "")):
            REAL_NOTIFY("t", "m", self.folder)
            with mock.patch.object(sg, "which", lambda n: None):
                REAL_NOTIFY("t", "m", self.folder)  # missing tool: quiet
        self.assertEqual(seen[0][0], "/usr/local/bin/osascript")
        self.assertEqual(len(seen), 1)

    def test_mcp_names_need_exact_lockfile_proof(self):
        inv = {"runtimes": [], "projects": [{"direct_npm": [], "private_npm": [], "deploy": [], "packages": [
            {"ecosystem": "npm", "name": "lodash", "version": "4.0.0", "dev": False}]}], "mcp": [
            {"name": "a", "source": "s", "package": {"ecosystem": "npm", "name": "unlisted-mcp", "version": "1.0.0"}, "unpinned": False, "unpinned_package": None, "command": "npx"},
            {"name": "b", "source": "s", "package": None, "unpinned": True, "unpinned_package": "other-unlisted", "command": "npx"}]}
        text = "\n".join(sg.public_components(inv))
        self.assertNotIn("unlisted-mcp", text)
        self.assertNotIn("other-unlisted", text)
        rep = sg.make_report(dict(inv, folder="x", unreadable=[], projects=[dict(inv["projects"][0], path=".", not_parsed=[])]), [], [], True)
        self.assertIn("kept out of the news search (no public proof)", sg.render_report(rep, {"first": True, "notes": []}))
        _, body = sg.notify_text({"date": "d", "not_checked": []}, {"first": True, "new": [], "fixed": [], "runtimes": [], "mcp": []})
        self.assertNotIn("unlisted-mcp", body)


if __name__ == "__main__":
    unittest.main()
