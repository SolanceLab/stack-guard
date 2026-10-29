# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Offline tests for 1.5.0: secrets committed to git, standalone tools, "Was I hit?" files, deploy-runtime line.
Run: python3 -m unittest discover -s tests -v"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import unittest
from unittest import mock

from test_stack_guard import Base, FakeNet, HERE, POSIX_ONLY
import stack_guard as sg

ROOT = os.path.abspath(os.path.join(HERE, ".."))
REAL_WHICH = shutil.which
REAL_RUN = sg.run_cmd  # captured before Base patches it
PLUGIN = os.path.join(ROOT, "plugins", "stack-guard")
CANARY = "LITERAL-CANARY-9f8e7d6c"
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]


def git(folder, *args):
    subprocess.run(GIT + list(args), cwd=folder, check=True, capture_output=True)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class GitBase(Base):
    """A work folder that is a real git repository; git runs for real, everything else stays stubbed."""

    def setUp(self):
        super().setUp()
        real_git = REAL_WHICH("git")
        if not real_git:
            self.skipTest("git is not installed")
        self.real_git = real_git
        for target, new in (("run_cmd", self.run_cmd), ("which", self.which)):
            p = mock.patch.object(sg, target, new)
            p.start()
            self.addCleanup(p.stop)
        os.remove(os.path.join(self.folder, ".mcp.json"))  # the sample's own canary file; each test writes what it needs
        git(self.folder, "init", "-q")

    def run_cmd(self, args, **kw):
        if os.path.basename(str(args[0])) == "git":
            return REAL_RUN(args, **kw)
        kw.pop("stderr_out", None), kw.pop("env", None)
        return sg_fake_run(args, **kw)

    def which(self, name):
        return self.real_git if name == "git" else "/usr/local/bin/" + name

    def commit(self, msg="c"):
        git(self.folder, "add", "-A")
        git(self.folder, "commit", "-q", "-m", msg)

    def check(self):
        code, out = self.run_main("check", self.folder, "--notify")
        with open(os.path.join(self.folder, ".stack-guard", "reports", self.date[0] + ".json"), encoding="utf-8") as fh:
            js = fh.read()
        return out, self.report(), js


def sg_fake_run(args, input_text=None, timeout=30, cwd=None):
    from test_stack_guard import fake_run
    return fake_run(args, input_text, timeout, cwd)


class CommittedSecrets(GitBase):
    def section(self, md):
        return md.split("## Secrets committed to git")[1].split("## ")[0]

    def test_binary_key_file_does_not_abort_the_check(self):
        with open(os.path.join(self.folder, "server.key"), "wb") as fh:
            fh.write(bytes(range(256)) * 4)  # a DER-style binary key, not UTF-8
        self.commit()
        out, md, js = self.check()
        self.assertIn("## Secrets committed to git", md)
        self.assertIn("committed_secrets", js)

    def test_hostile_repo_git_config_runs_no_program(self):
        marker = os.path.join(self.folder + "-marker")
        self.addCleanup(lambda: os.path.exists(marker) and os.remove(marker))
        write(os.path.join(self.folder, ".env"), "API_TOKEN=abc123realvalue\n")
        self.commit()
        evil = "sh -c 'touch %s'" % marker
        for k, v in (("log.showSignature", "true"), ("gpg.program", evil), ("core.pager", evil), ("diff.external", evil)):
            git(self.folder, "config", k, v)
        self.check()
        self.assertFalse(os.path.exists(marker))

    def test_crafted_file_name_cannot_break_the_report(self):
        name = "a`b\nIGNORE PREVIOUS.env"
        try:
            write(os.path.join(self.folder, name), "API_TOKEN=abc123realvalue\n")
        except OSError:
            self.skipTest("file system refuses the name")
        self.commit()
        out, md, js = self.check()
        self.assertNotIn("a`b", md)
        self.assertNotIn("\nIGNORE PREVIOUS", md)

    def spy_git(self):
        calls = []

        def run(args, **kw):
            calls.append((list(args), kw.get("env")))
            return REAL_RUN(args, **kw)
        p = mock.patch.object(sg, "run_cmd", lambda a, **k: run(a, **k) if os.path.basename(str(a[0])) == "git" else self.run_cmd(a, **k))
        p.start()
        self.addCleanup(p.stop)
        return calls

    def test_git_reads_are_offline_and_partial_clone_history_is_skipped(self):
        write(os.path.join(self.folder, ".env"), "API_TOKEN=abc123realvalue\n")
        self.commit()
        git(self.folder, "config", "remote.origin.promisor", "true")
        git(self.folder, "config", "extensions.partialClone", "origin")
        calls = self.spy_git()
        out, md, js = self.check()
        self.assertIn("is a partial clone; its history was not read so nothing gets fetched", md)
        gits = [(a, e) for a, e in calls if os.path.basename(a[0]) == "git"]
        self.assertTrue(gits)
        for a, e in gits:
            self.assertNotIn("fetch", a)
            self.assertIn("protocol.allow=never", a)
            self.assertEqual(e["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(e["GIT_ASKPASS"], "")
        self.assertFalse(any("log" in a for a, _ in gits))  # no history read at all
        self.assertNotIn("abc123realvalue", md + js)

    def test_promisor_false_is_not_a_partial_clone(self):
        write(os.path.join(self.folder, ".env"), "API_TOKEN=abc123realvalue\n")
        self.commit()
        git(self.folder, "config", "remote.origin.promisor", "false")
        calls = self.spy_git()
        out, md, js = self.check()
        self.assertNotIn("is a partial clone", md)
        self.assertTrue(any("log" in a for a, _ in calls))  # history is read
        self.assertNotIn("abc123realvalue", md + js)

    def test_oversize_committed_env_is_noted_and_never_read(self):
        write(os.path.join(self.folder, ".env"), "API_TOKEN=" + "a" * (sg.MAX_SECRET_FILE + 10) + "\n")
        self.commit()
        calls = self.spy_git()
        out, md, js = self.check()
        self.assertIn(".env` is too large to read", md)
        self.assertFalse(any("show" in a and any(x.startswith("HEAD:") for x in a) for a, _ in calls))

    def test_yaml_scan_has_no_regex_backtracking(self):
        import time as _t
        text = "x" * 200000 + "\n" + ("  " * 25000 + ":\n") * 3 + "API_KEY: realvalue1\n"
        t0 = _t.time()
        names, ok = sg.literal_secret_names("secrets.yaml", text)
        self.assertLess(_t.time() - t0, 0.5)
        self.assertEqual(names, ["API_KEY"])

    def test_padded_yaml_line_still_flags_secret(self):
        for text in (" " * 5000 + "API_KEY: live-secret-value\n", "API_KEY:" + " " * 5000 + "live-secret-value\n"):
            names, ok = sg.literal_secret_names("secrets.yaml", text)
            self.assertEqual((names, ok), (["API_KEY"], True))

    def test_long_yaml_line_stays_fast(self):
        import time as _t
        t0 = _t.time()
        sg.literal_secret_names("secrets.yaml", "a" * 200000 + "\n" + ("b" * 50000 + "\n") * 4)
        self.assertLess(_t.time() - t0, 2.0)

    def test_tracked_literal_is_found_by_name_and_value_never_written(self):
        write(os.path.join(self.folder, ".mcp.json"), json.dumps({"mcpServers": {"d": {"command": "npx", "args": ["-y", "x"], "env": {"DISCORD_TOKEN": CANARY}}}}))
        self.commit()
        out, md, js = self.check()
        sec = self.section(md)
        self.assertIn("`.mcp.json`", sec)
        self.assertIn("DISCORD_TOKEN", sec)
        self.assertIn("Rotate that key first", sec)
        self.assertIn("file in git since", sec)
        self.assertEqual(json.loads(js)["committed_secrets"][0]["keys"], ["DISCORD_TOKEN"])
        for blob in (out, md, js):
            self.assertNotIn(CANARY, blob)
        title, body = sg.notify_text(json.loads(js), {"first": True, "new": [], "fixed": [], "runtimes": [], "mcp": []})
        self.assertIn("1 secret file(s) committed to git", title)
        self.assertNotIn(CANARY, title + body)
        self.assertNotIn(".mcp.json", title + body)
        notified = " ".join(str(c) for c in sg.notify_desktop.call_args_list)
        self.assertNotIn(CANARY, notified)
        self.assertNotIn(".mcp.json", notified)
        self.assertIn("1 secret file(s) committed to git", notified)
        self.assertIn("Secret files committed to git: 1", out)

    def test_placeholder_is_not_a_finding(self):
        write(os.path.join(self.folder, ".mcp.json"), json.dumps({"mcpServers": {"d": {"command": "npx", "env": {"DISCORD_TOKEN": "${DISCORD_TOKEN}", "B": "$B", "C": "<your token>", "D": "your-key-here"}}}}))
        self.commit()
        _, md, js = self.check()
        self.assertIn("None found in the usual secret files.", self.section(md))
        self.assertEqual(json.loads(js)["committed_secrets"], [])

    def test_secret_later_replaced_by_placeholder_is_found_in_history(self):
        write(os.path.join(self.folder, ".env"), "TOKEN=%s\n" % CANARY)
        self.commit("add")
        write(os.path.join(self.folder, ".env"), "TOKEN=${TOKEN}\n")
        self.commit("placeholder")
        _, md, js = self.check()
        f = json.loads(js)["committed_secrets"]
        self.assertEqual(f[0]["keys"], ["TOKEN"])
        self.assertIn("earlier commit", self.section(md))
        self.assertNotIn(CANARY, md + js)

    def test_secret_file_deleted_from_working_folder_is_still_found(self):
        write(os.path.join(self.folder, ".env"), "TOKEN=%s\n" % CANARY)
        self.commit()
        os.remove(os.path.join(self.folder, ".env"))
        _, md, js = self.check()
        f = json.loads(js)["committed_secrets"]
        self.assertEqual(f[0]["keys"], ["TOKEN"])
        self.assertTrue(f[0]["tracked"])
        self.assertNotIn(CANARY, md + js)

    def test_placeholder_forms_are_exact(self):
        for real in ("prod-example-token-9a7b", "your-9f3a8c2d1e", "xxx9f3a8c2d1e", "changeme-live-77"):
            self.assertFalse(sg.is_placeholder(real), real)
        for ph in ("", "${X}", "$X", "<your token>", "your-key-here", "changeme", "xxxxxx", "example"):
            self.assertTrue(sg.is_placeholder(ph), ph)

    def test_example_and_test_fixture_files_are_ignored(self):
        write(os.path.join(self.folder, ".env.example"), "TOKEN=%s\n" % CANARY)
        write(os.path.join(self.folder, "tests", "fixtures", ".env"), "TOKEN=%s\n" % CANARY)
        write(os.path.join(self.folder, "app", "__fixtures__", ".mcp.json"), json.dumps({"env": {"T": CANARY}}))
        self.commit()
        _, md, _ = self.check()
        self.assertIn("None found in the usual secret files.", self.section(md))

    def test_only_the_ca_bundle_is_skipped_inside_vendored_folders(self):
        for rel in ("lib/site-packages/certifi/cacert.pem", ".venv/cacert.pem", "cacert.pem"):
            self.assertFalse(sg.secret_file_name(rel), rel)
        for rel in ("deployment/venv/.env", "node_modules/private-package/.npmrc", ".venv/service.key", ".venv/lib/python3/site-packages/pkg/.env"):
            self.assertTrue(sg.secret_file_name(rel), rel)
        self.assertTrue(sg.secret_file_name("app/.env"))
        self.assertTrue(sg.secret_file_name("deploy.pem"))

    def test_env_file_literal_found(self):
        write(os.path.join(self.folder, "api", ".env"), "PORT=3000\nSECRET_KEY=%s\nEMPTY=\nREF=${PORT}\n" % CANARY)
        self.commit()
        _, md, js = self.check()
        self.assertIn("`api/.env`", self.section(md))
        self.assertEqual(json.loads(js)["committed_secrets"][0]["keys"], ["PORT", "SECRET_KEY"])
        self.assertNotIn(CANARY, md + js)

    def test_private_key_file_found(self):
        write(os.path.join(self.folder, "deploy.pem"), "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n" % CANARY)
        write(os.path.join(self.folder, "public.pem"), "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n")
        self.commit()
        _, md, js = self.check()
        sec = self.section(md)
        self.assertIn("`deploy.pem`", sec)
        self.assertNotIn("public.pem", sec)
        self.assertNotIn(CANARY, md + js)

    def test_npmrc_and_pypirc(self):
        write(os.path.join(self.folder, ".npmrc"), "//registry.npmjs.org/:_authToken=%s\n" % CANARY)
        write(os.path.join(self.folder, "x", ".npmrc"), "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
        write(os.path.join(self.folder, ".pypirc"), "[pypi]\npassword = %s\n" % CANARY)
        self.commit()
        _, md, js = self.check()
        sec = self.section(md)
        self.assertIn("`.npmrc`", sec)
        self.assertIn("`.pypirc`", sec)
        self.assertNotIn("x/.npmrc", sec)
        self.assertNotIn(CANARY, md + js)

    def test_removed_from_tracking_but_in_history(self):
        write(os.path.join(self.folder, ".env"), "TOKEN=%s\n" % CANARY)
        self.commit("add")
        git(self.folder, "rm", "-q", "--cached", ".env")
        git(self.folder, "commit", "-q", "-m", "stop tracking")
        _, md, js = self.check()
        sec = self.section(md)
        self.assertIn("was committed earlier", sec)
        self.assertIn("`.env`", sec)
        f = json.loads(js)["committed_secrets"][0]
        self.assertFalse(f["tracked"])
        self.assertTrue(f["since"])
        self.assertNotIn(CANARY, md + js)

    def test_uncommitted_secret_is_not_reported_as_committed(self):
        write(os.path.join(self.folder, ".env"), "TOKEN=<your token here>\n")
        write(os.path.join(self.folder, "README.md"), "x\n")
        self.commit()
        write(os.path.join(self.folder, ".env"), "TOKEN=%s\n" % CANARY)  # edited after the commit, never committed
        write(os.path.join(self.folder, "new.pem"), "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n" % CANARY)
        git(self.folder, "add", "new.pem")  # staged, never committed
        _, md, js = self.check()
        sec = self.section(md)
        self.assertNotIn("`.env`", sec)
        self.assertNotIn("new.pem", sec)
        self.assertEqual(json.loads(js)["committed_secrets"], [])
        self.assertNotIn(CANARY, md + js)

    def test_old_secret_beyond_the_revision_cap_is_named_not_silent(self):
        write(os.path.join(self.folder, ".env"), "TOKEN=%s\n" % CANARY)
        self.commit("secret")
        for i in range(4):
            write(os.path.join(self.folder, ".env"), "TOKEN=<your token here>\n# %d\n" % i)
            self.commit("swap %d" % i)
        with mock.patch.object(sg, "HISTORY_REVS_MAX", 2):
            _, md, js = self.check()
        self.assertIn("older revisions that were not opened", md.split("## Not checked")[1])
        self.assertNotIn(CANARY, md + js)

    def test_old_secret_inside_the_cap_is_found(self):
        write(os.path.join(self.folder, ".env"), "TOKEN=%s\n" % CANARY)
        self.commit("secret")
        for i in range(35):  # beyond the old cap of 30
            write(os.path.join(self.folder, ".env"), "TOKEN=<your token here>\n# %d\n" % i)
            self.commit("swap %d" % i)
        _, md, js = self.check()
        self.assertIn("held a value under", self.section(md))
        self.assertNotIn(CANARY, md + js)

    def test_not_a_git_repo_says_so_and_does_not_crash(self):
        shutil.rmtree(os.path.join(self.folder, ".git"))
        write(os.path.join(self.folder, ".env"), "TOKEN=%s\n" % CANARY)
        _, md, js = self.check()
        self.assertIn("not a git repository", self.section(md))
        self.assertNotIn(CANARY, md + js)

    def test_git_missing_is_listed_under_not_checked(self):
        with mock.patch.object(sg, "which", lambda n: None if n == "git" else "/usr/local/bin/" + n):
            _, md, _ = self.check()
        self.assertIn("git was not found", md.split("## Not checked")[1])

    def test_unparseable_json_is_reported_not_skipped(self):
        write(os.path.join(self.folder, ".mcp.json"), "{ not json")
        self.commit()
        _, md, _ = self.check()
        self.assertIn("could not be parsed", md.split("## Not checked")[1])


@POSIX_ONLY  # the stand-in tools are /bin/sh scripts
class StandaloneTools(Base):
    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.home, "bin")
        os.makedirs(self.bin)
        self.tooldir = os.path.join(self.tmp, "uvtools")
        for env, certifi in (("httpie", "2024.2.2"), ("ruff", None)):
            sp = os.path.join(self.tooldir, env, "lib", "python3.12", "site-packages")
            os.makedirs(sp)
            os.makedirs(os.path.join(sp, "pip-24.0.dist-info"))
            if certifi:
                os.makedirs(os.path.join(sp, "certifi-%s.dist-info" % certifi))
        self.stub("uv", 'if [ "$1" = "tool" ]; then echo "%s"; else echo "uv 0.11.6 (abc 2026-01-02)"; fi' % self.tooldir)
        self.stub("pip3", 'echo "pip 24.0 from /x/site-packages/pip (python 3.12)"')
        self.stub("pip", 'echo "pip 24.0 from /x/site-packages/pip (python 3.12)"')
        self.stub("npm", "echo 10.8.2")
        self.stub("yarn", "echo 4.1.0")
        self.stub("bun", "echo 1.1.0")
        self.stub("deno", 'echo "deno 1.40.0 (stable)"')
        self.stub("poetry", 'echo "Poetry (version 1.8.3)"')
        for target, new in (("run_cmd", REAL_RUN),
                            ("which", lambda n: REAL_WHICH(n, path=self.bin))):
            p = mock.patch.object(sg, target, new)
            p.start()
            self.addCleanup(p.stop)

    def stub(self, name, body):
        path = os.path.join(self.bin, name)
        write(path, "#!/bin/sh\n%s\n" % body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    def test_inventory_lists_tools_with_home_as_tilde(self):
        inv = sg.build_inventory(self.folder)
        names = {t["name"]: t for t in inv["tools"]}
        self.assertEqual(names["uv"]["version"], "0.11.6")
        self.assertEqual(names["uv"]["path"], "~/bin/uv")
        self.assertEqual(names["poetry"]["version"], "1.8.3")
        self.assertEqual(names["deno"]["version"], "1.40.0")
        self.assertNotIn("pip", names)  # pip3 and pip are one tool
        self.assertEqual({e["tool"]: (e["certifi"], e["pip"]) for e in inv["tool_envs"]},
                         {"httpie": ("2024.2.2", "24.0"), "ruff": (None, "24.0")})
        text = sg.render_inventory(inv)
        self.assertIn("## Tools on this computer", text)
        self.assertIn("certifi 2024.2.2", text)
        self.assertNotIn(self.home, text)

    def test_osv_lookups_and_the_ones_with_no_feed(self):
        net = FakeNet({"uv": ["GHSA-aaaa-bbbb-cccc"], "certifi": ["GHSA-dddd-eeee-ffff"]})
        with mock.patch.object(sg, "http_json", net):
            self.run_main("check", self.folder)
        md = self.report()
        asked = set()
        inv = sg.build_inventory(self.folder)
        for t in sg.collect_targets(inv):
            asked.add((t["ecosystem"], t["name"], t["version"]))
        self.assertIn(("PyPI", "uv", "0.11.6"), asked)
        self.assertIn(("PyPI", "pip", "24.0"), asked)
        self.assertIn(("PyPI", "poetry", "1.8.3"), asked)
        self.assertIn(("PyPI", "certifi", "2024.2.2"), asked)
        self.assertIn(("npm", "npm", "10.8.2"), asked)
        self.assertNotIn("bun", {a[1] for a in asked})
        self.assertNotIn("deno", {a[1] for a in asked})
        self.assertNotIn("yarn", {a[1] for a in asked})  # yarn 4 is Berry, not the npm package
        tools = md.split("## Tools on this computer")[1].split("## ")[0]
        self.assertIn("uv 0.11.6", tools)
        self.assertIn("GHSA-aaaa-bbbb-cccc", tools)
        self.assertIn("certifi", tools)
        also = md.split("## 🟠 Also worth fixing")[1].split("## ")[0]
        self.assertNotIn("uv 0.11.6", also)
        nc = md.split("## Not checked")[1]
        self.assertIn("no advisory feed (not checked): bun, deno", nc)
        self.assertIn("Berry", nc)

    def test_tools_stay_out_of_the_news_search(self):
        inv = sg.build_inventory(self.folder)
        self.assertFalse([c for c in sg.ordered_components(inv) if c.startswith(("uv ", "npm ", "pip "))])


class WasIHitFiles(unittest.TestCase):
    def read(self, *parts):
        with open(os.path.join(PLUGIN, *parts), encoding="utf-8") as fh:
            return fh.read()

    def front(self, text):
        m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        return dict(re.findall(r"^(\w+):\s*(.*)$", m.group(1), re.M))

    def test_skill_agent_command_exist(self):
        skill = self.read("skills", "stack-breach-check", "SKILL.md")
        self.assertEqual(self.front(skill)["name"], "stack-breach-check")
        for word in ("Reachable?", "Window", "Traffic", "Traces", "Verdict", "signs found", "rotate these", "observability"):
            self.assertIn(word, skill)
        self.assertEqual(skill.count("never print, quote, paste or summarise the value of a token"), 1)

    def test_agent_is_least_privilege(self):
        fm = self.front(self.read("agents", "stack-breach-checker.md"))
        self.assertEqual(fm["model"], "sonnet")
        tools = [t.strip() for t in fm["tools"].split(",")]
        self.assertEqual(sorted(tools), ["Glob", "Grep", "Read", "WebFetch"])
        self.assertIn("Bash", fm["disallowedTools"])
        for banned in ("Edit", "Write", "NotebookEdit", "Agent"):
            self.assertNotIn(banned, tools)
            self.assertIn(banned, fm["disallowedTools"])

    def test_command_runs_stage_2b_in_audit_only(self):
        cmd = self.read("commands", "stack-guard.md")
        self.assertIn("Stage 2b", cmd)
        self.assertIn("Was I hit?", cmd)
        self.assertRegex(cmd, r"(?s)Stage 2b.*--audit-only")
        self.assertIn("## Secrets committed to git", cmd)

    def test_codex_skill_has_the_step(self):
        self.assertIn("stack-breach-check", self.read("skills", "run-stack-guard", "SKILL.md"))

    def test_watch_command_keeps_breach_checks_out(self):
        self.assertIn("Run /stack-guard to check whether these were used against you", self.read("commands", "watch.md"))

    def test_daily_notice_line_only_for_new_live_high(self):
        f = {"key": "k", "severity": "HIGH", "deploy": True, "dev": False}
        rep = {"date": "d", "not_checked": [], "findings": [f]}
        body = sg.notify_text(rep, {"first": False, "new": [{"text": "x", "key": "k"}], "fixed": [], "runtimes": [], "mcp": []})[1]
        self.assertIn("Run /stack-guard to check whether these were used against you.", body)
        rep["findings"] = [dict(f, dev=True)]
        body = sg.notify_text(rep, {"first": False, "new": [{"text": "x", "key": "k"}], "fixed": [], "runtimes": [], "mcp": []})[1]
        self.assertNotIn("used against you", body)


class DeployRuntimeAndVersion(unittest.TestCase):
    def test_stack_fix_has_the_deploy_runtime_line(self):
        with open(os.path.join(PLUGIN, "skills", "stack-fix", "SKILL.md"), encoding="utf-8") as fh:
            text = fh.read()
        for word in ("wrangler dev", "OpenNext", "not proven in the deploy runtime", "Docker app", "Fly app"):
            self.assertIn(word, text)
        with open(os.path.join(PLUGIN, "agents", "stack-fixer.md"), encoding="utf-8") as fh:
            self.assertIn("deploy-runtime check: passed / failed / not possible", fh.read())

    def test_all_manifests_say_the_script_version(self):
        self.assertEqual(sg.VERSION, "1.6.0")
        for rel in (("plugins", "stack-guard", ".claude-plugin", "plugin.json"), ("plugins", "stack-guard", ".codex-plugin", "plugin.json")):
            with open(os.path.join(ROOT, *rel), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["version"], sg.VERSION)
        for rel in ((".claude-plugin", "marketplace.json"), (".agents", "plugins", "marketplace.json")):
            with open(os.path.join(ROOT, *rel), encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotIn("1.4.0", text)




class WindowsPythonInHooks(unittest.TestCase):
    def commands(self):
        with open(os.path.join(PLUGIN, "hooks", "hooks.json"), encoding="utf-8") as fh:
            hooks = json.load(fh)["hooks"]
        return [h["command"] for es in hooks.values() for e in es for h in e["hooks"]]

    def run_with(self, command, os_name, names):
        import subprocess, tempfile
        if os.name != "posix":
            self.skipTest("the hook launcher is tried through /bin/sh")
        d = tempfile.mkdtemp()
        log = os.path.join(d, "ran")
        for n in names:
            p = os.path.join(d, n)
            with open(p, "w") as fh:
                fh.write("#!/bin/sh\necho %s >> %s\n" % (n, log))
            os.chmod(p, 0o755)
        env = {"PATH": d + os.pathsep + "/usr/bin:/bin", "CLAUDE_PLUGIN_ROOT": PLUGIN}
        if os_name:
            env["OS"] = os_name
        subprocess.run(["sh", "-c", command], env=env, input="{}", text=True, capture_output=True, timeout=20)
        if not os.path.exists(log):
            return []
        with open(log) as fh:
            return fh.read().split()

    def test_every_hook_picks_python_on_windows_and_python3_elsewhere(self):
        for c in self.commands():
            self.assertNotIn("python3 \"", c.replace('"$PY"', ""), c)
            self.assertEqual(self.run_with(c, "Windows_NT", ["python", "python3"]), ["python"], c)
            self.assertEqual(self.run_with(c, None, ["python", "python3"]), ["python3"], c)

if __name__ == "__main__":
    unittest.main()
