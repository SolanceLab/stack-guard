# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.6.3: services on this computer and lock-check."""
import contextlib
import datetime
import io
import json
import os
import plistlib
import tempfile
import unittest
from unittest import mock

import stack_guard as sg

ARG_VALUE = "sk-arg-fedcba9876543210"
TOKEN_VALUE = "sk-live-0123456789abcdef"


class FakeGrp:
    def __init__(self, groups):
        self.groups = groups

    def getgrgid(self, gid):
        return type("G", (), {"gr_mem": self.groups[gid]})()


class FakePwd:
    def __init__(self, users):
        self.users = [type("U", (), {"pw_name": n, "pw_uid": u, "pw_gid": g})() for n, u, g in users]

    def getpwall(self):
        return list(self.users)

    def getpwnam(self, name):
        for u in self.users:
            if u.pw_name == name:
                return u
        raise KeyError(name)


def blank_inventory():
    return {"generated": "2026-11-04", "folder": "proj", "projects": [], "mcp": [], "runtimes": [], "unreadable": [],
            "too_deep": [], "tools": [], "tool_envs": [], "outside": []}


class ServiceFixture(unittest.TestCase):
    """A temp HOME and project folder, with launchctl, lsof and every program run replaced."""

    def setUp(self):
        self.home = os.path.realpath(tempfile.mkdtemp())
        self.root = os.path.realpath(tempfile.mkdtemp())
        os.makedirs(os.path.join(self.home, "Library", "LaunchAgents"))
        os.makedirs(os.path.join(self.home, "bin"))
        self.trusted = os.path.realpath(tempfile.mkdtemp())  # stands in for a Homebrew Cellar folder
        self.launchctl = "PID\tStatus\tLabel\n"
        self.lsof = ""
        self.ran = []
        self.fake_programs = {}
        patches = [
            mock.patch.object(sg, "home_dir", lambda: self.home),
            mock.patch.object(sg, "platform_name", lambda: "darwin"),
            mock.patch.object(sg, "LAUNCHD_SYSTEM_DIRS", ()),
            mock.patch.object(sg, "TRUSTED_RUN_DIRS", (self.trusted,)),
            mock.patch.object(sg, "CELLAR_ROOTS", (os.path.join(self.trusted, "Cellar"),)),
            mock.patch.object(sg, "which", lambda n: "/usr/bin/" + n if n in ("launchctl", "lsof", "node") else None),
            mock.patch.object(sg, "run_cmd", self.fake_run),
            mock.patch.object(sg, "global_private_index", lambda: False),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def fake_run(self, args, **kw):
        self.ran.append(list(args))
        name = os.path.basename(args[0])
        if name == "launchctl":
            return 0, self.launchctl
        if name == "lsof":
            return (0, self.lsof) if self.lsof else (1, "")
        if args[1:] == ["--version"] and args[0] in self.fake_programs:
            return 0, self.fake_programs[args[0]]
        return 127, ""

    def program(self, name, mode=0o755, folder=None):
        path = os.path.join(folder or os.path.join(self.home, "bin"), name)
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n")
        os.chmod(path, mode)
        return path

    def plist(self, label, args, extra=None, program=None):
        data = {"Label": label, "ProgramArguments": args}
        if program:
            data["Program"] = program
        data.update(extra or {})
        with open(os.path.join(self.home, "Library", "LaunchAgents", label + ".plist"), "wb") as fh:
            plistlib.dump(data, fh)

    def scan(self, projects=True):
        inv = blank_inventory()
        if projects:  # the scanned folder's own projects, as a real run lists them before the services
            sg.scan_projects(self.root, inv)
        sg.scan_services(self.root, inv)
        return inv

    def service(self, inv, label):
        return next(s for s in inv["services"] if s["label"] == label)


class ServiceInventory(ServiceFixture):
    def test_environment_secret_and_extra_arguments_never_appear(self):
        script = os.path.join(self.home, "bin", "run.sh")
        open(script, "w").close()
        os.chmod(script, 0o755)
        self.plist("com.example.job", ["/bin/sh", script, "--token=" + ARG_VALUE],
                   extra={"EnvironmentVariables": {"API_TOKEN": TOKEN_VALUE}, "Sockets": {"x": {"SockPathName": "/tmp/" + TOKEN_VALUE}}})
        inv = self.scan()
        rep = sg.make_report(inv, [], [], True)
        everything = sg.render_inventory(inv) + sg.render_report(rep, sg.diff_reports(None, rep)) + json.dumps(rep) + json.dumps(inv)
        self.assertNotIn(TOKEN_VALUE, everything)
        self.assertNotIn(ARG_VALUE, everything)
        s = self.service(inv, "com.example.job")
        self.assertEqual(s["program"], "/bin/sh")
        self.assertEqual(s["script"], "~/bin/run.sh")  # a home path shows as ~/...

    def test_argument_that_is_not_a_file_is_not_shown(self):
        self.plist("com.example.args", ["/bin/sh", "-c", "curl -H 'Authorization: " + ARG_VALUE + "' x"])
        inv = self.scan()
        self.assertIsNone(self.service(inv, "com.example.args")["script"])
        self.assertNotIn(ARG_VALUE, json.dumps(inv))

    def test_unrecognised_program_is_flagged_and_never_run(self):
        mystery = self.program("mystery")
        self.plist("com.example.mystery", [mystery])
        inv = self.scan()
        self.assertIn("unrecognised", self.service(inv, "com.example.mystery")["flags"])
        self.assertFalse([c for c in self.ran if c[0] == mystery], self.ran)
        self.assertIn("com.example.mystery", sg.render_inventory(inv))
        self.assertTrue(any("no advisory feed" in n and "com.example.mystery" in n for n in inv["service_notes"]))

    def test_program_in_the_scanned_folder_is_recognised(self):
        inside = os.path.join(self.root, "tool")
        open(inside, "w").close()
        os.chmod(inside, 0o755)
        self.plist("com.example.inside", [inside])
        self.assertNotIn("unrecognised", self.service(self.scan(), "com.example.inside")["flags"])

    def test_missing_program_is_flagged(self):
        self.plist("com.example.gone", ["/opt/nowhere/prog"])
        self.assertIn("missing", self.service(self.scan(), "com.example.gone")["flags"])

    def test_known_runtime_is_run_for_its_version_only(self):
        py = self.program("python3", folder=self.trusted)
        self.fake_programs[py] = "Python 3.9.6"
        self.plist("com.example.py", [py, "app.py"])
        inv = self.scan()
        self.assertIn([py, "--version"], self.ran)
        self.assertEqual([c for c in self.ran if c[0] == py], [[py, "--version"]])
        self.assertIn({"name": "python", "version": "3.9.6", "source": "service com.example.py", "exact": True}, inv["runtimes"])

    def test_cloudflared_and_ollama_become_advisory_targets(self):
        cf, ol = self.program("cloudflared", folder=self.trusted), self.program("ollama", folder=self.trusted)
        self.fake_programs[cf] = "cloudflared version 2024.6.1 (built 2024-06-20)"
        self.fake_programs[ol] = "ollama version is 0.1.30"
        self.plist("com.example.cf", [cf, "tunnel"])
        self.plist("com.example.ol", [ol, "serve"])
        got = {(t["ecosystem"], t["name"], t["version"]) for t in self.scan()["service_targets"]}
        self.assertIn(("Go", "github.com/cloudflare/cloudflared", "2024.6.1"), got)
        self.assertIn(("Go", "github.com/ollama/ollama", "0.1.30"), got)

    def test_postgres_is_checked_for_support_dates(self):
        pg = self.program("postgres", folder=self.trusted)
        self.fake_programs[pg] = "postgres (PostgreSQL) 14.11"
        self.plist("com.example.pg", [pg, "-D", "/x"])
        inv = self.scan()
        rt = [r for r in inv["runtimes"] if r["name"] == "postgres"]
        self.assertEqual(rt[0]["version"], "14.11")
        with mock.patch.object(sg, "http_json", lambda url, body=None, timeout=30: [{"cycle": "14", "eol": "2099-11-12", "latest": "14.13"}]):
            sg.eol_check(rt, [])
        self.assertEqual(rt[0]["status"], "supported")

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_tamper_risk_flagged_and_that_program_is_not_run(self):
        py = self.program("python3", mode=0o777)
        self.fake_programs[py] = "Python 3.9.6"
        self.plist("com.example.loose", [py])
        s = self.service(self.scan(), "com.example.loose")
        self.assertIn("tamper", s["flags"])
        self.assertFalse([c for c in self.ran if c[0] == py], self.ran)

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_group_write_is_tamper_when_the_group_has_another_member(self):
        prog = self.program("grouped", mode=0o775)
        self.plist("com.example.grouped", [prog])
        with mock.patch.object(sg, "grp", FakeGrp({os.getgid(): ["someoneelse"]})), \
                mock.patch.object(sg, "pwd", FakePwd([("someoneelse", 1234, 9999)])):
            self.assertIn("tamper", self.service(self.scan(), "com.example.grouped")["flags"])

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_group_write_is_safe_only_when_the_group_is_exclusive(self):
        me, gid = os.getuid(), 4242
        me_name = "meuser"
        users = [("root", 0, 0), (me_name, me, gid)]
        cases = [
            ("only me and root", FakeGrp({gid: ["root", me_name]}), FakePwd(users), True),
            ("a real other member", FakeGrp({gid: [me_name, "bob"]}), FakePwd(users + [("bob", 7001, 77)]), False),
            ("another user with it as primary group", FakeGrp({gid: [me_name]}), FakePwd(users + [("carol", 7002, gid)]), False),
            ("a macOS system account below 500 still counts", FakeGrp({gid: [me_name]}), FakePwd(users + [("_spotlight", 89, gid)]), False),
            ("an underscore account at 500 or above", FakeGrp({gid: [me_name]}), FakePwd(users + [("_odd", 600, gid)]), False),
            ("a member with no account entry", FakeGrp({gid: ["ghost"]}), FakePwd(users), False),
            ("group not found", FakeGrp({}), FakePwd(users), False),
        ]
        for label, g, p, expect in cases:
            with self.subTest(label), mock.patch.object(sg, "grp", g), mock.patch.object(sg, "pwd", p):
                self.assertEqual(sg.group_is_exclusive(gid), expect)
        with mock.patch.object(sg, "grp", None), mock.patch.object(sg, "pwd", None):
            self.assertFalse(sg.group_is_exclusive(gid))

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_group_write_with_an_exclusive_group_is_not_tamper_but_other_write_always_is(self):
        d = tempfile.mkdtemp(dir=self.home)
        f = os.path.join(d, "svc.sh")
        open(f, "w").close()
        os.chmod(f, 0o755)
        os.chmod(d, 0o775)
        with mock.patch.object(sg, "group_is_exclusive", lambda gid: True):
            self.assertFalse(sg.changeable(f))
            os.chmod(d, 0o757)
            self.assertTrue(sg.changeable(f))
        os.chmod(d, 0o775)
        with mock.patch.object(sg, "group_is_exclusive", lambda gid: False):
            self.assertTrue(sg.changeable(f))

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_a_home_folder_fake_behind_a_trusted_symlink_is_never_run(self):
        fake = self.program("node")  # in the home folder
        self.fake_programs[fake] = "v22.1.0"
        link = os.path.join(self.trusted, "node")
        os.symlink(fake, link)
        self.fake_programs[link] = "v22.1.0"
        self.plist("com.example.node", [link, "app.js"])
        inv = self.scan()
        self.assertFalse([c for c in self.ran if c[0] in (fake, link)], self.ran)
        self.assertIn("com.example.node", inv["service_untrusted"])
        self.assertTrue(any("not a trusted install" in n and "com.example.node" in n for n in inv["service_notes"]))

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_a_user_owned_fake_in_applications_is_never_run(self):
        apps = os.path.join(self.home, "Applications")
        os.makedirs(os.path.join(apps, "Evil.app", "Contents", "MacOS"))
        fake = self.program("node", folder=os.path.join(apps, "Evil.app", "Contents", "MacOS"))
        self.fake_programs[fake] = "v22.1.0"
        self.plist("com.example.app", [fake])
        with mock.patch.object(sg, "APP_DIRS", (apps,)):
            inv = self.scan()
        self.assertFalse([c for c in self.ran if c[0] == fake], self.ran)
        self.assertIn("com.example.app", inv["service_untrusted"])

    def test_version_is_read_from_the_cellar_path_without_running(self):
        cellar = os.path.join(self.trusted, "Cellar", "node", "22.1.0", "bin")
        os.makedirs(cellar)
        prog = self.program("node", folder=cellar)
        self.plist("com.example.cellar", [prog])
        inv = self.scan()
        self.assertFalse([c for c in self.ran if c[0] == prog], self.ran)
        self.assertTrue(any(r["name"] == "node" and r["version"] == "22.1.0" for r in inv["runtimes"]), inv["runtimes"])

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_a_writable_cellar_shaped_path_does_not_forge_a_version(self):
        cellar = os.path.join(self.trusted, "Cellar", "node", "99.0.0", "bin")
        os.makedirs(cellar)
        prog = self.program("node", mode=0o777, folder=cellar)
        self.plist("com.example.forged", [prog])
        inv = self.scan()
        s = self.service(inv, "com.example.forged")
        self.assertIn("tamper", s["flags"])
        self.assertFalse([r for r in inv["runtimes"] if r["version"] == "99.0.0"], inv["runtimes"])
        self.assertIn("com.example.forged", inv["service_untrusted"])

    def test_a_cellar_look_alike_outside_homebrew_gives_no_version(self):
        fake = os.path.join(self.home, "Cellar", "node", "99.0.0", "bin")
        os.makedirs(fake)
        prog = self.program("node", folder=fake)
        self.assertIsNone(sg.version_without_running(prog, "node"))
        real = os.path.join(self.trusted, "Cellar", "wget", "1.2.3", "bin")
        os.makedirs(real)
        self.assertIsNone(sg.version_without_running(self.program("node", folder=real), "node"))  # wrong formula

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_group_write_on_a_sticky_folder_is_not_tamper(self):
        d = tempfile.mkdtemp(dir=self.home)
        os.chmod(d, 0o1777)
        f = os.path.join(d, "svc.sh")
        open(f, "w").close()
        os.chmod(f, 0o755)
        self.assertFalse(sg.changeable(f))
        os.chmod(d, 0o757)
        self.assertTrue(sg.changeable(f))

    @unittest.skipUnless(hasattr(os, "getuid"), "permission bits are POSIX")
    def test_tidy_files_are_not_flagged_as_tamper(self):
        self.plist("com.example.tidy", ["/bin/sh"])
        self.assertNotIn("tamper", self.service(self.scan(), "com.example.tidy")["flags"])

    def make_venv(self, home_dir):
        vdir = os.path.join(self.root, "proj", ".venv")
        os.makedirs(os.path.join(vdir, "bin"))
        with open(os.path.join(self.root, "proj", "requirements.txt"), "w") as fh:  # the owning project, public
            fh.write("requests==2.31.0\n")
        os.makedirs(os.path.join(vdir, "lib", "python3.11", "site-packages", "requests-2.31.0.dist-info"))
        with open(os.path.join(vdir, "pyvenv.cfg"), "w") as fh:
            fh.write("home = %s\nversion = 3.11.5\n" % home_dir)
        py = os.path.join(vdir, "bin", "python")
        open(py, "w").close()
        os.chmod(py, 0o755)
        return py

    def test_venv_with_a_removed_python_is_flagged_broken(self):
        py = self.make_venv("/opt/homebrew/opt/python@3.99/bin")
        self.plist("com.example.venv", [py, "app.py"])
        inv = self.scan()
        s = self.service(inv, "com.example.venv")
        self.assertIn("broken", s["flags"])
        self.assertIn("tied", s["flags"])
        self.assertIn(("requests", "2.31.0"), [(t["name"], t["version"]) for t in inv["service_targets"]])
        with mock.patch.object(sg, "http_json", lambda url, body=None, timeout=30: []):
            sg.eol_check(inv["runtimes"], [])  # the venv's Python version is read from pyvenv.cfg, so it gets a support date
        rep = sg.make_report(inv, [], [], True)
        self.assertIn("broken: its Python was removed", sg.render_report(rep, sg.diff_reports(None, rep)))

    def test_untrusted_venv_cfg_does_not_feed_the_runtimes_list(self):
        evil = os.path.join(self.home, "evil")
        os.makedirs(os.path.join(evil, "bin"))
        with open(os.path.join(evil, "pyvenv.cfg"), "w") as fh:
            fh.write("home = /usr/bin\nversion = 2.7.18\n")
        py = os.path.join(evil, "bin", "python")
        open(py, "w").close()
        os.chmod(py, 0o777)  # changeable, so flagged as tamper
        self.plist("com.example.evil", [py])
        inv = self.scan()
        self.assertNotIn("2.7.18", [r["version"] for r in inv["runtimes"]])
        self.assertIn("com.example.evil", inv["service_untrusted"])

    def test_venv_with_its_python_present_is_not_broken(self):
        py = self.make_venv(self.home)
        self.plist("com.example.venv2", [py])
        self.assertNotIn("broken", self.service(self.scan(), "com.example.venv2")["flags"])

    def test_service_packages_go_through_the_lookup_targets(self):
        py = self.make_venv(self.home)
        self.plist("com.example.venv3", [py])
        inv = self.scan()
        inv["mcp"] = []
        stats = {}
        targets = sg.collect_targets(inv, stats)
        self.assertIn(("PyPI", "requests", "2.31.0", "service com.example.venv3 (venv)"),
                      [(t["ecosystem"], t["name"], t["version"], t["project"]) for t in targets])
        with mock.patch.object(sg, "global_private_index", lambda: True):  # a private index: nothing leaves the computer
            self.assertFalse([t for t in sg.collect_targets(inv, {}) if t.get("service")])

    def test_status_comes_from_launchctl(self):
        self.plist("com.example.up", ["/bin/sh"])
        self.plist("com.example.bad", ["/bin/sh"])
        self.plist("com.example.off", ["/bin/sh"])
        self.launchctl += "123\t0\tcom.example.up\n-\t78\tcom.example.bad\n"
        inv = self.scan()
        self.assertEqual(self.service(inv, "com.example.up")["status"], "running")
        bad = self.service(inv, "com.example.bad")
        self.assertEqual(bad["status"], "failing")
        self.assertIn("failing", bad["flags"])
        self.assertEqual(self.service(inv, "com.example.off")["status"], "not loaded")

    def test_a_failed_command_becomes_a_note_not_a_crash(self):
        self.plist("com.example.a", ["/bin/sh"])
        with mock.patch.object(sg, "which", lambda n: None):
            inv = self.scan()
        self.assertTrue(any("not checked" in n for n in inv["service_notes"]), inv["service_notes"])
        self.assertEqual(self.service(inv, "com.example.a")["status"], "unknown")


class ListeningPorts(ServiceFixture):
    LSOF = ("COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "node     101 me   20u  IPv4 0x1      0t0  TCP 127.0.0.1:8001 (LISTEN)\n"
            "python3  102 me    4u  IPv4 0x2      0t0  TCP *:8002 (LISTEN)\n"
            "ollama   103 me    5u  IPv6 0x3      0t0  TCP [::1]:8003 (LISTEN)\n"
            "other    104 me    6u  IPv4 0x4      0t0  TCP 192.168.1.5:8004 (LISTEN)\n")

    def test_ports_are_classified(self):
        os.makedirs(os.path.join(self.home, ".cloudflared"))
        with open(os.path.join(self.home, ".cloudflared", "config.yml"), "w") as fh:
            fh.write("tunnel: abc\ningress:\n  - hostname: private-host.example.org\n    service: http://localhost:8001\n  - service: http_status:404\n")
        self.lsof = self.LSOF
        self.plist("com.example.web", ["/bin/sh"])
        self.launchctl += "101\t0\tcom.example.web\n"
        inv = self.scan()
        reach = {p["port"]: p["reach"] for p in inv["ports"]}
        self.assertEqual(reach, {8001: "tunnel", 8002: "network", 8003: "local", 8004: "network"})
        web = self.service(inv, "com.example.web")
        self.assertEqual(web["reach"], "tunnel")
        self.assertIn("tunnel", web["flags"])
        self.assertEqual(next(p["who"] for p in inv["ports"] if p["port"] == 8001), "com.example.web")
        text = sg.render_inventory(inv)
        self.assertIn("## Listening ports", text)
        self.assertIn("reachable from the internet through a tunnel", text)
        self.assertNotIn("private-host.example.org", text + json.dumps(inv))

    def cloudflared_service(self, args):
        cf = self.program("cloudflared")
        self.lsof = self.LSOF
        self.plist("com.example.tunnel", [cf] + args)
        self.plist("com.example.web", ["/bin/sh"])
        self.launchctl += "101\t0\tcom.example.web\n"
        inv = self.scan()
        return {p["port"]: p["reach"] for p in inv["ports"]}, inv

    def test_cloudflared_config_named_in_the_arguments_marks_its_port(self):
        cfg = os.path.join(self.root, "tun.yml")
        with open(cfg, "w") as fh:
            fh.write("tunnel: abc123tunnelid\ncredentials-file: /nowhere/creds.json\ningress:\n"
                     "  - hostname: private-host.example.org\n    service: http://localhost:8001\n  - service: http_status:404\n")
        for args in (["tunnel", "--config", cfg, "run"], ["tunnel", "--config=" + cfg, "run"]):
            reach, inv = self.cloudflared_service(args)
            self.assertEqual(reach[8001], "tunnel", args)
            self.assertEqual(reach[8003], "local")
            self.assertIn("tunnel", self.service(inv, "com.example.web")["flags"])
            blob = sg.render_inventory(inv) + json.dumps(inv)
            for secret in ("private-host.example.org", "abc123tunnelid", "creds.json"):
                self.assertNotIn(secret, blob)

    def test_cloudflared_url_form_marks_its_port(self):
        reach, _ = self.cloudflared_service(["tunnel", "--url", "http://localhost:8002"])
        self.assertEqual(reach[8002], "tunnel")
        reach, _ = self.cloudflared_service(["tunnel", "--url=https://127.0.0.1:8003"])
        self.assertEqual(reach[8003], "tunnel")
        reach, _ = self.cloudflared_service(["tunnel", "--url", "http://example.org:8002"])
        self.assertEqual(reach[8002], "network")

    def test_the_credentials_json_and_missing_configs_are_never_read(self):
        creds = os.path.join(self.root, "creds.json")
        with open(creds, "w") as fh:
            fh.write("service: http://localhost:8001\n")
        reach, _ = self.cloudflared_service(["tunnel", "--config", creds, "run"])
        self.assertEqual(reach[8001], "local")
        reach, _ = self.cloudflared_service(["tunnel", "--config", os.path.join(self.root, "missing.yml")])
        self.assertEqual(reach[8001], "local")

    def test_a_config_argument_on_another_program_is_ignored(self):
        cfg = os.path.join(self.root, "other.yml")
        with open(cfg, "w") as fh:
            fh.write("service: http://localhost:8001\n")
        self.assertEqual(sg.cloudflared_arg_ports("/usr/bin/node", ["node", "--config", cfg]), set())

    def tunnel_config(self, folder, name="tun.yml"):
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, name), "w") as fh:
            fh.write("tunnel: abc123tunnelid\ningress:\n  - hostname: private-host.example.org\n    service: http://localhost:8001\n")

    def test_relative_config_is_joined_to_the_working_directory(self):
        folder = os.path.join(self.root, "cfgdir")
        self.tunnel_config(folder)
        self.lsof = self.LSOF
        self.plist("com.example.tunnel", [self.program("cloudflared"), "tunnel", "--config", "tun.yml", "run"],
                   extra={"WorkingDirectory": folder})
        inv = self.scan()
        self.assertEqual({p["port"]: p["reach"] for p in inv["ports"]}[8001], "tunnel")
        self.assertFalse([n for n in inv["service_notes"] if "relative" in n])

    def test_relative_config_without_a_working_directory_is_said_not_checked(self):
        self.lsof = self.LSOF
        self.plist("com.example.tunnel", [self.program("cloudflared"), "tunnel", "--config", "tun.yml", "run"])
        inv = self.scan()
        self.assertTrue(any("not checked" in n and "com.example.tunnel" in n and "relative" in n for n in inv["service_notes"]),
                        inv["service_notes"])
        self.assertEqual({p["port"]: p["reach"] for p in inv["ports"]}[8001], "local")

    def test_systemd_and_scheduled_task_tunnel_configs_are_read(self):
        folder = os.path.join(self.root, "cfgdir")
        self.tunnel_config(folder)
        cfg = os.path.join(folder, "tun.yml")
        cf = self.program("cloudflared")
        unit = ("Id=tun.service\nFragmentPath=/x/tun.service\nMainPID=0\nActiveState=active\nResult=success\n"
                "WorkingDirectory=%s\nExecStart={ path=%s ; argv[]=%s tunnel --config %s run ; ignore_errors=no }\n")
        csv_head = '"TaskName","Task To Run","Start In","Last Result"\n'
        for rel in (False, True):
            conf = cfg if not rel else "tun.yml"
            def fake(args, root, timeout=10, _conf=conf):
                if args[0] == "systemctl" and args[2] == "list-units":
                    return 0, "tun.service loaded active running t\n"
                if args[0] == "systemctl":
                    return 0, unit % (folder, cf, cf, _conf)
                return 0, csv_head + '"\\tun","%s tunnel --config %s run","%s","0"\n' % (cf, _conf, folder)
            with mock.patch.object(sg, "run_system_tool", fake):
                for func in (sg.systemd_services, sg.task_services):
                    notes = []
                    svc = func(self.root, notes)
                    self.assertEqual(svc[0]["tunnel_ports"], {8001}, (func.__name__, conf))
                    self.assertEqual(notes, [])
                    self.assertNotIn("private-host.example.org", json.dumps(svc, default=list))
            if not rel:
                continue
            # relative with no working directory: a note, no ports
            unit_no_wd = unit.replace("WorkingDirectory=%s\n", "")
            def fake2(args, root, timeout=10):
                if args[0] == "systemctl" and args[2] == "list-units":
                    return 0, "tun.service loaded active running t\n"
                if args[0] == "systemctl":
                    return 0, unit_no_wd % (cf, cf, "tun.yml")
                return 0, csv_head + '"\\tun","%s tunnel --config tun.yml run","N/A","0"\n' % cf
            with mock.patch.object(sg, "run_system_tool", fake2):
                for func in (sg.systemd_services, sg.task_services):
                    notes = []
                    svc = func(self.root, notes)
                    self.assertEqual(svc[0]["tunnel_ports"], set(), func.__name__)
                    self.assertTrue(any("not checked" in n and "relative" in n for n in notes), (func.__name__, notes))

    def test_systemd_escaped_space_in_config_path_is_decoded(self):
        self.assertEqual(sg.systemd_unescape("a\\x20b\\\\c"), "a b\\c")
        folder = os.path.join(self.root, "my cfg")
        self.tunnel_config(folder)
        cf = self.program("cloudflared")
        conf = os.path.join(folder, "tun.yml").replace(" ", "\\x20")
        unit = ("Id=tun.service\nFragmentPath=/x/tun.service\nMainPID=0\nActiveState=active\nResult=success\n"
                "ExecStart={ path=%s ; argv[]=%s tunnel --config %s run ; ignore_errors=no }\n" % (cf, cf, conf))
        def fake(args, root, timeout=10):
            if args[2] == "list-units":
                return 0, "tun.service loaded active running t\n"
            return 0, unit
        notes = []
        with mock.patch.object(sg, "run_system_tool", fake):
            svc = sg.systemd_services(self.root, notes)
        self.assertEqual(svc[0]["tunnel_ports"], {8001})
        self.assertEqual(notes, [])

    def test_quoted_config_equals_path_with_spaces_in_a_scheduled_task(self):
        folder = os.path.join(self.root, "Program Files", "cloudflared")
        self.tunnel_config(folder)
        cf = self.program("cloudflared")
        out = ('"TaskName","Task To Run","Start In","Last Result"\n'
               '"\\tun","%s tunnel --config=""%s"" run","N/A","0"\n' % (cf, os.path.join(folder, "tun.yml")))
        self.assertEqual(sg.split_windows_command('a --config="C:\\Program Files\\t.yml" run'),
                         ["a", "--config=C:\\Program Files\\t.yml", "run"])
        with mock.patch.object(sg, "run_system_tool", lambda args, root, timeout=10: (0, out)):
            svc = sg.task_services(self.root, [])
        self.assertEqual(svc[0]["tunnel_ports"], {8001})

    def test_ipv6_loopback_url_argument_is_a_tunnel_port(self):
        self.assertEqual(sg.cloudflared_arg_ports("/usr/bin/cloudflared", ["cloudflared", "tunnel", "--url", "http://[::1]:8080"]), {8080})

    def test_tunnel_service_goes_to_the_top_of_the_report(self):
        os.makedirs(os.path.join(self.home, ".cloudflared"))
        with open(os.path.join(self.home, ".cloudflared", "a.yaml"), "w") as fh:
            fh.write("ingress:\n  - service: http://127.0.0.1:8001\n")
        self.lsof = self.LSOF
        self.plist("com.example.web", ["/bin/sh"])
        self.launchctl += "101\t0\tcom.example.web\n"
        rep = sg.make_report(self.scan(), [], [], True)
        text = sg.render_report(rep, sg.diff_reports(None, rep))
        self.assertLess(text.index("Reachable from the internet through a tunnel"), text.index("Fix first"))

    def test_no_listeners_is_not_an_error(self):
        inv = self.scan()
        self.assertEqual(inv["ports"], [])
        self.assertFalse([n for n in inv["service_notes"] if "ports" in n])

    def test_parsers_for_ss_and_netstat(self):
        ss = 'LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=55,fd=7))\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n'
        self.assertEqual(sg.parse_listeners("ss", ss), [("127.0.0.1", 631, 55, "cupsd"), ("0.0.0.0", 22, None, None)])
        ns = "  TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234\n  TCP    10.0.0.2:5000   1.1.1.1:443   ESTABLISHED   9\n"
        self.assertEqual(sg.parse_listeners("netstat", ns), [("0.0.0.0", 135, 1234, None)])


class InlineAssignments(ServiceFixture):
    """Round 5: a value set inline in a cron line or scheduled task never reaches a label, program or report."""
    FAKE = "FAKE" + "123"

    def crontab(self, text):
        def fake(args, root, timeout=10):
            return (0, text) if args[0] == "crontab" else (127, "")
        return mock.patch.object(sg, "run_system_tool", fake)

    def test_cron_inline_assignments_and_env_are_dropped(self):
        script = os.path.join(self.home, "bin", "x.py")
        open(script, "w").close()
        lines = ["*/5 * * * * API_TOKEN=%s /usr/bin/python3 %s" % (self.FAKE, script),
                 "@daily env -i API_TOKEN=%s A=1 /usr/bin/python3 %s" % (self.FAKE, script),
                 "0 1 * * * A=1 B=%s %s" % (self.FAKE, script),
                 "0 2 * * * API_TOKEN=%s" % self.FAKE]
        with self.crontab("\n".join(lines) + "\n"):
            found = sg.cron_services(self.root, [])
        self.assertEqual([s["label"] for s in found[:2]], ["cron: python3 x.py"] * 2)
        self.assertEqual(found[0]["program"], "/usr/bin/python3")
        self.assertEqual(found[2]["program"], script)
        self.assertEqual(len(found), 3)
        self.assertNotIn(self.FAKE, json.dumps(found, default=list))

    def test_env_argv0_option_takes_its_argument(self):
        for words in (["env", "-a", "worker-zero", "A=1", "/usr/bin/python3", "app.py"],
                      ["env", "--argv0", "worker-zero", "A=1", "/usr/bin/python3", "app.py"]):
            self.assertEqual(sg.drop_leading_assignments(words), ["/usr/bin/python3", "app.py"])

    def test_split_string_command_line_is_kept_and_its_assignments_dropped(self):
        for words in (["env", "-S", "API_TOKEN=%s python3 app.py" % self.FAKE],
                      ["env", "--split-string=API_TOKEN=%s python3 app.py" % self.FAKE],
                      ["/usr/bin/env", "-SAPI_TOKEN=%s python3 app.py" % self.FAKE]):
            self.assertEqual(sg.drop_leading_assignments(words), ["python3", "app.py"])
        line = "*/5 * * * * env -S 'API_TOKEN=%s python3 /srv/app.py'\n" % self.FAKE
        with self.crontab(line):
            found = sg.cron_services(self.root, [])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["program"], "python3")
        self.assertNotIn(self.FAKE, json.dumps(found, default=list))

    def test_a_token_in_a_cron_line_never_reaches_the_inventory_or_report(self):
        with self.crontab("*/5 * * * * API_TOKEN=%s /usr/bin/python3 /x.py\n" % self.FAKE), \
                mock.patch.object(sg, "platform_name", lambda: "linux"), \
                mock.patch.object(sg, "systemd_services", lambda root, notes: []), \
                mock.patch.object(sg, "listening_ports", lambda root, notes: []):
            inv = self.scan()
        rep = sg.make_report(inv, [], [], True)
        everything = sg.render_inventory(inv) + sg.render_report(rep, sg.diff_reports(None, rep)) + json.dumps(rep, default=list) + json.dumps(inv, default=list)
        self.assertNotIn(self.FAKE, everything)
        self.assertIn("cron: python3", everything)

    def test_scheduled_task_assignments_are_dropped_and_equals_words_never_shown(self):
        head = '"TaskName","Task To Run","Start In","Last Result"\n'
        rows = head + '"\\a","API_TOKEN=%s C:\\Python\\python.exe x.py","N/A","0"\n"\\b","--key=%s","N/A","0"\n' % (self.FAKE, self.FAKE)
        with mock.patch.object(sg, "run_system_tool", lambda args, root, timeout=10: (0, rows)):
            found = sg.task_services(self.root, [])
        self.assertEqual([s["label"] for s in found], ["\\a"])
        self.assertTrue(found[0]["program"].endswith("python.exe"))
        self.assertNotIn(self.FAKE, json.dumps(found, default=list))


class ServiceVenvPrivacy(ServiceFixture):
    """Round 5: a service venv's packages that may be private names are never sent to a public lookup."""

    def make_venv(self, base, direct_url=False, pip_conf=None, owner="requests==2.31.0\n"):
        vdir = os.path.join(base, ".venv")
        if owner is not None:  # the owning project: a public requirements file unless a test says otherwise
            with open(os.path.join(base, "requirements.txt"), "w") as fh:
                fh.write(owner)
        sp = os.path.join(vdir, "lib", "python3.11", "site-packages")
        os.makedirs(os.path.join(vdir, "bin"))
        os.makedirs(os.path.join(sp, "requests-2.31.0.dist-info"))
        os.makedirs(os.path.join(sp, "acme_internal-1.0.0.dist-info"))
        if direct_url:
            open(os.path.join(sp, "acme_internal-1.0.0.dist-info", "direct_url.json"), "w").close()
        with open(os.path.join(vdir, "pyvenv.cfg"), "w") as fh:
            fh.write("home = /opt/homebrew/opt/python@3.99/bin\nversion = 3.11.5\n")
        if pip_conf:
            open(os.path.join(vdir, pip_conf), "w").close()
        py = os.path.join(vdir, "bin", "python")
        open(py, "w").close()
        os.chmod(py, 0o755)
        return py

    def names(self, inv):
        return sorted(t["name"] for t in inv["service_targets"] if t["ecosystem"] == "PyPI")

    def test_a_dist_info_with_direct_url_is_skipped(self):
        os.makedirs(os.path.join(self.root, "p"))
        self.plist("com.example.v", [self.make_venv(os.path.join(self.root, "p"), direct_url=True)])
        self.assertEqual(self.names(self.scan()), ["requests"])

    def test_a_plain_venv_keeps_all_its_packages(self):
        os.makedirs(os.path.join(self.root, "p"))
        self.plist("com.example.v", [self.make_venv(os.path.join(self.root, "p"))])
        self.assertEqual(self.names(self.scan()), ["acme-internal", "requests"])

    def test_a_venv_with_its_own_pip_conf_or_ini_is_skipped(self):
        for n, conf in enumerate(("pip.conf", "pip.ini")):
            base = os.path.join(self.root, "p%d" % n)
            os.makedirs(base)
            self.plist("com.example.v%d" % n, [self.make_venv(base, pip_conf=conf)])
        inv = self.scan()
        self.assertEqual(self.names(inv), [])
        self.assertEqual(len(inv["services"]), 2)

    def test_a_venv_inside_a_project_with_a_private_index_is_skipped(self):
        proj = os.path.join(self.root, "app")
        os.makedirs(proj)
        self.plist("com.example.v", [self.make_venv(proj)])
        inv = blank_inventory()
        inv["projects"] = [dict(sg.new_project("app"), private_index=True)]
        sg.scan_services(self.root, inv)
        self.assertEqual(self.names(inv), [])
        inv = blank_inventory()
        inv["projects"] = [sg.new_project("app")]
        sg.scan_services(self.root, inv)
        self.assertEqual(self.names(inv), ["acme-internal", "requests"])

    def test_round7_outside_venv_sends_nothing_and_says_so_by_count(self):
        base = os.path.join(self.home, "p")
        os.makedirs(base)
        self.plist("com.example.v", [self.make_venv(base)])
        inv = self.scan()
        self.assertEqual(self.names(inv), [])
        self.assertIn("service com.example.v: 2 venv packages not looked up (outside the scanned folder; scan that folder to check them)",
                      inv["service_notes"])
        self.assertNotIn("requests", json.dumps(inv["service_notes"]) + json.dumps(inv["services"]))

    def test_round7_inside_venv_with_a_public_project_is_sent(self):
        proj = os.path.join(self.root, "app")
        os.makedirs(proj)
        self.plist("com.example.v", [self.make_venv(proj)])
        inv = blank_inventory()
        inv["projects"] = [sg.new_project("app")]
        sg.scan_services(self.root, inv)
        self.assertEqual(self.names(inv), ["acme-internal", "requests"])
        self.assertFalse([n for n in inv.get("service_notes", []) if "venv packages" in n])

    def test_round7_inside_venv_under_a_parent_uv_toml_private_index_sends_nothing(self):
        parent = os.path.join(self.root, "app")
        child = os.path.join(parent, "svc")
        os.makedirs(child)
        with open(os.path.join(parent, "uv.toml"), "w") as fh:
            fh.write('[[index]]\nname = "corp"\nurl = "https://pkgs.example.com/simple"\n')
        self.plist("com.example.v", [self.make_venv(child)])
        with open(os.path.join(child, "requirements.txt"), "w") as fh:
            fh.write("requests==2.31.0\n")
        inv = blank_inventory()
        sg.scan_projects(self.root, inv)
        sg.scan_services(self.root, inv)
        self.assertEqual(self.names(inv), [])

    def test_round8_uv_toml_only_root_private_index_sends_nothing_and_notes(self):
        with open(os.path.join(self.root, "uv.toml"), "w") as fh:
            fh.write('[[index]]\nname = "corp"\nurl = "https://pkgs.example.com/simple"\n')
        os.makedirs(os.path.join(self.root, "svc"))
        self.plist("com.example.v", [self.make_venv(os.path.join(self.root, "svc"))])
        inv = blank_inventory()
        sg.scan_projects(self.root, inv)
        self.assertIn(".", inv["private_dirs"])
        sg.scan_services(self.root, inv)
        self.assertEqual(self.names(inv), [])
        self.assertTrue([n for n in inv["service_notes"] if "2 venv packages not looked up" in n])

    def test_round8_inside_root_but_in_no_listed_project_is_count_only(self):
        os.makedirs(os.path.join(self.root, "p"))
        self.plist("com.example.v", [self.make_venv(os.path.join(self.root, "p"))])
        inv = self.scan(projects=False)
        self.assertEqual(self.names(inv), [])
        self.assertTrue([n for n in inv["service_notes"] if "2 venv packages not looked up" in n])
        self.assertNotIn("requests", json.dumps(inv["service_notes"]))

    def test_names_a_scanned_project_marks_private_are_filtered(self):
        os.makedirs(os.path.join(self.root, "p"))
        self.plist("com.example.v", [self.make_venv(os.path.join(self.root, "p"))])
        inv = blank_inventory()
        inv["projects"] = [dict(sg.new_project("p"), private_py=["acme-internal"])]
        sg.scan_services(self.root, inv)
        self.assertEqual(self.names(inv), ["requests"])


class ServiceReport(ServiceFixture):
    def test_new_service_diff(self):
        a = {"label": "com.a", "program": "/bin/sh", "where": "user", "flags": [], "script": None}
        b = {"label": "com.b", "program": "/tmp/x", "where": "user", "flags": ["unrecognised"], "script": None}
        base = {"osv_ok": True, "findings": [], "runtimes": [], "mcp": []}
        d = sg.diff_reports(dict(base, services=[a]), dict(base, services=[a, b]))
        self.assertEqual(len(d["services"]), 1)
        self.assertIn("com.b", d["services"][0]["text"])
        text = "\n".join(sg.diff_lines(d, False))
        self.assertIn("New background services since last check", text)
        self.assertNotIn("com.a", text)

    def test_older_report_without_services_starts_the_list_quietly(self):
        a = {"label": "com.a", "program": "/bin/sh", "where": "user", "flags": [], "script": None}
        base = {"osv_ok": True, "findings": [], "runtimes": [], "mcp": []}
        d = sg.diff_reports(dict(base), dict(base, services=[a]))
        self.assertEqual(d["services"], [])
        self.assertTrue(any("not recorded" in n for n in d["notes"]))

    def test_notification_carries_a_count_never_a_name(self):
        base = {"osv_ok": True, "findings": [], "runtimes": [], "mcp": []}
        b = {"label": "com.secretname", "program": "/tmp/x", "where": "user", "flags": [], "script": None}
        cur = dict(base, date="2026-11-04", services=[b], not_checked=[], committed_secrets=[])
        d = sg.diff_reports(dict(base, services=[]), cur)
        head, body = sg.notify_text(cur, d)
        self.assertIn("1 new background service", head)
        self.assertNotIn("com.secretname", body)

    def test_services_section_orders_the_worst_first(self):
        def svc(label, flags):
            return {"label": label, "program": "/p", "where": "user", "flags": flags, "script": None, "status": "loaded", "exit": None}
        rep = {"services": [svc("com.fail", ["failing"]), svc("com.mystery", ["unrecognised"]), svc("com.loose", ["tamper"]),
                            svc("com.fine", []), svc("com.web", ["network"]), svc("com.gone", ["missing"])], "findings": []}
        lines = sg.services_section(rep)
        order = [next(x for x in ("com.loose", "com.mystery", "com.gone", "com.fail") if x in ln) for ln in lines]
        self.assertEqual(order, ["com.loose", "com.mystery", "com.gone", "com.fail"])
        self.assertFalse([ln for ln in lines if "com.fine" in ln or "com.web" in ln])  # network alone, with no hole, is not listed
        rep["findings"] = [{"project": "service: com.web"}]
        self.assertIn("com.web", sg.services_section(rep)[0])  # network-reachable with a hole comes before the rest


class LockCheck(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.published = {}
        self.osv = {}
        self.fail_registry = False
        patch = mock.patch.object(sg, "http_json", self.fetch)
        patch.start()
        self.addCleanup(patch.stop)

    def lock(self, name, packages):
        path = os.path.join(self.dir, name)
        data = {"lockfileVersion": 3, "packages": {"": {"name": "x"}}}
        for pkg, ver in packages.items():
            data["packages"]["node_modules/" + pkg] = {"version": ver, "resolved": "https://registry.npmjs.org/%s/-/%s-%s.tgz" % (pkg, pkg.rsplit("/", 1)[-1], ver)}
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(data, fh)
        return path

    def fetch(self, url, body=None, timeout=30):
        if url == sg.OSV_BATCH:
            return {"results": [{"vulns": [{"id": i} for i in self.osv.get((q["package"]["name"], q["version"]), [])]} for q in body["queries"]]}
        if url.startswith(sg.OSV_VULN):
            vid = url[len(sg.OSV_VULN):]
            return {"id": vid, "summary": "bad package"}
        if url.startswith("https://registry.npmjs.org/"):
            if self.fail_registry:
                raise OSError("offline")
            name = url.rsplit("/", 1)[1]
            return {"time": {v: t for (n, v), t in self.published.items() if n == name}}
        raise AssertionError(url)

    def ago(self, hours):
        return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def run_check(self, before, after, *extra):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sg.main(["lock-check", before, after, *extra])
        return code, out.getvalue()

    def pair(self, old, new):
        return self.lock("before/package-lock.json", old), self.lock("after/package-lock.json", new)

    def test_old_enough_and_clean_exits_0(self):
        self.published[("left-pad", "1.3.0")] = self.ago(500)
        code, out = self.run_check(*self.pair({"left-pad": "1.2.0"}, {"left-pad": "1.3.0"}))
        self.assertEqual(code, 0, out)
        self.assertIn("left-pad 1.3.0", out)

    def test_nothing_changed_exits_0(self):
        code, out = self.run_check(*self.pair({"left-pad": "1.2.0"}, {"left-pad": "1.2.0"}))
        self.assertEqual((code, out.strip()), (0, "No added or changed versions."))

    def test_removed_packages_are_ignored(self):
        code, _ = self.run_check(*self.pair({"left-pad": "1.2.0", "gone": "1.0.0"}, {"left-pad": "1.2.0"}))
        self.assertEqual(code, 0)

    def test_too_new_exits_3(self):
        self.published[("left-pad", "1.3.0")] = self.ago(2)
        code, out = self.run_check(*self.pair({}, {"left-pad": "1.3.0"}))
        self.assertEqual(code, 3, out)
        self.assertIn("TOO NEW", out)

    def test_malicious_exits_4_even_when_old_enough(self):
        self.published[("evil-pkg", "9.9.9")] = self.ago(900)
        self.osv[("evil-pkg", "9.9.9")] = ["MAL-2026-1234"]
        code, out = self.run_check(*self.pair({}, {"evil-pkg": "9.9.9"}))
        self.assertEqual(code, 4, out)
        self.assertIn("MAL-2026-1234", out)

    def test_malicious_beats_too_new_beats_not_proven(self):
        self.published[("evil-pkg", "9.9.9")] = self.ago(1)
        self.published[("new-pkg", "1.0.0")] = self.ago(1)
        self.osv[("evil-pkg", "9.9.9")] = ["MAL-2026-1"]
        code, _ = self.run_check(*self.pair({}, {"evil-pkg": "9.9.9", "new-pkg": "1.0.0", "no-date-pkg": "1.0.0"}))
        self.assertEqual(code, 4)
        code, _ = self.run_check(*self.pair({}, {"new-pkg": "1.0.0", "no-date-pkg": "1.0.0"}))
        self.assertEqual(code, 3)

    def test_lookup_failure_fails_closed_exit_2(self):
        self.fail_registry = True
        code, out = self.run_check(*self.pair({}, {"left-pad": "1.3.0"}))
        self.assertEqual(code, 2, out)
        self.assertIn("unknown", out)

    def test_osv_unreachable_fails_closed(self):
        self.published[("left-pad", "1.3.0")] = self.ago(500)
        real = self.fetch

        def down(url, body=None, timeout=30):
            if url == sg.OSV_BATCH:
                raise OSError("offline")
            return real(url, body, timeout)
        with mock.patch.object(sg, "http_json", down):
            code, out = self.run_check(*self.pair({}, {"left-pad": "1.3.0"}))
        self.assertEqual(code, 2, out)

    def test_pnpm_yarn_and_bun_lockfiles_exit_2_with_a_plain_note(self):
        for name in ("pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"):
            d = tempfile.mkdtemp()
            a, b = os.path.join(d, "old", name), os.path.join(d, name)
            os.makedirs(os.path.dirname(a))
            for f in (a, b):
                open(f, "w").close()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = sg.cmd_lock_check(a, b, None, None)
            self.assertEqual(code, 2, name)
            self.assertIn("not read yet: check each changed version with release-age", out.getvalue())

    def test_round6_malformed_npm_lockfiles_exit_2(self):
        good = self.lock("before/package-lock.json", {})
        bad = {
            "list": [],
            "entry not a dict": {"packages": {"node_modules/a": "1.0.0"}},
            "no version": {"packages": {"node_modules/a": {"resolved": "x"}}},
            "packages not a dict": {"packages": ["a"]},
        }
        for label, data in bad.items():
            path = os.path.join(self.dir, "after", "package-lock.json")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                json.dump(data, fh)
            code, out = self.run_check(good, path)
            self.assertEqual(code, 2, "%s: %s" % (label, out))

    def test_round6_a_link_entry_without_a_version_is_fine(self):
        a, b = self.pair({}, {})
        with open(b) as fh:
            data = json.load(fh)
        data["packages"]["node_modules/mine"] = {"resolved": "../mine", "link": True}
        with open(b, "w") as fh:
            json.dump(data, fh)
        code, out = self.run_check(a, b)
        self.assertEqual(code, 0, out)

    def test_round6_lock_sources_exception_exits_2(self):
        with mock.patch.object(sg, "lock_sources", side_effect=RuntimeError("boom")):
            code, out = self.run_check(*self.pair({}, {"left-pad": "1.3.0"}))
        self.assertEqual(code, 2, out)

    def test_unreadable_lockfile_fails_closed(self):
        before = self.lock("before/package-lock.json", {})
        code, out = self.run_check(before, os.path.join(self.dir, "after", "package-lock.json"))
        self.assertEqual(code, 2, out)

    def test_private_scoped_name_is_not_looked_up_and_is_counted_not_named(self):
        code, out = self.run_check(*self.pair({}, {"@acme-private/secret-lib": "1.0.0"}))
        self.assertEqual(code, 2)
        self.assertNotIn("acme-private", out)
        self.assertIn("1 private", out)

    def raw_lock(self, name, data):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(data, fh)
        return path

    def npm_data(self, entries):
        data = {"lockfileVersion": 3, "packages": {"": {"name": "x"}}}
        data["packages"].update(entries)
        return data

    def test_npm_alias_uses_the_real_name_from_the_entry(self):
        self.published[("real-pkg", "1.0.0")] = self.ago(1)
        after = self.raw_lock("a/package-lock.json", self.npm_data({
            "node_modules/alias": {"name": "real-pkg", "version": "1.0.0", "resolved": "https://registry.npmjs.org/real-pkg/-/real-pkg-1.0.0.tgz"}}))
        code, out = self.run_check(self.lock("b/package-lock.json", {}), after)
        self.assertEqual(code, 3, out)
        self.assertIn("real-pkg 1.0.0", out)
        self.assertNotIn("alias", out)

    def test_npm_tarball_for_another_name_is_not_proven(self):
        self.published[("left-pad", "1.3.0")] = self.ago(900)
        after = self.raw_lock("a/package-lock.json", self.npm_data({
            "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.3.0.tgz"}}))
        code, out = self.run_check(self.lock("b/package-lock.json", {}), after)
        self.assertEqual(code, 2, out)
        self.assertIn("does not match their name", out)
        self.assertNotIn("left-pad", out)

    def test_a_source_change_at_the_same_version_is_not_proven(self):
        def data(resolved):
            return self.npm_data({"node_modules/left-pad": {"version": "1.2.0", "resolved": resolved, "integrity": "sha512-x"}})
        good = "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz"
        before = self.raw_lock("b/package-lock.json", data(good))
        same = self.raw_lock("a/package-lock.json", data(good))
        self.assertEqual(self.run_check(before, same)[0], 0)
        moved = self.raw_lock("c/package-lock.json", data(good + "?other"))
        code, out = self.run_check(before, moved)
        self.assertEqual(code, 2, out)
        self.assertIn("changed where they come from", out)

    def test_uv_lock_source_change_at_the_same_version_is_not_proven(self):
        try:
            import tomllib  # noqa: F401
        except ImportError:
            self.skipTest("needs Python 3.11+")
        def write(name, source):
            path = os.path.join(self.dir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write('[[package]]\nname = "requests"\nversion = "2.31.0"\nsource = %s\n' % source)
            return path
        pypi = '{ registry = "https://pypi.org/simple" }'
        before, after = write("b/uv.lock", pypi), write("a/uv.lock", '{ git = "https://example.org/r.git" }')
        code, out = self.run_check(before, after)
        self.assertEqual(code, 2, out)

    def req(self, name, text):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def test_requirements_with_anything_but_plain_pins_cannot_be_read(self):
        before = self.req("b/requirements.txt", "")
        for bad in ("-r other.txt\n", "--index-url https://x.example/simple\nrequests==2.31.0\n", "requests>=2\n",
                    "git+https://example.org/r.git#egg=r\n", "-e ./local\n"):
            code, out = self.run_check(before, self.req("a/requirements.txt", bad))
            self.assertEqual(code, 2, (bad, out))
            self.assertIn("could not be read", out)

    def test_requirements_with_hashes_markers_and_comments_are_read(self):
        text = "# pinned\nrequests==2.31.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\nidna==3.4 ; python_version >= '3.8'  # why\n\n"
        proj, why = sg.parse_lock_file(self.req("a/requirements.txt", text), "requirements.txt")
        self.assertIsNone(why)
        self.assertEqual(sorted((p["name"], p["version"]) for p in proj["packages"]), [("idna", "3.4"), ("requests", "2.31.0")])

    def test_osv_errors_make_the_answer_not_proven(self):
        self.published[("left-pad", "1.3.0")] = self.ago(500)
        real = self.fetch

        def partial(url, body=None, timeout=30):
            if url.startswith(sg.OSV_VULN):
                raise OSError("offline")
            return real(url, body, timeout)
        self.osv[("left-pad", "1.3.0")] = ["GHSA-aaaa-bbbb-cccc"]
        with mock.patch.object(sg, "http_json", partial):
            code, out = self.run_check(*self.pair({}, {"left-pad": "1.3.0"}))
        self.assertEqual(code, 2, out)

    def test_python_names_are_not_looked_up_without_a_folder(self):
        self.published[("requests", "2.31.0")] = self.ago(900)
        before, after = self.req("b/requirements.txt", ""), self.req("a/requirements.txt", "requests==2.31.0\n")
        with mock.patch.object(sg, "global_private_index", lambda: False):
            code, out = self.run_check(before, after)
        self.assertEqual(code, 2, out)
        self.assertNotIn("requests", out)


if __name__ == "__main__":
    unittest.main()
