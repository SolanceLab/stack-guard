# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Tests for hooks/secret_guard.py. Run: python3 -m unittest discover -s tests -v"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "..", "plugin", "hooks", "secret_guard.py")
FAKE_JWT = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12  # built in parts, not a real token


def run(stdin, *args, active=True):
    """Run the hook. active=True stands in for a stack-guard session (the env its agents set); False scrubs it."""
    env = {k: v for k, v in os.environ.items() if k != "STACK_GUARD_ACTIVE"}
    if active:
        env["STACK_GUARD_ACTIVE"] = "1"
    return subprocess.run([sys.executable, GUARD, *args], input=stdin, capture_output=True, text=True, env=env)


class OnlyWhileStackGuardIsInUse(unittest.TestCase):
    def transcript(self, *lines):
        f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        self.addCleanup(os.unlink, f.name)
        for t in lines:
            f.write(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": t}]}}) + "\n")
        f.close()
        return f.name

    def acts(self, path, active=False):
        """True when the guard counts as in use for this transcript: its output filter hides a fake token."""
        r = run(json.dumps({"tool_name": "Bash", "tool_input": {"command": "cat notes.txt"},
                            "tool_response": {"stdout": FAKE_JWT}, "transcript_path": path}), "--post", active=active)
        self.assertEqual(r.returncode, 0)
        return FAKE_JWT not in r.stdout and "REDACTED" in r.stdout

    def test_other_work_is_untouched(self):
        self.assertFalse(self.acts(self.transcript("just fixing a bug in /Users/me/proj/stack-guard-notes")))
        self.assertFalse(self.acts("/nonexistent/t.jsonl"))

    def test_post_and_stop_silent_without_marker(self):
        r = run(json.dumps({"tool_name": "Bash", "tool_response": {"stdout": FAKE_JWT}}), "--post", active=False)
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        r = run(json.dumps({"transcript_path": self.transcript(FAKE_JWT)}), "--stop", active=False)
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def entries(self, *entries):
        f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        self.addCleanup(os.unlink, f.name)
        for e in entries:
            f.write(e if isinstance(e, str) else json.dumps(e))
            f.write("\n")
        f.close()
        return f.name

    @staticmethod
    def tool_use(name, **inp):
        return {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": name, "input": inp}]}}

    def test_plugin_installed_only_stays_off(self):
        listing = "Skills: stack-guard:stack-audit, stack-guard:run-stack-guard, /stack-guard stack-auditor"
        path = self.entries(
            {"type": "system", "content": listing},
            {"type": "attachment", "attachment": {"content": listing}},
            {"type": "user", "message": {"content": listing}},
            {"type": "user", "message": {"content": [{"type": "text", "text": listing}]}},
            {"type": "user", "message": {"content": [{"type": "tool_result", "content": "<command-name>/stack-guard"}]}})
        self.assertFalse(self.acts(path))
        r = run(json.dumps({"transcript_path": self.transcript(FAKE_JWT)}), "--stop", active=False)
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_typed_command_switches_it_on(self):
        for cmd in ("/stack-guard", "/stack-guard:inventory", "/stack-guard:watch", "/stack-guard:stack-guard"):
            text = "<command-name>%s</command-name>" % cmd
            for content in (text, [{"type": "text", "text": text}]):
                path = self.entries({"type": "user", "message": {"content": content}})
                self.assertTrue(self.acts(path), cmd)

    def test_unprefixed_own_command_switches_it_on(self):
        for cmd in ("stack-fix", "/stack-fix", "stack-audit", "stack-guard"):
            path = self.entries({"type": "user", "message": {"content": "<command-name>%s</command-name>" % cmd}})
            self.assertTrue(self.acts(path), cmd)
        path = self.entries({"type": "user", "message": {"content": "<command-name>/other</command-name>"}})
        self.assertFalse(self.acts(path))

    def test_attribution_fields_switch_it_on(self):
        # shaped like a stack-news-scout run: attribution stamped, no command tag, no Skill/Task call, then Bash
        for field, value in (("attributionPlugin", "stack-guard"), ("attributionAgent", "stack-guard:stack-news-scout"),
                             ("attributionSkill", "stack-guard:stack-audit"), ("attributionAgent", "stack-fixer")):
            e = self.tool_use("Bash", command="ls")
            e[field] = value
            self.assertTrue(self.acts(self.entries(e)), field)
        e = self.tool_use("Bash", command="ls")
        e["attributionPlugin"] = "other"
        self.assertFalse(self.acts(self.entries(e)))

    def test_tool_calls_switch_it_on(self):
        for call in (self.tool_use("Skill", skill="stack-guard:stack-audit"),
                     self.tool_use("Skill", skill="run-stack-guard"),
                     self.tool_use("Agent", subagent_type="stack-guard:stack-fixer"),
                     self.tool_use("Task", subagent_type="stack-news-scout"),
                     self.tool_use("Bash", command="python3 /x/plugins/stack-guard/scripts/stack_guard.py check ."),
                     self.tool_use("Bash", command="cd /x && FOO=1 python3.12 -I 'scripts/stack_guard.py' check"),
                     self.tool_use("Bash", command="git status && python3 stack_guard.py check ."),
                     self.tool_use("Bash", command="cat <<'EOF'\nhi\nEOF\npython3 stack_guard.py check .")):
            self.assertTrue(self.acts(self.entries(call)), call)

    def test_unrelated_tool_calls_and_prose_stay_off(self):
        for e in (self.tool_use("Skill", skill="other:thing"), self.tool_use("Bash", command="ls"),
                  self.tool_use("Read", file_path="/x/stack_guard.py"),
                  *[self.tool_use("Bash", command=c) for c in (
                      "cat /x/stack_guard.py", "grep -n foo /x/stack_guard.py", "git log -- scripts/stack_guard.py",
                      "head -5 stack_guard.py", "ls /x/__pycache__/stack_guard.pyc", "python3 -m py_compile stack_guard.py",
                      "python3 tests/test_stack_guard.py", "python3 /tmp/not_stack_guard.py",
                      'echo "x; python3 stack_guard.py"', 'git commit -m "fix; python3 stack_guard.py check"',
                      "cat <<'EOF'\npython3 scripts/stack_guard.py\nEOF")]):
            self.assertFalse(self.acts(self.entries(e)), e)
        path = self.transcript("I will run /stack-guard and stack-guard:stack-audit for you")
        self.assertFalse(self.acts(path))

    def test_malformed_lines_are_skipped(self):
        path = self.entries("not json", "{broken", "[1, 2]", "",
                            {"type": "user", "message": {"content": "<command-name>/stack-guard</command-name>"}})
        self.assertTrue(self.acts(path))

    def test_env_switches_it_on(self):
        self.assertTrue(self.acts("/nonexistent/t.jsonl", active=True))

    def test_use_stays_on_after_a_long_session(self):
        path = self.entries({"type": "user", "message": {"content": "<command-name>/stack-guard</command-name>"}},
                            self.tool_use("Bash", command="x" * (6 * 1024 * 1024)))
        self.assertTrue(self.acts(path))

    def test_first_run_past_twenty_megabytes_still_switches_it_on(self):
        path = self.entries(self.tool_use("Bash", command="x" * (21 * 1024 * 1024)),
                            self.tool_use("Bash", command="python3 /x/scripts/stack_guard.py check ."))
        self.assertTrue(self.acts(path))


class PostToolUse(unittest.TestCase):
    def post(self, resp):
        return run(json.dumps({"tool_name": "Bash", "tool_response": resp}), "--post")

    def test_secret_in_output_is_replaced(self):
        r = self.post({"stdout": "token=" + FAKE_JWT, "stderr": "", "interrupted": False})
        self.assertEqual(r.returncode, 0)
        out = json.loads(r.stdout)["hookSpecificOutput"]
        self.assertEqual(out["updatedToolOutput"]["stdout"], "token=[REDACTED JWT/token]")
        self.assertFalse(out["updatedToolOutput"]["interrupted"])
        self.assertNotIn(FAKE_JWT, r.stdout)
        self.assertIn("rotate", out["additionalContext"])

    def test_clean_and_broken_are_silent(self):
        for r in (self.post({"stdout": "ok"}), self.post(None), run("garbage", "--post")):
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))


class NamedSecretRedaction(unittest.TestCase):
    """A value of no known shape is still removed when its name sounds secret; the name stays readable."""
    PLAIN = "a1b2c3d4" * 4  # built in parts, not a real token

    def clean(self, text):
        r = run(json.dumps({"tool_name": "Bash", "tool_response": {"stdout": text}}), "--post")
        return json.loads(r.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"] if r.stdout else text

    def test_docker_env_flag(self):
        out = self.clean("docker run -i --rm -e HA_URL=http://h:8123 -e HA_TOKEN=%s img" % self.PLAIN)
        self.assertEqual(out, "docker run -i --rm -e HA_URL=http://h:8123 -e HA_TOKEN=[REDACTED secret value] img")

    def test_json_and_flags(self):
        for text in ('{"apiKey": "%s"}', "DB_PASSWORD=%s", "--token %s", "--api-key=%s", "client_secret: %s"):
            self.assertNotIn(self.PLAIN, self.clean(text % self.PLAIN), text)

    def test_quoted_value_with_spaces_goes_whole(self):
        self.assertEqual(self.clean('{"apiKey": "first part second part"}'), '{"apiKey": "[REDACTED secret value]"}')
        self.assertEqual(self.clean("$env:HA_TOKEN = 'my long pass phrase'"), "$env:HA_TOKEN = '[REDACTED secret value]'")
        self.assertEqual(self.clean('export GH_TOKEN="${OTHER_TOKEN}"'), 'export GH_TOKEN="${OTHER_TOKEN}"')

    def test_bearer_header(self):
        self.assertNotIn(self.PLAIN, self.clean("Authorization: Bearer " + self.PLAIN))

    def test_references_counts_and_prose_stay(self):
        for text in ("HA_TOKEN=$HA_TOKEN", "TOKEN=${GH_TOKEN}", "max_tokens=1000000", "the token was rotated",
                     "password: <redacted>", "API_KEY=short"):
            self.assertEqual(self.clean(text), text)


class PrivateKeyRedaction(unittest.TestCase):
    def test_whole_pem_block_removed(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nPAYLOAD_STILL_VISIBLE_123456\nabc=\n-----END RSA PRIVATE KEY-----"
        r = run(json.dumps({"tool_name": "Bash", "tool_response": {"stdout": "x\n" + pem + "\ny"}}), "--post")
        self.assertNotIn("PAYLOAD_STILL_VISIBLE", r.stdout)
        self.assertNotIn("END RSA", r.stdout)
        self.assertIn("REDACTED private key", r.stdout)


class StopHook(unittest.TestCase):
    def transcript(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        self.addCleanup(os.unlink, f.name)
        f.write(json.dumps({"type": "user", "message": {"content": "hi"}}) + "\n")
        f.write(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}) + "\n")
        f.close()
        return f.name

    def stop(self, path, **extra):
        return run(json.dumps({"transcript_path": path, **extra}), "--stop")

    def test_secret_blocks_without_echo(self):
        r = self.stop(self.transcript("here: " + FAKE_JWT))
        self.assertEqual(r.returncode, 0)
        out = json.loads(r.stdout)
        self.assertEqual(out["decision"], "block")
        self.assertIn("JWT/token", out["reason"])
        self.assertNotIn(FAKE_JWT, r.stdout)

    def test_already_active_is_silent(self):
        r = self.stop(self.transcript(FAKE_JWT), stop_hook_active=True)
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_clean_and_broken_are_silent(self):
        for path in (self.transcript("all good"), "/nonexistent/t.jsonl"):
            r = self.stop(path)
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
        r = run("garbage", "--stop")
        self.assertEqual((r.returncode, r.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()


class NeverHangs(unittest.TestCase):
    """A device or pipe passed as the transcript must never be read: the hook finishes at once and steps aside."""

    def test_endless_transcript_paths_finish_fast(self):
        env = {k: v for k, v in os.environ.items() if k != "STACK_GUARD_ACTIVE"}
        for path in ("/dev/urandom", "/dev/zero"):
            for args, event in ((["--post"], "PostToolUse"), (["--stop"], "Stop")):
                payload = json.dumps({"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": "cat .env"},
                                      "transcript_path": path, "stop_hook_active": False})
                r = subprocess.run([sys.executable, GUARD, *args], input=payload, capture_output=True, text=True,
                                   timeout=10, env=env)
                self.assertEqual(r.returncode, 0, (path, event))


class NamedSecretStaysFast(unittest.TestCase):
    """Long unbroken text must not slow the named-secret redaction (an uncapped name pattern backtracked)."""

    def test_two_hundred_thousand_letters_finish_fast(self):
        import time
        sys.path.insert(0, os.path.dirname(GUARD))
        import secret_guard as g
        for text in ("x" * 200000, "MY_TOKEN_" + "a" * 200000):
            t = time.time()
            g.NAMED_SECRET.sub(g.hide_named, text)
            self.assertLess(time.time() - t, 1.0)


class EnvReferencesAndProcessListings(unittest.TestCase):
    """1.5.5 round 3: a key read from the environment is not a leak."""
    LITERAL = "abcd1234efgh5678ijkl"  # built in parts, not a real token

    def clean(self, text):
        r = run(json.dumps({"tool_name": "Bash", "tool_response": {"stdout": text}}), "--post")
        return json.loads(r.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"] if r.stdout else text

    def test_references_stay_and_raise_no_alarm(self):
        for text in ("const DISCORD_TOKEN = process.env.DISCORD_BOT_TOKEN || '';",
                     'TOKEN = os.environ["DISCORD_BOT_TOKEN"]', "TOKEN = os.getenv('DISCORD_BOT_TOKEN')",
                     "API_KEY: ${TOKEN_VALUE}", "api_key = settings.api_key", "apiKey: import.meta.env.VITE_API_KEY",
                     "token = config.get_token ?? ''"):
            r = run(json.dumps({"tool_name": "Bash", "tool_response": {"stdout": text}}), "--post")
            self.assertEqual((r.returncode, r.stdout), (0, ""), text)

    def test_literals_are_still_hidden(self):
        for text in ('TOKEN = "%s"' % self.LITERAL, 'apiKey: "sk-live-%s"' % self.LITERAL, "TOKEN=%s" % self.LITERAL):
            self.assertNotIn(self.LITERAL, self.clean(text), text)

    def test_bare_names_are_literals_and_hidden(self):
        for text in ("TOKEN=correct_horse_battery_staple", "TOKEN=hardcodedSecretValue", "API_KEY = my_secret_value_here"):
            out = self.clean(text)
            self.assertIn("[REDACTED secret value]", out, text)

    def test_dotted_literals_are_hidden(self):
        for text in ("TOKEN=secret.literal.value", "API_KEY = abc.def.ghi.jkl"):
            self.assertIn("[REDACTED secret value]", self.clean(text), text)
