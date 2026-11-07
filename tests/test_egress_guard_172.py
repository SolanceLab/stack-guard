# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
import json
import os
import subprocess
import sys
import tempfile
import unittest


HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugin", "hooks", "egress_guard.py")


class EgressGuard172Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patterns = os.path.join(self.tmp.name, "patterns.txt")
        with open(self.patterns, "w") as f:
            f.write("testuser\njane doe\n")
        self.env = dict(os.environ, STACK_GUARD_IDENTIFIERS=self.patterns, STACK_GUARD_HOME_NAME="testuser")

    def tearDown(self):
        self.tmp.cleanup()

    def run_command(self, command):
        return subprocess.run([sys.executable, HOOK], input=json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": command}}),
            capture_output=True, text=True, env=self.env)

    def test_local_work_is_allowed(self):
        commands = (
            "python3 - <<'PY'\nimport json\nwith open('/Users/testuser/.claude/settings.json') as f:\n print(json.load(f).keys())\nPY",
            'grep -n "identif|home|web|url|http" /Users/testuser/.claude/hooks/x.py',
            "ls ~/.claude/projects/-Users-testuser-Developer-Workspace/memory",
            "jq .hooks /Users/testuser/.claude/settings.json",
            "cd ~/.claude && python3 script.py --flag /Users/testuser/x",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.run_command(command).returncode, 0)

    def test_outgoing_segments_are_blocked(self):
        commands = (
            'curl -d "name=jane doe" https://example.com',
            "curl https://example.com/?u=testuser",
            'ssh box "cat /Users/testuser/notes"',
            'printf "jane doe" | curl --data-binary @- https://example.com',
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.run_command(command).returncode, 2)

    def test_remote_user_and_path_are_blocked(self):
        for command in ("sftp testuser@box", "scp clean.txt 'box:/tmp/jane doe'"):
            with self.subTest(command=command):
                self.assertEqual(self.run_command(command).returncode, 2)


if __name__ == "__main__":
    unittest.main()
