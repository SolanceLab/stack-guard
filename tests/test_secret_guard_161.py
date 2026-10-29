# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""1.6.1: extglob words are judged as written and as wildcards; exclusion tokens are skipped only for real exclude options."""
import os
import unittest

from test_secret_guard import pre


class Guard161(unittest.TestCase):
    def blocked(self, cmd):
        r = pre("Bash", command=cmd)
        self.assertEqual(r.returncode, 2, (cmd, r.stderr))

    def allowed(self, cmd):
        r = pre("Bash", command=cmd)
        self.assertEqual((r.returncode, r.stderr), (0, ""), cmd)

    def test_extglob_group_with_space_or_pipe_still_blocks(self):
        self.blocked("cat .@(env|foo)")
        self.blocked("cat .@(e nv|foo)")
        self.blocked("shopt -s extglob; cat .e!(x)")

    def test_groups_in_other_names_still_allowed(self):
        self.allowed("cat src/@(a|b).py")

    def test_bang_token_is_not_an_exclusion(self):
        self.blocked("python3 -c \"!print(open('.env').read())\"")
        self.allowed("rg TOKEN src -g '!.env'")
        self.allowed("rg TOKEN src --glob=!.env")
        self.allowed("grep -rn TOKEN src --exclude=.env")

    def test_exclude_only_for_searchers_and_before_double_dash(self):
        self.blocked("cat --exclude=.env")
        self.blocked("cat --exclude .env")
        self.blocked("grep TOKEN -- --exclude .env")
        self.blocked("sed -n p --exclude-dir=.ssh/id_rsa")
        self.allowed("grep -rn TOKEN src --exclude .env")

    def test_literal_placeholder_text_does_not_open_the_guard(self):
        self.blocked("echo __XG0__; cat .env")
        self.blocked("echo __XG7__ __XG0_1__; cat .@(env|foo)")
        self.allowed("echo __XG0__")


if __name__ == "__main__":
    unittest.main()
