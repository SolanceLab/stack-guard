# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""A key that names an environment variable (Codex's `bearer_token_env_var`) holds a reference, not a secret.
Found 7 Nov 2026: the nightly report told the House to rotate a key for a .mcp.json that held only `ANTECHAMBER_TOKEN`."""
import json
import unittest

from test_stack_guard import Base  # noqa: F401  (puts the plugin scripts on sys.path)
import stack_guard as sg


def names(obj):
    return sg.literal_secret_names(".mcp.json", json.dumps(obj))[0]


class EnvVarReference(unittest.TestCase):
    def test_env_var_name_is_not_a_secret(self):
        cfg = {"mcpServers": {"s": {"url": "https://example.org/mcp", "bearer_token_env_var": "ANTECHAMBER_TOKEN"}}}
        self.assertEqual(names(cfg), [])

    def test_other_env_name_keys(self):
        for key in ("token_env_var", "token_env_variable", "apiKeyEnvVar", "bearerTokenEnvVariable"):
            for val in ("MY_API_KEY_2", "_MY_API_KEY", "GITHUB_TOKEN"):
                self.assertEqual(names({"s": {key: val}}), [], (key, val))

    def test_literal_token_under_env_var_key_still_caught(self):
        self.assertEqual(names({"s": {"bearer_token_env_var": "sk-live-9fA2kQ7rT0zXc4Lm"}}), ["bearer_token_env_var"])

    def test_uppercase_or_hex_token_under_env_var_key_still_caught(self):
        # Codex review, 7 Nov: an all-caps or hex secret must not pass as a variable name
        for val in ("LIVESECRETABC123456789", "DEADBEEF0123456789ABCDEF", "A", "AKIA_4F7Q9Z2X8W1V3B6N", "AB12_CD34_EF56_GH78",
                    "QJTX_NZKP_VHMR_WBCF", "KEYA_TOKE_SAFE_HOME"):
            self.assertEqual(names({"s": {"token_env_var": val}}), ["token_env_var"], val)

    def test_loose_env_keys_keep_the_old_rule(self):
        # only a key that says env_var is exempt; password_env / authenvvar are environment-specific literals
        for key in ("password_env", "authenvvar", "api_key_env"):
            self.assertEqual(names({"s": {key: "PROD_DB_PASSWORD"}}), [key], key)

    def test_uppercase_value_under_plain_token_key_still_caught(self):
        # the exemption is for keys that SAY they name a variable; a bare token key keeps the old rule
        self.assertEqual(names({"s": {"token": "ABCDEF_1234567890_XYZ"}}), ["token"])

    def test_env_block_value_still_caught(self):
        # inside env/headers the value is the secret itself, whatever the key is called
        self.assertEqual(names({"s": {"env": {"TOKEN_ENV": "LIVEVALUE_ABC123"}}}), ["TOKEN_ENV"])


if __name__ == "__main__":
    unittest.main()
