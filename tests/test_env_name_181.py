# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""names_env_var accepts variable names that hold a short acronym and still refuses key-shaped values."""
import json
import unittest

from test_stack_guard import Base  # noqa: F401
import stack_guard as sg


class EnvNameAcronyms(unittest.TestCase):
    def test_names(self):
        for v in ("NOTEBOOK_MCP_KEY", "SSH_KEY_PATH", "HTTP_TOKEN", "HTTPS_PROXY_TOKEN", "GPG_PRIVATE_KEY",
                  "MY_JWT_SECRET", "GITHUB_MCP_PAT_TOKEN", "LIBRARY_TOKEN", "MY_API_KEY_2"):
            self.assertTrue(sg.names_env_var(v), v)

    def test_keys_stay_secrets(self):
        for v in ("QJTX_NZKP", "QJTXNZKP_KEY", "XKCDQRST_TOKEN_VALUE", "QJTX_NZKP_VHMR_WBCF", "KEYA_TOKE_SAFE_HOME",
                  "QJTA_NZKP_VHMR", "AB12_CD34_EF56_GH78", "AKIA_4F7Q9Z2X8W1V3B6N", "LIVESECRETABC123456789"):
            self.assertFalse(sg.names_env_var(v), v)

    def test_end_to_end(self):
        def cfg(value):
            return {"mcpServers": {"s": {"bearer_token_env_var": value}}}
        self.assertEqual(sg.json_secret_names(cfg("NOTEBOOK_MCP_KEY")), [])
        self.assertEqual(sg.json_secret_names(cfg("QJTX_NZKP")), ["bearer_token_env_var"])
        self.assertEqual(sg.literal_secret_names(".mcp.json", json.dumps(cfg("NOTEBOOK_MCP_KEY")))[0], [])
        self.assertEqual(sg.literal_secret_names(".mcp.json", json.dumps(cfg("QJTX_NZKP")))[0], ["bearer_token_env_var"])


if __name__ == "__main__":
    unittest.main()
