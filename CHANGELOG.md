# Changelog

## 1.5.0

- New: **Was I hit?** After the audit, for each high or critical hole in a deployed project, stack-guard checks whether the hole was reachable in your code, how long it was open, what your host's logs show for that window (and says so when logs are off), and whether the traces an advisory lists are on your computer. Read-only; it names the secrets to rotate, never their values.
- New: warns when a secret file (`.mcp.json`, `.env`, keys, `.npmrc`) is committed to git, now or earlier. Names only, never values. Thanks to Rowan, whose hand sweep found the case.
- New: lists standalone tools (uv, pip, pipx, poetry, npm, pnpm, yarn, bun, deno) and checks them for known holes.
- Fix step: tests the fix the way the project is deployed (for example `wrangler dev` for a Cloudflare Worker), because tests and a plain build can pass while the deployed runtime fails.

## 1.4.0

- A new Claude Code session says in one line when a newer stack-guard is out (at most once a day; off with `PLUGIN_UPDATE_CHECK=0`).

## 1.3.3

- Tells you when a newer stack-guard is out: `version-check`, the top of each report, the daily notification and the start of `/stack-guard`.
- README: how to turn on auto-update.

## 1.3.2

- Redacts any value under a secret-sounding name (`-e X_TOKEN=...`, `"apiKey": ...`, `--password ...`) and Bearer headers, with name parts capped so long text stays fast. Patch by Cygnus, with Aya ([@ayakohi](https://github.com/ayakohi)).

## 1.3.1

- The secret guard reads only real transcript files, with a size and time cap, so it can never hang a tool call.

## 1.3.0

- New: secret guard. While stack-guard is in use it blocks printing a secret file's value into the chat, redacts secrets in tool output, and checks the final reply. Thanks to Aya ([@ayakohi](https://github.com/ayakohi)), whose question started it.
- Agents start without your own instruction files (no CLAUDE.md / AGENTS.md persona). Cygnus caught this in his field report after reading the whole plugin.

## 1.2.2

- The secrets rule is in every instruction file; MCP servers are read only through the redacting script.

## 1.2.1 / 1.2.0

- Inventory script (standard-library Python) and the daily watch with a news scout and an explainer agent. Never runs code from the scanned folder; private package names never leave your computer.

## 1.1.0

- Codex support; news and MCP checks on every run.

## 1.0.0

- First release: one-prompt security audit, news scout and safe fix for Claude Code projects.
