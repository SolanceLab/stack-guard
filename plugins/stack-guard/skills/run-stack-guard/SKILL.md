---
name: run-stack-guard
description: Audit the current project's packages, runtimes, deploy configs and MCP servers, check this fortnight's security news, report in plain words, and apply safe package fixes only after approval. Use when the user asks to run stack-guard or to audit and fix their stack.
---

# Run stack-guard

**Secrets (applies to every step):** never print, quote, paste or summarise the value of a token, key, password, webhook URL or credential, not even when a tool's output shows one and not even back to the user; a secret that reaches the chat is stored in the session history. Never open files that hold secrets: `.env`, `.env.*`, `~/.claude.json`, `claude_desktop_config.json`, `.mcp.json` `env`/`headers` blocks, `.npmrc`, `.pypirc`, `secrets.yaml` (Home Assistant), `*.pem`, `*.key`, `credentials*`, `.dev.vars`, `wrangler` secrets. Read MCP servers only through the script (`stack_guard.py inventory`, which redacts) or a one-liner that prints names and commands only. When a secret appears anyway, do not repeat it: tell the user which kind of secret and where it showed up, and recommend rotating it.

This is the entry point for tools without a `/stack-guard` command (eg. Codex). In Claude Code, `/stack-guard` does the same thing.

Talk to the user in plain, short words; assume they are busy and not a security expert. Options the user may say: a folder to scan, "audit only" (report, and change none of their code or packages), "yes, fix" (counts as yes to package fixes only).

1. **Scope.** Use the folder the user named, else the current folder. When the current folder holds no project (eg. the home folder), list the code folders you can see (names only) and ask once which to scan; default to the current folder.
2. **Audit.** First run the plugin's script: `python3 <plugin folder>/scripts/stack_guard.py check "<folder>"` (find the plugin folder with `codex plugin list --json`, or `${CLAUDE_PLUGIN_ROOT}` in Claude Code). It writes the inventory and a report under `<folder>/.stack-guard/`. Then follow the `stack-audit` skill for what the script cannot judge, steps 1 to 4, for each project. When your tool can delegate in parallel, use at most four workers and never two on one lockfile (in Claude Code, the packaged `stack-auditor` agent); otherwise go project by project.
3. **News.** Do step 3b of `stack-audit`, on every run (audit only included), along with the MCP check of step 2b. When there is no `stack-news-scout` agent (eg. Codex), do the news search yourself, following the rules written for that agent: web only, last 14 days, primary sources, public package names only, and judge each story against the user's exact versions.
4. **Report** in the format of `stack-audit` step 5, then ask one closed question: "Fix the safe package updates now? I'll update packages inside each project, check that tests and builds still pass, and put things back if anything breaks. I won't deploy, commit, upgrade Node/Python, or restart services without asking you separately. (yes / no / only <project>)". Stop here when the user asked for audit only.
5. **Fix**, only after a yes: follow the `stack-fix` skill for each project (parallel workers when your tool has them, at most four, never two on one lockfile; in Claude Code, the packaged `stack-fixer` agent). Re-run each project's audit yourself before you repeat a claim.
6. **Inventory and daily watch.** For a list of everything they run: `python3 <plugin folder>/scripts/stack_guard.py inventory "<folder>"`. For a daily check: follow this plugin's `commands/watch.md` (it uses the script's `watch-install`, `webhook-set` and `watch-remove`).
7. **Finish** with: what got fixed, what is left and why, what needs a separate yes (runtime upgrade, service restart, major-version jump), and the exact deploy command from each project's own scripts.

In Codex, respect the active sandbox and approval policy. Ask for approval when needed for project writes and for network access to the package registry, `api.osv.dev`, `endoflife.date` and primary security-news sources. When access is denied, list that check under "Not checked" with the reason.
