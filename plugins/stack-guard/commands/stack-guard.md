---
description: Check what you build and run for known security holes, explain it in plain words, then apply the safe package fixes after your yes
argument-hint: '[folder to scan, default: this folder] [--audit-only] [--yes]'
---

**Secrets (applies to every step):** never print, quote, paste or summarise the value of a token, key, password, webhook URL or credential, not even when a tool's output shows one and not even back to the user; a secret that reaches the chat is stored in the session history. Never open files that hold secrets: `.env`, `.env.*`, `~/.claude.json`, `claude_desktop_config.json`, `.mcp.json` `env`/`headers` blocks, `.npmrc`, `.pypirc`, `secrets.yaml` (Home Assistant), `*.pem`, `*.key`, `credentials*`, `.dev.vars`, `wrangler` secrets. Read MCP servers only through the script (`stack_guard.py inventory`, which redacts) or a one-liner that prints names and commands only. When a secret appears anyway, do not repeat it: tell the user which kind of secret and where it showed up, and recommend rotating it.

You are running stack-guard for the user. Arguments: $ARGUMENTS

Work in three stages (plus Stage 2b). Talk to the user in plain, short words; assume they are busy and not a security expert.

**Stage 1 — Audit.** Before anything else run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/stack_guard.py" version-check`. When it says a newer stack-guard is out, tell the user that line in one sentence, then carry on with the audit (do not stop). Then run the plugin's script for the exact, repeatable part: `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/stack_guard.py" check "<folder>"`. It writes the inventory and a report (every package on OSV.dev, runtimes on endoflife.date, MCP servers that auto-update) under `<folder>/.stack-guard/`. Then load the `stack-guard:stack-audit` skill and follow it for what a script cannot judge: confirming what is live, production vs build-only, the news check, and plain-words explanations. When `python3` is missing, do every step from the skill by hand. Scope:
- A folder in the arguments → scan that folder.
- No folder → scan the current folder. When the current folder holds no project (eg. it is the home folder), list the code folders you can see (names only) and ask once: "Scan these? (yes / pick some / no)". Default to the current folder when there is no answer.
The script's report has a section "Secrets committed to git": read it first. The script already opened those files and named the keys; never open a file yourself to confirm (the secrets rule). Tell the user to rotate each key it names, then stop tracking the file. The report also lists the tools on this computer (uv, pip, npm and so on) under "Tools on this computer".
Run the per-project checks in parallel with the `stack-auditor` agent, one agent per project, when there are more than three projects. When the audits are done, start the `stack-news-scout` agent with the full list of components and versions (the skill's step 3b). The MCP check (step 2b) and the news check (step 3b) run on every audit, `--audit-only` included; the report may only list one under "Not checked" with the reason it failed.

**Stage 2b — Was I hit?** Right after the audit, on every run, `--audit-only` included (it changes nothing). Load the `stack-guard:stack-breach-check` skill. Take the audit's high and critical findings for projects that have a deploy config, plus the news scout's items that name a supply-chain compromise (a malicious package version). Run one `stack-breach-checker` agent per project, at most four at a time. Each finding gets one verdict: `not reachable`, `reachable, no signs found`, `reachable, cannot tell (no logs)` or `signs found`. For `signs found`, tell the user to treat it as an incident: stop, preserve evidence, get help. For `cannot tell` on a hole that runs code or reads files, name the secrets the app can reach (names only) and say "rotate these". This stage reads and reports only: it never edits, fixes, deploys, restarts, rotates or contacts anyone.

**Stage 2 — Report.** Give the user the report in the skill's format, with a "## Was I hit?" section (one verdict line per finding) placed right after "🔴 Fix first", and the script's "## Secrets committed to git" section after it. End with one closed question:
"Fix the safe package updates now? I'll update packages inside each project, check that tests and builds still pass, and put things back if anything breaks. I won't deploy, commit, upgrade Node/Python, or restart services without asking you separately. (yes / no / only <project>)"
- `--audit-only` in the arguments → stop after the report.
- When `.stack-guard/inventory.json` exists in the folder, use it as the starting list of projects and services, and still look for anything new.
- `--yes` in the arguments → counts as yes to this question only (package updates inside the projects). Runtime upgrades, service restarts, deploys, commits and pushes always get their own question.

**Stage 3 — Fix (only after a yes).** Load the `stack-guard:stack-fix` skill and follow it fully. Use one `stack-fixer` agent per project, at most four at a time, and never two agents on projects that share a lockfile or workspace root. Re-run each project's audit yourself before you repeat an agent's claim.

Finish with a short summary: what got fixed, what is left and why, what needs a separate yes (runtime upgrade, service restart, major-version jump), and the exact deploy command from each project's own scripts. Ask before any deploy, push, commit, runtime upgrade, or restart.
