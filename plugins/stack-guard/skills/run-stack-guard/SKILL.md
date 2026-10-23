---
name: run-stack-guard
description: Audit the current project's packages, runtimes, deploy configs and MCP servers, check this fortnight's security news, report in plain words, and apply safe package fixes only after approval. Use when the user asks to run stack-guard or to audit and fix their stack.
---

# Run stack-guard

This is the entry point for tools without a `/stack-guard` command (eg. Codex). In Claude Code, `/stack-guard` does the same thing.

Talk to the user in plain, short words; assume they are busy and not a security expert. Options the user may say: a folder to scan, "audit only" (report and change nothing), "yes, fix" (counts as yes to package fixes only).

1. **Scope.** Use the folder the user named, else the current folder. When the current folder holds no project (eg. the home folder), list the code folders you can see (names only) and ask once which to scan; default to the current folder.
2. **Audit.** Follow the `stack-audit` skill, steps 1 to 4, for each project. When your tool can delegate in parallel, use at most four workers and never two on one lockfile (in Claude Code, the packaged `stack-auditor` agent); otherwise go project by project.
3. **News.** Do step 3b of `stack-audit`, on every run (audit only included), along with the MCP check of step 2b. When there is no `stack-news-scout` agent (eg. Codex), do the news search yourself, following the rules written for that agent: web only, last 14 days, primary sources, public package names only, and judge each story against the user's exact versions.
4. **Report** in the format of `stack-audit` step 5, then ask one closed question: "Fix the safe package updates now? I'll update packages inside each project, check that tests and builds still pass, and put things back if anything breaks. I won't deploy, commit, upgrade Node/Python, or restart services without asking you separately. (yes / no / only <project>)". Stop here when the user asked for audit only.
5. **Fix**, only after a yes: follow the `stack-fix` skill for each project (parallel workers when your tool has them, at most four, never two on one lockfile; in Claude Code, the packaged `stack-fixer` agent). Re-run each project's audit yourself before you repeat a claim.
6. **Finish** with: what got fixed, what is left and why, what needs a separate yes (runtime upgrade, service restart, major-version jump), and the exact deploy command from each project's own scripts.

In Codex, respect the active sandbox and approval policy. Ask for approval when needed for project writes and for network access to the package registry, `api.osv.dev`, `endoflife.date` and primary security-news sources. When access is denied, list that check under "Not checked" with the reason.
