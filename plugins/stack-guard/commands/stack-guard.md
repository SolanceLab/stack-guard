---
description: Check what you build and run for known security holes, explain it in plain words, then apply the safe package fixes after your yes
argument-hint: '[folder to scan, default: this folder] [--audit-only] [--yes]'
---

You are running stack-guard for the user. Arguments: $ARGUMENTS

Work in three stages. Talk to the user in plain, short words; assume they are busy and not a security expert.

**Stage 1 — Audit.** Load the `stack-guard:stack-audit` skill and follow it fully. Scope:
- A folder in the arguments → scan that folder.
- No folder → scan the current folder. When the current folder holds no project (eg. it is the home folder), list the code folders you can see (names only) and ask once: "Scan these? (yes / pick some / no)". Default to the current folder when there is no answer.
Run the per-project checks in parallel with the `stack-auditor` agent, one agent per project, when there are more than three projects. When the audits are done, start the `stack-news-scout` agent with the full list of components and versions (the skill's step 3b). The MCP check (step 2b) and the news check (step 3b) run on every audit, `--audit-only` included; the report may only list one under "Not checked" with the reason it failed.

**Stage 2 — Report.** Give the user the report in the skill's format. End with one closed question:
"Fix the safe package updates now? I'll update packages inside each project, check that tests and builds still pass, and put things back if anything breaks. I won't deploy, commit, upgrade Node/Python, or restart services without asking you separately. (yes / no / only <project>)"
- `--audit-only` in the arguments → stop after the report.
- `--yes` in the arguments → counts as yes to this question only (package updates inside the projects). Runtime upgrades, service restarts, deploys, commits and pushes always get their own question.

**Stage 3 — Fix (only after a yes).** Load the `stack-guard:stack-fix` skill and follow it fully. Use one `stack-fixer` agent per project, at most four at a time, and never two agents on projects that share a lockfile or workspace root. Re-run each project's audit yourself before you repeat an agent's claim.

Finish with a short summary: what got fixed, what is left and why, what needs a separate yes (runtime upgrade, service restart, major-version jump), and the exact deploy command from each project's own scripts. Ask before any deploy, push, commit, runtime upgrade, or restart.
