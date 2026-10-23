---
name: stack-breach-check
description: For each serious hole stack-guard found (and each supply-chain compromise in the news), work out whether it could have been used against the user and whether anything shows it was. Checks that the hole is reachable, the window it was open, whether logs exist, and known traces on this computer. Read-only. Use after the stack audit, or when the user asks "was I hit?".
---

**Secrets (applies to every step):** never print, quote, paste or summarise the value of a token, key, password, webhook URL or credential, not even when a tool's output shows one and not even back to the user; a secret that reaches the chat is stored in the session history. Never open files that hold secrets: `.env`, `.env.*`, `~/.claude.json`, `claude_desktop_config.json`, `.mcp.json` `env`/`headers` blocks, `.npmrc`, `.pypirc`, `secrets.yaml` (Home Assistant), `*.pem`, `*.key`, `credentials*`, `.dev.vars`, `wrangler` secrets. Read MCP servers only through the script (`stack_guard.py inventory`, which redacts) or a one-liner that prints names and commands only. When a secret appears anyway, do not repeat it: tell the user which kind of secret and where it showed up, and recommend rotating it.

# Was I hit? (read-only)

Goal: for each serious hole, say whether it could have been used against the user, whether anything shows it was, and what to do. This skill never edits, fixes, deploys, restarts, rotates a key or contacts anyone. It runs no downloaded code.

Input: the audit's high and critical findings for projects that have a deploy config, and the news scout's items (supply-chain compromises such as a malicious package version). One finding at a time:

1. **Reachable?** Fetch EVERY advisory for the finding from its primary URL (the finding or the news item names it); never judge one advisory from another's text, and when a page will not load, say so and mark that one `unclear`. Write its preconditions in one line: the feature, config, route or version range an attacker needs. Search the project for each precondition (config flags, imports, directives, routes). Result: `not reachable` (name the absent precondition and where you looked), `reachable`, or `unclear`.
2. **Window.** From the day the affected version first went into the project (`git log` of the lockfile, or the first deploy that carried it), not the advisory's publish date: holes are often used before they are announced. For a malicious release, from its upload time. Until the date the fixed version was installed (`git log` of the lockfile), or today when it is not fixed yet.
3. **Traffic.** Only when the result is `reachable` or `unclear`. Check whether logs exist for that window, by host, with the user's already logged-in CLIs, read-only:
   - Cloudflare Workers: look for `observability` in the wrangler config. Absent → "no Workers Logs kept". Enabled → give the dashboard path (Workers > the worker > Logs) and the query to run for the advisory's pattern.
   - Fly, Vercel, Supabase, any other host: do not run `fly logs`, `vercel logs` or any command that prints raw log lines; the output would enter this chat. Name the dashboard or logs explorer path and give the user the query or filter to run themselves for the advisory's pattern (eg. count of requests to the vulnerable route in the window), then ask for the count only. Fly keeps recent minutes only; say so.
   Never download, open or paste log contents. Request data, credentials and personal data sit in them.
4. **Traces (IOCs).** When the advisory or a reputable primary write-up lists indicators (file names, paths, processes, domains), check this computer and the project, read-only: file existence under site-packages, venvs, the home folder and tmp; running processes by name (`ps -axo comm`); lockfiles naming the malicious version. Report found / not found per indicator.
5. **Verdict**, one of: `not reachable` · `reachable, no signs found` · `reachable, cannot tell (no logs)` · `signs found`.
   - For `signs found` or `cannot tell` on a hole that runs code or reads files: list the secrets the app can reach BY NAME (env var names from the wrangler config, fly.toml or .env.example; never values) and say "rotate these".
   - For `signs found`, also say: "treat as an incident: stop, preserve evidence, get help".

The checker has no shell (its tools are Read, Grep, Glob and WebFetch), so the limit is enforced, not just asked for. Indicator files: look with Glob/Read. The lockfile history and the process list come from the main session in the task; when one is missing, mark that part `unclear`. Open no secret file to check a variable name: read names from `wrangler` config, `fly.toml` and `.env.example`.

Return one line per finding: `<project> · <package/advisory> · <verdict>`, then under it the reachable precondition, the window, the log source or "no logs", and the indicators checked. Report a check you could not run under "Could not check".
