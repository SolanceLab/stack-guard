# stack-guard

**One prompt to check everything you build and run with Claude Code or Codex for known security holes, and fix the safe ones.**

Supply-chain attacks and urgent security releases are landing every week (hijacked PyPI and npm packages, Node.js and Python security releases, MCP SDK fixes). stack-guard lets Claude find what you actually run, check it against the public vulnerability databases, read this fortnight's security news for your exact versions, explain it all in plain words, and then patch what can be patched safely, after your yes.

## Install (once)

In Claude Code:

```
/plugin marketplace add SolanceLab/stack-guard
/plugin install stack-guard@stack-guard
```

### Codex users

```
codex plugin marketplace add SolanceLab/stack-guard
codex plugin add stack-guard@stack-guard
```

Start a new Codex conversation, then type `$stack-guard:run-stack-guard audit this folder`, or just ask: *"run stack-guard on this folder"* (add *"audit only"* to change none of your code or packages). Codex has no slash commands for plugins, so the `run-stack-guard` skill is the entry point; it does the same audit, news check and safe fixes.

## Update

Already installed an earlier version? Update, then restart your tool:

- Claude Code (terminal): `claude plugin marketplace update stack-guard` then `claude plugin update stack-guard@stack-guard`
- Codex: `codex plugin marketplace upgrade stack-guard` then `codex plugin add stack-guard@stack-guard`

Using the daily watch? Run `/stack-guard:watch` once more after updating: the morning routine runs its own copy of the script (in `~/.config/stack-guard/bin/`, so an update can never break it silently), and this refreshes that copy. Each morning's run is logged in `~/.config/stack-guard/logs/`.

## Use

Open Claude Code in your project folder (or the folder that holds your projects) and type:

```
/stack-guard
```

That is the whole thing. (If another plugin also has a `/stack-guard`, use `/stack-guard:stack-guard`.) Optional:

- `/stack-guard ~/Projects/my-bot` checks one folder
- `/stack-guard --audit-only` reports and changes none of your code or packages (it only writes its report into a `.stack-guard/` folder, which ignores itself in git; your own `.gitignore` is never edited)
- `/stack-guard --yes` reports, then applies the safe package updates without asking again. Node/Python upgrades, service restarts, deploys and commits still get their own question.

You can also just say: *"check my stack for security problems"*.

**Two more commands:**

- `/stack-guard:inventory` runs the script to write `STACK-INVENTORY.md`: a plain list of every project, where it's deployed, its runtime, package counts and MCP servers, with anything it couldn't place flagged at the top. Keep it (it describes your setup, so review it before committing it anywhere public). When the next security alert lands, you'll know in seconds whether it touches you.
- `/stack-guard:watch` sets up a **daily routine on your own computer** (launchd on Mac, cron on Linux, Task Scheduler on Windows). It shows you the exact entry and asks before adding it. Each morning the script checks everything on the list, a **news scout agent** reads the last 14 days of security news for your versions, and an **explainer agent** writes what's new in plain words. You get **only what changed since yesterday**: a desktop notification, a report in `.stack-guard/reports/`, and optionally a Discord or Slack webhook. `/stack-guard:watch --off` removes it.

## How it works: script + agents

- **The script** (`scripts/stack_guard.py`, Python standard library only) does the exact, repeatable part. It reads these lockfiles: npm `package-lock.json` (v2/v3), pinned `requirements*.txt`, `Pipfile.lock`, and `poetry.lock` / `uv.lock` on Python 3.11+. pnpm, Yarn, Bun, Go, Rust, Ruby and PHP projects are listed by the daily watch but package-checked only in a `/stack-guard` conversation. It lists every project, deploy config, runtime and MCP server, checks every package against [OSV.dev](https://osv.dev) and every runtime against [endoflife.date](https://endoflife.date), and compares with the last run. Same result every time, free to run every day.
- **The agents** do the judgment: the news scout (web search only), the explainer (no tools), and in a conversation, the auditor and the fixer. They only get public package names and versions.
- With no Python, the agents do everything by hand from the same instructions.

## Before you run it (please)

Best practice for **any** plugin, this one included, even from people you trust: a plugin is instructions that run commands on your computer.

1. **Read it.** stack-guard is instructions in plain Markdown plus **one small Python script** (`scripts/stack_guard.py`, standard library only, no installs) — no hooks, no MCP servers. After installing, see what it adds with `claude plugin details stack-guard`, and read the files in `~/.claude/plugins/cache/stack-guard/`.
2. **Commit or back up your project first**, so any change is easy to undo.
3. **Look before you fix.** Start with `/stack-guard --audit-only`: it reports and changes none of your code or packages.
4. **Turn on Claude Code's sandbox** (macOS, Linux, WSL2): type `/sandbox`. Commands can then only write inside your project folder, and every new website needs your OK. When asked, allow `registry.npmjs.org`, `api.osv.dev`, `endoflife.date` and `pypi.org`. The sandbox covers the commands Claude runs; Claude's own file edits still follow your normal permission prompts. Docs: https://code.claude.com/docs/en/sandboxing
5. **Strongest:** run Claude Code inside a dev container or a virtual machine, with no SSH keys or cloud credentials mounted. Docs: https://code.claude.com/docs/en/devcontainer

## What it does

1. **Finds what you run.** Code projects, their deploy configs (Cloudflare Workers/Pages, Fly.io, Vercel, Netlify, Docker), background services and tunnels on your computer, and the runtimes they use. When a host CLI is already installed and logged in, it confirms what is really live, because the repo and the running app can differ.
2. **Checks every package and MCP server**, without downloading new tools. It flags MCP servers that fetch themselves fresh on every start (`npx -y some-server` with no version), the easiest way in for a hijacked release. Packages are checked with `npm audit` / `pnpm` / `yarn` for JavaScript, and the free [OSV.dev](https://osv.dev) database for Python, Go, Rust, Ruby and PHP. Production packages are kept apart from build-only tools.
3. **Checks runtimes.** Node and Python versions against [endoflife.date](https://endoflife.date): unsupported, or a security update available.
4. **Reads the news.** A scout agent searches the last 14 days of security news for the parts of your stack, confirms each story on the project's own advisory, and tells you whether it affects your versions.
5. **Reports** what is internet-facing first, then what only runs on your computer, then what is clean.
6. **Fixes, after your yes.** One fixer agent per project: same-major package upgrades with install scripts switched off (never `--force`), then it proves the project still passes its tests, builds, and works (website pages render, MCP servers still list their tools and refuse strangers). Anything that breaks is put back. A major-version jump comes back to you as a question.

**It never deploys, pushes, commits, upgrades Node/Python, or restarts services on its own.** It hands you the exact command and waits for your yes. Projects with unsaved changes are left alone.

**Good to know:** fixing runs your project's own tests and build, which run your project's code. That is normal for your own projects; for a repo you cloned from someone else, stack-guard asks first.

## What leaves your computer

- Package names and versions: to OSV.dev (the daily watch never sends private npm names anywhere; they are counted, not listed), and in a conversation also to your package registry's audit service (`npm audit` sends your dependency list to the npm registry; private package names included).
- Runtime names and versions: to endoflife.date.
- Daily watch agents (when on): public package and runtime names and versions go to your own Claude Code or Codex account, and the news scout runs web searches with those generic names. The news scout agent is web-only and the explainer agent is tool-less (no file access, no shell) in both Claude and Codex. Turn them off with `--no-agents`.
- Webhook (only if you set one): a short summary of new findings (package names, versions, severities, counts) to the Discord or Slack channel you chose.
- When a host CLI (wrangler, fly) is installed and logged in, the conversation may use it, and it talks to your own account on that host, as it always does.

Your source code, keys, `.env` files and file paths are not sent anywhere, and stack-guard keeps tokens out of its reports.

## Not covered yet

Container image scanning, GitHub Actions pinning, package signatures/provenance, secret scanning, and Maven/Gradle/NuGet without lockfiles. macOS and Linux are fully supported; Windows works on a best-effort basis and the report lists what it skipped. On Windows the daily watch writes the report and sends the webhook; it shows no desktop pop-up.

## Needs

Claude Code or Codex. Node/npm for JavaScript projects. For Python, [`uv`](https://docs.astral.sh/uv/) (or `pipx`) makes the check faster; without it, stack-guard makes a throwaway environment and deletes it afterwards.

## Help make it better

Spotted a gap? A stack it misses, a check that's wrong, a fix that went sideways, a security story it should have caught? Please tell us.

- **Open an issue:** https://github.com/SolanceLab/stack-guard/issues. Say what you ran, what you expected, and what happened. Leave keys, tokens and private project names out.
- **Send a pull request:** everything lives in plain Markdown under `plugins/stack-guard/` (`commands/`, `skills/`, `agents/`). Keep the safety rules intact: the audit runs no freshly downloaded code, fixes stay same-major with install scripts off, and nothing deploys, commits, or touches the wider machine without the user's separate yes.
- **Found a security problem in stack-guard itself?** Please report it privately through GitHub's "Report a vulnerability" button on the Security tab, not in a public issue.

## License

MIT
