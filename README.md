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

**Turn on auto-update once (Claude Code):** `/plugin` → **Marketplaces** tab → **stack-guard** → **Enable auto-update**. Claude Code then installs new versions by itself a few minutes into a session and shows "Plugin updated: stack-guard · Run /reload-plugins to apply". (It is off by default for every marketplace that is not Anthropic's own.)

Or update by hand:

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

1. **Read it.** stack-guard is instructions in plain Markdown plus **one small Python script** (`scripts/stack_guard.py`, standard library only, no installs) — the secret-guard hooks (see Secret guard below) and one small update check at session start, no MCP servers. After installing, see what it adds with `claude plugin details stack-guard`, and read the files in `~/.claude/plugins/cache/stack-guard/`.
2. **Commit or back up your project first**, so any change is easy to undo.
3. **Look before you fix.** Start with `/stack-guard --audit-only`: it reports and changes none of your code or packages.
4. **Turn on Claude Code's sandbox** (macOS, Linux, WSL2): type `/sandbox`. Commands can then only write inside your project folder, and every new website needs your OK. When asked, allow `registry.npmjs.org`, `api.osv.dev`, `endoflife.date`, `raw.githubusercontent.com` and `pypi.org`. The sandbox covers the commands Claude runs; Claude's own file edits still follow your normal permission prompts. Docs: https://code.claude.com/docs/en/sandboxing
5. **Strongest:** run Claude Code inside a dev container or a virtual machine, with no SSH keys or cloud credentials mounted. Docs: https://code.claude.com/docs/en/devcontainer

## What it does

1. **Finds what you run.** Code projects, their deploy configs (Cloudflare Workers/Pages, Fly.io, Vercel, Netlify, Docker), background services and tunnels on your computer, and the runtimes they use. When a host CLI is already installed and logged in, it confirms what is really live, because the repo and the running app can differ.
2. **Checks every package and MCP server**, without downloading new tools. It flags MCP servers that fetch themselves fresh on every start (`npx -y some-server` with no version), the easiest way in for a hijacked release. Packages are checked with `npm audit` / `pnpm` / `yarn` for JavaScript, and the free [OSV.dev](https://osv.dev) database for Python, Go, Rust, Ruby and PHP. Production packages are kept apart from build-only tools.
3. **Checks runtimes.** Node and Python versions against [endoflife.date](https://endoflife.date): unsupported, or a security update available.
4. **Reads the news.** A scout agent searches the last 14 days of security news for the parts of your stack, confirms each story on the project's own advisory, and tells you whether it affects your versions.
5. **Checks whether it was used against you.** For each serious hole in something you deploy, a read-only breach checker asks whether the hole was reachable in your setup, how long it was open, whether logs exist for that window, and whether known traces are on this computer. See "Was I hit?" below.
6. **Finds secrets committed to git.** It looks in the usual secret files (`.mcp.json`, `.env`, keys, `.npmrc`, `.pypirc`) that git tracks, and in older commits, and names the key to rotate. It never prints a value.
7. **Checks the tools on your computer.** `uv`, `pip`, `pipx`, `poetry`, `npm`, `pnpm`, `yarn`, plus the `certifi` copy inside each uv tool environment, are looked up like any package. `bun` and `deno` have no advisory feed and are listed under "Not checked".
8. **Reports** what is internet-facing first, then what only runs on your computer, then what is clean.
9. **Fixes, after your yes.** One fixer agent per project: same-major package upgrades with install scripts switched off (never `--force`), then it proves the project still passes its tests, builds, and works (website pages render, MCP servers still list their tools and refuse strangers). It also serves the project the way it is deployed (a Worker with `wrangler dev`, a Docker or Fly app from its image), because tests and a plain build can pass while the deployed runtime fails. Anything that breaks is put back. A major-version jump comes back to you as a question. A fix also waits until the fixed version has been public for 48 hours (change it with the `min_release_hours` setting or `STACK_GUARD_MIN_RELEASE_HOURS`), because hijacked releases are usually caught and pulled within that time; the fixer tells you when to run again. After fixing, stack-guard checks the project again and undoes the fix if a known malicious release (an OSV `MAL-` record, flagged MALICIOUS and shown first) came in.

**It never deploys, pushes, commits, upgrades Node/Python, or restarts services on its own.** It hands you the exact command and waits for your yes. Projects with unsaved changes are left alone.

**Good to know:** fixing runs your project's own tests and build, which run your project's code. That is normal for your own projects; for a repo you cloned from someone else, stack-guard asks first.

## Was I hit?

The checker agent has no shell: it can only read files, search and open public advisory pages, so it cannot change or send anything. The few commands it needs (lockfile history, running process names) run in your main session, where you see them.

Fixing a hole does not tell you whether someone used it before you fixed it. After the audit, on every run (`--audit-only` too, since it changes nothing), stack-guard asks, for each high or critical finding in a project that has a deploy config and for each supply-chain story in the news:

1. **Reachable?** It reads the advisory and writes down what an attacker needs (a feature, a route, a version range), then searches your project for it. Not reachable means the precondition is absent, and it says where it looked.
2. **Window.** From the advisory's date to the day the fix was installed (from the lockfile's git history), or to today.
3. **Traffic.** Whether logs exist for that window, and where to look: Cloudflare Workers Logs, `fly logs`, `vercel logs`, the Supabase logs explorer. It reports counts and request paths, never log contents that hold personal data.
4. **Traces.** When the advisory lists indicators (file names, paths, processes, domains), it checks this computer and the project for them, read-only.

Each finding ends in one verdict: `not reachable`, `reachable, no signs found`, `reachable, cannot tell (no logs)` or `signs found`. For the last two on a hole that runs code or reads files, it names the secrets the app can reach (names only) and tells you to rotate them.

**What it cannot prove.** Without logs it cannot tell: "no signs found" means nothing it could check showed abuse, not that none happened. A host keeps no history unless you turned it on. For a Cloudflare Worker, add `[observability] enabled = true` to `wrangler.toml` (or `"observability": {"enabled": true}` in `wrangler.jsonc`) and deploy; Workers Logs then keep requests for the next time. Fly keeps only recent minutes with `fly logs`; ship them to a log service if you want history.

The daily watch does not run these checks (no agent works unattended). It adds one line to its report when there are new high or critical live findings: "Run /stack-guard to check whether these were used against you."

## Settings

Four settings (three switches, all on by default, and the fix release age, 48 hours). Change them when you install (`/plugin`), later with `/plugin configure stack-guard@stack-guard` or `/config`, or from a terminal install: `claude plugin install stack-guard@stack-guard --config reply_check=false`.

| Setting | What turning it off means |
| --- | --- |
| `secret_guard` ("Secret guard") | All three secret-guard hooks stop before they read anything. Nothing is blocked or redacted. |
| `reply_check` ("Final-reply check") | Only the Stop hook stops. It is the one that reads the session's history on this computer (nothing leaves the computer) to check each reply for secret shapes. The other two secret-guard hooks keep working. |
| `update_check` ("Update check") | No daily request to GitHub for the version number: not at session start, not in `/stack-guard`, not in the daily watch. `version-check` says "Update check is turned off." |

| `min_release_hours` ("Fix release age (hours)") | How long a fixed version must have been public before the fixer installs it (default 48). `0` takes new versions at once. `stack_guard.py release-age <npm\|PyPI> <name> <version>` shows the verdict; it asks the registry for public package names only. |

`PLUGIN_UPDATE_CHECK=0` still turns the update check off too.

## Secret guard

Your agents can still work with secrets: use them, rotate them, set them. During a stack-guard run, the guard only stops a secret's value from being printed into the chat.

Active only while stack-guard is working in a session (its commands, skills, agents, or the daily watch). Your other Claude Code work is untouched. Once you use stack-guard in a Claude Code session, the secret guard stays on for the rest of that session (a hook can see that stack-guard started, not reliably when it finished). Start a new session for work where you need the AI to open secret files.

Three layers:

1. **Stops before reading.** `Read`, `Grep` and shell commands (`cat`, `grep`, `head`, `sed`, `jq`, `python -c open(...)` and similar) that point at a secret file are blocked with a plain message: `.env` (but not `.env.example`), `.dev.vars`, `.npmrc`, `.netrc`, `.pgpass`, `secrets.*`, `*.pem`, `*.key`, SSH private keys, cloud credential files (`~/.aws/credentials`, gcloud, kube, docker), `~/.claude.json`, Codex `auth.json`. Bare `printenv` / `env` dumps and `security find-generic-password -w` printed to the screen are blocked too. Any shell command that names a secret file is blocked (so a Python, Ruby, Perl or Node one-liner that reads `.env` cannot slip past), unless it only uses the file without printing it: `export X=$(grep X .env)`, `source .env && npm test`, `cp`/`mv`/`rm`/`chmod`/`ls` on it, `sed -i`, writing to it (`>> .env`), or piping it into `wrangler secret put`, `gh secret set` or `security add-generic-password`. A secret file's content is never sent on by a network command (`curl`, `wget`, `nc`, `ssh`, `scp`, `rsync` and similar), and wildcards and brace forms that could match a secret file (`.e*`, `.env{,.local}`), nested `sh -c` / `bash -c`, environment dumps (`export -p`, `declare -p`) and content searches with the Grep tool that cover a whole folder are checked too (give them a file type or a single file; file-name and count searches are not affected). Recursive searches (`grep -r .`, `rg --hidden`, `find ... -exec cat`) are blocked too; use `rg PATTERN` (it skips ignored files like `.env`) or name the source folders. `curl -H "Authorization: $(security find-generic-password -s x -w)"` passes. A `$(...)` that feeds a printing command (`echo "$(cat .env)"`) is blocked, and so are `printenv API_TOKEN`, `echo "$API_TOKEN"` and copying a secret file to the screen.
2. **Redacts tool output.** After `Bash`, `Read` and `Grep` run, a PostToolUse hook scans the result for secret shapes and swaps each one for `[REDACTED ...]` before Claude sees it, then tells Claude to have you rotate (replace) the secret.
3. **Catches and warns after replying.** When Claude finishes, a Stop hook scans its last reply for secret shapes (GitHub, OpenAI/Anthropic, Slack, AWS and Google keys, JWTs, private keys, Discord bot tokens, passwords inside URLs). On a hit, Claude is told to say so in one line and to have you rotate (replace) the secret. The secret itself is never repeated.

It is a seatbelt, not a vault: it catches the common ways a secret gets printed, not every possible one. It cannot catch code that builds a file name in a way it cannot read, or a determined agent; for real protection turn on Claude Code's sandbox (`/sandbox`). To turn off all of it, or only the final-reply check, see [Settings](#settings). To remove it entirely, run `/plugin disable stack-guard` or remove the plugin.

**Claude Code only;** in Codex, the written secrets rule in every stack-guard instruction applies.

Thanks to Aya ([@ayakohi](https://github.com/ayakohi)), whose question started it.

## What leaves your computer

- Package names and versions: to OSV.dev (the daily watch never sends private npm names anywhere; they are counted, not listed), and in a conversation also to your package registry's audit service (`npm audit` sends your dependency list to the npm registry; private package names included).
- Runtime names and versions: to endoflife.date.
- Once a day, one request to raw.githubusercontent.com for this plugin's version number, to tell you when a newer stack-guard is out: at the start of a Claude Code session (one line in your terminal), in `/stack-guard`, and in the daily watch. Nothing about you or your projects is sent. Turn it off with the `update_check` setting (see [Settings](#settings)) or the environment variable `PLUGIN_UPDATE_CHECK=0`.
- Daily watch agents (when on): public package and runtime names and versions go to your own Claude Code or Codex account, and the news scout runs web searches with those generic names. The news scout agent is web-only and the explainer agent is tool-less (no file access, no shell) in both Claude and Codex. Turn them off with `--no-agents`.
- Webhook (only if you set one): a short summary of new findings (package names, versions, severities, counts) to the Discord or Slack channel you chose.
- "Was I hit?": the breach checker fetches advisory pages (public URLs only). It sends no project data to them.
- Secrets committed to git are local facts: they are never sent to OSV, and a webhook says only "N secret file(s) committed to git", with no file names.
- When a host CLI (wrangler, fly) is installed and logged in, the conversation may use it, and it talks to your own account on that host, as it always does.

Your source code, keys, `.env` files and file paths are not sent anywhere, and stack-guard keeps tokens out of its reports.

## Not covered yet

Container image scanning, GitHub Actions pinning, package signatures/provenance, full secret scanning of every file and of git history contents (it checks the usual secret files: .mcp.json, .env, keys, .npmrc), traffic analysis beyond what your host's own logs hold, and Maven/Gradle/NuGet without lockfiles. macOS and Linux are fully supported; Windows works on a best-effort basis and the report lists what it skipped. On Windows the daily watch writes the report and sends the webhook; it shows no desktop pop-up.

## Needs

Claude Code or Codex. Node/npm for JavaScript projects. For Python, [`uv`](https://docs.astral.sh/uv/) (or `pipx`) makes the check faster; without it, stack-guard makes a throwaway environment and deletes it afterwards.

## Help make it better

Spotted a gap? A stack it misses, a check that's wrong, a fix that went sideways, a security story it should have caught? Please tell us.

- **Open an issue:** https://github.com/SolanceLab/stack-guard/issues. Say what you ran, what you expected, and what happened. Leave keys, tokens and private project names out.
- **Send a pull request:** everything lives in plain Markdown under `plugins/stack-guard/` (`commands/`, `skills/`, `agents/`). Keep the safety rules intact: the audit runs no freshly downloaded code, fixes stay same-major with install scripts off, and nothing deploys, commits, or touches the wider machine without the user's separate yes.
- **Found a security problem in stack-guard itself?** Please report it privately through GitHub's "Report a vulnerability" button on the Security tab, not in a public issue.

## Thanks

Thanks to Aya ([@ayakohi](https://github.com/ayakohi)), whose question started the secret guard, and to Cygnus, who read the whole plugin, caught that agents loaded the user's own instruction files, and wrote the named-secret redaction.

## License

MIT
