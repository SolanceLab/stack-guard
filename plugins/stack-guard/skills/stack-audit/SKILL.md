---
name: stack-audit
description: Find what the user builds and runs (code projects, deploy configs, background services, runtimes), check every package and runtime for known security holes using public databases, and report in plain words, most exposed first. Read-only, and runs no downloaded code. Use when the user asks to check their stack, dependencies, or security, or when stack-guard runs.
---

# Stack audit (read-only)

**Secrets (applies to every step):** never print, quote, paste or summarise the value of a token, key, password, webhook URL or credential, not even when a tool's output shows one and not even back to the user; a secret that reaches the chat is stored in the session history. Never open files that hold secrets: `.env`, `.env.*`, `~/.claude.json`, `claude_desktop_config.json`, `.mcp.json` `env`/`headers` blocks, `.npmrc`, `.pypirc`, `secrets.yaml` (Home Assistant), `*.pem`, `*.key`, `credentials*`, `.dev.vars`, `wrangler` secrets. Read MCP servers only through the script (`stack_guard.py inventory`, which redacts) or a one-liner that prints names and commands only. When a secret appears anyway, do not repeat it: tell the user which kind of secret and where it showed up, and recommend rotating it.

Goal: an honest list of what the user runs, what is vulnerable, and how exposed each thing is. This skill changes none of the user's code or packages and executes no freshly downloaded code: during a supply-chain attack, the audit tool itself must not become the way in.

**Safe-tool rule for this skill:** use only tools already on the computer (`npm`, `pnpm`, `yarn`, `python`, `pip`, `git`, `curl`) and plain HTTPS requests to public databases. Use `npx`, `uvx`, `pipx run`, or any install only with an exact pinned version named below, and only when the step says so. Use a host CLI (`wrangler`, `fly`, `vercel`) only when it is already installed in the project (`node_modules/.bin/`) or on the PATH; never fetch one to run it.

## 1. Find what exists (in the scope stack-guard gave you)

A project is a folder holding `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`/`bun.lockb`, `requirements*.txt`, `pyproject.toml` with `poetry.lock` or `uv.lock`, `Pipfile.lock`, `go.mod`/`go.sum`, `Cargo.lock`, `Gemfile.lock`, or `composer.lock`. Skip `node_modules`, `.venv`, `venv`, `dist`, `build`, `.git`, and worktree copies. A nested folder with its own lockfile (`dashboard/`, `worker/`, `api/`) is its own project; a monorepo with one root lockfile is one project.

For each project, read how it is meant to run:
- `wrangler.toml|jsonc|json`, or a `package.json` script running `wrangler deploy` / `wrangler pages deploy --project-name <name>` → Cloudflare Worker/Pages config (note the name). `fly.toml` → Fly.io config (read the `Dockerfile` `FROM` line). `vercel.json`, `netlify.toml`, `render.yaml`, `railway.json`, `Procfile` → hosted config. `Dockerfile` alone → container.
- Call these **"deploy config found"**. Upgrade one to **"live (confirmed)"** only when an already-installed, logged-in CLI shows it: `wrangler deployments list`, `fly status -a <app>`, `fly image show -a <app>`. Say which one each row is. Reading the running Node version inside a live machine (`fly ssh console -a <app> -C "node --version"`) beats the Dockerfile, and it opens a session on a production machine: offer it as a question, and run it only after the user's yes.
- A project folder that says it is retired, moved, or a backup (`MOVED.md`, `DEPRECATED`, README notes) gets reported as such, with a warning not to deploy from it.
- Services on this computer, when stack-guard's scope includes them: macOS `~/Library/LaunchAgents/*.plist` (ProgramArguments), Linux `systemctl --user list-units --type=service` and `crontab -l`. Check what listens: `lsof -nP -iTCP -sTCP:LISTEN`. `127.0.0.1` = this computer only. A tunnel config (`cloudflared` ingress, `ngrok`, `tailscale funnel`) pointing at a port = reachable from the internet. `0.0.0.0` = reachable from the local network at least; say "may be reachable" unless a tunnel or port-forward confirms it.
- Windows: best effort. Use PowerShell equivalents when Bash is unavailable (`Get-ScheduledTask`, `Get-NetTCPConnection -State Listen`, `.venv\Scripts\python.exe`), and say in the report which checks were skipped.

## 2. Check packages

Give each check a three-minute deadline using your tool's command timeout (in Claude Code, the Bash tool's `timeout` parameter, 180000 ms); when the tool cannot enforce one, watch the process and stop it after three minutes (macOS has no `timeout` command). A check past the deadline is reported as not checked. Audit commands exit with a non-zero code when they find vulnerabilities: that is a finding, so read the JSON they printed; only a missing or unparseable JSON means "not checked".

- **npm**: `npm audit --omit=dev --json` (packages marked for production) and `npm audit --json` (everything). If npm crashes with an internal error such as `Cannot read properties of null (reading 'edgesOut')`, use the pinned newer npm: `npx -y npm@11.6.2 audit --omit=dev --json` (an exact old version: the npm registry never lets a published version be replaced, so this one cannot be swapped by an attacker).
- **pnpm**: `pnpm audit --prod --json`. **yarn berry**: `yarn npm audit --environment production --json`. **yarn classic**: `yarn audit --groups dependencies --json`. **bun**: `bun audit` when the installed bun has it; otherwise report "not checked".
- **Python**: no install needed. Get the package list from what actually runs: the interpreter in the service file or the project's `.venv` (`<python> -m pip list --format=json`), or the lockfile (`poetry.lock`, `uv.lock`, `Pipfile.lock`, pinned `requirements.txt`) when nothing runs locally. Send the names and versions to OSV in one request: POST `https://api.osv.dev/v1/querybatch` with `{"queries":[{"package":{"ecosystem":"PyPI","name":"<name>"},"version":"<version>"}, ...]}` (up to 1000 per request), then GET `https://api.osv.dev/v1/vulns/<id>` for each hit's summary, severity, and fixed versions.
- **Go / Rust / Ruby / PHP**: read exact versions from `go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, and query OSV the same way with ecosystems `Go`, `crates.io`, `RubyGems`, `Packagist`. Maven/Gradle/NuGet without a lockfile: report "not checked".

## 2b. Check MCP servers and other auto-updating tools (always, every run)

AI builders often run MCP servers that fetch themselves fresh on every start, which turns a hijacked release into an instant compromise. Get the MCP server list WITHOUT opening the config files (they hold tokens in their `env` and `headers` blocks): run `python3 <plugin>/scripts/stack_guard.py inventory "<folder>"` and read the MCP section of `STACK-INVENTORY.md`; the script reads `.mcp.json`, `~/.claude.json`, the Claude Desktop config and `.cursor/mcp.json` and keeps names, commands and package names only, redacting anything that looks like a secret. Without Python, use a one-liner that prints names and commands only, eg. `node -e 'const c=require(process.argv[1]);for(const[n,s]of Object.entries(c.mcpServers||{}))console.log(n,s.command||"(remote)")' <file>`, and never `cat` or Read the file itself. For each server whose command is `npx`, `bunx`, `uvx`, or `pipx run`:
- no version, or `@latest` → flag "auto-updates on every start; pin it to a version you trust". Suggest the version the user has already been running (look in `~/.npm/_npx/*/node_modules/<package>/package.json`, or `uv cache dir` for uvx), after checking that version on OSV and against the news scout's findings. Never suggest "whatever the registry has now": during an attack that may be the hijacked release. When no earlier version is found, say so and ask the user to choose one from the project's own release notes;
- a pinned version → check that package and version on OSV like any other package.
Remote MCP servers (a `url`) are out of scope for packages; list them under "Not checked".

## 3. Check runtimes

For each Node and Python version found (local, each venv, each Dockerfile `FROM`, each confirmed live machine): fetch `https://endoflife.date/api/nodejs.json` and `https://endoflife.date/api/python.json`.
- Cycle past its `eol` date → **unsupported** (serious: no more security fixes).
- Behind the `latest` patch of its cycle → **update available**. Call it a security fix only when the release notes say so (nodejs.org/en/blog/vulnerability, the python.org release page).

## 3b. Check the news (always, every run)

After the package checks, do the news check. In Claude Code, hand the packaged `stack-news-scout` agent the list of components with versions: runtimes, frameworks, hosts, MCP SDKs, and each project's direct production packages (not the whole tree). Include only names that are public: drop packages under a private scope or registry (a scope set in `.npmrc` with its own registry, `"private": true` workspace packages, or a name `npm view <name> name` cannot find on the public registry). It returns what this fortnight's security news means for these exact versions. Fold "Affects you" into the findings and "Check needed" into "Not checked". In Codex (or any tool without that agent), do the web research yourself by the same rules; with no web access, list the news check under "Not checked".

## 4. Read the results like an expert

- **Production vs build-only.** `--omit=dev` follows how packages are labelled: a good first cut, not proof. A server's runtime package is serious; a bundler or test tool matters far less. For a static site or bundled Worker, search the built output for the package (`grep -rl <package> dist/ build/ out/ .output/`) and report "not found in the built files" as supporting evidence.
- **Most exposed first.** Live internet-facing beats deploy-config-only beats this-computer-only.
- **Fixable without breaking.** For each finding: fixed version, and same major (safe) or major jump (the user decides).
- **Known-bad releases.** Check lockfiles and Python environments for packages and versions named in this week's supply-chain alerts (from the news scout). In Python `site-packages`, list `.pth` files and any `sitecustomize.py`; flag unfamiliar ones for a look rather than calling them malware.

## 5. Report

```
STACK GUARD REPORT — <date>
Checked: <N> projects · <N> live (confirmed) · <N> deploy configs · <N> packages · <N> MCP servers · runtimes: <list>

🔴 Fix now (internet-facing)
- <project> (<live confirmed | deploy config found>): <N> critical / <N> high in production packages. Worst: <package> <version> → fixed in <version> (<same major | major jump>). <one plain sentence on what the hole allows>.

📰 In the news (last 14 days)
- <component>: <one sentence>. You run <version> → <affects you, fixed in X | already safe>. Source: <url>

🟠 On this computer only
- ...
- MCP server <name> runs `npx -y <package>` with no version: it updates itself on every start. Pin it: `npx -y <package>@<version>`.

🟡 Runtimes
- Node 20 on <app>: unsupported since 30 Apr 2026 → move to 22.
- Python 3.14.7: update available (3.14.9, a security release).

🟢 Clean
- ...

Not checked (and why): ...
```

Keep secrets out of everything: never print tokens, keys, `.env` contents, or URLs carrying credentials; when a command's output contains one, summarise it instead of quoting it.
