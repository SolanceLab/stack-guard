---
name: stack-fix
description: Apply the safe package fixes that stack-audit found inside a project (same-major upgrades, install scripts off), prove tests and build still pass, put everything back if anything breaks, and stop before deploys, commits, runtime upgrades or service restarts. Use only after the user said yes to fixing.
---

# Stack fix (after the user's yes)

**Secrets (applies to every step):** never print, quote, paste or summarise the value of a token, key, password, webhook URL or credential, not even when a tool's output shows one and not even back to the user; a secret that reaches the chat is stored in the session history. Never open files that hold secrets: `.env`, `.env.*`, `~/.claude.json`, `claude_desktop_config.json`, `.mcp.json` `env`/`headers` blocks, `.npmrc`, `.pypirc`, `secrets.yaml` (Home Assistant), `*.pem`, `*.key`, `credentials*`, `.dev.vars`, `wrangler` secrets. Read MCP servers only through the script (`stack_guard.py inventory`, which redacts) or a one-liner that prints names and commands only. When a secret appears anyway, do not repeat it: tell the user which kind of secret and where it showed up, and recommend rotating it only when a literal value was hidden (a line that only reads a key from the environment, such as `process.env.X`, is not a leak).

Goal: close the holes without breaking anything, and leave a clear trail. The user's yes covers **package updates inside the named projects**. Runtime upgrades, service restarts, deploys, commits and pushes each need their own yes; offer them at the end with the exact command.

## Before touching a project

0. **Whose code is it?** Tests and builds execute the project's own scripts. For the user's own projects that is normal. For a project they did not write (a cloned repo, a template, a download: check `git remote -v` and the README), ask before running anything in it, and skip it without a yes.
1. **Clean start.** `git status --short` must be empty, not counting `.stack-guard/` and a `STACK-INVENTORY.md` that stack-guard made (ignore those two lines when reading it). When it shows other changes, skip the project and say why ("has unsaved work, left alone so nothing of yours gets mixed in"). Not a git repo → work on a copy instead: copy the project (without `node_modules`/`.venv`) to a scratch folder, fix there, and hand the user the changed files.
2. **Backup.** Copy every lockfile and manifest you may change (`package.json`, the lockfile, `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`) to a scratch folder.
3. **Baseline.** Record the audit numbers, the test result (passing count), and whether the build passes. Use the plain compile step when the `build` script also fetches data, rewrites content, or deploys (eg. `./node_modules/.bin/vite build`, `./node_modules/.bin/tsc --noEmit`). A project whose tests or build already fail gets reported, not fixed.

## Fix, safest first, install scripts off

**Release age first (every ecosystem).** Before applying any fixed version, run `python3 <plugin>/scripts/stack_guard.py release-age <npm|PyPI> <name> <fixed version> --folder "<project>"`.
- Exit 0 (OK): apply exactly that version and no other. Every command below installs the checked `<fixed version>` pinned (exact version, no caret range, no "latest"); a command that cannot pin it (`npm audit fix`, `bun update`, a bare `uv lock --upgrade-package`) may pick a newer release that was never age-checked, so run it only when `release-age` also passes for each version it then installed (read them from the lockfile diff), and otherwise restore the backup and use the pinned form.
- Exit 3 (TOO NEW): leave that package alone and report "fix released <H> hours ago; run again after <time>". Take the brand-new version only when the user explicitly said to take brand-new versions now, and then state the risk in one line (a hijacked release is usually pulled within a day or two).
- Exit 2 (not proven): leave that package alone and report the printed reason as not proven old enough.

- **npm**: `npm install <pkg>@<fixed> --save-exact --ignore-scripts` for each checked package (or `npm audit fix --ignore-scripts` with the lockfile-diff re-check above; no `--force`, no `--legacy-peer-deps`). If npm crashes with an internal error, use `npx -y npm@11.6.2 audit fix --ignore-scripts`. For a finding that remains whose fix is the same major, set that direct dependency to the exact checked patched version (eg. `"vite": "7.3.7"`) and run `npm install --ignore-scripts`. When tests then fail because a native package was not built (eg. `sharp`, `better-sqlite3`, `bcrypt`), run `npm rebuild <that package>` for that one named package only, and name it in the report: rebuilding runs that package's own build script.
- **pnpm**: `pnpm update <pkg>@<fixed> --ignore-scripts` (same major). **yarn berry**: `yarn up <pkg>@<fixed>` with `enableScripts: false` for the run (`YARN_ENABLE_SCRIPTS=false`). **yarn classic**: `yarn upgrade <pkg>@<fixed> --ignore-scripts`. **bun**: `bun add <pkg>@<fixed> --exact --ignore-scripts`, then confirm the version.
- **Python**: install from ready-made wheels only, so no freshly downloaded build code runs. With a lockfile, use its tool so the lock stays the truth: `uv lock --upgrade-package <pkg>`, then check the locked version equals `<fixed>` (when it is newer, run `release-age` on it too, or pin `<pkg>==<fixed>` in `pyproject.toml` first), then `uv sync --no-build`; Poetry and pipenv projects are **report-only**: give the exact command (`poetry update <pkg>` / `pipenv update <pkg>`), say that it may build the package from source, and ask before running it. With `requirements.txt`: set `<pkg>==<fixed>` in the file, keeping any upper bound, then `<venv python> -m pip install --only-binary=:all: -r requirements.txt`. A bare venv: `<venv python> -m pip install --only-binary=:all: "<pkg>==<fixed>"`, after saving `pip freeze` to scratch. When a package has no wheel for this computer, leave it and report it.
- **Major-version jump needed** → leave it; report what the jump would change and let the user decide.
- **Runtime or system packages** (Node/Python version, `brew`/`apt` packages, Docker base image): do not change them under this yes. Report the exact command (eg. `brew upgrade python@3.14`, `nvm install 22`, Dockerfile `FROM node:22-slim`) and ask separately.

## Prove it still works

After the fix, compare with the baseline:
1. Audit again: production high/critical down to 0 or the documented leftovers.
2. Tests: the same count passes. Build: passes.
3. Website: serve the built output locally with the project's own installed command (eg. `./node_modules/.bin/vite preview --port <free port>`; use `npx` only for an executable already installed in the project, so nothing gets downloaded), open the main routes with a browser tool when available, confirm each page shows its heading and the console has no errors, then stop the server. Serve it the way it is deployed: a Cloudflare Worker with the project's own `wrangler dev` (OpenNext: build with its Cloudflare build script first), a Docker app by building and running its image, a Fly app by its Dockerfile. Tests and a plain build can pass while the deployed runtime fails (seen: Next.js 16.4.1 with an older OpenNext adapter). If the deploy runtime cannot run locally, say so in the report as 'not proven in the deploy runtime'.
4. MCP server (whenever an MCP SDK changed — required, because SDK upgrades have changed session handling before): start it locally, then send JSON-RPC `initialize` and `tools/list` (or connect with the SDK client). Confirm the tool list is unchanged and a request without credentials is still refused. Stop it afterwards.
5. Leftovers: for each unfixed finding, check the built output (`grep -rl <pkg> dist/`) and report the result as evidence.

## Check again for known malicious releases

After all fixes, run `python3 <plugin>/scripts/stack_guard.py check "<project>"` again. Any MALICIOUS finding means restore the backup from step 2, reinstall from the restored lockfile as described below, stop, and put it first in the hand-back with the line from stack-audit.

## When something breaks

Put it back exactly: restore the backed-up files from scratch over the changed ones (only those files), then reinstall from the restored lockfile with scripts off (`npm ci --ignore-scripts`, then `npm rebuild <pkg>` only for native packages that were built before; `pip install --only-binary=:all: -r`, `uv sync --no-build`), and delete any new untracked files you created (`git status --short` shows them). Confirm `git status --short` is empty again (or matches what it was), and report the failure with its error.

## Leave things as you found them

Stop every server, preview, and container you started; remove Docker images you built; delete scratch folders. Leave deliberate locks alone: a route that answers 404 or 401 on purpose (a paywall, an embargo, a login) is working, not broken.

## Hand back

Per project: packages changed (old → new), audit/tests/build before and after, leftovers and whether they appear in the built output, what needs a separate yes (runtime, service restart, major jump) with the exact command, and the deploy command from the project's own scripts. Commit only when the user asks ("Security update: <packages>"). After the user deploys, offer to check that the live site or service answers as before.
