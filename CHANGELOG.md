# Changelog

## 1.7.2

- The egress guard now checks only what leaves the computer: URLs, outgoing flag values, remote-shell arguments, and uploaded files.
- Purely local commands, inline interpreters, and local paths no longer cause false blocks.
- Names and emails in outgoing data are still blocked, and uploaded or copied-out files are still read and checked.
- Claude Code's sandbox is the wall for Bash as a whole.

## 1.7.1

- Fixed: a `.mcp.json` key that says it names an environment variable (`bearer_token_env_var`, `tokenEnvVar`) and holds a variable name such as `MY_SERVICE_TOKEN` is no longer reported as a committed secret. A literal token, an all-caps or hex key, or grouped key under such a name is still reported.

## 1.7.0

- Changed: from this version stack-guard is released under the PolyForm Noncommercial License 1.0.0 (free for noncommercial use, credit required, commercial use needs permission). Versions up to 1.6.3 were released under the MIT licence and stay under it. The MIT notice and permission text for them stays in NOTICE.md.
- Changed: the plugin now lives in the `plugin/` folder of the repository. Installing and updating work the same way (`/plugin install stack-guard@stack-guard`); copies installed before 1.7.0 still hear about updates.
- New: a `stack-guard` skill that says where to start, a contract file, a `make test` command, a secret scan on every push, and weekly dependency updates for the repository's own workflows.
- Every source file's first line now names the project and its licence.

## 1.6.3

- New: background services on this computer are listed and security-checked. macOS launchd, Linux user systemd and cron, and Windows scheduled tasks are read (names and paths only, never a service's arguments or settings), together with what listens on which port. The inventory has two new sections, `Services on this computer` and `Listening ports`; the check report has a `Services` section and a new-services line in "New since last check".
- Each service is checked five ways: its program's version (only a known runtime is ever run, and only for `--version`), the packages in its virtualenv, how far it is reachable (this computer only, the local network, or the internet through a cloudflared tunnel), whether someone else could change its files, and whether its program is somewhere unrecognised. A broken virtualenv (its Python was removed in a Homebrew upgrade) and a missing program are flagged.
- A cloudflared service's tunnel is found from its `--config <file>` or `tunnel --url http://localhost:PORT` arguments too (launchd, systemd and Windows scheduled tasks; ports only, a relative config path is joined to the service's working directory, else it is listed as not checked). Postgres is now checked against its support dates; cloudflared and ollama services are looked up for known holes.
- Safety of the service check itself: a program is asked for its version only when its real file (shortcuts followed) sits in an Apple system folder or a Homebrew Cellar/opt folder and nobody else can change it or any folder above it; stack-guard then runs exactly that checked file, never the shortcut. Otherwise the version is read from the Homebrew folder name or the virtualenv's `pyvenv.cfg`, without running anything. A file or folder writable by a group counts as "can be changed by someone else" unless every member of that group is you or the system (so `/Applications` and Homebrew's `admin` folders on a one-person Mac stay quiet, and a shared group is flagged).
- New command `lock-check <before> <after>`: after an install, every added or changed lockfile version gets the release-age and known-malware check (exit 0 clean, 3 too new, 4 malicious, 2 not proven). The fixer runs it after every install step.
- Hardening found by security review before release: cron lines and scheduled tasks drop inline `NAME=value` words and the launcher command before choosing the program, so a token set there never shows; a service's virtualenv packages are not looked up when they may be private (a URL/git/path install, its own pip.conf, or a project with a private index); `lock-check` uses a package-lock entry's real name, and treats a tarball filed under another name, a source that changed at the same version, an unreadable requirements line, a failed malware lookup, and any Python name without `--folder` as not proven (exit 2).
- A service's virtualenv sends its package names to a public lookup only when it sits inside a scanned project that is proven public (no private index of its own or above it, none set for the whole computer). Any other venv sends nothing; the report says how many packages were not looked up and tells you to scan that folder.
- Secret guard: it now passes ordinary searches, awk/sed on named files, globs inside `-c` strings, piped greps and heredocs written to files; it newly blocks folder names hidden in variables and file names built with `chr()`. Reads of secret files, brace tricks and `-f`/`--file` pattern files stay blocked; an awk/sed program that runs a command (`system()`, a pipe, `getline`, sed `e`) is still checked as code, and when the guard is unsure it still blocks. A file name built while a command runs cannot be seen (see Known limits in SECURITY.md).
- The fixer lists other `package.json` and `requirements*.txt` files that declare a package it just pinned ("same bump needed here"), without editing them.

## 1.6.2

- Daily watch: the script copy refreshes itself only from your own plugin folders (owned by you, not writable by others), never from a scanned project or any other place.

## 1.6.1

- Secret guard: fixed three ways a command could get past it (found by automatic review). Details are in [SECURITY.md](SECURITY.md).
- Daily watch: the schedule names a Python that survives package-manager upgrades, and each run logs a clear line and stops when that Python or the script copy is missing.
- Daily watch: the script copy refreshes itself when the installed plugin has a newer version.
- A folder deeper than the depth limit is now listed under "Not checked" with how to scan it; `check` and `inventory` accept `--depth N` (default unchanged).
- Egress guard: the home-folder name is no longer counted inside Claude Code's own folder names (`-Users-<name>-…`) when they appear in a local part of a shell command, so reading your own session files is not a false alarm. In anything outgoing (web addresses, sent data, MCP messages, uploaded files) it still counts, and names and emails always count.
- New: [SECURITY.md](SECURITY.md) lists every security fix by version and says how to report one privately.

## 1.6.0

- New: the egress guard. It runs in every session, not only during a stack-guard run, and stops any outgoing request (web fetches, searches, network commands, MCP sends) that carries your name or email, including encoded forms: the defence against websites that ask your agent to identify you. Add your identifiers to `~/.config/stack-guard/identifiers.txt` (on Windows `%APPDATA%\stack-guard\identifiers.txt`); turn it off with the `egress_guard` setting. With no identifiers listed it does nothing, and says so once at session start.
- New setting `egress_exempt_servers`: comma-separated MCP server names the egress guard never checks (none by default).
- Prompted by a community discussion of agents leaking user details in request headers.

## 1.5.7

- The release-age check looks up a Python package only when it is one of the scanned project's own packages from a public index; with no project folder it answers "not proven" and nothing leaves the computer.

## 1.5.6

- Fixes wait until a fixed version has been public for 48 hours (adjustable), because hijacked releases are usually caught and pulled within that time; the fixer says when to run again.
- Known malicious releases (OSV `MAL-` records) are flagged as MALICIOUS and shown first, instead of as unknown severity.
- After fixing, stack-guard checks the project again and undoes the fix if a known malicious release came in.

## 1.5.5

- Secret guard hardening: catches more ways of reading or sending a secret file (including wildcard and brace forms) and environment dumps; whole-folder content searches need a file type or a single file while stack-guard is in use.
- Python packages stay on your computer when a private package index is set for your whole computer, in the environment or in your pip/uv/Poetry settings.
- Files and folders that point outside the scanned folder are not read.
- Secret guard: a secret may be piped only into a trusted command named bare, in its exact form, as the last step. A content search narrowed by a file pattern or type is checked against the real files under the search folder.
- More private-index settings count: a project `uv.toml` or `poetry.toml`, and the Windows, virtualenv and Poetry config locations. An empty `PIP_NO_INDEX` counts as set.
- The committed-secrets check skips the public certificate bundle `cacert.pem` (vendored folders such as `.venv` and `node_modules` are still checked).
- Windows: folder junctions are treated like links, and tests skip with a stated reason where a symlink or POSIX feature is missing.
- The secret guard no longer treats code that reads a key from the environment as a leaked key, and process listings show names only while stack-guard is running.
- Marta S. — reporter
- Cassian Varen — technical contributor/co-author

## 1.5.4

- Settings: turn off the secret guard, only its final-reply check, or the update check, when you install or later with `/plugin configure stack-guard@stack-guard`. When off, that hook stops before reading anything and nothing is fetched. Prompted by Ajax Vale's review, with Shaz ([@ajxvale](https://github.com/ajxvale)), together with the Windows fix in 1.5.3.

## 1.5.3

- Windows: the hooks and the daily watch use `python` there, as the script already did. `python3` on Windows is often a Microsoft Store shortcut or a different Python. Reported by Ajax Vale, with Shaz ([@ajxvale](https://github.com/ajxvale)).

## 1.5.2

- Reading git history of a scanned repo never fetches anything or runs anything from that repo: network protocols, credential helpers and prompts are switched off, and a partial clone is skipped with a "Not checked" line instead of being fetched.
- Every secret-file read checks the size first (the committed copy as well as old revisions), so a huge file is never opened.
- The YAML key scan is faster on crafted files.

## 1.5.1

- The "Was I hit?" checker no longer has a shell: it can only read, search and open advisory pages, so "read-only" is enforced rather than asked for. The two commands it needs run in your main session, where you see them.
- Reading git history of a scanned repo can never start a program from that repo's own git settings (signature, pager, external diff and ssh programs are overridden; file contents are read with text converters off).
- File names from a scanned repo are cleaned (no backticks, line breaks or control characters) before they reach the report.
- Old revisions of a secret file are size-checked before they are read, and the YAML key pattern no longer spans lines, so a crafted file stays fast.

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
