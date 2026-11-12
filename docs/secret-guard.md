# Secret guard

[← back to the README](../README.md)

Your agents can still work with secrets: use them, rotate them, set them. During a stack-guard run, the guard only stops a secret's value from being printed into the chat.

Active only while stack-guard is working in a session (its commands, skills, agents, or the daily watch). Your other Claude Code work is untouched. Once you use stack-guard in a Claude Code session, the secret guard stays on for the rest of that session (a hook can see that stack-guard started, not reliably when it finished). Start a new session for work where you need the AI to open secret files.

Three layers:

1. **Stops before reading.** `Read`, `Grep` and shell commands (`cat`, `grep`, `head`, `sed`, `jq`, `python -c open(...)` and similar) that point at a secret file are blocked with a plain message: `.env` (but not `.env.example`), `.dev.vars`, `.npmrc`, `.netrc`, `.pgpass`, `secrets.*`, `*.pem`, `*.key`, SSH private keys, cloud credential files (`~/.aws/credentials`, gcloud, kube, docker), `~/.claude.json`, Codex `auth.json`. Bare `printenv` / `env` dumps and `security find-generic-password -w` printed to the screen are blocked too. Any shell command that names a secret file is blocked (so a Python, Ruby, Perl or Node one-liner that reads `.env` cannot slip past), unless it only uses the file without printing it: `export X=$(grep X .env)`, `source .env && npm test`, `cp`/`mv`/`rm`/`chmod`/`ls` on it, `sed -i`, writing to it (`>> .env`), or piping it into `wrangler secret put`, `gh secret set` or `security add-generic-password`. A secret file's content is never sent on by a network command (`curl`, `wget`, `nc`, `ssh`, `scp`, `rsync` and similar), and wildcards and brace forms that could match a secret file (`.e*`, `.env{,.local}`), nested `sh -c` / `bash -c`, environment dumps (`export -p`, `declare -p`) and content searches with the Grep tool that cover a whole folder are checked too (give them a file type or a single file; file-name and count searches are not affected). Recursive searches (`grep -r .`, `rg --hidden`, `find ... -exec cat`) are blocked too; use `rg PATTERN` (it skips ignored files like `.env`) or name the source folders. `curl -H "Authorization: $(security find-generic-password -s x -w)"` passes. A `$(...)` that feeds a printing command (`echo "$(cat .env)"`) is blocked, and so are `printenv API_TOKEN`, `echo "$API_TOKEN"` and copying a secret file to the screen.
2. **Redacts tool output.** After `Bash`, `Read` and `Grep` run, a PostToolUse hook scans the result for secret shapes and swaps each one for `[REDACTED ...]` before Claude sees it, then tells Claude to have you rotate (replace) the secret.
3. **Catches and warns after replying.** When Claude finishes, a Stop hook scans its last reply for secret shapes (GitHub, OpenAI/Anthropic, Slack, AWS and Google keys, JWTs, private keys, Discord bot tokens, passwords inside URLs). On a hit, Claude is told to say so in one line and to have you rotate (replace) the secret. The secret itself is never repeated.

It is a seatbelt, not a vault: it catches the common ways a secret gets printed, not every possible one. It cannot catch code that builds a file name in a way it cannot read, or a determined agent; for real protection turn on Claude Code's sandbox (`/sandbox`). To turn off all of it, or only the final-reply check, see [Settings](settings.md). To remove it entirely, run `/plugin disable stack-guard` or remove the plugin.

**Claude Code only;** in Codex, the written secrets rule in every stack-guard instruction applies.

Thanks to Aya ([@ayakohi](https://github.com/ayakohi)), whose question started it.
