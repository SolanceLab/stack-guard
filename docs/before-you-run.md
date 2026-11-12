# Before you run it

[← back to the README](../README.md)

Best practice for **any** plugin, this one included, even from people you trust: a plugin is instructions that run commands on your computer.

1. **Read it.** stack-guard is instructions in plain Markdown plus **one small Python script** (`scripts/stack_guard.py`, standard library only, no installs) — the secret-guard hooks (see [Secret guard](secret-guard.md)) and one small update check at session start, no MCP servers. After installing, see what it adds with `claude plugin details stack-guard`, and read the files in `~/.claude/plugins/cache/stack-guard/`.
2. **Commit or back up your project first**, so any change is easy to undo.
3. **Look before you fix.** Start with `/stack-guard --audit-only`: it reports and changes none of your code or packages.
4. **Turn on Claude Code's sandbox** (macOS, Linux, WSL2): type `/sandbox`. Commands can then only write inside your project folder, and every new website needs your OK. When asked, allow `registry.npmjs.org`, `api.osv.dev`, `endoflife.date`, `raw.githubusercontent.com` and `pypi.org`. The sandbox covers the commands Claude runs; Claude's own file edits still follow your normal permission prompts. Docs: https://code.claude.com/docs/en/sandboxing
5. **Strongest:** run Claude Code inside a dev container or a virtual machine, with no SSH keys or cloud credentials mounted. Docs: https://code.claude.com/docs/en/devcontainer
