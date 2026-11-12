# How it works, in depth

[← back to the README](../README.md)

- **The script** (`scripts/stack_guard.py`, Python standard library only) does the exact, repeatable part. It reads these lockfiles: npm `package-lock.json` (v2/v3), pinned `requirements*.txt`, `Pipfile.lock`, and `poetry.lock` / `uv.lock` on Python 3.11+. pnpm, Yarn, Bun, Go, Rust, Ruby and PHP projects are listed by the daily watch but package-checked only in a `/stack-guard` conversation. It lists every project, deploy config, runtime and MCP server, checks every package against [OSV.dev](https://osv.dev) and every runtime against [endoflife.date](https://endoflife.date), and compares with the last run. Same result every time, free to run every day.
- **The agents** do the judgment: the news scout (web search only), the explainer (no tools), and in a conversation, the auditor and the fixer. They only get public package names and versions. The news scout is told to treat web pages as data, never as instructions. In the daily watch it holds nothing private and has no file or shell access, and what it writes is shown in the report as quoted third-party text. A web page can still fool an AI agent: this limits what a fooled agent can do, it does not make one impossible to fool.
- With no Python, the agents do everything by hand from the same instructions.
