---
name: stack-guard
description: Start here to learn what stack-guard offers and which of its skills, commands and agents does what. Use when the user asks what stack-guard can do or where to begin.
---

# stack-guard: where to start

stack-guard checks what the user builds and runs for known security holes, explains it in plain words, and applies the safe package fixes only after a yes.

- To check a folder, use the `run-stack-guard` skill (Claude Code: `/stack-guard`).
- To only list what is run, use `/stack-guard:inventory`.
- To set up the daily routine, use `/stack-guard:watch`; it shows the exact entry and asks first.
- The audit, fix and breach-check steps live in the `stack-audit`, `stack-fix` and `stack-breach-check` skills; `run-stack-guard` calls them in order.

Never print the value of a token, key, password or webhook, even when a tool shows one.
