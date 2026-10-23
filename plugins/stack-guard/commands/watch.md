---
description: Set up (or remove) a daily stack-guard watch on this computer — the script checks everything you run every morning, a news scout agent reads the security news for your versions, and an explainer agent tells you only what is new
argument-hint: '[folder, default: this folder] [--time HH:MM, default 09:00] [--no-agents] [--off]'
---

You are setting up the user's daily stack-guard watch. Arguments: $ARGUMENTS

The daily routine is the plugin's script, run by the computer's own scheduler. Each morning it lists everything, checks every package and runtime against OSV.dev and endoflife.date, then (unless `--no-agents`) hands public package names and versions to two locked-down agents using the user's own Claude Code or Codex: a **news scout** (web tools only) and an **explainer** (no tools). It saves a report, compares it with yesterday, and notifies the user only of what is new. It never fixes anything; fixing stays a conversation with `/stack-guard`.

Script path: `"${CLAUDE_PLUGIN_ROOT}/scripts/stack_guard.py"`. Folder: the named one, else the current folder.

## With `--off`

Run `python3 <script> watch-remove "<folder>"` and `python3 <script> webhook-remove "<folder>"` (the second only if the user wants the webhook gone too). Tell them the reports stay in `<folder>/.stack-guard/reports/`. Stop.

## Setting it up

1. **First check, now.** Run `python3 <script> check "<folder>"` (add `--agents` unless the user passed `--no-agents`) so there is a baseline and the user sees today's state. Summarise the report in plain words.
2. **Optional Discord or Slack.** Ask once: "Also send the daily summary to a Discord or Slack channel? (yes / no)". On yes, ask them to create a channel webhook, then run `python3 <script> webhook-set "<folder>"` and let them paste the URL into its prompt (it reads from the keyboard, stores it outside the project with owner-only access, and accepts only Discord/Slack webhook URLs). Never repeat the URL back.
3. **Show the schedule entry.** Run `python3 <script> watch-install "<folder>" --time <HH:MM>` (default 09:00; add `--no-agents` when the user passed it) without `--yes`. It prints the exact launchd / cron / Task Scheduler entry and which agent CLI it found. Show the user that entry and say: the agents use their own Claude/Codex plan, a few cents of usage a day; `--no-agents` turns them off.
4. **Ask:** "Add this daily check at <time>? (yes / no)". Install nothing before the yes.
5. **Install** after the yes: the same command with `--yes` (and `--no-agents` if used).
6. **Where things live.** The schedule runs a copy of the script kept at `~/.config/stack-guard/bin/stack_guard.py` (Windows `%APPDATA%\stack-guard\bin\`), so plugin updates cannot break it silently; each run writes a log to `~/.config/stack-guard/logs/` (the exact file is printed at install). After updating stack-guard, run `/stack-guard:watch` again so the copy is refreshed. Tell the user both.
7. **Prove it.** Run the scheduled command once now exactly as printed in the entry (it includes `check --notify`, plus `--agents` unless turned off), confirm a new report appears in `<folder>/.stack-guard/reports/` and (macOS and Linux) the desktop notification shows. On Windows there is no desktop pop-up: confirm the report file (and the webhook message, if one is set) instead. Tell the user how to stop it: `/stack-guard:watch --off`.

## Codex users

Same script, same commands, run from Codex (`python3 <plugin folder>/scripts/stack_guard.py …`; the plugin folder is listed by `codex plugin list --json`). `watch-install` detects the `codex` CLI for the agents when `claude` is absent.
