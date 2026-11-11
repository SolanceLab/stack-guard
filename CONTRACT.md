# stack-guard contract

## Doors it offers

| Door | What it answers |
|---|---|
| `/stack-guard` (Codex: `$stack-guard:run-stack-guard`) | A plain-words security report for the folder, and safe fixes after a yes |
| `/stack-guard:inventory` | `STACK-INVENTORY.md`: what the user builds and runs |
| `/stack-guard:watch` | A daily routine on the user's own computer, set up after a yes |
| `plugin/scripts/stack_guard.py` | The same checks from a terminal: `inventory`, `check`, `lock-check`, `release-age`, `version-check` |
| Hooks | Secret guard, daily update check (each can be switched off) |

## Data it owns

| Table / bucket / file | What is in it |
|---|---|
| `.stack-guard/` in the scanned folder | Dated reports and the inventory copy; ignores itself in git |
| `STACK-INVENTORY.md` | The plain list written by the inventory command |
| `~/.config/stack-guard/` | The daily routine's own copy of the script, its settings and the time of its last run |
| `plugins/stack-guard/.claude-plugin/plugin.json` | A version-only file kept for copies installed before 1.7.0, which look for updates at that path. Update it with every release |

## Settings and secrets it needs

Named here, never valued. stack-guard needs no key and holds none.

| Name | What it is |
|---|---|
| `secret_guard`, `reply_check`, `update_check` | Switches, on by default |
| `min_release_hours` | How long a fixed version must be public before the fixer installs it (48) |
