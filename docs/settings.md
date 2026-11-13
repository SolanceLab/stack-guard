# Settings

[← back to the README](../README.md)

Four settings (three switches, all on by default, and the fix release age of 48 hours). Change them when you install (`/plugin`), later with `/plugin configure stack-guard@solancelab` or `/config`, or from a terminal install: `claude plugin install stack-guard@solancelab --config reply_check=false`.

| Setting | What turning it off means |
| --- | --- |
| `secret_guard` ("Secret guard") | Both secret-guard hooks stop before they read anything. Nothing is redacted and the final reply is not checked. |
| `reply_check` ("Final-reply check") | Only the Stop hook stops. It is the one that reads the session's history on this computer (nothing leaves the computer) to check each reply for secret shapes. The output filter keeps working. |
| `update_check` ("Update check") | No daily request to GitHub for the version number: not at session start, not in `/stack-guard`, not in the daily watch. `version-check` says "Update check is turned off." |

| `min_release_hours` ("Fix release age (hours)") | How long a fixed version must have been public before the fixer installs it (default 48). `0` takes new versions at once. `stack_guard.py release-age <npm\|PyPI> <name> <version>` shows the verdict; it asks the registry for public package names only. |

`PLUGIN_UPDATE_CHECK=0` still turns the update check off too.

Upgrading to 1.8.0: it removes the old outgoing-request check. Its two settings no longer do anything and can be deleted, and so can the identifiers file you made for it (`~/.config/stack-guard/identifiers.txt`, on Windows `%APPDATA%\stack-guard\identifiers.txt`). The plugin never deletes your files.
