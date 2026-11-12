# Updating stack-guard

[← back to the README](../README.md)

**Turn on auto-update once (Claude Code):** `/plugin` → **Marketplaces** tab → **solancelab** → **Enable auto-update**. Claude Code then installs new versions by itself a few minutes into a session and shows "Plugin updated: stack-guard · Run /reload-plugins to apply". (It is off by default for every marketplace that is not Anthropic's own.)

Or update by hand:

Already installed an earlier version? Update, then restart your tool:

- Claude Code (terminal): `claude plugin marketplace update solancelab` then `claude plugin update stack-guard@solancelab`
- Codex: `codex plugin marketplace upgrade solancelab` then `codex plugin add stack-guard@solancelab`

Using the daily watch? Run `/stack-guard:watch` once more after updating: the morning routine runs its own copy of the script (in `~/.config/stack-guard/bin/`, so an update can never break it silently), and this refreshes that copy. Each morning's run is logged in `~/.config/stack-guard/logs/`. Set the watch up before 1.8.1? Running `/stack-guard:watch` once more also makes it catch up after a missed morning (Mac and Linux).
