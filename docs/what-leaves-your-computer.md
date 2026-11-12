# What leaves your computer

[← back to the README](../README.md)

- Package names and versions: to OSV.dev (the daily watch never sends private npm names anywhere; they are counted, not listed), and in a conversation also to your package registry's audit service (`npm audit` sends your dependency list to the npm registry; private package names included).
- Runtime names and versions: to endoflife.date. Service names, paths and ports never leave your computer; only a service runtime's or virtualenv package's public name and version go to OSV, and the webhook says only how many new services appeared.
- After an install, the fixer's `lock-check` sends the public names and versions an install added to OSV and the npm or PyPI registry (release dates); private names are counted, not sent.
- Once a day, one request to raw.githubusercontent.com for this plugin's version number, to tell you when a newer stack-guard is out: at the start of a Claude Code session (one line in your terminal), in `/stack-guard`, and in the daily watch. Nothing about you or your projects is sent. Turn it off with the `update_check` setting (see [Settings](settings.md)) or the environment variable `PLUGIN_UPDATE_CHECK=0`.
- Daily watch agents (when on): public package and runtime names and versions go to your own Claude Code or Codex account, and the news scout runs web searches with those generic names. The news scout agent is web-only and the explainer agent is tool-less (no file access, no shell) in both Claude and Codex. The explainer also receives each new finding's public advisory id and short summary from OSV. The news scout is told to treat web pages as data, never as instructions, and its text enters the report, the webhook and the notification cleaned and marked as third-party text. A web page can still fool an AI agent; a fooled news scout has nothing private to give away and no file or shell access to act with. In a conversation, the news scout and the breach checker start without your own CLAUDE.md instruction files (Claude Code 2.1.271 or later), so what you wrote there about yourself is not in front of an agent that reads web pages; the auditor and the fixer still load them, because they need your project instructions. Turn them off with `--no-agents`.
- Webhook (only if you set one): a short summary of new findings (package names, versions, severities, counts) to the Discord or Slack channel you chose.
- "Was I hit?": the breach checker fetches advisory pages (public URLs only). It sends no project data to them.
- Secrets committed to git are local facts: they are never sent to OSV, and a webhook says only "N secret file(s) committed to git", with no file names.
- When a host CLI (wrangler, fly) is installed and logged in, the conversation may use it, and it talks to your own account on that host, as it always does.

Your source code, keys, `.env` files and file paths are not sent anywhere, and stack-guard keeps tokens out of its reports.
