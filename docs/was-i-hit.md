# Was I hit?

[← back to the README](../README.md)

The checker agent has no shell: it can only read files, search and open public advisory pages, so it cannot change or send anything. The few commands it needs (lockfile history, running process names) run in your main session, where you see them.

Fixing a hole does not tell you whether someone used it before you fixed it. After the audit, on every run (`--audit-only` too, since it changes nothing), stack-guard asks, for each high or critical finding in a project that has a deploy config and for each supply-chain story in the news:

1. **Reachable?** It reads the advisory and writes down what an attacker needs (a feature, a route, a version range), then searches your project for it. Not reachable means the precondition is absent, and it says where it looked.
2. **Window.** From the advisory's date to the day the fix was installed (from the lockfile's git history), or to today.
3. **Traffic.** Whether logs exist for that window, and where to look: Cloudflare Workers Logs, `fly logs`, `vercel logs`, the Supabase logs explorer. It reports counts and request paths, never log contents that hold personal data.
4. **Traces.** When the advisory lists indicators (file names, paths, processes, domains), it checks this computer and the project for them, read-only.

Each finding ends in one verdict: `not reachable`, `reachable, no signs found`, `reachable, cannot tell (no logs)` or `signs found`. For the last two on a hole that runs code or reads files, it names the secrets the app can reach (names only) and tells you to rotate them.

**What it cannot prove.** Without logs it cannot tell: "no signs found" means nothing it could check showed abuse, not that none happened. A host keeps no history unless you turned it on. For a Cloudflare Worker, add `[observability] enabled = true` to `wrangler.toml` (or `"observability": {"enabled": true}` in `wrangler.jsonc`) and deploy; Workers Logs then keep requests for the next time. Fly keeps only recent minutes with `fly logs`; ship them to a log service if you want history.

The daily watch does not run these checks (no agent works unattended). It adds one line to its report when there are new high or critical live findings: "Run /stack-guard to check whether these were used against you."
