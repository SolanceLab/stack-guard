# Secret guard

[← back to the README](../README.md)

Your agents can still work with secrets: use them, rotate them, set them. During a stack-guard run, the guard only stops a secret's value from being printed into the chat.

Active only while stack-guard is working in a session (its commands, skills, agents, or the daily watch). Your other Claude Code work is untouched. Once you use stack-guard in a Claude Code session, the secret guard stays on for the rest of that session (a hook can see that stack-guard started, not reliably when it finished). Start a new session for work where you need the AI to see a secret's value.

Two layers:

1. **Redacts tool output.** After `Bash`, `Read` and `Grep` run, a PostToolUse hook scans the result for secret shapes and swaps each one for `[REDACTED ...]` before Claude sees it, then tells Claude to have you rotate (replace) the secret. Only the output of calls that succeed is checked; a failed call's error text is not.
2. **Catches and warns after replying.** When Claude finishes, a Stop hook scans its last reply for secret shapes (GitHub, OpenAI/Anthropic, Slack, AWS and Google keys, JWTs, private keys, Discord bot tokens, passwords inside URLs). On a hit, Claude is told to say so in one line and to have you rotate (replace) the secret. The secret itself is never repeated.

It does not block commands. Earlier versions did, by guessing from the words in a command, and that stopped ordinary work. To keep Claude Code's Read tool away from secret files, use its own permission deny rules (see [Settings in the README](../README.md#settings)). They cover the Read tool only; a shell command such as cat or grep can still open the file.

It is a seatbelt, not a vault: it catches secret values whose shape it knows, not every possible one. To turn off all of it, or only the final-reply check, see [Settings](settings.md). To remove it entirely, run `/plugin disable stack-guard` or remove the plugin.

**Claude Code only;** in Codex, the written secrets rule in every stack-guard instruction applies.

Thanks to Aya ([@ayakohi](https://github.com/ayakohi)), whose question started it.
