# Help make it better

[← back to the README](../README.md)

Spotted a gap? A stack it misses, a check that's wrong, a fix that went sideways, a security story it should have caught? Please tell us.

- **Open an issue:** https://github.com/SolanceLab/stack-guard/issues. Say what you ran, what you expected, and what happened. Leave keys, tokens and private project names out.
- **Send a pull request:** everything lives in plain Markdown under `plugin/` (`commands/`, `skills/`, `agents/`). Keep the safety rules intact: the audit runs no freshly downloaded code, fixes stay same-major with install scripts off, and nothing deploys, commits, or touches the wider machine without the user's separate yes.
- **Found a security problem in stack-guard itself?** Please report it privately through GitHub's "Report a vulnerability" button on the Security tab, not in a public issue. Past fixes are listed in [SECURITY.md](SECURITY.md).
