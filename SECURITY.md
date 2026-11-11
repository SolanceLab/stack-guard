# Security

## Report a problem privately

Use GitHub's private vulnerability reporting: open the Security tab of this repository and choose "Report a vulnerability". Please do not open a public issue for a security problem. You will get a reply in plain words, and a fix goes out before the details are made public.

## Security fixes

Every security fix, by version, in plain words.

- **1.6.3** - A fixer install can no longer slip in a too-new or known-malicious version unnoticed: `lock-check` checks every version a lockfile gained and fails closed when it cannot prove a release is old enough. Background services are now listed and checked, including those reachable from the internet through a tunnel.
- **1.6.2** - The daily watch's self-refresh accepts a newer script only from your own plugin folders, with every folder up to your home folder yours and not writable by others (on Windows the location is checked, not file permissions). Found by automatic review.
- **1.6.1** - Three ways a shell command could get past the secret guard were closed. Found by automatic review.
- **1.5.7** - Release-age lookups for Python packages now fail closed: when the check cannot prove a release is old enough, it says so and does not allow the fix. Found by automatic review.
- **1.5.6** - Fixes wait until a fixed version has been public for a safe time, and known malicious releases are shown first.
- **1.5.5** - Secret-guard bypasses were closed, private package names no longer go to the public vulnerability database (OSV), and symlinked inputs are no longer followed outside the scanned folder. Reported privately by Marta S. with Cassian Varen. Advisory: GHSA-fxh7-86f2-jmfp.
- **1.5.1 and 1.5.2** - A hostile git configuration in a scanned folder could start a program. Found by automatic review.

## Known limits

- The secret guard reads the text of a shell command. A file name built while the command runs (for example from `printf` or another program's output) cannot be seen, so the guard is not the only wall: Claude Code's sandbox (`/sandbox`) and file permissions are the others.
- A web page, search result or advisory can hold text written to steer an AI agent. stack-guard tells every web-reading agent that pages are data, never instructions; in the daily watch the news agent holds nothing private, has no file or shell access, and its text is shown as quoted third-party text. This limits what a fooled agent can do; it does not make an agent impossible to fool. In a conversation the agents run inside your own Claude Code or Codex session, and stack-guard cannot remove what that session already knows. In a conversation, the news scout and the breach checker start without your own CLAUDE.md instruction files (Claude Code 2.1.271 or later), so what you wrote there about yourself is not in front of an agent that reads web pages; the auditor and the fixer still load them, because they need your project instructions.
