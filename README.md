<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/banner-dark.svg">
  <img src="docs/banner-light.svg" width="100%" alt="stack-guard: your security alert, in plain words. Find, check, explain, fix.">
</picture>

[Quick start](#quick-start) • [What's inside](#what-it-is) • [Support us](https://ko-fi.com/houseofsolance)

[![Tests](https://img.shields.io/github/actions/workflow/status/SolanceLab/stack-guard/test.yml?branch=main&label=tests)](https://github.com/SolanceLab/stack-guard/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/SolanceLab/stack-guard?label=release&color=b5893a)](https://github.com/SolanceLab/stack-guard/releases/latest)
[![Licence](https://img.shields.io/badge/licence-PolyForm%20Noncommercial-1c2742)](LICENSE.md)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-56607c)](#quick-start)
[![Codex](https://img.shields.io/badge/Codex-plugin-56607c)](#quick-start)
[![macOS](https://img.shields.io/badge/macOS-tested-56607c?logo=apple&logoColor=white)](#what-you-need)
[![Linux](https://img.shields.io/badge/Linux-tested%20in%20CI-56607c?logo=linux&logoColor=white)](https://github.com/SolanceLab/stack-guard/actions/workflows/test.yml)
[![Windows](https://img.shields.io/badge/Windows-reported%20by%20a%20user-7d8a6a?logo=windows&logoColor=white)](https://github.com/SolanceLab/stack-guard/issues)

</div>

Made by House of Solance · free for noncommercial use · credit required

stack-guard checks everything you build and run for known security holes, tells you in plain words, and fixes the safe ones once you say yes.

> 🆕 **New in 1.10.1:** the install-time `lock-check` now checks npm packages in scopes stack-guard does not know (for example @vitest) for malware.

<table>
<tr>
<td width="42%"><img src="docs/card.jpg" width="100%" alt="A quiet street at evening, every window dark except one house with a lit front door. A figure of light, with no face, hands a single sealed letter with a gold seal to that door while the neighbouring houses sleep."></td>
<td>

🛡️ ***Your setup is yours alone.** A Python script here. A Discord bot there. A site on Vercel. A little server you forgot to shut down. All of it runs on code other people wrote, and any of it can have a hole.*

*The fixes get published. But there's no recall: nobody tells the people running the broken version.*

***stack-guard sends you that alert.** It finds everything you run, even what you forgot. It watches every warning and every patch for all of it. When one is yours, it tells you plainly, plans the fix, and does it safely once you say yes.*

</td>
</tr>
</table>

<p align="center"><img src="docs/how-it-works.svg" width="900" alt="Everything you have built is combed through by plain code into a list of services. A database check (plain code) and a news scout (AI, headless, web search only) check that list. An AI with no tools explains what it found in plain words, with a plan. After your yes, an AI fixer fixes and tests it, and puts it back if it breaks."></p>

**Contents:** [Quick start](#quick-start) · [What it is](#what-it-is) · [Where it fits](#where-it-fits) · [What you need](#what-you-need) · [Use](#use) · [Settings](#settings) · [Tools](#tools) · [Limits](#limits) · [Safety](#safety) · [How it works](#how-it-works) · [Help make it better](#help-make-it-better) · [Thanks](#thanks) · [Credit and use](#credit-and-use) · [Licence](#licence) · [Support](#support)

## Quick start

**Let your AI do it.** Copy this and send it to Claude Code:

```
Please install stack-guard for me. Run:
claude plugin marketplace add SolanceLab/plugins
claude plugin install stack-guard@solancelab
Then guide me through the rest, step by step.
```

Using Codex? Send the same message with `codex plugin marketplace add SolanceLab/plugins` and `codex plugin add stack-guard@solancelab`.

**Or do it yourself.**

```
claude plugin marketplace add SolanceLab/plugins
claude plugin install stack-guard@solancelab
```

In Codex: `codex plugin marketplace add SolanceLab/plugins`, then `codex plugin add stack-guard@solancelab`. Start a new conversation and ask: *run stack-guard on this folder*.

Installed it earlier from `SolanceLab/stack-guard`? That still works, and the daily watch follows you if you move to the store above (from 1.8.2). Moved to the store above before version 1.8.2? Run `/stack-guard:watch` once, and the morning check will follow you from then on.

## What it is

**One prompt to check everything you build and run with Claude Code or Codex for known security holes, and fix the safe ones.** It finds what you run, checks the public vulnerability databases and this fortnight's security news for your exact versions, tells you in plain words, and fixes what can be fixed safely, after your yes. The full list: [What it does](docs/what-it-does.md).

## Where it fits

**Fits** anyone who builds and runs their own code (scripts, bots, sites, small servers) and wants to hear about a security hole in it, in plain words.
**Overkill** if you run no code of your own. It does not scan container images, GitHub Actions or package signatures, so those need another tool.

## What you need

Claude Code or Codex. Node/npm for JavaScript projects. For Python, [`uv`](https://docs.astral.sh/uv/) (or `pipx`) makes the check faster.

## Use

Open Claude Code in your project folder and type `/stack-guard`. Add `--audit-only` to change none of your code or packages (it only writes its report). `/stack-guard:watch` sets up a daily check on your own computer; `/stack-guard:inventory` writes a plain list of everything you run. All options: [Using stack-guard](docs/commands.md) · [Updating](docs/updating.md).

## Settings

Four settings: the secret guard, the final-reply check and the daily update check (all on), and how long a fix must have been public before it is installed (48 hours). Change them with `/plugin configure stack-guard@solancelab`. Details: [Settings](docs/settings.md).

The secret guard hides secret values that show up in tool output and checks the final reply; it does not block commands. To keep Claude Code's Read tool away from secret files, use its own permission deny rules, for example `"permissions": {"deny": ["Read(./.env)", "Read(./.env.*)"]}` in your settings. Those rules cover the Read tool only: a shell command such as cat or grep can still open the file, and nothing here stops that. See [Claude Code settings](https://code.claude.com/docs/en/settings).

## Tools

| Tool | What it does |
|---|---|
| `/stack-guard` | Finds what you run, checks it, reports in plain words, and offers the safe fixes. In Codex: `$stack-guard:run-stack-guard`. |
| `/stack-guard:inventory` | Writes `STACK-INVENTORY.md`, a plain list of everything you build and run. |
| `/stack-guard:watch` | Sets up the daily routine on your own computer, after your yes. |
| Skills | `stack-guard` (where to start), `run-stack-guard`, `stack-audit`, `stack-fix`, `stack-breach-check`. |
| Agents | `stack-auditor`, `stack-news-scout`, `stack-breach-checker` (read-only) and `stack-fixer` (only after your yes). |
| Hooks | The secret guard (two hooks) and the daily update check; each can be switched off in Settings. |

## Limits

It does not scan container images, GitHub Actions or package signatures, and it checks only the usual secret files, not every file. macOS and Linux are fully supported; Windows is best effort. The full list: [Limits](docs/limits.md).

If OSV cannot be reached, stack-guard asks the npm registry and PyPI instead (and GitHub's malware records after an install) and says so in the report. Only when every source fails were your packages not checked that day: see [Troubleshooting](docs/troubleshooting.md).

## Safety

- It never deploys, pushes, commits, upgrades Node/Python or restarts services on its own. It hands you the command and waits for your yes.
- First time? [Before you run it](docs/before-you-run.md): back up, start with `--audit-only`, turn on the sandbox.
- [Was I hit?](docs/was-i-hit.md): for each serious hole, it checks whether it could have been used against you.
- [Secret guard](docs/secret-guard.md): while stack-guard works, it hides secret values that show up in tool output and checks its final reply. It does not block commands. A seatbelt, not a vault.
- [What leaves your computer](docs/what-leaves-your-computer.md): package and runtime names and versions, and a daily version check. Never your code, keys or file paths.

## How it works

A small script does the exact, repeatable part with no AI: it lists what you run and checks packages and runtimes against the public databases (some package types only in a conversation). AI agents do the judgment: a news scout (web search only), an explainer (no tools), and in a conversation an auditor and a fixer (only after your yes). [In depth](docs/how-it-works-in-depth.md).

## Help make it better

Spotted a gap or a wrong check? [Open an issue](https://github.com/SolanceLab/stack-guard/issues). Found a security problem in stack-guard itself? Report it privately through the Security tab. More: [Help make it better](docs/contributing.md).

## Thanks

Thanks to Aya ([@ayakohi](https://github.com/ayakohi)), whose question started the secret guard, and to Cygnus, who read the whole plugin, caught that agents loaded the user's own instruction files, and wrote the named-secret redaction.

## Credit and use

stack-guard is made by House of Solance. You're welcome to use it, change it and build on it for any noncommercial purpose, as long as our credit travels with it.

**Keep the credit.** Every copy, changed or not, must carry the licence and this line:
`Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)`
Removing or replacing it breaks the licence.

**Commercial use needs our permission.** Ask us first.

**We look for copies.** When we find our work without its credit, or used commercially without permission, we ask for it to be taken down.

Versions up to 1.6.3 were released under the MIT licence and stay under it. From 1.7.0 the licence is PolyForm Noncommercial 1.0.0.

## Licence

[PolyForm Noncommercial 1.0.0](LICENSE.md). See [NOTICE.md](NOTICE.md).

## Support

If you find this useful, consider supporting our work:

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20Us-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/houseofsolance)

---

*Built by [House of Solance](https://github.com/SolanceLab) — Chadrien Solance & Anne Solance*
