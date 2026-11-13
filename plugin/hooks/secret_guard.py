#!/usr/bin/env python3
# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Secret guard. It hides secret-shaped values that show up in tool output (PostToolUse, --post) and checks the
final reply for them (Stop, --stop). It no longer blocks commands. Both act only while stack-guard is in use."""
import json
import os
import re
import secrets
import shlex
import stat
import sys
import time

SECRET_SHAPES = [
    ("GitHub token", r"(?:ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]{20,}"),
    ("API key", r"sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),
    ("Slack token", r"xox[abpr]-[A-Za-z0-9-]{10,}"),
    ("AWS key", r"AKIA[0-9A-Z]{16}"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{35}"),
    ("JWT/token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[A-Za-z0-9+/=\s]*)"),
    ("Discord bot token", r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
    ("password in a URL", r"https?://[^/\s:@]+:[^/\s@]+@"),
    ("bearer token", r"(?i)(?<=bearer )[A-Za-z0-9._~+/-]{16,}=*"),
]
# A value of any shape, given under a secret-sounding name: `-e HA_TOKEN=...`, `"apiKey": "..."`, `--password ...`.
# The name stays visible, the value goes (a quoted value up to its closing quote, spaces included).
# Skips $VAR references, bare numbers, and values already redacted. Name parts are capped at 64 characters so the
# pattern stays linear on long unbroken text (an uncapped name backtracked: 200k letters never finished).
NAMED_SECRET = re.compile(
    r"""((?<![\w.-])(?:[\w.-]{0,64}?(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)[\w.-]{0,64}["']?\s{0,8}[=:]"""
    r"""|--[\w-]{0,64}?(?:token|secret|password|api[_-]?key)\s)\s{0,8})"""
    r"""(?:"(?![$\[<])([^"\n]{8,})"|'(?![$\[<])([^'\n]{8,})'|(?![$\[<"'])(?!\d+\b)([^\s"'`,;})\]]{8,}))""", re.I)


# Explicit reference syntax only, matched through to the end of the value: the code prefix, then name characters.
ENV_REFERENCE = re.compile(
    r"(?:(?:process\.env\.|import\.meta\.env\.|os\.environ|os\.getenv\(|getenv\(|ENV\[|Deno\.env\.get\(|env::var\(|"
    r"System\.getenv\()[\w.\[(]*|\$\{?\w+|%[A-Za-z_]\w*%)")
# A property path such as settings.api_key: two or more names joined by dots. A bare name is never a reference.
# It counts only when it starts at a settings holder; any other dotted text (secret.literal.value) is a literal.
FALLBACK_TAIL = re.compile(r"\s*(?:\|\||\?\?|\bor\b)\s*(?:''|\"\")\s*$")
PROPERTY_PATH = re.compile(
    r"(?:settings|config|configuration|cfg|conf|env|environment|options|opts|self|this|args|params|vars|secrets|"
    r"app|props|ctx|context|process|os|st)(?:\.[A-Za-z_]\w*)+")


def is_env_reference(value, quoted):
    """True when a value only points at a variable or setting (process.env.X, os.environ[..], ${X}, settings.api_key)."""
    v = FALLBACK_TAIL.sub("", value.strip())
    if ENV_REFERENCE.fullmatch(v):
        return True
    # shortcut: an unquoted dotted name counts as a reference only when it starts at a known settings holder; a bare
    # name (correct_horse, apiSecret) or other dotted text is a literal. Upgrade path: read the source line's imports.
    return not quoted and PROPERTY_PATH.fullmatch(v) is not None


def hide_named(m, hidden=None):
    value = next((g for g in m.group(2, 3, 4) if g is not None), "")
    if is_env_reference(value, m.group(4) is None):
        return m.group(0)
    if hidden is not None:
        hidden.append(1)
    quote = '"' if m.group(2) is not None else "'" if m.group(3) is not None else ""
    return m.group(1) + quote + "[REDACTED secret value]" + quote


# Bash extglob groups, @(a|b) ?(a) +(a) *(a) !(a): judged as a wildcard in their place.
EXTGLOB_GROUP = re.compile(r"[@?*+!]\([^()]*\)")


def unquoted_mask(cmd):
    """One flag per character: True where the character sits outside single quotes, double quotes and backslash escapes."""
    mask, quote, esc = [], None, False
    for ch in cmd:
        mask.append(quote is None and not esc)
        if esc:
            esc = False
        elif ch == "\\" and quote != "'":
            esc = True
        elif quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
    return mask


def protect_extglobs(cmd, groups, nonce):
    """Swap each unquoted extglob group for a placeholder (innermost first) so the lexer keeps one word. The text is untouched otherwise."""
    prev = None
    while prev != cmd:
        prev, mask = cmd, unquoted_mask(cmd)
        def take(m):
            if not mask[m.start()]:
                return m.group(0)
            groups.append(m.group(0))
            return "__XG%s_%d__" % (nonce, len(groups) - 1)
        cmd = EXTGLOB_GROUP.sub(take, cmd)
    return cmd


def restore_extglobs(tok, groups, normalise, nonce):
    """Put the groups back as written, or (normalise) as a plain wildcard. Only markers made in this parse (random nonce) count."""
    mark = re.compile(r"__XG%s_(\d+)__" % nonce)
    def back(m):
        i = int(m.group(1))
        if i >= len(groups):
            return m.group(0)
        return "*" if normalise else restore_extglobs(groups[i], groups, False, nonce)
    return mark.sub(back, tok)


def segments_sep(cmd, normalise=False):
    """Yield (tokens, separator that follows) for each simple command. The words keep their written form; with
    normalise, each unquoted extglob group in them reads as a plain wildcard."""
    groups = []
    nonce = secrets.token_hex(6)
    cmd = protect_extglobs(cmd, groups, nonce)
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        toks = cmd.split()  # shortcut: crude split when quoting is broken
    seg = []
    for t in toks:
        if t and set(t) <= set(";&|"):
            yield seg, t
            seg = []
        else:
            seg.append(restore_extglobs(t, groups, normalise, nonce))
    yield seg, ""


TIME_BUDGET = 3.0  # seconds; a hook must never hang a tool call
MAX_TRANSCRIPT_BYTES = 1 << 30  # 1 GB: far beyond a real session, but never endless


def transcript_lines(path, binary=False):
    """Lines of a REAL transcript file only. A device, pipe or socket (eg. /dev/urandom) is never read, and reading
    stops at MAX_TRANSCRIPT_BYTES or TIME_BUDGET; then TranscriptUnreadable is raised so the caller steps aside."""
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise TranscriptUnreadable(path)
    start, seen = time.monotonic(), 0
    with open(path, "rb" if binary else "r", **({} if binary else {"encoding": "utf-8", "errors": "replace"})) as f:
        for line in f:
            seen += len(line)
            if seen > MAX_TRANSCRIPT_BYTES or time.monotonic() - start > TIME_BUDGET:
                raise TranscriptUnreadable(path)
            yield line


class TranscriptUnreadable(Exception):
    pass


def last_assistant_text(path):
    last = ""
    if True:
        for line in transcript_lines(path):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            msg = e.get("message") if isinstance(e, dict) else None
            if e.get("type") == "assistant" and isinstance(msg, dict):
                c = msg.get("content")
                if isinstance(c, str):
                    last = c
                elif isinstance(c, list):
                    last = "\n".join(b.get("text", "") for b in c
                                     if isinstance(b, dict) and b.get("type") == "text")
    return last


def redact(obj, found):
    """Copy of a tool result with every secret-shaped string replaced; kinds go into found."""
    if isinstance(obj, str):
        for kind, rx in SECRET_SHAPES:
            obj, n = re.subn(rx, "[REDACTED %s]" % kind, obj)
            if n:
                found.append(kind)
        hidden = []
        obj = NAMED_SECRET.sub(lambda m: hide_named(m, hidden), obj)
        if hidden:
            found.append("literal secret value under a secret-sounding name")
        return obj
    if isinstance(obj, list):
        return [redact(x, found) for x in obj]
    if isinstance(obj, dict):
        return {k: redact(v, found) for k, v in obj.items()}
    return obj


def post_tool(data):
    found = []
    clean = redact(data.get("tool_response"), found)
    if not found:
        return
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "updatedToolOutput": clean,
        "additionalContext": (
            "stack-guard secret guard: the output of that command held what looks like a %s, so it was "
            "removed from the chat. Do not try to print it again. Tell the user in one line which kind of value "
            "was hidden and that they should rotate (replace) it, because a literal value was hidden. A line that "
            "only reads a key from the environment is left as it is and needs no rotation." % found[0])}}))


def stop(data):
    if data.get("stop_hook_active"):
        return
    text = last_assistant_text(data["transcript_path"])
    for kind, rx in SECRET_SHAPES:
        if re.search(rx, text):
            print(json.dumps({"decision": "block", "reason": (
                "stack-guard secret guard: your last reply contains what looks like a %s. "
                "Do not repeat it. Tell the user now, in one line, that a %s appeared in this chat "
                "and that they should rotate (replace) it, and where to do that if you know." % (kind, kind))}))
            return


SCRIPT_TOKEN = re.compile(r"(?:.*/)?stack_guard\.py")
OWN_SKILLS = ("run-stack-guard", "stack-audit", "stack-fix")
OWN_AGENTS = ("stack-auditor", "stack-fixer", "stack-news-scout")
INTERPRETER = re.compile(r"python[\d.]*")
COMMAND_TAG = re.compile(r"<command-name>\s*/?([^<\s]*)")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")


def without_heredoc_bodies(cmd):
    """Drop the text lines a heredoc feeds to its command; they are data, not commands."""
    out, end = [], None
    for line in cmd.split("\n"):
        if end is not None:
            if line.strip() == end:
                end = None
            continue
        out.append(line)
        m = HEREDOC.search(line)
        if m:
            end = m.group(2)
    return "\n".join(out)


def runs_script(cmd):
    """True when a command line starts an interpreter on stack_guard.py (a path ending in that file name).
    Quoted text, heredoc bodies, grep/cat/git arguments and other files that merely end in the name do not count."""
    if "stack_guard.py" not in cmd:
        return False  # cheap exit: shlex is slow on huge commands
    # shortcut: a quoted string that spans lines is cut at the newline and re-read by crude split; upgrade to a real shell parser if that matters
    for line in without_heredoc_bodies(cmd).split("\n"):
        for seg, _ in segments_sep(line):
            while seg and re.fullmatch(r"\w+=.*", seg[0]):
                seg = seg[1:]
            if not seg:
                continue
            head = os.path.basename(seg[0])
            rest = seg[1:]
            if head == "uv" and rest[:1] == ["run"]:
                rest = rest[1:]
            elif not INTERPRETER.fullmatch(head):
                continue
            while rest and rest[0].startswith("-"):
                rest = rest[1:]
            if rest and SCRIPT_TOKEN.fullmatch(rest[0]):
                return True
    return False


def blocks(entry):
    content = (entry.get("message") or {}).get("content")
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []


def own_name(name, own):
    """True for stack-guard itself, anything in its namespace, or one of its own skill/agent names."""
    name = str(name or "")
    return name == "stack-guard" or name.startswith("stack-guard:") or name in own


def stamped_as_ours(entry):
    """Claude Code stamps assistant entries of a plugin skill or agent run with attribution fields."""
    return (entry.get("attributionPlugin") == "stack-guard"
            or own_name(entry.get("attributionSkill"), OWN_SKILLS)
            or own_name(entry.get("attributionAgent"), OWN_AGENTS))


def entry_is_use(entry):
    """True only for real use: a typed /stack-guard command, or a Skill/Agent/Bash tool call that runs stack-guard."""
    kind = entry.get("type")
    if kind == "assistant" and stamped_as_ours(entry):
        return True
    for b in blocks(entry):
        if kind == "user" and b.get("type") == "text":
            if any(own_name(m, OWN_SKILLS + OWN_AGENTS) for m in COMMAND_TAG.findall(str(b.get("text")))):
                return True
        if kind == "assistant" and b.get("type") == "tool_use":
            name, inp = b.get("name"), b.get("input") or {}
            if name == "Skill":
                skill = str(inp.get("skill"))
                if own_name(skill, OWN_SKILLS):
                    return True
            elif name in ("Agent", "Task"):
                agent = str(inp.get("subagent_type"))
                if own_name(agent, OWN_AGENTS):
                    return True
            elif name == "Bash" and runs_script(str(inp.get("command") or "")):
                return True
    return False


def marker_in_file(path):
    """Read the transcript as JSONL; skill listings, reminders and prose never count. Bad lines are skipped."""
    if True:  # whole file within the size/time caps: a full scan of a 373 MB transcript takes ~1.3 s
        for line in transcript_lines(path, binary=True):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and entry_is_use(entry):
                return True
    return False


def stack_guard_in_use(data):
    """True while stack-guard is working in this session: its agents set the env, or the transcript shows a real call."""
    try:
        if os.environ.get("STACK_GUARD_ACTIVE") == "1":
            return True
        return marker_in_file(data["transcript_path"])
    except Exception:  # shortcut: any error means "not in use", so the guard stays out of other work
        return False


def option_off(name):
    """True when the plugin setting `name` is false/0/no/off (env CLAUDE_PLUGIN_OPTION_<NAME>, any case)."""
    return os.environ.get("CLAUDE_PLUGIN_OPTION_" + name.upper(), "").strip().lower() in ("false", "0", "no", "off")


def main():
    # First thing: a turned-off hook exits before it reads stdin or any transcript.
    if option_off("secret_guard") or ("--stop" in sys.argv and option_off("reply_check")):
        return
    try:
        data = json.load(sys.stdin)
        if not stack_guard_in_use(data):
            return
        if "--stop" in sys.argv:
            stop(data)
        elif "--post" in sys.argv:
            post_tool(data)
    except Exception:  # shortcut: any internal error allows the call, so a bug never breaks the session
        sys.exit(0)


if __name__ == "__main__":
    main()
