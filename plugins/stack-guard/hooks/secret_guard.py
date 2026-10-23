#!/usr/bin/env python3
# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Secret guard. PreToolUse: block reads of secret files. PostToolUse (--post): redact secrets from tool output.
Stop (--stop): warn when a reply holds a secret. All three act only while stack-guard is in use."""
import fnmatch
import json
import os
import re
import shlex
import sys

EXEMPT = {".env.example", ".env.sample", ".env.template", ".env.dist"}
NAME_GLOBS = [".env", ".env.*", ".dev.vars", ".npmrc", ".pypirc", ".netrc", ".pgpass",
              "secrets.yaml", "secrets.yml", "secrets.json", "secrets.toml",
              "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "id_ecdsa*",
              "credentials", "credentials.json", "*service-account*.json",
              ".claude.json", "claude_desktop_config.json"]
PATH_PARTS = ["/.docker/config.json", "/.kube/config", "/.codex/auth.json", "/.config/gcloud/"]
READERS = {"cat", "head", "tail", "less", "more", "bat", "grep", "rg", "ag", "sed", "awk", "cut",
           "strings", "xxd", "od", "hexdump", "base64", "jq", "yq"}
SCRIPTERS = {"python", "python3", "node"}
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
]


def is_secret_path(p):
    p = os.path.expanduser(str(p)).replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if not name or name in EXEMPT or name.endswith(".pub"):
        return False
    if any(part in "/" + p for part in PATH_PARTS):
        return True
    return any(fnmatch.fnmatchcase(name, g) for g in NAME_GLOBS)


PRINTERS = READERS | SCRIPTERS | {"echo", "printf", "print", "tee", "yes", "cp", "dd", "ruby", "perl"}
SECRET_VAR = re.compile(r"\$\{?[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL)[A-Za-z0-9_]*",
                        re.I)
SECRET_ENV_NAME = re.compile(r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.I)
SUBST = re.compile(r"\$\([^()]*\)|`[^`]*`")
HOLE = re.compile(r"__SUBST(\d+)__")


def hoist_substitutions(cmd, bodies):
    """Swap each $(...) / backtick for a placeholder and keep its body, innermost first."""
    def take(m):
        bodies.append(m.group(0)[2:-1] if m.group(0).startswith("$(") else m.group(0)[1:-1])
        return " __SUBST%d__ " % (len(bodies) - 1)
    prev = None
    while prev != cmd:
        prev = cmd
        cmd = SUBST.sub(take, cmd)
    return cmd


def segments_sep(cmd):
    """Yield (tokens, separator that follows) for each simple command."""
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
            seg.append(t)
    yield seg, ""


RECURSIVE_READERS = {"grep", "rg", "ag", "git", "find"}
BROAD_PATHS = {".", "./", "..", "../", "~", "/", "*", "./*", "-"}


def explicit_paths_only(args, has_pattern_flag):
    """True when every search path is a named, non-secret folder or file (never ., .., ~ or *)."""
    pos = [t for t in args if not t.startswith("-")]
    paths = pos if has_pattern_flag else pos[1:]
    return bool(paths) and not any(p.rstrip("/") in BROAD_PATHS or p in BROAD_PATHS or is_secret_path(p)
                                   or p.endswith("/.") or p.startswith("~") for p in paths)


def recursive_unfiltered(head, seg):
    """grep -R / rg --hidden / find -exec cat walk into .env files; allowed only with named source folders."""
    args = seg[1:]
    flags = [t for t in args if t.startswith("-")]
    long = {t.split("=")[0] for t in flags if t.startswith("--")}
    short = "".join(t[1:] for t in flags if not t.startswith("--"))
    if head == "grep":
        walks = bool(long & {"--recursive", "--dereference-recursive"}) or "r" in short or "R" in short
    elif head in ("rg", "ag"):
        walks = bool(long & {"--hidden", "--no-ignore", "--no-ignore-vcs", "--unrestricted"}) or "u" in short
    elif head == "git":
        walks = "grep" in args[:1] and "--untracked" in long
    else:  # find ... -exec cat/grep
        i = next((n for n, t in enumerate(args) if t in ("-exec", "-execdir", "-ok", "-okdir")), None)
        if i is None or i + 1 >= len(args) or os.path.basename(args[i + 1]) not in READERS:
            return False
        start = []  # every search root comes before the first expression token; each one must be safe
        for t in args[:i]:
            if t.startswith("-") or t in ("(", "!"):
                break
            start.append(t)
        return not (start and all(explicit_paths_only([x], True) for x in start))
    if not walks:
        return False
    has_pat = bool({"-e", "-f", "--regexp", "--file"} & set(flags)) or any(
        t.startswith(("--regexp=", "--file=")) for t in flags)
    rest, skip = [], False
    for t in (args[1:] if head == "git" else args):
        if skip:
            skip = False  # the pattern (or pattern file) after -e/-f is not a search path
            continue
        if t in ("-e", "-f", "--regexp", "--file"):
            skip = True
            continue
        rest.append(t)
    return not explicit_paths_only(rest, has_pat)


SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
PIPE_PRODUCERS = {"grep", "cat", "cut", "head", "tail", "tr"}


def wrapped_command(head, seg):
    """The command string a shell wrapper runs (sh -c 'x', bash -lc 'x', eval x), or ''."""
    if head == "eval":
        return " ".join(seg[1:])
    if head in SHELLS:
        for i, t in enumerate(seg[1:-1], 1):
            if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", t):
                return seg[i + 1]
    return ""


# Paths that write to the chat: /dev/stdout, /dev/stderr, /dev/tty, /dev/fd/N, /proc/self/fd/N, /proc/<pid>/fd/N.
OUTPUT_ALIAS = re.compile(r"/dev/(?:stdout|stderr|tty)|/dev/fd/\d+|/proc/(?:self|\d+|thread-self)/fd/\d+")
OK_HEADS = {"cp", "mv", "rm", "chmod", "touch", "ls", "stat", "test", "[", "[[", "source", "."}
KEYWORDS = {"if", "then", "else", "elif", "while", "until", "do", "!", "{", "(", ")", "time", "&&", "||"}
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>"}
MENTION_SPLIT = re.compile(r"[^\s'\"(),=:;@]+")
IN_PLACE = re.compile(r"^-(?!-)[a-zA-Z]*i|^--in-place")


def secret_mention(tok):
    """The protected path a token names (as a whole or inside quoted code), or None."""
    for c in [tok] + MENTION_SPLIT.findall(tok):
        if "/" not in c and c == "credentials":
            continue  # shortcut: the bare word 'credentials' is too common in prose to count as a file
        if is_secret_path(c):
            return c
    return None


def is_consumer(seg):
    """A command that takes a secret on stdin and prints nothing back."""
    w = [os.path.basename(t) for t in seg[:1]]
    if not w:
        return False
    if w[0] == "wrangler":
        return "secret" in seg and ("put" in seg or "bulk" in seg)
    if w[0] == "gh":
        return "secret" in seg and "set" in seg
    if w[0] == "security":
        return "add-generic-password" in seg
    if w[0] == "curl":
        return any(t in ("-d", "--data", "--data-binary", "--data-raw") and i + 1 < len(seg) and seg[i + 1] == "@-"
                   for i, t in enumerate(seg)) or any(t.startswith(("-d@-", "--data-binary=@-", "--data=@-")) for t in seg)
    return False


def mention_ok(head, seg, i, piped_to_consumer):
    """A named secret file is fine when the command uses or writes it and prints nothing."""
    if head in OK_HEADS or piped_to_consumer:
        return True
    if i > 0 and seg[i - 1] in WRITE_REDIRECTS:
        return True
    return head in ("sed", "perl") and any(IN_PLACE.search(t) for t in seg[1:])


STDERR_REDIRECT = re.compile(r"(?<!\w)1?>>?\s*&\s*2\b")


def expand_holes(body, bodies):
    return HOLE.sub(lambda m: expand_holes(bodies[int(m.group(1))], bodies), body)


def stderr_leak(body, bodies):
    """The secret file a substitution body names while sending output to stderr or the terminal, or None."""
    text = expand_holes(body, bodies)
    if not (OUTPUT_ALIAS.search(text) or STDERR_REDIRECT.search(text)):
        return None
    for seg, _ in segments_sep(text):
        for t in seg:
            hit = secret_mention(t)
            if hit:
                return hit
    return None


def bash_violation(cmd, bodies=None):
    bodies = [] if bodies is None else bodies
    cmd = hoist_substitutions(cmd, bodies)
    parts = list(segments_sep(cmd))
    for n, (seg, sep) in enumerate(parts):
        words = [os.path.basename(t) for t in seg]
        for i, t in enumerate(seg):
            if t in ("<", "<<<") and i + 1 < len(seg) and is_secret_path(seg[i + 1]):
                return seg[i + 1]
        if not seg:
            continue
        head = words[0]
        inner = wrapped_command(head, seg)
        if inner:
            hit = bash_violation(inner, bodies)
            if hit:
                return hit
        holes = [int(n) for n in HOLE.findall(" ".join(seg))]
        # A substitution always shares the shell's stderr, so a body that names a secret must not write to it.
        for k in holes:
            hit = stderr_leak(bodies[k], bodies)
            if hit:
                return hit
        # Its stdout reaches the chat only when the outer command prints; the printer decides.
        if holes and (head in PRINTERS or HOLE.search(seg[0])):
            for k in holes:
                hit = bash_violation(bodies[k], bodies)
                if hit:
                    return hit
        if head in ("printenv", "env", "set") and len(seg) == 1:
            return head
        if head == "printenv" and any(SECRET_ENV_NAME.search(t) for t in seg[1:]):
            return "printenv " + seg[1]
        if head in PRINTERS and any(SECRET_VAR.search(t) for t in seg[1:]):
            return next(t for t in seg[1:] if SECRET_VAR.search(t))
        if any(OUTPUT_ALIAS.fullmatch(t) for t in seg) and any(
                is_secret_path(t) for t in seg):
            return next(t for t in seg if is_secret_path(t))
        if head == "security" and any(w in seg for w in ("find-generic-password", "find-internet-password")):
            if any(re.fullmatch(r"-[a-zA-Z]*[wg][a-zA-Z]*", t) for t in seg):
                return "security find-generic-password"
        if head in RECURSIVE_READERS and recursive_unfiltered(head, seg):
            return "recursive:" + " ".join(seg[:3])
        if inner:
            continue  # the wrapped command was checked on its own above
        # Generic rule: a command that names a secret file must be one that uses it without printing it.
        k = 0
        while k < len(seg) - 1 and (seg[k] in KEYWORDS or re.fullmatch(r"[A-Za-z_]\w*=.*", seg[k])):
            k += 1
        main = os.path.basename(seg[k])
        # The secret may only feed an approved consumer directly: any stage between them (tee, cat, head...)
        # could copy it to stderr, the terminal or a file.
        # Only plain text tools may feed the consumer: an interpreter could also copy the secret to stderr.
        piped = sep == "|" and n + 1 < len(parts) and is_consumer(parts[n + 1][0]) and main in PIPE_PRODUCERS
        for i, t in enumerate(seg):
            hit = secret_mention(t)
            if hit and not mention_ok(main, seg, i, piped):
                return hit
    return None


def pre_tool(data):
    tool, inp = data.get("tool_name"), data.get("tool_input") or {}
    if tool == "Read":
        hit = inp.get("file_path") if is_secret_path(inp.get("file_path") or "") else None
    elif tool == "Grep":
        hit = next((v for v in (inp.get("path"), inp.get("glob"))
                    if v and (is_secret_path(v) or os.path.basename(v).startswith(".env")
                              and os.path.basename(v) not in EXEMPT)), None)
    elif tool == "Bash":
        hit = bash_violation(inp.get("command") or "")
    else:
        hit = None
    if hit:
        hint = ""
        if hit.startswith("recursive:"):
            hit = "any secret file under that search"
            hint = " To search code, use `rg PATTERN` (it skips ignored files like .env) or name the source folders."
        sys.stderr.write(
            "stack-guard secret guard: that would put the contents of %s into this chat. "
            "stack-guard never needs a secret's value; let the project's own scripts load it "
            "(eg. `$(...)`, `source`, or the script itself).%s\n" % (hit, hint))
        sys.exit(2)


def last_assistant_text(path):
    last = ""
    with open(path, encoding="utf-8") as f:
        for line in f:
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
            "removed from the chat. Do not try to print it again. Tell the user in one line that it appeared "
            "and that they should rotate (replace) it." % found[0])}}))


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


COMMAND_TAG = re.compile(r"<command-name>\s*/?([^<\s]*)")
OWN_SKILLS = ("run-stack-guard", "stack-audit", "stack-fix")
OWN_AGENTS = ("stack-auditor", "stack-fixer", "stack-news-scout")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")
SCRIPT_TOKEN = re.compile(r"(?:.*/)?stack_guard\.py")
INTERPRETER = re.compile(r"python[\d.]*")


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
    with open(path, "rb") as f:  # whole file: a full scan of a 373 MB transcript takes ~1.3 s
        for line in f:
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


def main():
    try:
        data = json.load(sys.stdin)
        if not stack_guard_in_use(data):
            return
        if "--stop" in sys.argv:
            stop(data)
        elif "--post" in sys.argv:
            post_tool(data)
        else:
            pre_tool(data)
    except Exception:  # shortcut: any internal error allows the call, so a bug never breaks the session
        sys.exit(0)


if __name__ == "__main__":
    main()
