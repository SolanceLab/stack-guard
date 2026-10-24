#!/usr/bin/env python3
# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Secret guard. PreToolUse: block reads of secret files. PostToolUse (--post): redact secrets from tool output.
Stop (--stop): warn when a reply holds a secret. All three act only while stack-guard is in use."""
import fnmatch
import json
import os
import re
import shlex
import stat
import sys
import time

PATH_PARTS = ["/.docker/config.json", "/.kube/config", "/.codex/auth.json", "/.config/gcloud/"]
EXEMPT = {".env.example", ".env.sample", ".env.template", ".env.dist"}
NAME_GLOBS = [".env", ".env.*", ".dev.vars", ".npmrc", ".pypirc", ".netrc", ".pgpass",
              "secrets.yaml", "secrets.yml", "secrets.json", "secrets.toml",
              "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "id_ecdsa*",
              "credentials", "credentials.json", "*service-account*.json",
              ".claude.json", "claude_desktop_config.json"]
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
READERS = {"cat", "head", "tail", "less", "more", "bat", "grep", "rg", "ag", "sed", "awk", "cut",
           "strings", "xxd", "od", "hexdump", "base64", "jq", "yq"}


# A path with a wildcard is judged by the names it could match, so no folder listing is needed.
GLOB_CHARS = re.compile(r"[*?\[]|[@+!]\(")
# Bash extglob groups, @(a|b) ?(a) +(a) *(a) !(a): judged as a wildcard in their place.
SECRET_DIR_MARKS = (".aws", ".ssh", ".config/gcloud", ".docker", ".kube", ".codex")
BRACE_EXPANSION = re.compile(r"\{([^{}]*(?:,|\.\.)[^{}]*)\}")
SECRET_DIR_SAMPLES = ["credentials", "credentials.db", "config", "config.json", "auth.json", "id_rsa", "id_ed25519"]
EXTGLOB_GROUP = re.compile(r"[@?*+!]\([^()]*\)")
SAMPLE_SECRET_NAMES = [".env", ".env.", ".env.local", ".env.production", ".dev.vars", ".npmrc", ".pypirc", ".netrc", ".pgpass",
                       "secrets.yaml", "secrets.yml", "secrets.json", "secrets.toml", "server.pem", "server.key",
                       "credentials", "credentials.json", "prod-service-account.json", "id_rsa", "id_ed25519",
                       "claude.json", ".claude.json"]


def glob_is_secret(directory, name):
    if any(fnmatch.fnmatchcase(sample, name) for sample in SAMPLE_SECRET_NAMES):
        return True
    return any(mark in directory for mark in SECRET_DIR_MARKS) and any(
        fnmatch.fnmatchcase(sample, name) for sample in SECRET_DIR_SAMPLES)


def brace_variants(pattern, cap=64):
    """Bounded shell-style brace expansion: {a,b} is expanded; a range such as {1..5} stands for one character class
    (numbers) or one character (letters). None when the expansion would pass the cap."""
    out = [pattern]
    for _ in range(8):
        expanded, changed = [], False
        for item in out:
            match = BRACE_EXPANSION.search(item)
            if not match:
                expanded.append(item)
                continue
            changed = True
            body = match.group(1)
            if "," not in body:  # a range: not expanded one by one
                stand_in = "[0-9]*" if re.fullmatch(r"-?\d+\.\.-?\d+(\.\.-?\d+)?", body) else "?"
                expanded.append(item[:match.start()] + stand_in + item[match.end():])
                continue
            for choice in body.split(","):
                expanded.append(item[:match.start()] + choice + item[match.end():])
            if len(expanded) > cap:
                return None
        out = expanded
        if not changed:
            return out
    return None


def _is_secret_one(p):
    name = p.rsplit("/", 1)[-1]
    if not name or name in EXEMPT or name.endswith(".pub"):
        return False
    if any(part in "/" + p for part in PATH_PARTS):
        return True
    if GLOB_CHARS.search(name) and glob_is_secret(p[:len(p) - len(name)], name):
        return True
    return any(fnmatch.fnmatchcase(name, g) for g in NAME_GLOBS)


def is_secret_path(p):
    p = os.path.expandvars(os.path.expanduser(str(p))).replace("\\", "/")
    prev = None
    while prev != p:  # nested groups collapse from the inside out
        prev, p = p, EXTGLOB_GROUP.sub("*", p)
    if len(p) > 4096:
        return bool(GLOB_CHARS.search(p) or BRACE_EXPANSION.search(p))  # too long to judge: stay on the safe side
    if BRACE_EXPANSION.search(p):
        variants = brace_variants(p)
        if variants is None:
            variants = [BRACE_EXPANSION.sub("*", p)]  # shortcut: too many choices, so test every choice at once as a wildcard
        return any(_is_secret_one(v) for v in variants)
    return _is_secret_one(p)


def secret_glob(p):
    """Whether a wildcard path or glob can select a protected name (used by the Grep tool rule)."""
    return bool(GLOB_CHARS.search(str(p)) or BRACE_EXPANSION.search(str(p))) and is_secret_path(p)


SECRET_VAR = re.compile(r"\$\{?[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL)[A-Za-z0-9_]*",
                        re.I)
PRINTERS = READERS | SCRIPTERS | {"echo", "printf", "print", "tee", "yes", "cp", "dd", "ruby", "perl"}
SUBST = re.compile(r"\$\([^()]*\)|`[^`]*`")
HOLE = re.compile(r"__SUBST(\d+)__")
SECRET_ENV_NAME = re.compile(r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.I)


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
    prev = None
    while prev != cmd:  # shortcut: extglob groups become a plain wildcard (also inside quotes) so the lexer keeps one word
        prev, cmd = cmd, EXTGLOB_GROUP.sub("*", cmd)
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
        if t in ("-e", "-f", "--regexp", "--file", "--exclude", "--exclude-dir"):
            skip = True  # the argument of these flags is a pattern, not a search path
            continue
        rest.append(t)
    return not explicit_paths_only(rest, has_pat)


WRAPPERS = {"env", "command", "exec", "nohup", "sudo", "time", "nice"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
MAX_SHELL_DEPTH = 3
# Options of each wrapper that consume the next token (so it is not mistaken for the wrapped command).
WRAPPER_ARG_OPTS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
             "--user", "--group", "--host", "--prompt", "--chdir", "--chroot", "--role", "--type",
             "--other-user", "--command-timeout", "--close-from"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"},
    "nice": {"-n", "--adjustment"},
    "time": {"-f", "-o", "--format", "--output"},
    "exec": {"-a"},
}
PIPE_PRODUCERS = {"grep", "cat", "cut", "head", "tail", "tr"}


def wrapped_command(head, seg):
    """The command string a shell wrapper runs (sh -c 'x', bash -lc 'x', eval x), or ''."""
    while head in WRAPPERS and len(seg) > 1:  # `env bash -c ...`: look at the command the wrapper starts
        takes_arg = WRAPPER_ARG_OPTS.get(head, set())
        rest, skip = [], False
        for t in seg[1:]:
            if skip:
                skip = False  # this token is the previous option's argument
            elif t.startswith("-") and not rest:
                skip = t in takes_arg
            elif rest or not re.fullmatch(r"[A-Za-z_]\w*=.*", t):
                rest.append(t)
        seg = rest
        if not seg:
            return ""
        head = os.path.basename(seg[0])
    if head == "eval":
        return " ".join(seg[1:])
    if head in SHELLS:
        for i, t in enumerate(seg[1:-1], 1):
            if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", t):
                return seg[i + 1]
    return ""


# Paths that write to the chat: /dev/stdout, /dev/stderr, /dev/tty, /dev/fd/N, /proc/self/fd/N, /proc/<pid>/fd/N.
OK_HEADS = {"cp", "mv", "rm", "chmod", "touch", "ls", "stat", "test", "[", "[[", "source", "."}
KEYWORDS = {"if", "then", "else", "elif", "while", "until", "do", "!", "{", "(", ")", "time", "&&", "||"}
IN_PLACE = re.compile(r"^-(?!-)[a-zA-Z]*i|^--in-place")
OUTPUT_ALIAS = re.compile(r"/dev/(?:stdout|stderr|tty)|/dev/fd/\d+|/proc/(?:self|\d+|thread-self)/fd/\d+")
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>"}
MENTION_SPLIT = re.compile(r"[^\s'\"(),=:;@<>]+")


def secret_mention(tok):
    """The protected path a token names (as a whole or inside quoted code), or None."""
    if tok.startswith(("--exclude", "--glob=!", "!")):
        return None  # an exclusion pattern names what to skip, not what to read
    for c in [tok] + MENTION_SPLIT.findall(tok):
        if "/" not in c and c == "credentials":
            continue  # shortcut: the bare word 'credentials' is too common in prose to count as a file
        if is_secret_path(c):
            return c
    return None


# Approved consumers: the BARE command name, then exactly this subcommand shape, then one name.
# Flags that take a value (their value is not the secret's name).
CONSUMER_SHAPES = {
    "gh": (("secret", "set"), {"-R", "--repo", "-e", "--env", "-o", "--org", "-a", "--app", "-u", "--user", "-r", "--repos",
                               "-v", "--visibility", "-f", "--env-file", "-b", "--body"}),
    "wrangler": (("secret", "put"), {"--name", "-n", "--env", "-e", "--config", "-c"}),
    "security": (("add-generic-password",), {"-a", "-s", "-l", "-j", "-c", "-C", "-D", "-k", "-A", "-T", "-U"}),
}


PATH_CHANGE = re.compile(r"(?<![\w.-])PATH\s*\+?=|\bexport\s+(?:-\w+\s+)?PATH\b|\bhash\s+-p\b")


def shadowed_consumers(cmd):
    """Trusted names this command redefines (a function or alias), or every name when it changes PATH:
    a bare name is trusted only when it still reaches the real program."""
    if PATH_CHANGE.search(cmd):
        return set(CONSUMER_SHAPES)
    return {n for n in CONSUMER_SHAPES
            if re.search(r"(?<![\w./-])%s\s*\(\s*\)|\bfunction\s+%s\b|\balias\s+%s=" % ((re.escape(n),) * 3), cmd)}


def is_consumer(seg, final=True, shadowed=()):
    """A command that takes a secret on stdin, prints nothing back and sends it nowhere: a trusted CLI named bare
    (no path), with its exact subcommand shape and one name, as the last stage of the pipeline."""
    if not final or not seg or seg[0] not in CONSUMER_SHAPES or seg[0] in shadowed:
        return False
    sub, value_flags = CONSUMER_SHAPES[seg[0]]
    rest = seg[1:]
    if tuple(rest[:len(sub)]) != sub:
        return False
    names, skip = [], False
    for t in rest[len(sub):]:
        if skip:
            skip = False
        elif t.startswith("-"):
            skip = "=" not in t and t in value_flags
        else:
            names.append(t)
    return len(names) == (0 if seg[0] == "security" else 1)  # curl and other senders are not approved: the content must not leave this computer


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


def env_lists_all(head, seg):
    """True when env or printenv carries only option flags (and NAME=VALUE for env), so it still prints every variable."""
    if head not in ("env", "printenv"):
        return False
    rest, i = seg[1:], 0
    while i < len(rest):
        t = rest[i]
        if head == "env" and (t in ("--ignore-environment", "--help", "--version") or (
                re.fullmatch(r"-[0v]*[i][0v]*", t))):
            return False  # clears the environment or runs nothing: nothing inherited is printed
        if t.startswith("-") and t != "-":
            i += 2 if head == "env" and t in ("-u", "-C", "-S", "--unset", "--chdir") else 1
        elif head == "env" and "=" in t:
            i += 1
        else:
            return False
    return True


def env_dump(head, seg):
    """The command when it prints the shell's variables (export, declare -p, typeset -x ...), or a secret-named one."""
    if head not in ("export", "declare", "typeset"):
        return None
    args = seg[1:]
    flags = "".join(t[1:] for t in args if re.fullmatch(r"-[A-Za-z]+", t))
    names = [t for t in args if not t.startswith("-")]
    lists = (head == "export" and ("p" in flags or not args)) or (head != "export" and ("p" in flags or "x" in flags))
    if head != "export" and not args:
        lists = True
    if lists and not any("=" in t for t in names):
        if not names or any(SECRET_ENV_NAME.search(t) for t in names):
            return " ".join(seg[:2])
    return None


PROC_FILE = re.compile(r"/proc/[^/\s]*/(?:task/[^/\s]*/)?(?:cmdline|environ)\b")
PS_UNSAFE_FIELDS = {"args", "command", "cmd", "cmdline", "arguments"}
PS_BSD_ONLY_BLOCK = set("e")  # BSD `e` appends the environment; with a dash, -e means every process
PS_VALUE_LETTERS = set("pPtCGgUsq")
PS_BLOCK_LETTERS = set("fFlwWuE")  # full listing, long, wide, user format, environment


def proc_file_reachable(token):
    """True when a word names, or by wildcard or brace could name, /proc/<pid>/cmdline or /proc/<pid>/environ."""
    if "/proc/" not in token:
        return False
    if PROC_FILE.search(token):
        return True
    variants = brace_variants(EXTGLOB_GROUP.sub("*", token))
    if variants is None:
        return True  # too many brace choices to judge: treat as a hit
    for v in variants:
        rest = v.partition("/proc/")[2].split("/")
        if len(rest) >= 2 and any(fnmatch.fnmatchcase(f, rest[-1]) for f in ("cmdline", "environ")):
            return True
    return False


def ps_fields_unsafe(value):
    # GNU procps allows a width suffix (args:100), so drop `:<width>` before comparing
    return any(f.split("=")[0].split(":")[0].strip().lower() in PS_UNSAFE_FIELDS for f in re.split(r"[,\s]+", value) if f)


def ps_prints_arguments(seg):
    """True unless ps is given an explicit -o list of names and numbers only (plain ps prints arguments on macOS)."""
    toks, i, has_format = seg[1:], 0, False
    while i < len(toks):
        t = toks[i]
        i += 1
        if t.startswith("--"):
            name, _, val = t.partition("=")
            if name == "--format":
                has_format = True
                val = val or (toks[i] if i < len(toks) else "")
                i += 0 if "=" in t else 1
                if ps_fields_unsafe(val):
                    return True
            elif name in ("--width", "--cols", "--columns", "--forest"):
                return True
            continue
        letters = t[1:] if t.startswith("-") else t  # BSD words (aux, axo) are read like clusters
        if not letters or not re.fullmatch(r"[A-Za-z]+", letters):
            continue
        dash = t.startswith("-")
        if dash and letters == "u":
            i += 1  # `-u NAME` selects a user
            continue
        for k, ch in enumerate(letters):
            if ch in "oO":
                has_format = has_format or ch == "o"
                rest = letters[k + 1:]
                val = rest or (toks[i] if i < len(toks) else "")
                i += 0 if rest else 1
                if ch == "O" or ps_fields_unsafe(val):
                    return True
                break
            if ch in PS_VALUE_LETTERS:
                i += 0 if letters[k + 1:] else 1
                break
            if ch in PS_BLOCK_LETTERS or (not dash and ch in PS_BSD_ONLY_BLOCK):
                return True
    return not has_format


def unwrap_runner(head, seg):
    """(head, seg) of the program a runner word starts: `env ps aux`, `sudo -u x ps aux`, `nice -n 5 ps aux`,
    `timeout 5 ps aux`. Shell bodies (`sh -c`) are handled separately by wrapped_command."""
    runners = WRAPPERS | {"timeout", "stdbuf"}
    while head in runners and len(seg) > 1:
        takes_arg = WRAPPER_ARG_OPTS.get(head, set()) | ({"-s", "-k", "--signal", "--kill-after"} if head == "timeout" else set())
        rest, skip, need_duration = [], False, head == "timeout"
        for t in seg[1:]:
            if skip:
                skip = False
            elif t.startswith("-") and not rest:
                skip = t in takes_arg
            elif need_duration and not rest:
                need_duration = False  # timeout's DURATION
            elif rest or not re.fullmatch(r"[A-Za-z_]\w*=.*", t):
                rest.append(t)
        if not rest:
            return head, seg
        seg = rest
        head = os.path.basename(seg[0])
    return head, seg


def process_listing_violation(head, seg):
    """A hit string when the command prints other programs' command lines or environments, else None."""
    head, seg = unwrap_runner(head, seg)
    if head == "find" and any(t == "/proc" or t.startswith("/proc/") for t in seg[1:]) and any(
            "cmdline" in t or "environ" in t for t in seg[1:]):
        return "process:/proc"
    if any(proc_file_reachable(t) for t in seg):
        return "process:/proc"
    if head == "ps" and ps_prints_arguments(seg):
        return "process:ps"
    if head == "pgrep":
        # short flags in any split or cluster (-a, -f -l, -lf) and the long forms
        short = "".join(t[1:] for t in seg[1:] if re.fullmatch(r"-[A-Za-z]+", t))
        longs = {t.partition("=")[0] for t in seg[1:] if t.startswith("--")}
        if "a" in short or ("f" in short and "l" in short) or longs & {"--list-full"} or (
                longs & {"--full"} and longs & {"--list-name", "--list-full"}):
            return "process:pgrep"
    return None


def bash_violation(cmd, bodies=None, depth=0):
    bodies = [] if bodies is None else bodies
    cmd = hoist_substitutions(cmd, bodies)
    parts = list(segments_sep(cmd))
    shadowed = shadowed_consumers(cmd)
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
            if depth >= MAX_SHELL_DEPTH:
                return "a shell nested more than %d deep" % MAX_SHELL_DEPTH
            hit = bash_violation(inner, bodies, depth + 1)
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
        listing = process_listing_violation(head, seg)
        if listing:
            return listing
        if head in ("printenv", "env", "set") and len(seg) == 1:
            return head
        if env_lists_all(head, seg):
            return " ".join(seg[:2])
        dump = env_dump(head, seg)
        if dump:
            return dump
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
        piped = (sep == "|" and n + 1 < len(parts) and main in PIPE_PRODUCERS
                 and is_consumer(parts[n + 1][0], final=parts[n + 1][1] != "|", shadowed=shadowed))
        for i, t in enumerate(seg):
            if i and seg[i - 1] in ("--exclude", "--exclude-dir"):
                continue  # the pattern after an exclude flag names what to skip
            hit = secret_mention(t)
            if hit and not mention_ok(main, seg, i, piped):
                return hit
    return None


CODE_TYPES = {"c", "cpp", "cs", "go", "java", "js", "jsx", "kt", "lua", "php", "py", "rb", "rs", "scala", "swift", "ts", "tsx"}


TYPE_EXTENSIONS = {  # mirrors ripgrep's built-in type list (rg --type-list); a name ending in .in also counts for c and cpp
    "c": (".c", ".h", ".cats"), "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".h", ".c", ".inl"),
    "cs": (".cs",), "go": (".go",), "java": (".java", ".jsp", ".jspx", ".properties"),
    "js": (".js", ".mjs", ".cjs", ".jsx", ".vue"), "jsx": (".jsx",), "kt": (".kt", ".kts"), "lua": (".lua",),
    "php": (".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".pht", ".phtml"), "py": (".py", ".pyi"),
    "rb": (".rb",), "rs": (".rs",), "scala": (".scala", ".sbt"), "swift": (".swift",),
    "ts": (".ts", ".tsx", ".mts", ".cts"), "tsx": (".tsx",), "vue": (".vue",), "svelte": (".svelte", ".svelte.ts"),
}
WALK_MAX_ENTRIES, WALK_MAX_SECONDS = 5000, 1.0
WALK_SKIP = {".git"}


def gitignores_node_modules(directory, cache={}):
    """Whether ripgrep would skip a node_modules folder inside this directory: only when a .gitignore at or below the
    repository root names it (and nothing un-ignores it). Outside a git repository ripgrep reads no .gitignore."""
    directory = os.path.abspath(directory)
    if directory in cache:
        return cache[directory]
    chain, here, root = [], directory, None
    while True:
        chain.append(here)
        if os.path.exists(os.path.join(here, ".git")):
            root = here
            break
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    ignored = False
    if root:
        for d in reversed(chain):
            try:
                lines = [ln.strip() for ln in open(os.path.join(d, ".gitignore"), errors="replace")]
            except OSError:
                continue
            if any(ln in ("!node_modules", "!node_modules/", "!/node_modules", "!**/node_modules") for ln in lines):
                ignored = False
            elif any(ln in ("node_modules", "node_modules/", "/node_modules", "/node_modules/", "**/node_modules", "**/node_modules/")
                     for ln in lines):
                ignored = True
    cache[directory] = ignored
    return ignored


def selected_by(name, rel, file_glob, exts):
    """Whether a Grep glob and/or type would select this file. Over-selecting is safe: it can only block more."""
    low = name.lower()
    if exts and not (low.endswith(exts) or (low.endswith(".in") and low[:-3].endswith(exts))):
        return False
    if file_glob:
        pats = brace_variants(file_glob) or [file_glob]
        if not any(fnmatch.fnmatchcase(name, g) or fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(rel, "*/" + g.lstrip("/"))
                   for g in pats):
            return False
    return True


def protected_file_selected(root, file_glob, exts):
    """Walk root (bounded, dot-folders included) for a protected file the glob/type would select.
    Returns its path, "narrow:search" when the walk hit its bound, or None."""
    root = os.path.expanduser(root or ".")
    if os.path.isfile(root):
        return None  # a protected single file was already refused by name
    start, seen = time.monotonic(), 0
    for here, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in WALK_SKIP
                   and not (d == "node_modules" and gitignores_node_modules(here)) and not (  # a Windows junction is a link os.walk may still enter
            hasattr(os.path, "isjunction") and os.path.isjunction(os.path.join(here, d)))]
        for name in files:
            seen += 1
            if seen > WALK_MAX_ENTRIES or time.monotonic() - start > WALK_MAX_SECONDS:
                return "narrow:search"
            full = os.path.join(here, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if is_secret_path(full) and selected_by(name, rel, file_glob, exts):
                return full
        seen += len(dirs)
    return None


def unrestricted_content_search(inp):
    """A content search that can print lines from secret files. A glob or code type narrows it only when no protected
    file under the search path would be selected (checked by walking the path); without either, a folder is refused.
    Searches that list file names or counts print no file content."""
    if inp.get("output_mode") != "content":  # the tool's default (and files_with_matches / count) shows no file content
        return None
    path, file_glob = inp.get("path"), inp.get("glob")
    file_type = str(inp.get("type") or "").lower()
    exts = TYPE_EXTENSIONS.get(file_type)
    positive_glob = bool(file_glob) and not str(file_glob).lstrip().startswith("!")
    path_text = str(path or "")
    basename = os.path.basename(path_text.rstrip("/\\"))
    single_file = (bool(path_text) and path_text.rstrip("/") not in BROAD_PATHS
                   and ("." in basename or os.path.isfile(os.path.expanduser(path_text)))  # README, Makefile: real files
                   and not path_text.startswith("~") and not GLOB_CHARS.search(path_text)
                   and not BRACE_EXPANSION.search(path_text) and not os.path.isdir(os.path.expanduser(path_text)))
    if single_file:
        return None
    if not (exts or positive_glob):
        return "broad:search"
    if GLOB_CHARS.search(path_text) or BRACE_EXPANSION.search(path_text):
        return "broad:search"
    return protected_file_selected(path_text, str(file_glob) if positive_glob else None, tuple(exts) if exts else None)


def pre_tool(data):
    tool, inp = data.get("tool_name"), data.get("tool_input") or {}
    if tool == "Read":
        hit = inp.get("file_path") if is_secret_path(inp.get("file_path") or "") else None
    elif tool == "Grep":
        content = inp.get("output_mode") == "content"
        # A named secret file is refused in every mode; a wildcard that could select one only when lines are printed.
        hit = next((v for v in (inp.get("path"), inp.get("glob"))
                    if v and (content or not (GLOB_CHARS.search(str(v)) or BRACE_EXPANSION.search(str(v))))
                    and (is_secret_path(v) or os.path.basename(v).startswith(".env")
                         and os.path.basename(v) not in EXEMPT)), None)
        hit = hit or unrestricted_content_search(inp)
    elif tool == "Bash":
        hit = bash_violation(inp.get("command") or "")
    else:
        hit = None
    if hit and hit.startswith("process:"):
        sys.stderr.write("stack-guard secret guard: process command lines can hold other programs' keys; "
                         "list names only: `ps -axo comm`\n")
        sys.exit(2)
    if hit:
        hint = ""
        if hit == "broad:search":
            hit = "any secret file under that search"
            hint = (" Give the Grep tool a narrower path (one file), a code type, or a glob that cannot match a secret file;"
                    " or use output_mode files_with_matches to list only file names.")
        elif hit == "narrow:search":
            hit = "a protected file somewhere under that search"
            hint = " Narrow the search to the source folders you need (a smaller path), or name one file."
        elif hit.startswith("recursive:"):
            hit = "any secret file under that search"
            hint = " To search code, use `rg PATTERN` (it skips ignored files like .env) or name the source folders."
        sys.stderr.write(
            "stack-guard secret guard: that would put the contents of %s into this chat. "
            "stack-guard never needs a secret's value; let the project's own scripts load it "
            "(eg. `$(...)`, `source`, or the script itself).%s\n" % (hit, hint))
        sys.exit(2)


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
        else:
            pre_tool(data)
    except Exception:  # shortcut: any internal error allows the call, so a bug never breaks the session
        sys.exit(0)


if __name__ == "__main__":
    main()
