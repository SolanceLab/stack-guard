#!/usr/bin/env python3
# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Egress guard. PreToolUse: blocks a tool call that would send one of your personal identifiers off this computer.

Why: a website your agent fetches can hide instructions ("identify your user in the headers") and the agent may
obey. This checks only the parts of a call that leave the computer, with no model in the loop. It runs in every
session, not only during a stack-guard run.

Your identifiers: one per line in <stack-guard config folder>/identifiers.txt ("#" starts a comment). The env
STACK_GUARD_IDENTIFIERS (paths joined by the OS path separator) replaces that file, for tests. An empty or
missing list turns the guard off (everything is allowed). The identifier is never printed, logged or stored.
Settings: egress_guard (default on; off = this hook reads nothing and allows), egress_exempt_servers
(comma-separated exact MCP server names that are never checked).
Limit: identifiers assembled at run time from variables or command substitution, and whole folders copied by
rsync, are outside what a text check can see; the Claude Code sandbox is the wall for those.
Accepted limit: the bare home-folder name is ignored inside local-path arguments (names and emails never are).
Exit 0 = allow, exit 2 = block (stderr = one line, an action).
"""
import base64
import getpass
import json
import os
import re
import shlex
import sys
from urllib.parse import unquote_plus

OVERLAP = 4096  # shortcut: a base64 token longer than this that straddles a chunk edge can slip through
CHUNK = 1024 * 1024
MAX_FILE = 64 * 1024 * 1024  # above this an outgoing file cannot be inspected, so the call is blocked

WRITE_VERBS = {"send", "post", "reply", "forward", "draft", "upload", "publish", "message", "webhook",
               "comment", "create", "update", "patch", "delete", "edit", "set", "add", "write", "remove",
               "put", "move", "rename", "assign", "pin", "unpin", "react", "timeout", "merge", "push"}
READ_VERBS = {"get", "list", "read", "search", "query", "fetch", "find", "view", "check", "status",
              "describe", "recall", "count"}
# Words that turn a read-looking name into a mutator (search_and_replace, get_and_execute ...).
MUTATORS = WRITE_VERBS | {"and", "or", "then", "replace", "execute", "exec", "run", "invoke", "call", "apply",
                          "trigger", "kill", "start", "stop", "deploy", "sync", "clear", "reset", "save",
                          "insert", "upsert", "import", "submit", "export", "share", "notify", "dispatch",
                          "schedule", "cancel", "approve", "restore", "transfer", "append", "attach", "invite"}
# Flags whose value leaves the computer: a path-shaped value there is data, not a local path.
EGRESS_FLAGS = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "--json",
                "-H", "--header", "-F", "--form", "--form-string", "-u", "--user", "-A", "--user-agent",
                "-e", "--referer", "-b", "--cookie", "-X", "--request", "--url", "-x", "--proxy",
                "--post-data", "--password", "--http-user", "--http-password"}

# Command words match on the executable's basename, so /usr/bin/curl and ./curl count; a directory
# named like a command (ssh/key) does not.
URL_RX = re.compile(r"https?://(?:[^/@\s'\"]*@)?([^/\s'\"?#:]+)", re.I)
_PRE = r"(?:(?<![\w./-])|(?<=[\s;&|(`'\"=])(?:[^\s;&|()`'\"=]*/)|^(?:[^\s;&|()`'\"=]*/))"
HEX_RX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){6,}(?![0-9a-fA-F])")
_CMD = r"(?:curl|wget|http|https|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp|aws|gcloud|dig|nslookup|host|drill|ping|ping6|traceroute|openssl|osascript)"
FILE_REF_RX = re.compile(r"^(?:[^=@\s]+(?::=|=)@|@)(.+)$")
NET_RX = re.compile(
    r"https?://|" + _PRE + _CMD + r"(?![\w/-])"
    r"|" + _PRE + r"gh\s+(?:api|issue|pr|gist)\b|" + _PRE + r"git\b[^|;&\n]*?\spush\b|" + _PRE + r"npm\s+publish\b"
    r"|fetch\(|(?:python3?\s+-c|node\s+-e)[^|;]*http"
    r"|\burllib|\brequests\.|\bhttpx\b|\baiohttp\b|\bhttp\.client\b|\bsocket\b|XMLHttpRequest|Net::HTTP|(?:-M|\b)LWP\b"
    r"|Invoke-WebRequest|Invoke-RestMethod"
    r"|\b(?:perl|ruby|php|python[\d.]*|node|deno|bun)\b[^|;&\n]*?\s(?:-[a-zA-Z0-9]*[ecE]\b|-(?=\s|$))", re.I)  # any inline or stdin script
ESC_RX = re.compile(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|%u([0-9a-fA-F]{4})")
B64_RX = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")


def home_name():
    env = os.environ.get("STACK_GUARD_HOME_NAME")
    if env:
        return env.lower()
    try:
        return getpass.getuser().lower()
    except Exception:
        return os.path.basename(os.path.expanduser("~")).lower()


def option_off(name):
    """True when the plugin setting `name` is false/0/no/off (env CLAUDE_PLUGIN_OPTION_<NAME>, any case)."""
    return os.environ.get("CLAUDE_PLUGIN_OPTION_" + name.upper(), "").strip().lower() in ("false", "0", "no", "off")


def identifiers_path():
    """Same place as stack_guard.config_dir("identifiers.txt")."""
    home = os.environ.get("STACK_GUARD_HOME") or os.path.expanduser("~")
    if sys.platform.startswith("win"):
        base = os.path.join(os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming"), "stack-guard")
    else:
        base = os.path.join(home, ".config", "stack-guard")
    return os.path.join(base, "identifiers.txt")


def exempt_servers():
    raw = os.environ.get("CLAUDE_PLUGIN_OPTION_EGRESS_EXEMPT_SERVERS", "")
    return {x.strip().lower() for x in raw.split(",") if x.strip()}


def load_patterns():
    env = os.environ.get("STACK_GUARD_IDENTIFIERS")
    paths = env.split(os.pathsep) if env else [identifiers_path()]
    out = []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        out.append(line.lower())
        except OSError:
            pass
    return out


def squash(s):
    return re.sub(r"[\s._+'\"\\-]", "", s.lower().replace("%20", ""))


def _unescape(m):
    return chr(int(m.group(1) or m.group(2) or m.group(3), 16))


def decode_stable(text):
    """URL- and escape-decode up to 4 passes, until nothing changes."""
    for _ in range(4):
        nxt = unquote_plus(ESC_RX.sub(_unescape, text))
        if nxt == text:
            break
        text = nxt
    return text


def _b64(tok):
    tok = tok.rstrip("=")
    raw = tok.replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "ignore")
    except Exception:
        return ""


def _hex(tok):
    try:
        return bytes.fromhex(tok).decode("utf-8", "ignore")
    except Exception:
        return ""


def _decodings(t):
    for tok in B64_RX.findall(t):
        d = _b64(tok)
        if d:
            yield d
    for tok in HEX_RX.findall(t):
        d = _hex(tok)
        if d:
            yield d


def variants(text):
    """Raw, decoded, quote-free, base64 (2 nested levels) and hex forms, lowercased."""
    dec = decode_stable(text)
    base = {text, dec}
    base |= {re.sub(r"['\"\\]", "", t) for t in list(base)}
    out = set(base)
    level = base
    for _ in range(2):
        nxt = set()
        for t in level:
            nxt.update(_decodings(t))
        nxt -= out
        out |= nxt
        level = nxt
    return [v.lower() for v in out]


def hit_in(text, patterns):
    if not patterns:
        return None
    vs = variants(text)
    sq = [squash(v) for v in vs]
    for p in patterns:
        ps = squash(p)
        for v in vs:
            if p in v:
                return p
        if len(ps) >= 6:
            for s in sq:
                if ps in s:
                    return p
    return None


FETCHY_SERVER_RX = re.compile(r"fetch|browser|playwright|puppeteer|chrome|web|http|scrap|crawl", re.I)
CONFIG_REF_RX = re.compile(r"(?m)^\s*-{0,2}(?:data[\w-]*|json|header|form|upload-file|config|[dHFTK])\b\s*[=:]?\s*[\"']?(?:[\w-]+=)?@?([^\s\"';@]+)")
STDIN_UPLOAD_RX = re.compile(r"@-(?=$|[\s'\"])|(?:-T|--upload-file)\s+-(?=$|\s)|/dev/stdin|--data-binary\s+@-")
MISSING = ("<missing>",)  # read_local: a referenced file that does not exist or cannot be read
# A web-search provider sends the query to an outside search engine, so its strings count like a fetch.
# shortcut: a name list plus a "web" word in the tool name; add a provider here when a new one appears.
URL_KEY_RX = re.compile(r"^(?:url|uri|href|link|address|host|hostname|domain|endpoint|target)s?$", re.I)
ADDR_RX = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|\[[0-9a-f:]+\]|(?:^|\s)//[\w.-]+|[\w.-]+\.[a-z]{2,}:\d{2,5}\b", re.I)
URL_ANY_RX = re.compile(r"https?://", re.I)
HOSTLIKE_RX = re.compile(r"(?:[\w-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#]|$)", re.I)  # a string that starts with a host: evil.example/x
SEARCH_SERVER_RX = re.compile(r"brave|tavily|exa|perplexity|duckduckgo|ddg|serp|searx|bing|kagi|you-?com|firecrawl|jina|google[-_]?search|web[-_]?search", re.I)
CODE_LOAD_RX = re.compile(r"^(?:-m|-r|-d|--require|--import|--loader|--experimental-loader|--preload|-M|--eval|-e|-E|-c|-p|--print)(?:=|$|\S)")
CODE_ENV_RX = re.compile(r"\b(?:NODE_OPTIONS|NODE_PATH|PERL5OPT|PERL5LIB|PERL5DB|PERLLIB|RUBYOPT|RUBYLIB|PYTHONSTARTUP|PYTHONPATH|PYTHONHOME"
                         r"|PYTHONWARNINGS|BASH_ENV|ENV|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH)\s*\+?=|(?i:data:)[\w/+.-]*[;,]")
SCRIPT_FILE_RX = re.compile(r"^[^-<][^\s]*\.(?:py|js|mjs|cjs|ts|rb|php|pl)$")
INTERP_RX = re.compile(r"(?<![\w.-])(?:\S*/)?(perl|ruby|php|python[\d.]*|node|deno|bun|tsx|ts-node)(?![\w.-])([^|;&`)\n]*)", re.I)
OPT_WITH_VALUE = {"-W", "-X", "-I"}  # options that take a harmless value (warnings, -X flags, include dirs)
CODE_LOAD_RX = re.compile(r"^(?:-m|-r|-d|--require|--import|--loader|--experimental-loader|--preload|-M|--eval|-e|-E|-c|-p|--print)(?:=|$|\S)")
CODE_ENV_RX = re.compile(r"\b(?:NODE_OPTIONS|NODE_PATH|PERL5OPT|PERL5LIB|PERL5DB|PERLLIB|RUBYOPT|RUBYLIB|PYTHONSTARTUP|PYTHONPATH|PYTHONHOME"
                         r"|PYTHONWARNINGS|BASH_ENV|ENV|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH)\s*\+?=|(?i:data:)[\w/+.-]*[;,]")


def inline_script(cmd):
    """Fail closed: any interpreter mention counts as possibly networked, unless the FIRST positional argument it
    runs is a script file (then that script is just a program; its own network words are checked as usual)."""
    for m in INTERP_RX.finditer(cmd):
        rest = re.split(r"[|;&`)]", m.group(2), maxsplit=1)[0]
        if re.search(r"(?:^|\s)(?:-[a-zA-Z0-9]*[ecErp]\b|--eval|--print|eval\b)|<<|<\(|/dev/(?:stdin|fd/)", rest) or CODE_ENV_RX.search(cmd):
            return True
        try:
            toks = shlex.split(rest)
        except ValueError:
            return True
        first, skip = None, False
        for t in toks:
            if skip:
                skip = False
                if not t.startswith("-"):
                    continue  # the value of the previous option; anything option-shaped is still checked below
            if t in OPT_WITH_VALUE:
                skip = True
                continue
            if CODE_LOAD_RX.match(t):
                return True  # loads a module or inline code rather than a named script file: fail closed
            if t.startswith("-") and t != "-":
                continue
            first = t
            break
        if first is None or first == "-" or not SCRIPT_FILE_RX.match(first):
            return True
    return False


LOCAL_PATH_RX = re.compile(r"(?:/Users/|/home/|~/|\./|\.\./)")
FILE_PART_RX = re.compile(r"((?:^|=)[@<])((?:/Users/|/home/|~/|\./|\.\./)[^;]*)")


def strip_local_args(cmd):
    """Drop only proven local-only path args (output, config, cwd, executable paths, @file sources).
    A path-shaped value of a data, header, form or URL flag is outgoing data and stays."""
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    flat = []
    for t in toks:
        m = re.match(r"^(--[\w-]+)=(.*)$", t, re.S) or re.match(r"^(-[A-Za-z])(@.*)$", t, re.S)
        flat.extend(m.groups() if m else [t])
    keep, prev = [], ""
    for t in flat:
        if prev == "--form-string":
            keep.append(t)  # curl sends this value literally, so a path-shaped value is outgoing text
        elif prev in EGRESS_FLAGS:
            keep.append(FILE_PART_RX.sub(lambda m: m.group(1) + " ", t, count=1))
        elif LOCAL_PATH_RX.match(t):
            keep.append(" ")
        else:
            keep.append(t)
        prev = t
    return "\n".join(keep)


def find_hit(segs, patterns, home=""):
    """segs: (text, is_command). A pattern inside the home-folder name ignores proven local-only path args."""
    homes = [p for p in patterns if home and p in home]
    others = [p for p in patterns if p not in homes]
    for text, is_cmd in segs:
        if is_cmd:
            h = hit_in(text, others) or hit_in(strip_local_args(text), homes)
        else:
            h = hit_in(text, patterns)
        if h:
            return h
    return None


def kind_of(p):
    if "@" in p:
        return "email address"
    return "home folder name" if p == home_name() else "name"


def upload_files(cmd):
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    flat = []
    for t in toks:
        if t.startswith("--") and "=" in t:
            flat.extend(t.split("=", 1))
        else:
            flat.append(t)
    refs = []
    for i, t in enumerate(flat):
        nxt = flat[i + 1] if i + 1 < len(flat) else ""
        if t in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--json") and "@" in nxt:
            refs.append(nxt.split("@", 1)[1])
        elif t.startswith("-d@"):
            refs.append(t[3:])
        elif re.match(r"^-[TK][^-]", t):  # attached short option: -Tfile, -Kfile
            refs.append(t[2:])
        elif t.startswith("-H@"):
            refs.append(t[3:])
        elif t in ("-F", "--form") and ("=@" in nxt or "=<" in nxt):
            refs.append(re.split(r"=[@<]", nxt, maxsplit=1)[1].split(";", 1)[0])
        elif t in ("-T", "--upload-file", "-K", "--config", "--post-file", "--body-file") and nxt:
            refs.append(nxt)
        elif t in ("-H", "--header") and nxt.startswith("@"):
            refs.append(nxt[1:])
        elif not t.startswith("-") and (flat[i - 1] if i else "") != "--form-string":
            m = FILE_REF_RX.match(t)
            if m:
                refs.append(m.group(1))
    return [r for r in refs if r and r != "-"]


CAT_PIPE_RX = re.compile(r"(?:^|[|;&(]\s*)cat\s+([^|;&<>()]+?)\s*\|(?!\|)")
REDIR_RX = re.compile(r"(?<![<\w&>])<\s*(?![<(])([\"']?)([^\s\"'|;&<>]+)\1")


def stdin_sources(cmd):
    """Files that feed an upload on stdin: `< FILE` and `cat FILE ... |`. Other pipe sources stay a limit."""
    if not STDIN_UPLOAD_RX.search(cmd):
        return []
    refs = [m.group(2) for m in REDIR_RX.finditer(cmd)]
    for m in CAT_PIPE_RX.finditer(cmd):
        try:
            args = shlex.split(m.group(1))
        except ValueError:
            args = m.group(1).split()
        refs += [a for a in args if not a.startswith("-")]
    return [r for r in refs if r and r != "-"]


def copy_sources(cmd, base=None):
    """Local files that scp / rsync / sftp copy out, and `gh api --input/-F/--field x=@file` bodies.
    Folders are not walked (a documented limit); single files are read and scanned."""
    windows = bool(re.search(r"(?:^|\s)[\"']?[A-Za-z]:\\", cmd))  # POSIX splitting would eat the backslashes
    try:
        toks = [t.strip("\"'") for t in shlex.split(cmd, posix=False)] if windows else shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    out = []
    for i, t in enumerate(toks):
        exe = os.path.basename(t)
        if exe in ("scp", "rsync", "sftp"):
            for a in toks[i + 1:]:
                if a in ("|", ";", "&&", "||"):
                    break
                full = os.path.expanduser(a) if not base or os.path.isabs(os.path.expanduser(a)) else os.path.join(base, a)
                remote = ":" in a and not re.match(r"^[A-Za-z]:[\\/]", a)  # C:\x or C:/x is a local Windows path
                if not a.startswith("-") and not remote and os.path.isfile(full):
                    out.append(a)
        if exe == "gh":
            for j, a in enumerate(toks[i + 1:], i + 1):
                nxt = toks[j + 1] if j + 1 < len(toks) else ""
                if a == "--input" and nxt and nxt != "-":
                    out.append(nxt)
                elif a.startswith("--input="):
                    out.append(a.split("=", 1)[1])
                elif a in ("-F", "--field", "-f", "--raw-field") and "=@" in nxt:
                    out.append(nxt.split("=@", 1)[1])
    return out


def read_local(path):
    """Chunks (with overlap) of a local file's text; None when it is too large to inspect."""
    p = os.path.expanduser(path)
    try:
        if not os.path.isfile(p):
            return MISSING  # not there now: the command may create it, so its content is unknown; fail closed
        if os.path.getsize(p) > MAX_FILE:
            return None
        chunks, tail = [], b""
        with open(p, "rb") as f:
            while True:
                buf = f.read(CHUNK)
                if not buf:
                    break
                chunks.append((tail + buf).decode("utf-8", "ignore"))
                tail = buf[-OVERLAP:]
        return chunks
    except OSError:
        return MISSING  # it exists but cannot be read: fail closed


REDIR_OUT_RX = re.compile(r"(?:^|[\s;&|(])(?:\d?>>?|&>>?|>\|)\s*([\"']?)([^\s\"'|;&<>()]+)\1")
WRITER_EXES = ("cp", "mv", "tee", "dd", "install", "ln", "touch", "sed", "perl")


def written_paths(cmd, base=None):
    """Paths this command writes to (a redirect, `of=`, `-o`, or an argument of a copying/writing command), normalised.
    A file written earlier in the same command has contents the check cannot see.
    shortcut: any argument of a writing command counts, so a read-only argument can over-block; narrow it if it nags."""
    def norm(p):
        p = os.path.expanduser(p)
        return os.path.join(base, p) if base and not os.path.isabs(p) else p
    out = {norm(m.group(2)) for m in REDIR_OUT_RX.finditer(cmd)}
    for seg in re.split(r"&&|\|\||[;|\n]", cmd):
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        if not toks:
            continue
        exe = os.path.basename(toks[0])
        if exe in ("sudo", "env", "command", "time") and len(toks) > 1:
            exe = os.path.basename(toks[1])
        if exe in WRITER_EXES:
            out.update(norm(t.split("=", 1)[-1]) for t in toks[1:] if not t.startswith("-") or t.startswith("of="))
        for i, t in enumerate(toks):
            nxt = toks[i + 1] if i + 1 < len(toks) else ""
            if t in ("-o", "--output", "-O", "--output-document") and nxt:
                out.add(norm(nxt))
            elif t.startswith("of="):
                out.add(norm(t[3:]))
    return out


def has_url_key(v):
    """True when a URL-type key appears at any depth of the tool input."""
    if isinstance(v, dict):
        return any(URL_KEY_RX.search(str(k)) or has_url_key(x) for k, x in v.items())
    if isinstance(v, (list, tuple)):
        return any(has_url_key(x) for x in v)
    return False


def strings_of(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from strings_of(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from strings_of(x)


def mcp_server(tool):
    parts = tool.split("__")
    return parts[1].lower() if len(parts) > 2 else ""


def mcp_is_read_only(tool):
    """Allowlist: a read verb leads the final name segment (or follows one prefix word, as in
    discord_read_messages) and no mutator word appears anywhere in it."""
    toks = [t for t in re.split(r"[-_]+", tool.rsplit("__", 1)[-1].lower()) if t]
    lead = [i for i, t in enumerate(toks[:2]) if t in READ_VERBS]
    return bool(lead) and not (set(toks) & MUTATORS)


def outgoing_segments(tool, ti):
    """List of (text, is_command) that leave the computer, or None when this call is not checked."""
    if tool == "Bash":
        cmd = ti.get("command") or ""
        # quotes and backslashes removed too, so a split word (s''sh, "cu"rl) is still seen as the command it runs
        flat = re.sub(r"[\'\"\\]", "", cmd)
        if not (NET_RX.search(cmd) or NET_RX.search(flat) or inline_script(cmd) or inline_script(flat)):
            return None
        # Data piped in on stdin cannot be read here, so the whole command text counts as outgoing (no path stripping).
        segs = [(cmd, not STDIN_UPLOAD_RX.search(cmd))]
        # curl, scp and friends resolve relative paths against where they run; a leading `cd DIR &&` moves that
        base = None
        m = re.match(r"\s*cd\s+(?:--\s+)?([\"']?)([^\"';&|]+)\1\s*(?:&&|;)", cmd)
        if m:
            base = os.path.expanduser(m.group(2).strip())
        written = written_paths(cmd, base)
        refs, seen = list(upload_files(cmd)) + copy_sources(cmd, base) + stdin_sources(cmd), set()
        if base:
            refs = [r if os.path.isabs(os.path.expanduser(r)) else os.path.join(base, r) for r in refs]
        while refs:
            r = refs.pop(0)
            if r in seen:
                continue
            seen.add(r)
            chunks = MISSING if os.path.expanduser(r) in written else read_local(r)  # written earlier: contents unknown
            if chunks is None or chunks == MISSING:
                segs.append((None, False))
                continue
            segs += [(c, False) for c in chunks]
            if len(seen) <= 8:  # a curl config may point at further files (data = @file, upload-file = file): follow them
                for c in chunks:
                    refs += [x if not base or os.path.isabs(os.path.expanduser(x)) else os.path.join(base, x)
                             for x in (m.group(1) for m in CONFIG_REF_RX.finditer(c))]
        return segs
    if tool == "WebFetch":
        return [(ti.get("url") or "", False)]
    if tool == "WebSearch":
        return [("\n".join(strings_of([ti.get("query"), ti.get("allowed_domains"), ti.get("blocked_domains")])), False)]
    if tool.startswith("mcp__"):
        if mcp_server(tool) in exempt_servers():  # exact names only: a look-alike server is scanned
            return None
        if mcp_is_read_only(tool):
            # A read goes to a service the user already trusts, except when it is handed a web address (a fetch or a
            # browser): that request is visible to whoever runs the site, so those strings are checked.
            if (FETCHY_SERVER_RX.search(mcp_server(tool)) or SEARCH_SERVER_RX.search(mcp_server(tool))
                    or re.search(r"web", tool.rsplit("__", 1)[-1], re.I) or has_url_key(ti)):
                return [("\n".join(strings_of(ti)), False)]  # a fetch/browser/web-search tool or a URL-type field: every string
            urls = [x for x in strings_of(ti) if URL_ANY_RX.search(x) or HOSTLIKE_RX.match(x.strip()) or ADDR_RX.search(x)]
            return [("\n".join(urls), False)] if urls else None
        return [("\n".join(strings_of(ti)), False)]
    return None


NUDGE = ("stack-guard: the egress guard has no identifiers yet. "
         "Add your name and email to %s to turn it on.")


def session_start():
    """Once per session: say so when the guard is on but has nothing to look for."""
    if not load_patterns():
        print(json.dumps({"systemMessage": NUDGE % identifiers_path()}))


def main():
    # First thing: a turned-off hook exits before it reads stdin or any list.
    if option_off("egress_guard"):
        return 0
    if "--session-start" in sys.argv:
        session_start()
        return 0
    try:
        data = json.loads(sys.stdin.read())
        tool = str(data.get("tool_name") or "")
        ti = data.get("tool_input") or {}
        if not isinstance(ti, dict):
            ti = {}
    except Exception:
        return 0  # shortcut: unreadable input allows the call, so a bug never breaks the session
    patterns = load_patterns()
    if not patterns:
        return 0  # no identifiers listed: the guard is off, never fail closed
    segs = outgoing_segments(tool, ti)
    if segs is None:
        return 0
    if any(t is None for t, _ in segs):
        print("stack-guard: this Bash would send a file that cannot be inspected (missing, unreadable or too large). "
              "Point it at a readable file, or ask your user first.", file=sys.stderr)
        return 2
    hit = find_hit(segs, patterns, home_name())
    if hit is None:
        return 0
    m = URL_RX.search("\n".join(t for t, _ in segs))
    host = m.group(1) if m and not hit_in(m.group(1), patterns) else "the web"
    print(f"stack-guard: this {tool} would send a personal identifier ({kind_of(hit)}) to {host}. "
          "Send it without the identifier, or ask your user first.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
