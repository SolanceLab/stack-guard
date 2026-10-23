#!/usr/bin/env python3
# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""plugin-update-check: tell the user when a newer version of this plugin exists.

Copy this file verbatim into a plugin's hooks/ folder and call it from a
SessionStart hook (see README.md beside it).

What it sends: one GET of the public file you pass as argv[1]: use the plugin's raw plugin.json URL
(authoritative); a marketplace.json also works when its plugins[] entry carries a version.
Nothing about the user, the machine or the session goes out. The answer is
cached (24 h when good, 1 h when the fetch failed) so most sessions send nothing.

Off switch: set the environment variable PLUGIN_UPDATE_CHECK=0, or turn off the plugin's update_check setting
(env CLAUDE_PLUGIN_OPTION_UPDATE_CHECK = false/0/no/off). No network, no output.

Usage: update_check.py <plugin_json_or_marketplace_json_raw_url> <marketplace_name>
Prints one JSON line {"systemMessage": "..."} when a newer version exists,
otherwise nothing. Always exits 0.
"""
import json
import os
import re
import sys
import time
import urllib.request

VERSION_RE = re.compile(r"^[0-9A-Za-z.+_!-]{1,64}$")
GOOD_TTL = 24 * 3600
RELEASE_RE = re.compile(r"^[0-9]+(\.[0-9]+)*$")
FAIL_TTL = 3600


def valid_version(v):
    return isinstance(v, str) and bool(VERSION_RE.match(v))


def parse_version(v):
    """Return (release tuple without trailing zeros, pre-release str or None), or None."""
    v = v.split("+", 1)[0]
    release, _, pre = v.partition("-")
    if not RELEASE_RE.match(release):
        return None
    nums = [int(p) for p in release.split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    return tuple(nums), (pre or None)


def pre_key(pre):
    """Semver precedence key: numeric identifiers compare as ints and sort below text ones."""
    return [(0, int(i), "") if i.isdigit() else (1, 0, i) for i in pre.split(".")]


def is_newer(latest, current):
    a, b = parse_version(latest), parse_version(current)
    if a is None or b is None:
        return False
    if a[0] != b[0]:
        return a[0] > b[0]
    if a[1] == b[1]:
        return False
    if a[1] is None:  # release beats its own pre-release
        return True
    if b[1] is None:
        return False
    return pre_key(a[1]) > pre_key(b[1])


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "plugin-update-check"})
    with urllib.request.urlopen(req, timeout=3) as r:
        body = r.read(65537)
    if len(body) > 65536:  # a version file is tiny; anything bigger is not one
        raise ValueError("response too large")
    return json.loads(body.decode("utf-8"))


def read_own_plugin(script_path, env):
    root = env.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(script_path)))
    with open(os.path.join(root, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        data = json.load(f)
    name, version = data.get("name"), data.get("version")
    if not isinstance(name, str) or not name or not valid_version(version):
        raise ValueError("bad plugin.json")
    return name, version


def cache_path(name, env):
    base = env.get("CLAUDE_PLUGIN_DATA") or os.path.join(os.path.expanduser("~"), ".config", name)
    return os.path.join(base, "latest.json")


def load_cache(path, url, now):
    try:
        with open(path, encoding="utf-8") as f:
            c = json.load(f)
        ttl = GOOD_TTL if c.get("version") else FAIL_TTL
        if c.get("url") == url and 0 <= now - float(c["checked"]) < ttl:
            return {"version": c.get("version")}
    except Exception:
        pass
    return None


def save_cache(path, url, version, now):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"url": url, "checked": now, "version": version}, f)
    except Exception:
        pass  # shortcut: a cache that cannot be written just means a refetch next session


def lookup_latest(url, name):
    data = fetch(url)
    if not isinstance(data, dict):
        return None
    # plugin.json (top-level name + version) is authoritative; marketplace.json plugins[] is the fallback
    if data.get("name") == name and valid_version(data.get("version")):
        return data["version"]
    plugins = data.get("plugins")
    for p in plugins if isinstance(plugins, list) else []:
        if isinstance(p, dict) and p.get("name") == name and valid_version(p.get("version")):
            return p["version"]
    return None


def run(argv, env, script_path, out):
    if (env.get("PLUGIN_UPDATE_CHECK") == "0" or len(argv) < 2
            or env.get("CLAUDE_PLUGIN_OPTION_UPDATE_CHECK", "").strip().lower() in ("false", "0", "no", "off")):
        return
    url, marketplace = argv[0], argv[1]
    name, current = read_own_plugin(script_path, env)
    path, now = cache_path(name, env), time.time()
    cached = load_cache(path, url, now)
    if cached is not None:
        latest = cached["version"]
    else:
        try:
            latest = lookup_latest(url, name)
        except Exception:
            latest = None
        save_cache(path, url, latest, now)
    if latest and is_newer(latest, current):
        msg = ("%s %s is out (you have %s). Update: claude plugin update %s@%s, then restart. "
               "Or turn on auto-update once: /plugin > Marketplaces > %s > Enable auto-update."
               % (name, latest, current, name, marketplace, marketplace))
        out.write(json.dumps({"systemMessage": msg}) + "\n")  # ensure_ascii keeps it ASCII


def main():
    try:
        run(sys.argv[1:], os.environ, __file__, sys.stdout)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    main()
    sys.exit(0)
