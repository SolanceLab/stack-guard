---
description: Write STACK-INVENTORY.md, a plain list of everything you build and run (projects, where each is deployed, runtimes, packages, MCP servers), so nothing gets forgotten when the next security alert lands
argument-hint: '[folder, default: this folder]'
---

You are building the user's stack inventory. Arguments: $ARGUMENTS

The list is made by the plugin's script, so it comes out the same every time. Run it, then explain the result.

1. Folder: the one named in the arguments, else the current folder.
2. Run (Python 3.9+, standard library only, nothing to install):

```
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/stack_guard.py" inventory "<folder>"
```

It writes `<folder>/STACK-INVENTORY.md` and `<folder>/.stack-guard/inventory.json`, adds `.stack-guard/` to the folder's `.gitignore` when it is a git repo, and prints one summary line. It sends nothing over the network.
3. Read `STACK-INVENTORY.md` and tell the user, in plain words: how many projects, deploy configs, MCP servers and runtimes it found; the "Needs a look" rows first; any MCP server that updates itself on every start; any runtime past its support date.
4. When `python3` is missing, say so and offer to build the list by hand from the `stack-guard:stack-audit` skill's steps 1, 2b and 3, written in the same shape.
5. Suggest next: `/stack-guard` to check everything on the list for security holes, and `/stack-guard:watch` to check it every day.
