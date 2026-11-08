"""Drift guard for the agent skills.

``skills/`` is the single source of truth; ``.pi/skills/`` is a byte-for-byte
mirror for Pi (refresh it with ``make skills``). Also enforces the strict-YAML
rule from INSTALL.md: Cline and the ``skills`` CLI reject a frontmatter value
that starts with a reserved character, so every scalar value is quoted.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "skills")
MIRROR = os.path.join(ROOT, ".pi", "skills")

# Bare scalars that no YAML parser can misread (e.g. MIT, reverse-engineers).
_SAFE_BARE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")

failures = []


def check(cond, msg):
    print(("  ok: " if cond else "  FAIL: ") + msg)
    if not cond:
        failures.append(msg)


def tree(base):
    out = {}
    for dirpath, _dirs, files in os.walk(base):
        for f in files:
            full = os.path.join(dirpath, f)
            with open(full, "rb") as fh:
                out[os.path.relpath(full, base).replace(os.sep, "/")] = fh.read()
    return out


src, mirror = tree(SRC), tree(MIRROR)
check(bool(src), "skills/ is not empty")
missing = sorted(set(src) - set(mirror))
extra = sorted(set(mirror) - set(src))
differ = sorted(p for p in set(src) & set(mirror) if src[p] != mirror[p])
check(not missing, f".pi/skills has every file of skills/ (missing: {missing})")
check(not extra, f".pi/skills has no files absent from skills/ (extra: {extra})")
check(not differ, f".pi/skills mirrors skills/ byte-for-byte (differ: {differ}; run `make skills`)")


def frontmatter(text):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "---":
            return lines[1:i]
    return None


for rel, data in sorted(src.items()):
    if not rel.endswith("SKILL.md"):
        continue
    fm = frontmatter(data.decode("utf-8"))
    check(fm is not None, f"{rel}: has a --- frontmatter block")
    for line in fm or []:
        key, sep, value = line.partition(":")
        value = value.strip()
        if not sep or not value or line.lstrip().startswith("#"):
            continue  # nested mapping header (e.g. "metadata:") or comment
        quoted = len(value) >= 2 and value[0] == value[-1] == '"'
        check(quoted or _SAFE_BARE.fullmatch(value) is not None,
              f"{rel}: {key.strip()!r} is double-quoted or a plain identifier (strict YAML)")

print("\n" + "=" * 50)
if failures:
    print(f"FAILED ({len(failures)}): " + "; ".join(failures))
    sys.exit(1)
print("ALL SKILLS SYNC TESTS PASSED")
