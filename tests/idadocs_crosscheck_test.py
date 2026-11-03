"""Cross-check our API usage against the official IDAPython reference.

Self-contained (carries its own HTML parsing) so it needs neither the ad-hoc
`tools/` explorer nor a committed copy of the Hex-Rays docs. SKIPS (green) when
the reference is absent, so CI — which never ships the copyrighted docs — stays
green. Locally, point IDAPYTHON_DOCS_DIR at a copy (default
`docs/idapython-reference`) and it FAILS on NEW drift beyond the known
false-positive allowlist.

Why: stubbed harnesses can't see real API drift; this is how `idc.Assemble`
and `ida_search.find_binary` would have been caught earlier.
"""
import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOCS = os.environ.get("IDAPYTHON_DOCS_DIR", os.path.join(ROOT, "docs", "idapython-reference"))
CHEATSHEET = os.path.join(ROOT, "skills", "ida-scripting", "references", "api-reference.md")

# Known false positives (mod.attr). Each is documented; revisit if the docs or
# our code change.
ALLOWLIST = {
    # compat.badaddr(): guarded pre-9.3 fallback; ida_ida.BADADDR was removed
    # in 9.x so it's absent from the 9.x reference, but the hasattr guard makes
    # it a correct fallback on older IDAs.
    "ida_ida.BADADDR",
    "ida_bytes.BADADDR",
    # cheat-sheet "Wrong vs Correct" table: these are the intentionally-wrong
    # examples (the ❌ column). Their presence confirms the cheat-sheet is right.
    "idc.SN_FORCE",
    "ida_bytes.get_segm_by_name",
    "ida_bytes.STRTYPE_C",
    "ida_ua.ida_ua",
    # cheat-sheet breaking-changes note documents the removed symbol by name.
    "ida_search.find_binary",
}

IDA_MODULES_HINT = {"idaapi", "idc", "idautils"}
_DT_ID_RE = re.compile(r'<dt class="sig[^"]*" id="([A-Za-z_][\w.]*)"')
_FQN_RE = re.compile(r"\b(ida\w+|idc|idautils|idaapi)\.([A-Za-z_]\w+)\b")


def build_index(docs_dir):
    index = {}
    for name in sorted(os.listdir(docs_dir)):
        page = os.path.join(docs_dir, name, "index.html")
        if not os.path.isfile(page):
            continue
        if not (name.startswith("ida") or name in ("idc", "idautils", "idaapi")):
            continue
        with open(page, encoding="utf-8", errors="replace") as f:
            src = f.read()
        syms = index.setdefault(name, set())
        for dotted in _DT_ID_RE.findall(src):
            if dotted.startswith(name + "."):
                syms.add(dotted[len(name) + 1:].split(".")[0])
    global_toplevel = set()
    for s in index.values():
        global_toplevel |= s
    return index, global_toplevel


def known(index, global_toplevel, mod, attr):
    if mod == "idaapi":
        return attr in global_toplevel or attr in index.get("idaapi", set())
    return mod in index and attr in index[mod]


def check_sources(index, global_toplevel):
    findings = []
    for dirpath, _dirs, files in os.walk(os.path.join(ROOT, "ida_mcp")):
        if "zeromcp" in dirpath or "__pycache__" in dirpath:
            continue
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, ROOT)
            tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        imported.add(a.asname or a.name.split(".")[0])
            seen = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    mod, attr = node.value.id, node.attr
                    if mod not in imported and mod != "idaapi":
                        continue
                    if not (mod.startswith("ida") or mod in IDA_MODULES_HINT):
                        continue
                    if attr.startswith("__"):
                        continue
                    if mod not in index and mod != "idaapi":
                        continue
                    sym = f"{mod}.{attr}"
                    if sym in seen or sym in ALLOWLIST:
                        continue
                    if not known(index, global_toplevel, mod, attr):
                        seen.add(sym)
                        findings.append((rel, sym))
    return findings


def check_cheatsheet(index, global_toplevel):
    findings = []
    if not os.path.isfile(CHEATSHEET):
        return findings
    seen = set()
    for mod, sym in _FQN_RE.findall(open(CHEATSHEET, encoding="utf-8").read()):
        fqn = f"{mod}.{sym}"
        if fqn in seen or fqn in ALLOWLIST:
            continue
        if mod not in index and mod != "idaapi":
            continue
        if not known(index, global_toplevel, mod, sym):
            seen.add(fqn)
            findings.append(fqn)
    return findings


def main():
    if not os.path.isdir(DOCS):
        print(f"SKIP: IDAPython reference not found at {DOCS} "
              f"(set IDAPYTHON_DOCS_DIR). Nothing to cross-check.")
        return 0
    index, global_toplevel = build_index(DOCS)
    print(f"Indexed {len(index)} modules, {len(global_toplevel)} top-level symbols.")

    src = check_sources(index, global_toplevel)
    cs = check_cheatsheet(index, global_toplevel)

    for rel, sym in src:
        print(f"  SOURCE drift: {rel}  {sym}")
    for sym in cs:
        print(f"  CHEATSHEET drift: {sym}")

    if src or cs:
        print(f"\nFAILED: {len(src) + len(cs)} new drift(s) vs the IDAPython reference "
              f"(not in the allowlist).")
        return 1
    print("\nALL DOCS CROSS-CHECK PASSED (no drift beyond the allowlist).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
