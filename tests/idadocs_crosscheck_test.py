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
    # --- compat.py: guarded fallbacks for pre-9.4/9.5 spellings. Each is
    #     reached only when the replacement named in its comment is absent,
    #     so the 9.x reference legitimately does not list it.
    "ida_ida.BADADDR",            # pre-9.3; 9.x uses idaapi.BADADDR
    "ida_bytes.BADADDR",          # ida_bytes never had it (dead branch kept safe)
    "ida_name.del_name",          # split into del_global_name/del_local_name
    "ida_typeinf.get_ordinal_qty",  # renamed get_ordinal_limit/count
    "ida_funcs.FUNC_STATIC",      # renamed FUNC_STATICDEF
    "ida_bytes.get_original_bytes",  # bulk reader removed; per-byte fallback
    "ida_lines.get_extra_cmt_qty",   # removed; first-free-index fallback
    "ida_typeinf.get_cc_name",    # removed in 9.4; constants mapped locally
    "idaapi.get_inf_structure",   # removed; inf_is_64bit path preferred
    "idc.del_bookmark",           # pre-9.x delete path in _clear_bookmark
    "ida_hexrays.guess_tinfo",    # optional; never existed on 9.x bindings
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
    targets = [os.path.join(ROOT, "ida_mcp_loader.py")]
    for dirpath, _dirs, files in os.walk(os.path.join(ROOT, "ida_mcp")):
        if "zeromcp" in dirpath or "__pycache__" in dirpath:
            continue
        for fn in sorted(files):
            if fn.endswith(".py"):
                targets.append(os.path.join(dirpath, fn))
    for path in targets:
        if os.path.isfile(path):
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
                elif (isinstance(node, ast.Call)
                      and isinstance(node.func, ast.Name)
                      and node.func.id == "getattr"
                      and len(node.args) >= 2
                      and isinstance(node.args[0], ast.Name)
                      and isinstance(node.args[1], ast.Constant)
                      and isinstance(node.args[1].value, str)):
                    # getattr(ida_mod, "name"): the guarded-fallback idiom (a
                    # plain ast.Attribute walk cannot see these).
                    mod, attr = node.args[0].id, node.args[1].value
                else:
                    continue
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
