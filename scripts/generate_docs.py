#!/usr/bin/env python3
"""Generate the README tool inventory from the @tool registry.

The source of truth is the AST of ``ida_mcp/*.py``. This script does not import
IDA or the package, so it is safe in CI and in a checkout without a license.

Usage:
    python scripts/generate_docs.py          # rewrite README.md
    python scripts/generate_docs.py --check  # fail if README is stale
    python scripts/generate_docs.py --stdout # print the generated block

README.md must contain exactly one pair of these markers:

    <!-- BEGIN GENERATED TOOL INVENTORY -->
    ...
    <!-- END GENERATED TOOL INVENTORY -->

The ``tool_inventory_test.py`` harness also compares the block, so a new tool
cannot ship with a stale count or a missing name.
"""
import argparse
import ast
import difflib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "ida_mcp")
README = os.path.join(ROOT, "README.md")
BEGIN = "<!-- BEGIN GENERATED TOOL INVENTORY -->"
END = "<!-- END GENERATED TOOL INVENTORY -->"

# User-facing order; unknown/new modules are appended alphabetically.
MODULE_ORDER = [
    "api_analysis", "api_comments", "api_composite", "api_debug",
    "api_fingerprint",
    "api_entries", "api_functions", "api_hexrays", "api_hooks", "api_info",
    "api_instructions", "api_memory", "api_modify", "api_names",
    "api_python", "api_query", "api_sigmaker", "api_search", "api_segments",
    "api_strings", "api_typeinfo", "api_xrefs", "server",
]


def _tool_names(tree):
    names = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            text = ast.unparse(dec).strip()
            if text == "tool" or text.startswith("tool("):
                names.append(node.name)
                break
    return sorted(names)


def collect_tools():
    """Return ``{module_stem: [tool, ...]}`` for modules with @tool functions."""
    found = {}
    for fname in sorted(os.listdir(PKG)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        path = os.path.join(PKG, fname)
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=path)
        names = _tool_names(tree)
        if names:
            found[fname[:-3]] = names
    return found


def _module_key(name):
    try:
        return (0, MODULE_ORDER.index(name), name)
    except ValueError:
        return (1, 0, name)


def render_inventory():
    """Render the content between the README markers (no heading)."""
    tools = collect_tools()
    lines = [
        "Every registered tool, grouped by module (names match `tools/list` "
        "exactly).",
        "",
    ]
    total = 0
    for module in sorted(tools, key=_module_key):
        names = tools[module]
        total += len(names)
        lines.append(f"### `{module}` ({len(names)})")
        lines.append("")
        lines.append(", ".join(f"`{name}`" for name in names))
        lines.append("")
    lines.append(f"<!-- total: {total} tools -->")
    return "\n".join(lines)


def _extract(text):
    start = text.index(BEGIN) + len(BEGIN)
    finish = text.index(END, start)
    return text[start:finish].strip("\n")


def _replace(text, block):
    start = text.index(BEGIN)
    finish = text.index(END, start) + len(END)
    return text[:start] + BEGIN + "\n" + block + "\n" + END + text[finish:]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="fail instead of rewriting when README is stale")
    parser.add_argument("--stdout", action="store_true",
                        help="print the generated block only")
    args = parser.parse_args(argv)

    block = render_inventory()
    if args.stdout:
        print(block)
        return 0

    with open(README, encoding="utf-8") as f:
        text = f.read()
    if BEGIN not in text or END not in text:
        raise SystemExit(
            f"README.md is missing the generated block markers:\n  {BEGIN}\n  {END}")
    current = _extract(text)
    if current == block:
        print("README tool inventory is up to date")
        return 0
    if args.check:
        diff = "\n".join(difflib.unified_diff(
            current.splitlines(), block.splitlines(),
            fromfile="README.md", tofile="generated", lineterm=""))
        print(diff)
        print("README tool inventory is stale; run "
              "`python scripts/generate_docs.py`")
        return 1
    with open(README, "w", encoding="utf-8") as f:
        f.write(_replace(text, block))
    print("updated README tool inventory")
    return 0


if __name__ == "__main__":
    sys.exit(main())
