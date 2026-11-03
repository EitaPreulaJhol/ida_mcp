"""Build the IDA plugin zip: dist/ida_mcp-<version>.zip.

Contains exactly what IDA needs to load the plugin (the ``ida_mcp/`` package
plus ``ida_mcp_loader.py``) and the user docs. No tests, caches, plans, or the
vendored reference. Version is read from ``ida_mcp/__init__.py`` without
importing the package (which would require IDA).

Usage:
    python scripts/package.py
"""
import ast
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Top-level files shipped alongside the package.
EXTRA_FILES = ["ida_mcp_loader.py", "README.md", "INSTALL.md", "LICENSE"]
# Directories (recursively) shipped. zeromcp is part of the package.
PACKAGE_DIR = "ida_mcp"
EXCLUDE_DIR_NAMES = {"__pycache__"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo")


def read_version():
    src = open(os.path.join(ROOT, PACKAGE_DIR, "__init__.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if getattr(t, "id", "") == "__version__" and isinstance(node.value, ast.Constant):
                    return node.value.value
    raise SystemExit("could not find __version__ in ida_mcp/__init__.py")


def iter_package_files():
    base = os.path.join(ROOT, PACKAGE_DIR)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIR_NAMES]
        for fn in filenames:
            if fn.endswith(EXCLUDE_SUFFIXES):
                continue
            full = os.path.join(dirpath, fn)
            yield full, os.path.relpath(full, ROOT)


def main():
    version = read_version()
    dist = os.path.join(ROOT, "dist")
    os.makedirs(dist, exist_ok=True)
    out = os.path.join(dist, f"ida_mcp-{version}.zip")

    count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for full, arc in iter_package_files():
            z.write(full, arc)
            count += 1
        for rel in EXTRA_FILES:
            full = os.path.join(ROOT, rel)
            if not os.path.isfile(full):
                print(f"[warn] missing {rel}, skipping")
                continue
            z.write(full, rel)
            count += 1

    size = os.path.getsize(out)
    print(f"built {os.path.relpath(out, ROOT)}  ({count} files, {size} bytes, v{version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
