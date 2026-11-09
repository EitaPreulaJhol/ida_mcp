"""Tests for scripts/package.py (release zip + tag/version guard).

Runs against a throwaway tree (package.ROOT is redirected), so the real
dist/ is never touched.
"""
import importlib.util
import os
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "scripts", "package.py")

spec = importlib.util.spec_from_file_location("package_under_test", SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)

failures = []


def check(cond, msg):
    print(("  ok: " if cond else "  FAIL: ") + msg)
    if not cond:
        failures.append(msg)


root = tempfile.mkdtemp(prefix="idamcp_pkg_")
os.makedirs(os.path.join(root, "ida_mcp", "profiles"))
os.makedirs(os.path.join(root, "ida_mcp", "__pycache__"))
with open(os.path.join(root, "ida_mcp", "__init__.py"), "w") as f:
    f.write('__version__ = "1.2.3"\n')
for rel in ("ida_mcp/profiles/triage.txt", "ida_mcp/__pycache__/x.cpython-311.pyc",
            "ida_mcp_loader.py", "README.md", "INSTALL.md", "LICENSE"):
    with open(os.path.join(root, rel), "w") as f:
        f.write("x\n")
package.ROOT = root

# mismatch: refuse BEFORE building anything
try:
    package.main(["--expect-version", "1.2.4"])
    check(False, "mismatched --expect-version must exit")
except SystemExit as e:
    check("version mismatch" in str(e.code), "mismatch explains itself")
check(not os.path.exists(os.path.join(root, "dist")), "mismatch builds nothing")

# match: builds dist/ida_mcp-<version>.zip with the expected content
check(package.main(["--expect-version", "1.2.3"]) == 0, "matching version builds")
out = os.path.join(root, "dist", "ida_mcp-1.2.3.zip")
check(os.path.isfile(out), "zip named after __version__")
names = set(zipfile.ZipFile(out).namelist()) if os.path.isfile(out) else set()
check({"ida_mcp/__init__.py", "ida_mcp/profiles/triage.txt", "ida_mcp_loader.py",
       "LICENSE"} <= names, "zip carries the package, profiles, loader and docs")
check(not any("__pycache__" in n or n.endswith(".pyc") for n in names),
      "zip excludes caches")

# no flag: unchanged behaviour (local builds)
check(package.main([]) == 0, "plain build still works without the flag")

print("\n" + "=" * 50)
if failures:
    print(f"FAILED ({len(failures)}): " + "; ".join(failures))
    sys.exit(1)
print("ALL PACKAGE TESTS PASSED")
