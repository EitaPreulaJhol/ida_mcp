"""Tests for scripts/package.py (release ZIPs + tag/version guard).

Runs against a throwaway tree (package.ROOT is redirected), so the real
dist/ is never touched.
"""
import importlib.util
import json
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
with open(os.path.join(root, "ida-plugin.json"), "w", encoding="utf-8") as f:
    json.dump({
        "IDAMetadataDescriptorVersion": 1,
        "plugin": {
            "name": "ida-mcp-bridge",
            "version": "1.2.3",
            "entryPoint": "ida_mcp_loader.py",
            "urls": {"repository": "https://example.invalid/repo"},
            "authors": [{"name": "Test", "email": "test@example.invalid"}],
        },
    }, f)
package.ROOT = root

# mismatch: refuse BEFORE building anything
try:
    package.main(["--expect-version", "1.2.4"])
    check(False, "mismatched --expect-version must exit")
except SystemExit as e:
    check("version mismatch" in str(e.code), "mismatch explains itself")
check(not os.path.exists(os.path.join(root, "dist")), "mismatch builds nothing")

# match: builds both the modern folder and the legacy root archive
check(package.main(["--expect-version", "1.2.3"]) == 0, "matching version builds")
modern = os.path.join(root, "dist", "ida_mcp-1.2.3.zip")
legacy = os.path.join(root, "dist", "ida-mcp-legacy-1.2.3.zip")
check(os.path.isfile(modern), "modern zip named after __version__")
check(os.path.isfile(legacy), "legacy zip named after __version__")

modern_names = set(zipfile.ZipFile(modern).namelist()) if os.path.isfile(modern) else set()
legacy_names = set(zipfile.ZipFile(legacy).namelist()) if os.path.isfile(legacy) else set()
check({"ida-mcp-bridge/ida-plugin.json", "ida-mcp-bridge/ida_mcp_loader.py",
       "ida-mcp-bridge/ida_mcp/__init__.py", "ida-mcp-bridge/ida_mcp/profiles/triage.txt",
       "ida-mcp-bridge/LICENSE"} <= modern_names,
      "modern zip is one ida-mcp-bridge/ folder with manifest, loader, package and docs")
check("ida_mcp_loader.py" not in modern_names, "modern zip has no root loader")
check({"ida_mcp/__init__.py", "ida_mcp/profiles/triage.txt",
       "ida_mcp_loader.py", "LICENSE"} <= legacy_names,
      "legacy zip keeps the IDA 8.3/8.4 root layout")
check("ida-plugin.json" not in legacy_names, "legacy zip carries no manifest")
check(not any("__pycache__" in n or n.endswith(".pyc")
              for n in modern_names | legacy_names), "both zips exclude caches")

# a manifest/__version__ drift is a hard error even without --expect-version
with open(os.path.join(root, "ida-plugin.json"), "w", encoding="utf-8") as f:
    json.dump({"IDAMetadataDescriptorVersion": 1, "plugin": {
        "name": "ida-mcp-bridge", "version": "9.9.9",
        "entryPoint": "ida_mcp_loader.py",
        "urls": {"repository": "https://example.invalid/repo"},
        "authors": [{"email": "test@example.invalid"}]}}, f)
try:
    package.main([])
    check(False, "manifest/version drift must exit")
except SystemExit as e:
    check("version mismatch" in str(e.code), "manifest drift explains itself")

# no flag: unchanged behaviour (local builds, after restoring the manifest)
with open(os.path.join(root, "ida-plugin.json"), "w", encoding="utf-8") as f:
    json.dump({"IDAMetadataDescriptorVersion": 1, "plugin": {
        "name": "ida-mcp-bridge", "version": "1.2.3",
        "entryPoint": "ida_mcp_loader.py",
        "urls": {"repository": "https://example.invalid/repo"},
        "authors": [{"email": "test@example.invalid"}]}}, f)
check(package.main([]) == 0, "plain build still works without the flag")

print("\n" + "=" * 50)
if failures:
    print(f"FAILED ({len(failures)}): " + "; ".join(failures))
    sys.exit(1)
print("ALL PACKAGE TESTS PASSED")
