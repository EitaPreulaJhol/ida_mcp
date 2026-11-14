"""Build the IDA plugin ZIPs.

Outputs:

- ``dist/ida_mcp-<version>.zip``: one top-level ``ida-mcp-bridge/`` folder containing
  ``ida-plugin.json``, the entry point, the ``ida_mcp/`` package and docs.
  This is the IDA 8.5+ / HCLI / Plugin Manager layout.
- ``dist/ida-mcp-legacy-<version>.zip``: the old root layout
  (``ida_mcp/`` + ``ida_mcp_loader.py``) for IDA 8.3/8.4, which do not
  understand ``ida-plugin.json`` folders.

Version is read from ``ida_mcp/__init__.py`` without importing the package
(which would require IDA).

Usage:
    python scripts/package.py
    python scripts/package.py --expect-version 0.3.0   # release: tag guard
"""
import argparse
import ast
import hashlib
import json
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PLUGIN_NAME = "ida-mcp-bridge"
MANIFEST_NAME = "ida-plugin.json"
PACKAGE_DIR = "ida_mcp"
# Shipped next to the package in both layouts.
EXTRA_FILES = ["ida_mcp_loader.py", "README.md", "INSTALL.md", "LICENSE", "logo.png"]
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


def read_manifest(version):
    """Load and validate the root ``ida-plugin.json`` (shared by both ZIPs)."""
    path = os.path.join(ROOT, MANIFEST_NAME)
    try:
        with open(path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"missing {MANIFEST_NAME} at the repository root") from None
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"could not parse {MANIFEST_NAME}: {e}") from e
    if manifest.get("IDAMetadataDescriptorVersion") != 1:
        raise SystemExit("ida-plugin.json: unsupported IDAMetadataDescriptorVersion")
    plugin = manifest.get("plugin")
    if not isinstance(plugin, dict):
        raise SystemExit("ida-plugin.json: missing 'plugin' object")
    if plugin.get("name") != PLUGIN_NAME:
        raise SystemExit(
            f"ida-plugin.json: plugin.name must be {PLUGIN_NAME!r} "
            f"(found {plugin.get('name')!r})")
    if plugin.get("version") != version:
        raise SystemExit(
            f"version mismatch: ida_mcp/__init__.py has {version!r} but "
            f"ida-plugin.json has plugin.version {plugin.get('version')!r}")
    entry = plugin.get("entryPoint")
    if entry != "ida_mcp_loader.py" or os.path.dirname(entry):
        raise SystemExit(
            "ida-plugin.json: entryPoint must be the top-level "
            "'ida_mcp_loader.py'")
    if not os.path.isfile(os.path.join(ROOT, entry)):
        raise SystemExit(f"ida-plugin.json: entryPoint file {entry!r} is missing")
    urls = plugin.get("urls")
    if not isinstance(urls, dict) or not urls.get("repository"):
        raise SystemExit("ida-plugin.json: plugin.urls.repository is required")
    authors = plugin.get("authors")
    if not isinstance(authors, list) or not any(
            isinstance(a, dict) and (a.get("email") or a.get("name")) for a in authors):
        raise SystemExit("ida-plugin.json: at least one author/maintainer is required")
    return manifest


def iter_package_files():
    base = os.path.join(ROOT, PACKAGE_DIR)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIR_NAMES]
        for fn in filenames:
            if fn.endswith(EXCLUDE_SUFFIXES):
                continue
            full = os.path.join(dirpath, fn)
            yield full, os.path.relpath(full, ROOT)


def _write_zip(out, prefix, include_manifest):
    """Write one archive; every entry is under ``prefix``."""
    count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for full, rel in iter_package_files():
            z.write(full, prefix + rel)
            count += 1
        for rel in EXTRA_FILES:
            full = os.path.join(ROOT, rel)
            if not os.path.isfile(full):
                print(f"[warn] missing {rel}, skipping")
                continue
            z.write(full, prefix + rel)
            count += 1
        if include_manifest:
            full = os.path.join(ROOT, MANIFEST_NAME)
            z.write(full, prefix + MANIFEST_NAME)
            count += 1
    return count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--expect-version", metavar="X.Y.Z",
        help="fail (before building) unless ida_mcp.__version__ and "
             "ida-plugin.json plugin.version equal this; the release workflow "
             "passes the pushed tag without its 'v'")
    args = parser.parse_args(argv)
    version = read_version()
    read_manifest(version)
    if args.expect_version is not None and args.expect_version != version:
        raise SystemExit(
            f"version mismatch: tag says {args.expect_version!r} but "
            f"ida_mcp/__init__.py and ida-plugin.json say {version!r}. Bump "
            f"both before tagging, or re-tag.")

    dist = os.path.join(ROOT, "dist")
    os.makedirs(dist, exist_ok=True)
    modern = os.path.join(dist, f"ida_mcp-{version}.zip")
    legacy = os.path.join(dist, f"ida-mcp-legacy-{version}.zip")

    modern_count = _write_zip(modern, f"{PLUGIN_NAME}/", include_manifest=True)
    legacy_count = _write_zip(legacy, "", include_manifest=False)

    print(f"built {os.path.relpath(modern, ROOT)}  "
          f"({modern_count} files, {os.path.getsize(modern)} bytes, v{version}, "
          f"modern folder layout)")
    print(f"built {os.path.relpath(legacy, ROOT)}  "
          f"({legacy_count} files, {os.path.getsize(legacy)} bytes, v{version}, "
          f"legacy IDA 8.3/8.4 layout)")

    sums_path = os.path.join(dist, "SHA256SUMS")
    with open(sums_path, "w", encoding="utf-8") as f:
        for path in (modern, legacy):
            h = hashlib.sha256()
            with open(path, "rb") as src:
                for chunk in iter(lambda: src.read(1 << 20), b""):
                    h.update(chunk)
            f.write(f"{h.hexdigest()}  {os.path.basename(path)}\n")
    print(f"wrote {os.path.relpath(sums_path, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
