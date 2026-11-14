"""Validate the root ida-plugin.json against the IDA plugin format.

Keep the manifest at the repository root so the GitHub source archive is also
a valid plugin archive; scripts/package.py copies the same file into the
modern single-folder ZIP.
"""
import ast
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MANIFEST = os.path.join(ROOT, "ida-plugin.json")
INIT = os.path.join(ROOT, "ida_mcp", "__init__.py")

PLATFORMS = {"windows-x86_64", "linux-x86_64", "macos-x86_64", "macos-aarch64"}
CATEGORIES = {
    "disassembly-and-processor-modules", "file-parsers-and-loaders",
    "decompilation", "debugging-and-tracing", "deobfuscation",
    "collaboration-and-productivity",
    "integration-with-third-parties-interoperability",
    "api-scripting-and-automation", "ui-ux-and-visualization",
    "malware-analysis", "vulnerability-research-and-exploit-development",
    "other",
}


def read_version():
    tree = ast.parse(open(INIT, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if getattr(target, "id", "") == "__version__":
                    return node.value.value
    raise AssertionError("__version__ not found")


def check(cond, msg):
    assert cond, msg
    print("  ok:", msg)


with open(MANIFEST, encoding="utf-8") as f:
    data = json.load(f)  # strict JSON: catches trailing commas

check(data.get("IDAMetadataDescriptorVersion") == 1,
      "IDAMetadataDescriptorVersion is 1")
plugin = data.get("plugin")
check(isinstance(plugin, dict), "plugin object exists")
check(plugin.get("name") == "ida-mcp-bridge", "plugin.name is ida-mcp-bridge")
check(plugin.get("version") == read_version(),
      "plugin.version matches ida_mcp.__version__")
check(plugin.get("entryPoint") == "ida_mcp_loader.py",
      "entryPoint is the top-level loader")
check(os.path.isfile(os.path.join(ROOT, plugin["entryPoint"])),
      "entryPoint file exists")
logo = plugin.get("logoPath")
check(isinstance(logo, str) and logo and os.path.isfile(os.path.join(ROOT, logo)),
      "logoPath points at a shipped image")
if isinstance(logo, str) and logo:
    with open(os.path.join(ROOT, logo), "rb") as f:
        header = f.read(24)
    check(header[:8] == b"\x89PNG\r\n\x1a\n", "logo is a PNG")
    width, height = struct.unpack(">II", header[16:24])
    check(width * 9 == height * 16, f"logo is 16:9 ({width}x{height})")
check(isinstance(plugin.get("description"), str) and plugin["description"].strip(),
      "description is present")
check(plugin.get("license") == "MIT", "license is MIT")
check(isinstance(plugin.get("urls"), dict) and
      plugin["urls"].get("repository") == "https://github.com/EitaPreulaJhol/ida_mcp",
      "urls.repository points at the repository")
authors = plugin.get("authors") or plugin.get("maintainers") or []
check(any(isinstance(a, dict) and a.get("email") for a in authors),
      "at least one author/maintainer has an email")
versions = plugin.get("idaVersions")
check(isinstance(versions, list) and versions and
      all(isinstance(v, str) and v for v in versions),
      "idaVersions is a non-empty string list")
platforms = plugin.get("platforms")
check(isinstance(platforms, list) and set(platforms) <= PLATFORMS,
      "platforms use the allowed identifiers")
categories = plugin.get("categories")
check(isinstance(categories, list) and categories and
      set(categories) <= CATEGORIES, "categories use the allowed identifiers")
keywords = plugin.get("keywords")
check(isinstance(keywords, list) and keywords and
      all(isinstance(k, str) and k for k in keywords),
      "keywords is a non-empty string list")
deps = plugin.get("pythonDependencies")
check(not deps, "pythonDependencies is absent/empty (zero-runtime-deps invariant)")

print("ALL PLUGIN MANIFEST TESTS PASSED")
