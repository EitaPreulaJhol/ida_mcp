"""Packaging drift guard: the wheel must ship the profile files (review 14.7).

`pip install .` used to produce a wheel with `ida_mcp/profiles.py` but no
`ida_mcp/profiles/*.txt`. `get_profile()` then returns None for every name, so
`?profile=triage` silently means "no filter" (185 tools) instead of the
documented 16. The fix lives in `pyproject.toml`; this test keeps it there
without building a wheel (dependency-free, runs in milliseconds).
"""
import fnmatch
import glob
import os

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - the package requires >= 3.11
    tomllib = None

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG = os.path.join(ROOT, "ida_mcp")
PYPROJECT = os.path.join(ROOT, "pyproject.toml")

assert tomllib is not None, "tomllib is stdlib on Python >= 3.11"

with open(PYPROJECT, "rb") as f:
    cfg = tomllib.load(f)

package_data = cfg.get("tool", {}).get("setuptools", {}).get("package-data", {})
patterns = package_data.get("ida_mcp", [])
assert patterns, (
    "pyproject.toml has no [tool.setuptools.package-data] entry for ida_mcp: "
    "a pip-installed wheel would ship no profile files, silently disabling "
    "?profile=")
print(f"package-data declared OK ({patterns})")

# every shipped profile file must be matched by at least one pattern
profiles = sorted(glob.glob(os.path.join(PKG, "profiles", "*.txt")))
assert profiles, "no ida_mcp/profiles/*.txt found"
unmatched = []
for path in profiles:
    arc = "profiles/" + os.path.basename(path)
    if not any(fnmatch.fnmatch(arc, pat) for pat in patterns):
        unmatched.append(arc)
assert not unmatched, f"profile files not matched by package-data: {unmatched}"
print(f"{len(profiles)} profile files covered by package-data OK")

# the two documented profiles must exist and be non-empty (drift guard)
for name in ("triage.txt", "readonly.txt"):
    path = os.path.join(PKG, "profiles", name)
    assert os.path.isfile(path), f"missing {path}"
    with open(path, encoding="utf-8") as f:
        entries = [ln.strip() for ln in f
                   if ln.strip() and not ln.lstrip().startswith("#")]
    assert entries, f"{name} has no tool entries"
print("triage/readonly profiles present and non-empty OK")

print("ALL PACKAGING TESTS PASSED")
