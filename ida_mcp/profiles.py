"""Tool profiles (lazy-loading allowlists) for ida_mcp.

Profiles are plain ``*.txt`` files shipped in ``ida_mcp/profiles/``
(``#`` comments and blanks ignored, one tool name per line). Clients pick
one via ``?profile=<name>`` on the endpoint URL:

- ``triage`` — ~16 starter tools (survey, enumerate, decompile, trace)
- ``readonly`` — every non-mutating, non-debugger tool
- (no profile) — the full set, still gated by ``?unsafe=`` / ``?ext=``

Stdlib-only: importable from ``zeromcp`` without touching IDA modules.
"""
import os

_PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")

_cache: dict[str, set[str] | None] = {}
_cache_complete = False


def _load_all() -> dict[str, set[str]]:
    global _cache_complete
    found: dict[str, set[str]] = {}
    try:
        names = sorted(os.listdir(_PROFILES_DIR))
    except OSError:
        names = []
    for fname in names:
        if not fname.endswith(".txt"):
            continue
        profile = fname[:-len(".txt")]
        tools: set[str] = set()
        try:
            with open(os.path.join(_PROFILES_DIR, fname), "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        tools.add(line.split()[0])
        except OSError:
            continue
        found[profile] = tools
    _cache.clear()
    _cache.update(found)
    _cache_complete = True
    return found


def list_profiles() -> dict[str, set[str]]:
    """Return {profile_name: tool_names}, loading from disk once."""
    if not _cache_complete:
        return _load_all()
    return dict(_cache)


def get_profile(name: str) -> set[str] | None:
    """Return the tool set for ``name``, or None when unknown/empty."""
    profiles = list_profiles()
    tools = profiles.get((name or "").strip().lower())
    return set(tools) if tools else None


def reload_profiles() -> dict[str, set[str]]:
    """Force a reload from disk (picks up edited profile files)."""
    return _load_all()


__all__ = ["list_profiles", "get_profile", "reload_profiles"]
