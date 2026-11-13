"""Shared loader for the standalone test harnesses (not a test itself).

Harnesses used to read an ``ida_mcp`` source file, string-replace its
relative imports with stubs and ``exec`` the result under a fake name. That
works, but coverage cannot attribute the executed lines to the real file
(the report showed ``sync.py`` at 0% while it is heavily tested), and every
new import line broke the string replacements.

This module instead imports the REAL file under its real path:

1. ``ida_mcp`` is registered as a bare package (``__path__`` = the source
   directory) WITHOUT running ``ida_mcp/__init__.py``, which would import
   every tool module and need a full IDA;
2. the siblings a module imports relatively (``.rpc``, ``.sync``,
   ``.api_analysis``...) are installed as stub modules ``ida_mcp.<name>``;
3. the module under test is executed from its real file, so its relative
   imports resolve to those stubs and coverage sees true paths and lines.

IDA SDK modules (``idaapi``, ``ida_*``) are still stubbed by each harness in
``sys.modules`` before calling :func:`load`.
"""
import importlib
import importlib.util
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG_DIR = os.path.join(ROOT, "ida_mcp")
PKG = "ida_mcp"

# Identity decorators + no-op helpers covering everything the tool modules
# import from .rpc / .sync. Harnesses that need different semantics pass
# their own source for that sibling.
RPC_STUB = """
tool = lambda f: f
unsafe = lambda f: f
def ext(group):
    return lambda f: f
"""

SYNC_STUB = """
idasync = lambda f: f
keep_batch = lambda f: f
hard_interrupt = lambda f: f
def tool_timeout(seconds):
    return lambda f: f
def check_cancelled():
    return None
def update_wait_box(text):
    return None
def ensure_analysis():
    return None
def get_tool_deadline():
    return None
def get_pre_call_batch():
    return None
class IDAError(Exception):
    pass
class IDASyncError(Exception):
    pass
class CancelledError(Exception):
    pass
class ToolInterrupt(BaseException):
    def __init__(self, reason="timeout", message="interrupted"):
        super().__init__(message)
        self.reason = reason
        self.message = message
"""

# The real ``clamp_int`` / ``_as_int`` from ``api_analysis``, for harnesses that
# stub that sibling: they must behave identically, otherwise a clamp test would
# be asserting the stub instead of the shipped policy.
API_ANALYSIS_HELPERS = """
def _as_int(value, default=0):
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        try:
            return int(text, 0)
        except ValueError:
            num = float(text)
            return int(num) if num.is_integer() else default
    except (TypeError, ValueError):
        return default


def clamp_int(value, default, hi):
    n = _as_int(value, default)
    return default if n <= 0 else min(n, hi)


def clamp_limit(value, default, hi):
    n = _as_int(value, default)
    return hi if n <= 0 else min(n, hi)
"""


def package() -> types.ModuleType:
    """The bare ``ida_mcp`` package (created once; ``__init__`` never runs)."""
    pkg = sys.modules.get(PKG)
    if pkg is None or not getattr(pkg, "__ida_mcp_harness__", False):
        pkg = types.ModuleType(PKG)
        pkg.__path__ = [PKG_DIR]
        pkg.__package__ = PKG
        pkg.__ida_mcp_harness__ = True
        sys.modules[PKG] = pkg
    return pkg


def stub(name: str, source: str = "", **attrs) -> types.ModuleType:
    """Install ``ida_mcp.<name>`` as a stub built from ``source`` and ``attrs``.

    ``source`` runs in the stub's own namespace, pre-populated with the IDA
    stub modules already in ``sys.modules`` (``idaapi``, ``idc``,
    ``idautils``, ``ida_*``); anything else it uses must be imported.
    """
    pkg = package()
    full = f"{PKG}.{name}"
    mod = types.ModuleType(full)
    mod.__package__ = PKG
    # Stub code historically ran inside the module under test, where the IDA
    # modules were already imported; keep that convenience.
    mod.__dict__.update({k: v for k, v in sys.modules.items()
                         if k in ("idaapi", "idc", "idautils") or k.startswith("ida_")})
    mod.__dict__.update(attrs)
    if source:
        exec(compile(source, f"<stub {full}>", "exec"), mod.__dict__)
    sys.modules[full] = mod
    setattr(pkg, name, mod)
    return mod


def load(name: str, stubs: dict | None = None, *, alias: str | None = None,
         stub_globals: dict | None = None):
    """Execute the REAL ``ida_mcp/<name>.py`` and return the module.

    ``stubs`` maps sibling names to a stub: a source string, a dict of
    attributes, or a ready module. Siblings not listed are imported for
    real when the module asks for them (only safe for IDA-free ones such as
    ``zeromcp``, ``profiles`` or ``regex_guard``). ``alias`` also registers
    the module under that name in ``sys.modules`` (for tests that import it
    by a short name). ``stub_globals`` are injected into every stub built
    from source (fixtures the stub code refers to, e.g. a fake memory map).
    """
    pkg = package()
    for sub, spec in (stubs or {}).items():
        if isinstance(spec, types.ModuleType):
            sys.modules[f"{PKG}.{sub}"] = spec
            setattr(pkg, sub, spec)
        elif isinstance(spec, dict):
            stub(sub, **{**(stub_globals or {}), **spec})
        else:
            stub(sub, spec, **(stub_globals or {}))
    full = f"{PKG}.{name}"
    path = os.path.join(PKG_DIR, *name.split(".")) + ".py"
    spec = importlib.util.spec_from_file_location(full, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full] = mod
    if "." not in name:
        setattr(pkg, name, mod)
    spec.loader.exec_module(mod)
    if alias:
        sys.modules[alias] = mod
    return mod


def load_with_preamble(name: str, preamble: str, *, alias: str | None = None,
                       stub_globals: dict | None = None):
    """Load the REAL module with ONE preamble faking all its relative imports.

    For harnesses (the server ones) that used to strip every relative import
    and prepend a single block of fakes: that block becomes one stub module
    serving every ``from .x import ...`` sibling, and each ``from . import x``
    gets an empty module. Preamble names the module does not import are
    mirrored onto it, so harnesses can keep reading them as ``mod.<name>``.
    """
    import ast
    path = os.path.join(PKG_DIR, *name.split(".")) + ".py"
    tree = ast.parse(open(path, encoding="utf-8").read())
    shared = stub("_harness_preamble", preamble, **(stub_globals or {}))
    stubs: dict = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            if node.module:
                stubs[node.module] = shared
            else:
                for a in node.names:
                    stubs[a.name] = types.ModuleType(f"{PKG}.{a.name}")
    mod = load(name, stubs, alias=alias)
    for key, value in vars(shared).items():
        if not key.startswith("__"):
            mod.__dict__.setdefault(key, value)
    return mod


def real(name: str):
    """Import an IDA-free sibling (e.g. ``zeromcp``) for real, as a submodule."""
    package()
    return importlib.import_module(f"{PKG}.{name}")


__all__ = ["ROOT", "PKG_DIR", "RPC_STUB", "SYNC_STUB", "package", "stub", "load",
           "load_with_preamble", "real"]
