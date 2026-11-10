"""Execute IDA Python scripts in a rich context (ported from ida-pro-mcp api_python.py).

The core logic lives in :func:`_run_code` (not decorated) so it can be called
directly from other ``@idasync`` tools without re-entering ``execute_sync``.
"""
import ast
import io
import os
import re
import sys
import traceback
import types

import idaapi
import idc
import ida_bytes
import ida_dbg
import ida_entry
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_xref
import idautils

from .rpc import tool, unsafe
from .sync import idasync, hard_interrupt, ToolInterrupt


# ---------------------------------------------------------------------------
# Runtime hardening + clearer error hints for IDAPython scripts
# ---------------------------------------------------------------------------
# LLM-authored scripts routinely (a) ``import ida_imports`` (there is no such
# module) and (b) reach for a constant/function on the wrong module
# (``idc.SN_FORCE``, ``ida_bytes.STRTYPE_C``, ``ida_bytes.get_segm_by_name``,
# ``ida_ua.ida_ua`` ...). We therefore (1) register a forwarding
# ``ida_imports`` -> ``ida_nalt`` shim so the import simply works, and (2)
# append a precise "it actually lives in <module>" hint to the traceback for
# the usual AttributeError / ModuleNotFoundError / NameError misses, so the
# model self-corrects on the next call instead of guessing again.

def _install_ida_imports_shim() -> None:
    """Register a forwarding ``ida_imports`` module (-> ``ida_nalt``) in
    ``sys.modules`` so ``import ida_imports`` resolves. No-op if a real module
    exists or the shim is already installed."""
    if "ida_imports" in sys.modules:
        return
    try:
        __import__("ida_imports")  # a real module on some future IDA? keep it.
        return
    except Exception:
        pass
    shim = types.ModuleType("ida_imports")
    shim.__doc__ = ("ida_mcp compatibility shim: there is no real `ida_imports` "
                    "module. Import enumeration lives in `ida_nalt`; attribute "
                    "access is forwarded there.")
    shim.__ida_mcp_shim__ = True
    for _fn in ("get_import_module_qty", "get_import_module_name",
                "enum_import_names"):
        if hasattr(ida_nalt, _fn):
            setattr(shim, _fn, getattr(ida_nalt, _fn))

    def _forward(name, _nalt=ida_nalt):
        try:
            return getattr(_nalt, name)
        except AttributeError:
            raise AttributeError(
                f"module 'ida_imports' (ida_mcp shim -> ida_nalt) has no "
                f"attribute {name!r}; imports use get_import_module_qty / "
                f"get_import_module_name / enum_import_names") from None

    shim.__getattr__ = _forward  # PEP 562 module-level __getattr__
    sys.modules["ida_imports"] = shim


_install_ida_imports_shim()


# Whole-module relocations: module the script asked for -> what to use instead.
_MODULE_RELOCATION = {
    "ida_imports": "there is no ida_imports module \u2014 enumerate imports via "
                   "ida_nalt (get_import_module_qty / get_import_module_name / "
                   "enum_import_names).",
    "ida_struct": "ida_struct was removed in IDA 9 \u2014 use ida_typeinf "
                  "(udt_type_data_t / udm_t).",
    "ida_enum": "ida_enum was removed in IDA 9 \u2014 use ida_typeinf "
                "(enum_type_data_t / edm_t).",
}

# Modules scanned to locate where a mis-attributed name actually lives. Ordered
# canonical-first (specific modern module before the idaapi/idc monoliths) so
# the suggestion points at ida_nalt.STRTYPE_C rather than idc.STRTYPE_C, etc.
_SCAN_MODULES = (
    "ida_nalt", "ida_name", "ida_segment", "ida_funcs", "ida_bytes",
    "ida_typeinf", "ida_xref", "ida_ua", "ida_lines", "ida_entry", "ida_frame",
    "ida_hexrays", "ida_kernwin", "ida_idp", "ida_gdl", "ida_auto",
    "ida_search", "ida_netnode", "ida_dbg", "idautils", "idaapi", "idc",
)

_RE_ATTR = re.compile(r"module '([\w.]+)' has no attribute '(\w+)'")
_RE_NOMOD = re.compile(r"No module named '([\w.]+)'")
_RE_NAME = re.compile(r"name '(\w+)' is not defined")


def _locate_name(attr: str, exec_globals: dict) -> list:
    """Modules (in scan order) that actually define ``attr``."""
    found = []
    for name in _SCAN_MODULES:
        mod = (exec_globals or {}).get(name) or sys.modules.get(name)
        if mod is not None and hasattr(mod, attr) and name not in found:
            found.append(name)
    return found


def _error_hint(exc: BaseException, exec_globals: dict) -> str:
    """One-line, actionable hint for the common module/attribute misses, or
    "" when nothing useful can be said."""
    msg = str(exc)
    try:
        if isinstance(exc, AttributeError):
            m = _RE_ATTR.search(msg)
            if m:
                mod_name, attr = m.group(1), m.group(2)
                # Doubled prefix typo, e.g. ida_ua.ida_ua.decode_insn.
                if attr == mod_name.rsplit(".", 1)[-1]:
                    return (f"ida_mcp hint: '{attr}' is already the module \u2014 drop the "
                            f"doubled prefix (use {attr}.<name>, not {mod_name}.{attr}).")
                where = [w for w in _locate_name(attr, exec_globals) if w != mod_name]
                if where:
                    return (f"ida_mcp hint: '{attr}' lives in {', '.join(where)} \u2014 "
                            f"use {where[0]}.{attr}, not {mod_name}.{attr}.")
                return (f"ida_mcp hint: no loaded IDA module defines '{attr}'. "
                        f"List candidates with: [m for m in dir({mod_name}) "
                        f"if '{attr[:4].lower()}' in m.lower()].")
        elif isinstance(exc, ImportError):  # covers ModuleNotFoundError
            m = _RE_NOMOD.search(msg)
            name = (m.group(1) if m else getattr(exc, "name", "")) or ""
            if name in _MODULE_RELOCATION:
                return f"ida_mcp hint: {_MODULE_RELOCATION[name]}"
            if name:
                return (f"ida_mcp hint: '{name}' is not importable. Every ida_* module "
                        f"is already pre-loaded \u2014 you usually don't need `import`.")
        elif isinstance(exc, NameError):
            m = _RE_NAME.search(msg)
            if m:
                name = m.group(1)
                if sys.modules.get(name) is not None:
                    return (f"ida_mcp hint: module '{name}' exists but was not auto-loaded; "
                            f"add `import {name}` at the top of your script.")
                where = _locate_name(name, exec_globals)
                if where:
                    return (f"ida_mcp hint: '{name}' is defined in {', '.join(where)} \u2014 "
                            f"qualify it, e.g. {where[0]}.{name}.")
    except Exception:
        return ""
    return ""


def _make_exec_globals() -> dict:
    """Build an execution context with all IDA modules available."""
    def lazy_import(module_name):
        try:
            return __import__(module_name)
        except Exception:
            return None

    g = {
        "__builtins__": __builtins__,
        "idaapi": idaapi,
        "idc": idc,
        "idautils": idautils,
        "ida_bytes": ida_bytes,
        "ida_dbg": ida_dbg,
        "ida_entry": ida_entry,
        "ida_frame": ida_frame,
        "ida_funcs": ida_funcs,
        "ida_hexrays": ida_hexrays,
        "ida_ida": ida_ida,
        "ida_kernwin": ida_kernwin,
        "ida_lines": ida_lines,
        "ida_nalt": ida_nalt,
        "ida_name": ida_name,
        "ida_segment": ida_segment,
        "ida_typeinf": ida_typeinf,
        "ida_xref": ida_xref,
    }
    # Modules the ida-scripting skill documents as pre-loaded; imported
    # lazily so a module missing on this IDA version is simply absent.
    for name in ("ida_auto", "ida_ua", "ida_gdl", "ida_netnode", "ida_search",
                 "ida_imports"):
        mod = lazy_import(name)
        if mod is not None:
            g[name] = mod
    return g


def _script_bindings(namespace: dict, before: dict) -> dict:
    """Names the script bound or rebound in ``namespace``, in binding order."""
    return {k: v for k, v in namespace.items()
            if k not in before or before[k] is not v}


def _pick_result(bound: dict):
    """Return the value to surface: ``result`` or ``__result__`` if the
    script set it, else the last variable it assigned."""
    if "result" in bound:
        return str(bound["result"])
    if "__result__" in bound:
        return str(bound["__result__"])
    if bound:
        return str(bound[next(reversed(bound))])
    return None


def _collect_ida_messages(pre_count: int) -> str:
    """Capture IDA message-window lines produced since pre_count was sampled.

    FIX: new messages are appended at the END of the log, so we take the last
    ``new_count`` entries (the original code took the first ``new_count``,
    which returned the oldest lines).
    """
    try:
        post_lines = ida_kernwin.msg_get_lines(-1)
    except Exception:
        return ""
    new_count = len(post_lines) - pre_count
    if new_count <= 0:
        return ""
    return "\n".join(post_lines[-new_count:])


def _run_code(code: str) -> dict:
    """Execute ``code`` on the IDA main thread and return result/stdout/stderr.

    Must be called from within an ``@idasync`` context (i.e. on the main
    thread). Never raises -- failures are returned in ``stderr``.

    ``sys.stdout``/``sys.stderr`` are swapped for the duration (that is what
    makes a script's ``print()`` come back in the result), so they are
    process-wide: a concurrent IDA plugin or HTTP thread writing to stdout
    during the call also lands in the capture. The call is serialized on the
    main thread and short by contract, which is why this is acceptable.
    """
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    pre_count = 0
    try:
        pre_lines = ida_kernwin.msg_get_lines(-1)
        pre_count = len(pre_lines)
    except Exception:
        pre_count = 0

    exec_globals: dict = {}
    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture
        # ONE namespace for globals and locals, exactly like a module or the
        # IDA console. With separate dicts, top-level names land in the
        # locals dict while functions/comprehensions resolve free names via
        # globals, so `BASE = 1; def f(): return BASE` raised NameError.
        exec_globals = _make_exec_globals()
        before = dict(exec_globals)
        result_value = None

        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Let exec raise the SyntaxError with its usual message/location.
            exec(code, exec_globals)
            result_value = _pick_result(_script_bindings(exec_globals, before))
        else:
            if not tree.body:
                pass
            elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                # Single expression - use eval.
                result_value = str(eval(code, exec_globals))
            elif isinstance(tree.body[-1], ast.Expr):
                # Multiple statements, last one is an expression (Jupyter-style).
                exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                exec(compile(exec_tree, "<string>", "exec"), exec_globals)
                eval_tree = ast.Expression(body=tree.body[-1].value)
                result_value = str(eval(compile(eval_tree, "<string>", "eval"), exec_globals))
            else:
                exec(code, exec_globals)
                result_value = _pick_result(_script_bindings(exec_globals, before))

        ida_msgs = _collect_ida_messages(pre_count)
        stderr_text = stderr_capture.getvalue()
        if ida_msgs:
            stderr_text = (stderr_text + "\n" + ida_msgs).strip()
        return {
            "result": result_value or "",
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_text,
        }
    except ToolInterrupt as e:
        # Timeout / cancel reached the script body. Return what it printed so
        # far (often most of the work) instead of discarding it.
        stderr_text = stderr_capture.getvalue()
        hint = (f"{e.message}. The script was interrupted on the IDA main thread; "
                f"output above is partial. Split the work into smaller batches "
                f"(e.g. process N functions per call, resume from the last printed "
                f"address) instead of re-running the same script.")
        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": (stderr_text + "\n" + hint).strip(),
            "error": e.message,
        }
    except SystemExit as e:
        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": (stderr_capture.getvalue() + f"\nScript called exit({e.code!r}); "
                       f"execution stopped there (IDA itself keeps running).").strip(),
        }
    except Exception as exc:
        tb = traceback.format_exc()
        hint = _error_hint(exc, exec_globals)
        if hint:
            tb = tb.rstrip() + "\n\n" + hint
        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": tb,
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


@tool
@idasync
@unsafe
@hard_interrupt
def py_eval(code: str) -> dict:
    """Execute Python in IDA context and return result/stdout/stderr.

    Assign to ``result`` (or ``__result__``) to return a value; the last
    top-level expression is also returned when not assigned.
    """
    return _run_code(code)


@tool
@idasync
@unsafe
@hard_interrupt
def py_exec_file(file_path: str) -> dict:
    """Execute a Python script file in IDA context and return stdout/stderr."""
    if not os.path.isfile(file_path):
        return {"result": "", "stdout": "", "stderr": f"File not found: {file_path}"}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception as e:
        return {"result": "", "stdout": "", "stderr": f"Could not read file: {e}"}
    return _run_code(code)
