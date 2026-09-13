"""Execute IDA Python scripts in a rich context (ported from ida-pro-mcp api_python.py).

The core logic lives in :func:`_run_code` (not decorated) so it can be called
directly from other ``@idasync`` tools without re-entering ``execute_sync``.
"""
import ast
import io
import os
import sys
import traceback

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
from .sync import idasync


def _make_exec_globals() -> dict:
    """Build an execution context with all IDA modules available."""
    def lazy_import(module_name):
        try:
            return __import__(module_name)
        except Exception:
            return None

    return {
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


def _pick_result(exec_locals: dict, exec_globals: dict):
    """Return the value to surface: ``result`` or ``__result__`` if set, else
    the last locally-assigned variable."""
    if "result" in exec_locals:
        return str(exec_locals["result"])
    if "__result__" in exec_globals:
        return str(exec_globals["__result__"])
    if exec_locals:
        last_key = list(exec_locals.keys())[-1]
        return str(exec_locals[last_key])
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

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture
        exec_globals = _make_exec_globals()
        result_value = None
        exec_locals = {}

        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fall back to direct exec on parse failure.
            exec(code, exec_globals, exec_locals)
            exec_globals.update(exec_locals)
            result_value = _pick_result(exec_locals, exec_globals)
        else:
            if not tree.body:
                pass
            elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                # Single expression - use eval.
                result_value = str(eval(code, exec_globals))
            elif isinstance(tree.body[-1], ast.Expr):
                # Multiple statements, last one is an expression (Jupyter-style).
                if len(tree.body) > 1:
                    exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                    exec(compile(exec_tree, "<string>", "exec"), exec_globals, exec_locals)
                eval_tree = ast.Expression(body=tree.body[-1].value)
                # Pass exec_locals so names bound by the preceding statements are
                # visible to the trailing expression (Jupyter-style REPL behavior).
                result_value = str(eval(compile(eval_tree, "<string>", "eval"), exec_globals, exec_locals))
            else:
                exec(code, exec_globals, exec_locals)
                exec_globals.update(exec_locals)
                result_value = _pick_result(exec_locals, exec_globals)

        ida_msgs = _collect_ida_messages(pre_count)
        stderr_text = stderr_capture.getvalue()
        if ida_msgs:
            stderr_text = (stderr_text + "\n" + ida_msgs).strip()
        return {
            "result": result_value or "",
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_text,
        }
    except Exception:
        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": traceback.format_exc(),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


@tool
@idasync
@unsafe
def py_eval(code: str) -> dict:
    """Execute Python in IDA context and return result/stdout/stderr.

    Assign to ``result`` (or ``__result__``) to return a value; the last
    top-level expression is also returned when not assigned.
    """
    return _run_code(code)


@tool
@idasync
@unsafe
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
