"""IDA main-thread synchronization (ported from ida-pro-mcp sync.py).

All IDA SDK calls must run on the main thread. ``idasync`` wraps a function so
it executes via ``idaapi.execute_sync(MFF_WRITE)``. A ``queue.Queue`` result
container guarantees the wrapped callable never raises out of ``execute_sync``
-- otherwise ``execute_sync`` would never return and hang the IDA UI.
"""
import functools
import logging
import os
import queue
import sys
import threading
import time

import idaapi
import ida_kernwin
import idc

logger = logging.getLogger(__name__)

try:
    from .zeromcp.jsonrpc import RequestCancelledError
except ImportError:  # standalone test harness execs this file without package context
    RequestCancelledError = Exception

try:
    from .zeromcp.mcp import McpToolError
except ImportError:  # same harness caveat (clean -32000 mapping when available)
    McpToolError = Exception

_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 60.0


class IDASyncError(Exception):
    pass


class IDAError(McpToolError):
    """Tool-facing IDA error; maps to JSON-RPC -32000 (no traceback leak)."""

    @property
    def message(self) -> str:
        return self.args[0] if self.args else ""


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


def _normalize_timeout(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# Thread-local: while a synchronized tool body is running, holds the batch
# value that was in effect *before* the sync wrapper bumped it to 1. Tools
# decorated with @keep_batch (e.g. dbg_start, whose async work runs after
# execute_sync exits) read this via get_pre_call_batch() so they can restore
# the caller's original state instead of a hard-coded default.
_sync_state = threading.local()


def get_pre_call_batch() -> int | None:
    """Return the pre-call batch state, or None if not inside a sync body."""
    return getattr(_sync_state, "pre_call_batch", None)


# Reentrancy guard: tracks the stack of @idasync bodies currently executing
# on the IDA main thread. A nested @idasync call (tool calling another tool)
# raises IDASyncError with a clear message instead of deadlocking inside a
# re-entrant idaapi.execute_sync.
call_stack = queue.LifoQueue()

# Thread-local: while a synchronized tool body is running, holds the monotonic
# deadline (or None if no timeout). Tools can poll get_tool_deadline() to
# self-monitor and return partial results gracefully.
_deadline_state = threading.local()


def get_tool_deadline() -> float | None:
    """Return the monotonic deadline for the current tool call, or None.

    Only meaningful inside an @idasync function body. Tools that walk large
    structures should check ``time.monotonic() >= get_tool_deadline()`` to
    bail cleanly instead of relying solely on the profile-hook timeout.
    """
    return getattr(_deadline_state, "deadline", None)


def _show_tool_wait_box(tool_name: str) -> bool:
    """Show a cancellable wait box for a tool running on the main thread.

    Without this, a slow tool inside execute_sync looks like a UI freeze
    with no Cancel option. show_wait_box pumps UI messages so IDA stays
    responsive and the user can abort (SDK calls polling user_cancelled
    / the sync timeout timer then unwind the tool). Best-effort: never
    raises, even outside the GUI or when another box is already shown.
    Returns True if a box was shown (caller must hide it).
    """
    show = getattr(ida_kernwin, "show_wait_box", None)
    if not callable(show):
        return False
    try:
        # Skip when headless/batch: a modal box has nowhere to pump.
        is_idaq = getattr(ida_kernwin, "is_idaq", None)
        if callable(is_idaq) and not is_idaq():
            return False
    except Exception:
        pass
    try:
        show(f"[ida-mcp] {tool_name} running... (Cancel aborts)")
        return True
    except Exception:
        return False


def _hide_tool_wait_box() -> None:
    hide = getattr(ida_kernwin, "hide_wait_box", None)
    if not callable(hide):
        return
    try:
        hide()
    except Exception:
        pass


def _resolve_sync_mode(explicit) -> int:
    """Resolve the execute_sync mode, tolerating stubbed IDA modules.

    Test harnesses stub ``idaapi`` with only ``MFF_WRITE``; fall back to it
    when ``MFF_READ`` is unavailable so ``idasync_read`` still works there.
    """
    if explicit is not None:
        return explicit
    return getattr(idaapi, "MFF_WRITE", 2)


def check_cancelled() -> None:
    """Raise if the current tool should abort (poll from long loops).

    Checks, in order: request-level cancellation
    (``notifications/cancelled``), the per-tool deadline, and IDA's
    cancellable-flag (set by the wait-box Cancel button or the sync
    timeout timer). Call every N iterations in any loop that can walk a
    whole binary; on timeout/cancel the caller should return partial
    results (see ``survey_binary``) or let it propagate (mapped to a
    clean JSON-RPC error, never a hang). No-op outside a tool body.
    Best-effort: never raises for missing IDA APIs, only for real cancel.
    """
    try:
        from .zeromcp.jsonrpc import get_current_cancel_event
    except ImportError:
        get_current_cancel_event = None  # type: ignore[assignment]
    if get_current_cancel_event is not None:
        try:
            event = get_current_cancel_event()
        except Exception:
            event = None
        if event is not None:
            try:
                is_set = event.is_set()
            except Exception:
                is_set = False
            if is_set:
                raise CancelledError("Request was cancelled")
    try:
        deadline = getattr(_deadline_state, "deadline", None)
    except Exception:
        deadline = None
    if deadline is not None:
        try:
            expired = time.monotonic() >= deadline
        except Exception:
            expired = False
        if expired:
            raise IDASyncError(f"Tool timed out after {_get_tool_timeout_seconds():.2f}s")
    try:
        user_cancelled = getattr(ida_kernwin, "user_cancelled", None)
        if callable(user_cancelled) and bool(user_cancelled()):
            raise CancelledError("Cancelled by user")
    except (CancelledError, RequestCancelledError):
        raise
    except Exception:
        pass


def update_wait_box(text: str) -> None:
    """Refresh the tool wait-box label (progress heartbeat). Best-effort."""
    replace = getattr(ida_kernwin, "replace_wait_box", None)
    if not callable(replace):
        return
    try:
        replace(f"[ida-mcp] {text}")
    except Exception:
        pass


def _sync_wrapper(ff, keep_batch: bool = False, mode=None):
    """Run ``ff`` on the IDA main thread (default write mode).

    Uses a result container so the callable can never raise out of
    ``execute_sync`` (which would deadlock the main thread).
    """
    res_container = queue.Queue()

    def runned():
        if not call_stack.empty():
            # Non-blocking: a concurrent reentrant @idasync call from
            # within another tool's ff() on the same main thread may
            # have drained the queue between empty() and get().
            try:
                last_func_name = call_stack.get_nowait()
            except queue.Empty:
                last_func_name = "<empty>"
            error_str = (f"Call stack is not empty while calling the function "
                         f"{ff.__name__} from {last_func_name}")
            raise IDASyncError(error_str)

        call_stack.put(ff.__name__)
        old_batch = idc.batch(1)
        prev_pre_call = getattr(_sync_state, "pre_call_batch", None)
        _sync_state.pre_call_batch = old_batch
        wait_shown = _show_tool_wait_box(ff.__name__)
        completed = False
        try:
            res_container.put(ff())
            completed = True
        except Exception as x:  # noqa: BLE001 - capture, never re-raise here
            res_container.put(x)
        finally:
            if wait_shown:
                _hide_tool_wait_box()
            if not (completed and keep_batch):
                try:
                    idc.batch(old_batch)
                except Exception:
                    pass
            _sync_state.pre_call_batch = prev_pre_call
            # Non-blocking: a reentrant @idasync invoked synchronously
            # inside ff() may have already popped our entry. Default
            # block=True would freeze the IDA main thread on an empty
            # queue and hang every subsequent @idasync call.
            try:
                call_stack.get_nowait()
            except queue.Empty:
                pass

    idaapi.execute_sync(runned, _resolve_sync_mode(mode))
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res


def sync_wrapper(ff, timeout_override=None, keep_batch=False, mode=None):
    """Wrapper to enable timeout and cancellation during IDA synchronization."""
    from .zeromcp.jsonrpc import get_current_cancel_event

    cancel_event = get_current_cancel_event()
    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:

        def timed_ff():
            # Calculate deadline when execution starts on the IDA main thread,
            # not when the request was queued (avoids stale deadlines).
            deadline = time.monotonic() + timeout if timeout > 0 else None

            # Native cancellation: clear any stale flag and schedule a
            # set_cancelled() at the deadline. Many IDA SDK calls poll
            # user_cancelled() and bail within one poll cycle, freeing the
            # main thread instead of running to natural completion.
            ida_kernwin.clr_cancelled()
            cancel_fired_at: list[float | None] = [None]
            native_timer: threading.Timer | None = None
            if deadline is not None:
                def _fire_native_cancel():
                    cancel_fired_at[0] = time.monotonic()
                    ida_kernwin.set_cancelled()

                native_timer = threading.Timer(timeout, _fire_native_cancel)
                native_timer.daemon = True
                native_timer.start()

            def profilefunc(frame, event, arg):
                # Check request-level cancellation first (higher priority).
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                # If native cancel just fired, give the tool a short grace
                # period to format a partial response rather than racing the
                # IDASyncError. Beyond that we still raise to bound the
                # response time.
                fired_at = cancel_fired_at[0]
                if fired_at is not None and time.monotonic() < fired_at + 5.0:
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            # Expose the deadline so tool bodies can self-monitor and
            # return partial results gracefully (independent of the Timer).
            _deadline_state.deadline = deadline
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)
                _deadline_state.deadline = None
                if native_timer is not None:
                    native_timer.cancel()
                # Sticky flag: clear unconditionally so the next tool starts
                # with a clean state.
                ida_kernwin.clr_cancelled()

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, keep_batch=keep_batch, mode=mode)
    return _sync_wrapper(ff, keep_batch=keep_batch, mode=mode)


def _idasync_with_mode(f, mode):
    """Shared body for @idasync (write) and @idasync_read (read)."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(getattr(f, "__ida_mcp_timeout_sec__", None))
        keep_batch = bool(getattr(f, "__ida_mcp_keep_batch__", False))
        return sync_wrapper(ff, timeout_override, keep_batch=keep_batch,
                            mode=mode)

    return wrapper


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    Default for all tools. Read-only tools may use @idasync_read, but
    anything touching Hex-Rays/decompilation must stay on WRITE.
    """
    return _idasync_with_mode(f, getattr(idaapi, "MFF_WRITE", 2))


def idasync_read(f):
    """Run the function on the IDA main thread in read (shared) mode.

    For pure read-only tools (listings, queries). Never use for tools that
    mutate the IDB, call the decompiler, or change types/names/comments.
    Falls back to WRITE when the IDA version lacks MFF_READ.
    """
    return _idasync_with_mode(
        f, getattr(idaapi, "MFF_READ", getattr(idaapi, "MFF_WRITE", 2)))


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    Must be applied BEFORE @idasync (i.e. listed AFTER it) so the attribute
    exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """

    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func

    return decorator


def keep_batch(func):
    """Decorator to skip the sync wrapper's post-call batch-mode restore.

    Apply when the tool schedules asynchronous work that runs on the IDA main
    thread *after* execute_sync exits. The decorated function MUST arrange
    batch-mode restoration itself.
    """

    setattr(func, "__ida_mcp_keep_batch__", True)
    return func
