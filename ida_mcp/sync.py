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


def _sync_wrapper(ff, keep_batch: bool = False):
    """Run ``ff`` on the IDA main thread in write mode.

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
        completed = False
        try:
            res_container.put(ff())
            completed = True
        except Exception as x:  # noqa: BLE001 - capture, never re-raise here
            res_container.put(x)
        finally:
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

    idaapi.execute_sync(runned, idaapi.MFF_WRITE)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res


def sync_wrapper(ff, timeout_override=None, keep_batch=False):
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
        return _sync_wrapper(timed_ff, keep_batch=keep_batch)
    return _sync_wrapper(ff, keep_batch=keep_batch)


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    Unified decorator for all IDA synchronization. Read-only operations may
    still require write access (e.g. decompilation), so a single decorator is
    used.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(getattr(f, "__ida_mcp_timeout_sec__", None))
        keep_batch = bool(getattr(f, "__ida_mcp_keep_batch__", False))
        return sync_wrapper(ff, timeout_override, keep_batch=keep_batch)

    return wrapper


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
