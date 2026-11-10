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


class IDASyncError(McpToolError):
    """A tool failed at the sync layer (timeout, dropped request, abort).

    Inherits ``McpToolError`` so it maps to a clean JSON-RPC ``-32000`` with
    just the message: a timeout is a tool error, not an internal crash, and a
    traceback of the sync wrapper tells the client nothing actionable.
    """


class IDAError(McpToolError):
    """Tool-facing IDA error; maps to JSON-RPC -32000 (no traceback leak)."""

    @property
    def message(self) -> str:
        return self.args[0] if self.args else ""


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""


class ToolInterrupt(BaseException):
    """Timeout/cancel injected into a running tool body.

    Deliberately a ``BaseException``: agent-written scripts routinely wrap
    work in ``try/except Exception``. An ``Exception``-derived timeout raised
    from the profile hook would be swallowed once -- and CPython *removes* a
    profile hook that raises, so the script would then run unbounded with the
    IDA UI frozen. Converted to ``IDASyncError`` / ``CancelledError`` at the
    sync boundary (see :func:`sync_wrapper`), so callers never see it.
    """

    def __init__(self, reason: str = "timeout",
                 message: str = "Tool hard-interrupted after exceeding its time limit"):
        super().__init__(message)
        self.reason = reason
        self.message = message

    def to_error(self) -> Exception:
        if self.reason == "cancel":
            return CancelledError(self.message)
        return IDASyncError(self.message)


# After the native set_cancelled() fires, tools get this long to format a
# partial result before the profile hook raises.
_NATIVE_CANCEL_GRACE_SEC = 5.0
# How often the profile hook polls ida_kernwin.user_cancelled() while a tool
# runs. In the GUI that repaints the wait box and makes its Cancel button
# work even for scripts that never poll it themselves. IDA_MCP_UI_PUMP=0
# disables it.
_UI_PUMP_INTERVAL_SEC = 0.3
# How often the profile hook runs its cancel/deadline/pump checks (see the
# ticker in sync_wrapper); between ticks the hook is a single flag read.
_PROFILE_CHECK_INTERVAL_SEC = 0.05
# Hard-interrupt watchdog (script tools only): extra time after the soft
# timeout (or after a cancel request) before an async ToolInterrupt is
# injected into the main thread, the retry period, and the max attempts.
_HARD_INTERRUPT_EXTRA_SEC = 5.0
_HARD_INTERRUPT_RETRY_SEC = 2.0
_HARD_INTERRUPT_MAX_ATTEMPTS = 10
# How long to wait for the result after execute_sync returned. A blocking
# execute_sync has already run the callback, so this only matters when IDA
# dropped the request; it bounds the wait instead of hanging forever.
_EXECUTE_SYNC_RESULT_GRACE_SEC = 2.0


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
    """Resolve the execute_sync mode, tolerating stubbed IDA modules."""
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
    # The request's cancel event is registered on the HTTP worker thread, but
    # this function runs on the IDA main thread, where that thread-local is
    # unset. sync_wrapper publishes the same event into _sync_state (which is
    # set on the main thread); the thread-local stays as a fallback for
    # direct, same-thread callers.
    event = getattr(_sync_state, "cancel_event", None)
    if event is None and get_current_cancel_event is not None:
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


def ensure_analysis() -> None:
    """Ensure IDA auto-analysis is complete before reading the IDB.

    Preferred over a bare ``ida_auto.auto_wait()`` at the top of tools that
    read analysis-derived data (functions, xrefs, names, decompilation):

    - **Fast path:** returns immediately when ``auto_is_ok()`` already reports
      analysis done (the steady-state case), skipping the wait entirely.
    - **Bounded wait:** otherwise it calls ``auto_wait()``, which the sync
      wrapper's deadline-driven ``set_cancelled()`` unblocks at the tool
      timeout. If analysis is still incomplete afterwards it raises a clean,
      retryable ``IDAError`` instead of letting the tool hold the IDA main
      thread (and the serial concurrency gate) for the whole timeout only to
      fail with a generic "timed out" message.

    Degrades to a plain ``auto_wait()`` when ``auto_is_ok`` is unavailable
    (older IDA / stubbed test modules), so it is always safe to call.
    """
    import ida_auto
    auto_is_ok = getattr(ida_auto, "auto_is_ok", None)
    if callable(auto_is_ok):
        try:
            if bool(auto_is_ok()):
                return
        except Exception:
            auto_is_ok = None  # can't tell; fall through to a plain wait
    auto_wait = getattr(ida_auto, "auto_wait", None)
    if callable(auto_wait):
        try:
            auto_wait()
        except Exception:
            pass
    if callable(auto_is_ok):
        try:
            still_running = not bool(auto_is_ok())
        except Exception:
            still_running = False
        if still_running:
            raise IDAError("Auto-analysis still in progress; retry shortly.")


def update_wait_box(text: str) -> None:
    """Refresh the tool wait-box label (progress heartbeat). Best-effort."""
    replace = getattr(ida_kernwin, "replace_wait_box", None)
    if not callable(replace):
        return
    try:
        replace(f"[ida-mcp] {text}")
    except Exception:
        pass


def _ui_pump():
    """Return ``ida_kernwin.user_cancelled`` when UI pumping is enabled.

    None when headless, when the API is missing, or when disabled with
    ``IDA_MCP_UI_PUMP=0``.
    """
    if os.getenv("IDA_MCP_UI_PUMP", "").strip().lower() in ("0", "false", "no", "off"):
        return None
    fn = getattr(ida_kernwin, "user_cancelled", None)
    if not callable(fn):
        return None
    try:
        is_idaq = getattr(ida_kernwin, "is_idaq", None)
        if callable(is_idaq) and not is_idaq():
            return None
    except Exception:
        return None
    return fn


def _guarded_body(ff, hard=None):
    """Sentinel frame: the watchdog only injects while THIS frame is live.

    The main thread cannot leave it normally without ``disarm()``, which takes
    the watchdog lock -- so a check-then-inject in the watchdog can never land
    after the tool returned, even if the GIL switches between the two.
    """
    if hard is None:
        return ff()
    hard.frame = sys._getframe()
    try:
        return ff()
    finally:
        hard.disarm()


def _load_set_async_exc():
    if os.getenv("IDA_MCP_NO_HARD_INTERRUPT", "").strip().lower() in ("1", "true", "yes"):
        return None
    try:
        import ctypes
        return (ctypes.pythonapi.PyThreadState_SetAsyncExc, ctypes.c_ulong,
                ctypes.py_object(ToolInterrupt))
    except Exception:  # non-CPython / ctypes unavailable
        return None


class _HardInterruptWatchdog:
    """Last-resort stop for runaway scripts (execute_script / py_eval / ...).

    The soft timeout lives in a profile hook, which (a) CPython removes after
    its first raise -- so a bare ``except:`` in a script defeats it -- and
    (b) never fires inside a call-free loop (``while True: n += 1``). Either
    way the IDA main thread, and with it the whole UI and the MCP server,
    stays blocked indefinitely.

    This watchdog runs on its own thread. Once the soft timeout (plus grace)
    or a cancel request is overdue, it injects ``ToolInterrupt`` into the main
    thread with ``PyThreadState_SetAsyncExc``, retrying a bounded number of
    times. It injects only while :func:`_guarded_body` is on the main
    thread's stack -- checked and injected under the GIL, so it can never
    fire into unrelated IDA/plugin code after the tool returned. A pending
    exception is delivered at the next bytecode boundary, i.e. right after a
    long SDK call returns (C code itself cannot be interrupted). Disable with
    ``IDA_MCP_NO_HARD_INTERRUPT=1``.
    """

    def __init__(self, deadline, cancel_event):
        self._tid = threading.get_ident()  # called on the IDA main thread
        self._deadline = deadline
        self._cancel_event = cancel_event
        self._done = threading.Event()
        self._lock = threading.Lock()
        self._api = _load_set_async_exc()
        self._ctid = self._api[1](self._tid) if self._api else None
        self.frame = None  # set by _guarded_body; identity-checked

    def start(self) -> None:
        if self._api is None or (self._deadline is None and self._cancel_event is None):
            return
        t = threading.Thread(target=self._run, name="ida-mcp-hard-interrupt",
                             daemon=True)
        t.start()

    def _main_in_tool(self) -> bool:
        target = self.frame
        if target is None:
            return False
        frame = sys._current_frames().get(self._tid)
        while frame is not None:
            if frame is target:
                return True
            frame = frame.f_back
        return False

    def _due_at(self, cancel_seen):
        due = None
        if self._deadline is not None:
            due = self._deadline + _NATIVE_CANCEL_GRACE_SEC + _HARD_INTERRUPT_EXTRA_SEC
        if cancel_seen is not None:
            c = cancel_seen + _HARD_INTERRUPT_EXTRA_SEC
            due = c if due is None else min(due, c)
        return due

    def _run(self) -> None:
        cancel_seen = None
        attempts = 0
        next_try = None
        while not self._done.wait(0.25):
            now = time.monotonic()
            ev = self._cancel_event
            if cancel_seen is None and ev is not None and ev.is_set():
                cancel_seen = now
            due = self._due_at(cancel_seen)
            if due is None or now < due:
                continue
            if next_try is not None and now < next_try:
                continue
            with self._lock:
                if self._done.is_set() or not self._main_in_tool():
                    return
                self._api[0](self._ctid, self._api[2])
            attempts += 1
            logger.warning("[MCP] tool still running past its limit; hard "
                           "interrupt injected (attempt %d/%d)",
                           attempts, _HARD_INTERRUPT_MAX_ATTEMPTS)
            if attempts >= _HARD_INTERRUPT_MAX_ATTEMPTS:
                return
            next_try = now + _HARD_INTERRUPT_RETRY_SEC

    def disarm(self) -> None:
        """Stop the watchdog (no further injections after this returns).

        Deliberately does NOT call ``PyThreadState_SetAsyncExc(tid, NULL)`` to
        "clear" a pending interrupt: on CPython 3.11 doing so when nothing is
        pending leaves the eval-breaker async flag stuck, and the next call
        made under a profile hook spins forever (would hang IDA). Clearing is
        unnecessary anyway: injection only happens while ``_guarded_body`` is
        on the stack (checked under the GIL), and a pending async exception is
        delivered at the latest when that call returns into ``timed_ff``'s
        ``try`` (CPython checks the eval breaker after every CALL), where it
        is caught and converted.
        """
        with self._lock:
            self._done.set()


def _sync_wrapper(ff, keep_batch: bool = False, mode=None):
    """Run ``ff`` on the IDA main thread (default write mode).

    Uses a result container so the callable can never raise out of
    ``execute_sync`` (which would deadlock the main thread).
    """
    res_container = queue.Queue()
    # Handshake with the waiter below: once the waiter gives up on a request
    # IDA never started, a late start must not run the tool body (its result
    # would be dropped and its side effects unexpected).
    state_lock = threading.Lock()
    state = {"started": False, "abandoned": False}

    def runned():
        with state_lock:
            if state["abandoned"]:
                return
            state["started"] = True
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
        t0 = time.monotonic()
        try:
            res_container.put(ff())
            completed = True
        except BaseException as x:  # noqa: BLE001 - capture, never re-raise here
            # BaseException too: a script calling exit() raises SystemExit,
            # which would otherwise escape execute_sync with the container
            # still empty -- the HTTP thread then blocks forever on get()
            # while holding the tool gate ("Server busy" until IDA restarts).
            res_container.put(x)
        finally:
            # Telemetry for two-phase targeting: how long each tool held
            # the IDA main thread (the serial resource behind UI freezes).
            try:
                hold_ms = (time.monotonic() - t0) * 1000.0
            except Exception:
                hold_ms = -1.0
            logger.debug("[MCP] tool %s held main thread %.1fms",
                          ff.__name__, hold_ms)
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

    rc = idaapi.execute_sync(runned, _resolve_sync_mode(mode))
    # execute_sync (without MFF_NOWAIT) returns only after runned() finished,
    # so the result is normally already queued. If IDA refused/dropped the
    # request (database closing, shutdown), runned() never runs: an unbounded
    # get() would then block this HTTP thread forever while it holds the tool
    # gate, and every later call would answer "Server busy" until restart.
    try:
        res = res_container.get(timeout=_EXECUTE_SYNC_RESULT_GRACE_SEC)
    except queue.Empty:
        with state_lock:
            never_started = not state["started"]
            if never_started:
                state["abandoned"] = True
        if never_started:
            # The cause is an internal queue timeout; the message below is the
            # whole story for the caller.
            raise IDASyncError(
                f"IDA did not run '{ff.__name__}' on the main thread "
                f"(execute_sync returned {rc!r}); the database may be closing. "
                f"Retry once IDA is idle.") from None
        # Started but still running (should not happen for a blocking
        # execute_sync): the tool timeout / hard interrupt bound it.
        res = res_container.get()
    if isinstance(res, ToolInterrupt):
        raise res.to_error()
    if isinstance(res, Exception):
        raise res
    if isinstance(res, BaseException):
        # SystemExit / KeyboardInterrupt from a tool body: never let them
        # unwind the HTTP worker thread (no reply would ever be sent).
        raise IDAError(f"Tool aborted by {type(res).__name__}: {res}")
    return res


def sync_wrapper(ff, timeout_override=None, keep_batch=False, mode=None,
                 hard_interrupt=False):
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

            pump = _ui_pump()
            next_pump = [time.monotonic() + _UI_PUMP_INTERVAL_SEC]

            # The hook fires on EVERY Python call/return and C call/return of
            # the tool body (every SDK call is 2-4 events), so its body is
            # the hot path: running the full checks each time made call-heavy
            # tools ~10x slower. A ticker thread raises ``tick`` every
            # _PROFILE_CHECK_INTERVAL_SEC and the hook does real work only
            # then -- one list read per event otherwise. Latency stays bounded
            # by time (not by event count, which slow SDK calls would stretch).
            tick = [True]
            stop_ticker = threading.Event()

            def _ticker():
                while not stop_ticker.wait(_PROFILE_CHECK_INTERVAL_SEC):
                    tick[0] = True

            def profilefunc(frame, event, arg):
                if not tick[0]:
                    return
                tick[0] = False
                # NOTE: CPython unsets the profile hook as soon as it raises,
                # so each raise below is a one-shot. ToolInterrupt is a
                # BaseException so `except Exception` in the tool body cannot
                # swallow it; the hard-interrupt watchdog covers the rest.
                # Check request-level cancellation first (higher priority).
                if cancel_event is not None and cancel_event.is_set():
                    raise ToolInterrupt("cancel", "Request was cancelled")
                now = time.monotonic()
                # If native cancel just fired, give the tool a short grace
                # period to format a partial response rather than racing the
                # timeout. Beyond that we still raise to bound the response
                # time.
                fired_at = cancel_fired_at[0]
                if fired_at is not None and now < fired_at + _NATIVE_CANCEL_GRACE_SEC:
                    return
                if deadline is not None and now >= deadline:
                    raise ToolInterrupt("timeout", f"Tool timed out after {timeout:.2f}s")
                # Keep the wait box alive: polling user_cancelled() lets IDA
                # repaint it and honours its Cancel button even for scripts
                # that never poll it themselves.
                if pump is not None and now >= next_pump[0]:
                    next_pump[0] = now + _UI_PUMP_INTERVAL_SEC
                    try:
                        user_hit_cancel = bool(pump()) and cancel_fired_at[0] is None
                    except Exception:
                        user_hit_cancel = False
                    if user_hit_cancel:
                        raise ToolInterrupt("cancel", "Cancelled by user (IDA wait box)")

            hard = None
            if hard_interrupt:
                hard = _HardInterruptWatchdog(deadline, cancel_event)
                hard.start()

            # Started last, right before the try whose finally stops it.
            threading.Thread(target=_ticker, name="ida-mcp-profile-tick",
                             daemon=True).start()
            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            # Expose the deadline so tool bodies can self-monitor and
            # return partial results gracefully (independent of the Timer).
            # The cancel event travels with it: check_cancelled() runs on
            # this (main) thread, where the HTTP thread's thread-local is
            # invisible.
            _deadline_state.deadline = deadline
            _sync_state.cancel_event = cancel_event
            try:
                return _guarded_body(ff, hard)
            except ToolInterrupt as e:
                raise e.to_error() from None
            finally:
                if hard is not None:
                    # Backup for an interrupt delivered inside the sentinel's
                    # own finally (before disarm ran). The sentinel frame is
                    # gone now, so the watchdog can no longer inject anyway.
                    hard._done.set()
                    hard.frame = None
                if sys.getprofile() is not profilefunc:
                    # The tool body (typically execute_script) installed its
                    # own hook, which also removed our soft-timeout hook for
                    # the rest of the call. Restore the host's hook anyway: a
                    # script must not leave a global profiler behind. Script
                    # tools are still bounded by the hard-interrupt watchdog.
                    logger.warning(
                        "[MCP] tool %s replaced sys.setprofile; the soft "
                        "timeout was not enforced for the rest of the call",
                        ff.__name__)
                sys.setprofile(old_profile)
                stop_ticker.set()
                _deadline_state.deadline = None
                _sync_state.cancel_event = None
                if native_timer is not None:
                    native_timer.cancel()
                # Sticky flag: clear unconditionally so the next tool starts
                # with a clean state.
                ida_kernwin.clr_cancelled()

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, keep_batch=keep_batch, mode=mode)
    return _sync_wrapper(ff, keep_batch=keep_batch, mode=mode)


def _idasync_with_mode(f, mode):
    """Decorate ``f`` to run on the IDA main thread with ``execute_sync(mode)``."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(getattr(f, "__ida_mcp_timeout_sec__", None))
        keep_batch = bool(getattr(f, "__ida_mcp_keep_batch__", False))
        hard = bool(getattr(f, "__ida_mcp_hard_interrupt__", False))
        return sync_wrapper(ff, timeout_override, keep_batch=keep_batch,
                            mode=mode, hard_interrupt=hard)

    return wrapper


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    The single sync decorator: every tool mutates something on its way in
    (``ensure_analysis()`` runs auto-analysis, the decompiler caches, type and
    name queries touch caches), so MFF_WRITE is the honest mode for all of
    them. Hex-Rays calls require WRITE regardless.
    """
    return _idasync_with_mode(f, getattr(idaapi, "MFF_WRITE", 2))


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


def hard_interrupt(func):
    """Decorator: arm the hard-interrupt watchdog for this tool.

    For tools that run arbitrary user/agent code (``execute_script``,
    ``py_eval``, ``py_exec_file``) where the profile-hook timeout can be
    swallowed or never reached. Apply like :func:`keep_batch` (innermost,
    after ``@idasync``).
    """

    setattr(func, "__ida_mcp_hard_interrupt__", True)
    return func
