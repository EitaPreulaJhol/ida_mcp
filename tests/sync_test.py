import os
import sys
import types

# --- Stub IDA modules so we can import sync.py outside IDA ---
fake_idaapi = types.ModuleType("idaapi")
call_log = []


def fake_execute_sync(runned, reqf):
    # Run synchronously to simulate the IDA main thread.
    return runned()


fake_idaapi.execute_sync = fake_execute_sync
fake_idaapi.MFF_WRITE = 2
sys.modules["idaapi"] = fake_idaapi

fake_idc = types.ModuleType("idc")


def fake_batch(v):
    call_log.append(("batch", v))
    return 0


fake_idc.batch = fake_batch
sys.modules["idc"] = fake_idc

fake_kernwin = types.ModuleType("ida_kernwin")


def fake_clr():
    call_log.append("clr")


def fake_set():
    call_log.append("set")


fake_kernwin.clr_cancelled = fake_clr
fake_kernwin.set_cancelled = fake_set
sys.modules["ida_kernwin"] = fake_kernwin

# --- Load sync.py with the relative import patched out ---
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
src = open(os.path.join(PKG, "sync.py")).read()
src = src.replace(
    "from .zeromcp.jsonrpc import get_current_cancel_event",
    "def get_current_cancel_event(): return None",
)
mod = types.ModuleType("sync_test")
exec(compile(src, "sync_test", "exec"), mod.__dict__)
sys.modules["sync_test"] = mod

# Test 1: normal return
@mod.idasync
def ok(x):
    return x * 2


assert ok(21) == 42
print("normal return OK")

# Test 2: exception is re-raised to the caller, batch restored
@mod.idasync
def bad():
    raise ValueError("nope")


try:
    bad()
    raise AssertionError("should have raised")
except ValueError as e:
    assert "nope" in str(e)
assert ("batch", 1) in call_log, call_log
assert ("batch", 0) in call_log, call_log  # restored to previous value
print("exception re-raised + batch restored OK")

# Test 3: the wrapped callable can NEVER raise out of execute_sync.
# If runned() let an exception escape, fake_execute_sync would propagate it and
# we'd see a hang/crash. Since runned catches everything into the queue, this
# returns cleanly and the exception is delivered via the container.
@mod.idasync
def raises():
    raise RuntimeError("deadlock?")


try:
    raises()
except RuntimeError:
    pass
print("result-container prevents execute_sync deadlock OK")

# Test 4: nested @idasync raises IDASyncError (loud) instead of deadlocking.
@mod.idasync
def inner():
    return "inner"


@mod.idasync
def outer():
    return inner()


try:
    outer()
    raise AssertionError("nested call should have raised IDASyncError")
except mod.IDASyncError as e:
    assert "Call stack is not empty" in str(e), e
print("reentrancy guard raises IDASyncError OK")

# Test 5: get_tool_deadline defaults to None outside a timed body.
assert mod.get_tool_deadline() is None
print("get_tool_deadline default OK")

# Test 6: get_pre_call_batch tracks the bumped batch state.
seen = []


@mod.idasync
def probe_batch():
    seen.append(mod.get_pre_call_batch())
    return True


assert probe_batch() is True
assert seen == [0], seen  # fake batch() returns 0
assert mod.get_pre_call_batch() is None  # restored after call
print("get_pre_call_batch OK")

# Test 7: ensure_analysis fast-path, bounded-wait, and timeout-raise.
fake_auto = types.ModuleType("ida_auto")
sys.modules["ida_auto"] = fake_auto

# 7a) already complete -> no wait at all
fake_auto.auto_is_ok = lambda: True
waited = []
fake_auto.auto_wait = lambda: waited.append(True)
mod.ensure_analysis()
assert waited == [], "fast path must skip auto_wait when analysis is done"

# 7b) completes during the wait -> returns cleanly
state = {"ok": False}
fake_auto.auto_is_ok = lambda: state["ok"]
fake_auto.auto_wait = lambda: state.__setitem__("ok", True)
mod.ensure_analysis()
assert state["ok"] is True

# 7c) still running after the (deadline-bounded) wait -> clean IDAError
fake_auto.auto_is_ok = lambda: False
fake_auto.auto_wait = lambda: None
try:
    mod.ensure_analysis()
    assert False, "expected IDAError when analysis never completes"
except mod.IDAError as e:
    assert "in progress" in str(e), e

# 7d) no auto_is_ok (old IDA / stub) -> degrades to a plain auto_wait, no raise
del fake_auto.auto_is_ok
calls = []
fake_auto.auto_wait = lambda: calls.append(True)
mod.ensure_analysis()
assert calls == [True], "must fall back to a plain auto_wait"
print("ensure_analysis OK")

# Test 8: runaway-script protection. Shrink the timing knobs so this runs fast.
import time as _time
mod._NATIVE_CANCEL_GRACE_SEC = 0.2
mod._HARD_INTERRUPT_EXTRA_SEC = 0.3
mod._HARD_INTERRUPT_RETRY_SEC = 0.3


def _helper():
    return 1


# 8a) `except Exception` in the tool body cannot swallow the soft timeout.
#     (Before: IDASyncError was swallowed once, CPython then removed the
#     profile hook, and the loop ran unbounded.)
@mod.idasync
@mod.tool_timeout(0.3)
def swallow_exception():
    end = _time.monotonic() + 10
    while _time.monotonic() < end:
        try:
            _helper()
        except Exception:
            pass
    return "ran to completion"


t0 = _time.monotonic()
try:
    swallow_exception()
    raise AssertionError("timeout was swallowed by `except Exception`")
except mod.IDASyncError as e:
    assert "timed out" in str(e), e
assert _time.monotonic() - t0 < 3, _time.monotonic() - t0
print("soft timeout survives `except Exception` OK")


# 8b) bare `except:` swallows the one-shot profile interrupt; the hard
#     watchdog (script tools only) must still stop it.
@mod.idasync
@mod.tool_timeout(0.3)
@mod.hard_interrupt
def swallow_everything():
    end = _time.monotonic() + 10
    while _time.monotonic() < end:
        try:
            _helper()
        except:  # noqa: E722 - this is the scenario under test
            pass
    return "ran to completion"


t0 = _time.monotonic()
try:
    swallow_everything()
    raise AssertionError("bare except defeated the hard interrupt")
except mod.IDASyncError:
    pass
assert _time.monotonic() - t0 < 5, _time.monotonic() - t0
print("hard interrupt beats bare `except:` OK")


# 8c) call-free tight loop: the profile hook never fires at all.
@mod.idasync
@mod.tool_timeout(0.3)
@mod.hard_interrupt
def tight_loop():
    n = 0
    end = _time.monotonic() + 10
    while True:
        n += 1
        if n % 10_000_000 == 0 and _time.monotonic() > end:
            return "ran to completion"


t0 = _time.monotonic()
try:
    tight_loop()
    raise AssertionError("tight loop was not interrupted")
except mod.IDASyncError:
    pass
assert _time.monotonic() - t0 < 5, _time.monotonic() - t0
print("hard interrupt stops call-free loop OK")

# 8d) after an interrupted tool, nothing stray is left pending and the next
#     tool runs normally (watchdog disarmed, call stack clean).
_time.sleep(1.0)
assert ok(5) == 10
print("clean state after hard interrupt OK")


# 8e) exit()/SystemExit from a tool body must not escape execute_sync
#     (in IDA that left the result container empty -> server busy forever).
@mod.idasync
def calls_exit():
    raise SystemExit(2)


try:
    calls_exit()
    raise AssertionError("SystemExit should map to IDAError")
except mod.IDAError as e:
    assert "SystemExit" in str(e), e
print("SystemExit contained OK")


# 8f) IDA drops the request (execute_sync never runs the callback, e.g. the
#     database is closing): the caller must get a clean IDASyncError within
#     the grace period instead of blocking forever on the result container
#     (which, holding the tool gate, meant "Server busy" until restart).
mod._EXECUTE_SYNC_RESULT_GRACE_SEC = 0.2
_real_execute_sync = fake_idaapi.execute_sync
_dropped = []


def _dropping_execute_sync(runned, reqf):
    _dropped.append(runned)  # queued, never run
    return -1


fake_idaapi.execute_sync = _dropping_execute_sync
_side_effects = []


@mod.idasync
def never_runs():
    _side_effects.append("ran")
    return "should not happen"


t0 = _time.monotonic()
try:
    never_runs()
    raise AssertionError("dropped execute_sync must raise")
except mod.IDASyncError as e:
    assert "did not run" in str(e) and "-1" in str(e), e
assert _time.monotonic() - t0 < 2, _time.monotonic() - t0
print("dropped execute_sync -> bounded IDASyncError OK")

# 8g) if IDA runs the abandoned request late, the tool body must NOT run
#     (its result would be lost and the side effects unexpected).
fake_idaapi.execute_sync = _real_execute_sync
assert len(_dropped) == 1
_dropped[0]()
assert _side_effects == [], _side_effects
assert ok(4) == 8  # call stack / batch state still clean afterwards
print("late start of abandoned request is a no-op OK")

print("ALL SYNC RESULT-CONTAINER TESTS PASSED")
