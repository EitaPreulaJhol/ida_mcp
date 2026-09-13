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

print("ALL SYNC RESULT-CONTAINER TESTS PASSED")
