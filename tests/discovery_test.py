import os
import sys
import tempfile

# Make the stdlib-only discovery module importable without loading the
# IDA-dependent ida_mcp package __init__.
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

# Point the instances dir at a temp location so the test neither touches
# the real user dir nor sees real IDA instances. NOTE: setting APPDATA alone
# only works on Windows (_get_ida_user_dir uses expanduser("~") elsewhere),
# so patch the resolver directly.
tmp = tempfile.mkdtemp()
os.environ["APPDATA"] = tmp  # kept for the Windows branch

import discovery

# Capture the real resolver before redirecting it: 14.16 exercises it directly.
_orig_get_ida_user_dir = discovery._get_ida_user_dir
discovery._get_ida_user_dir = lambda: os.path.join(tmp, ".idapro")

# Test-local port: 13337 is the plugin default and a real IDA may listen on
# it (live PID + open TCP => entry kept => flaky assert below).
TEST_PORT = 18993

# register_instance writes a JSON file
path = discovery.register_instance("127.0.0.1", TEST_PORT, os.getpid(), "bin", "idb", "gui")
assert os.path.isfile(path), path
print("register_instance OK", path)

# unregister_instance removes it
assert discovery.unregister_instance(TEST_PORT) is True
assert not os.path.isfile(path)
print("unregister_instance OK")

# register again, then discover_instances should clean it up (nothing listening on TEST_PORT)
discovery.register_instance("127.0.0.1", TEST_PORT, os.getpid(), "bin", "idb", "gui")
found = discovery.discover_instances()
# probe_instance fails (no server) -> entry removed -> empty list
assert found == [], found
assert not os.path.isfile(path)
print("discover_instances cleanup OK")

# is_pid_alive: own process alive, a finished one dead (on Windows the
# Popen object still holds a handle, so an exit-code check is required).
import subprocess
assert discovery.is_pid_alive(os.getpid())
_p = subprocess.Popen([sys.executable, "-c", "pass"])
_p.wait()
assert not discovery.is_pid_alive(_p.pid), _p.pid
if sys.platform == "win32":
    # PID 4 (System) always exists but is not ours: OpenProcess is denied.
    assert discovery.is_pid_alive(4), "access-denied process must count as alive"
else:
    # EPERM from kill(pid, 0) = the process exists under another user.
    _real_kill = os.kill

    def _eperm(pid, sig):
        raise PermissionError(1, "Operation not permitted")

    os.kill = _eperm
    try:
        assert discovery.is_pid_alive(12345), "EPERM must count as alive"
    finally:
        os.kill = _real_kill
print("is_pid_alive (dead / foreign-owned) OK")

# 14.16: the real resolver must not raise when APPDATA is missing (Windows
# services / stripped profiles), and must still land in the IDA user dir.
_real_platform = sys.platform
_saved_appdata = os.environ.pop("APPDATA", None)
try:
    sys.platform = "win32"
    _path = _orig_get_ida_user_dir()
finally:
    sys.platform = _real_platform
    if _saved_appdata is not None:
        os.environ["APPDATA"] = _saved_appdata
assert _path.endswith(os.path.join("Hex-Rays", "IDA Pro")), _path
print("missing APPDATA falls back to the home profile OK")

# 6.4: the instance file is local, but its `host` is data. Probing whatever it
# says would turn discovery into a port scanner for the IDA process, so only
# addresses that can be this machine are probed; the rest are reported as
# unverified.
_real_probe = discovery.probe_instance
_probed = []


def _recording_probe(host, port, timeout=2.0):
    _probed.append((host, port))
    return True


discovery.probe_instance = _recording_probe
discovery._LOCAL_ADDRESSES = {"127.0.0.1", "::1", "localhost"}
try:
    cases = [
        ("127.0.0.1", 18981, True, "127.0.0.1"),      # loopback: probed as-is
        ("0.0.0.0", 18982, True, "127.0.0.1"),        # wildcard bind -> loopback
        ("localhost", 18983, True, "127.0.0.1"),      # name for this machine
        ("evil.example.com", 18984, False, None),     # not resolved, not probed
        ("8.8.8.8", 18985, False, None),              # not this machine
    ]
    for host, port, should_probe, target in cases:
        _probed.clear()
        discovery.register_instance(host, port, os.getpid(), "b", "i", "gui")
        found = {e["port"]: e for e in discovery.discover_instances()}
        assert port in found, (host, found)
        if should_probe:
            assert _probed == [(target, port)], (host, _probed)
            assert not found[port].get("unverified"), found[port]
        else:
            assert _probed == [], (host, _probed)
            assert found[port].get("unverified") is True, found[port]
        discovery.unregister_instance(port)
finally:
    discovery.probe_instance = _real_probe
print("discovery probes only local addresses OK")

print("ALL DISCOVERY TESTS PASSED")
