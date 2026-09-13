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

print("ALL DISCOVERY TESTS PASSED")
