import os
import sys
import tempfile

# Make the stdlib-only discovery module importable without loading the
# IDA-dependent ida_mcp package __init__.
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "ida_mcp")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

# Point the IDA user dir at a temp location so instance files don't touch the real one.
tmp = tempfile.mkdtemp()
os.environ["APPDATA"] = tmp

import discovery

# register_instance writes a JSON file
path = discovery.register_instance("127.0.0.1", 13337, os.getpid(), "bin", "idb", "gui")
assert os.path.isfile(path), path
print("register_instance OK", path)

# unregister_instance removes it
assert discovery.unregister_instance(13337) is True
assert not os.path.isfile(path)
print("unregister_instance OK")

# register again, then discover_instances should clean it up (nothing listening on 13337)
discovery.register_instance("127.0.0.1", 13337, os.getpid(), "bin", "idb", "gui")
found = discovery.discover_instances()
# probe_instance fails (no server) -> entry removed -> empty list
assert found == [], found
assert not os.path.isfile(path)
print("discover_instances cleanup OK")

print("ALL DISCOVERY TESTS PASSED")
