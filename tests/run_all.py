"""Run all ida_mcp standalone test harnesses.

Each test is a self-contained script (stubs IDA modules / loads sources via
exec) so it can run outside IDA. This runner executes them in subprocesses and
reports a summary.

Usage:
    python tests/run_all.py
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

TESTS = [
    "discovery_test.py",
    "api_test.py",
    "plugin_test.py",
    "server_test.py",
    "sync_test.py",
    "smoke.py",
    "analysis_test.py",
    "memory_test.py",
    "inspection_test.py",
    "annotation_test.py",
    "names_test.py",
    "query_test.py",
    "composite_test.py",
    "tool_inventory_test.py",
    "api_memory_test.py",
    "xrefs_test.py",
    "strings_test.py",
    "hexrays_test.py",
    "info_types_test.py",
    "server_extra_test.py",
    "debug_test.py",
    "hooks_test.py",
    "sigmaker_test.py",
    "transport_test.py",
    "disconnect_test.py",
    "gate_test.py",
]


def main() -> int:
    failures = []
    for name in TESTS:
        path = os.path.join(HERE, name)
        print(f"\n=== {name} ===")
        rc = subprocess.call([sys.executable, path])
        if rc != 0:
            failures.append(name)

    print("\n" + "=" * 50)
    if failures:
        print(f"FAILED ({len(failures)}): {', '.join(failures)}")
        return 1
    print(f"ALL {len(TESTS)} TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
