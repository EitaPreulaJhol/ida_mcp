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

# Per-harness wall-clock limit. The slowest harness (sync_test, with its
# timeout/cancel timing knobs) runs in ~15 s; 300 s catches a hang without
# ever failing a slow-but-healthy machine.
TEST_TIMEOUT_SEC = 300

TESTS = [
    "discovery_test.py",
    "compat_test.py",
    "api_test.py",
    "plugin_test.py",
    "server_test.py",
    "sync_test.py",
    "smoke.py",
    "analysis_test.py",
    "memory_test.py",
    "inspection_test.py",
    "annotation_test.py",
    "bookmark_test.py",
    "modify_test.py",
    "names_test.py",
    "functions_test.py",
    "ida94_calls_test.py",
    "query_test.py",
    "search_flags_test.py",
    "composite_test.py",
    "tool_inventory_test.py",
    "api_memory_test.py",
    "xrefs_test.py",
    "strings_test.py",
    "hexrays_test.py",
    "info_types_test.py",
    "typeinfo_upsert_test.py",
    "server_extra_test.py",
    "debug_test.py",
    "hooks_test.py",
    "sigmaker_test.py",
    "session_test.py",
    "conn_cap_test.py",
    "profile_http_test.py",
    "transport_test.py",
    "disconnect_test.py",
    "gate_test.py",
    "metrics_audit_test.py",
    "resources_test.py",
    "robustness_test.py",
    "skills_sync_test.py",
    "packaging_test.py",
    "package_test.py",
    "idadocs_crosscheck_test.py",  # skips if IDAPYTHON_DOCS_DIR absent
]


def main() -> int:
    failures = []
    for name in TESTS:
        path = os.path.join(HERE, name)
        print(f"\n=== {name} ===")
        # A hanging harness (deadlock, wait box, an infinite loop in stubbed
        # IDA code) used to hang the whole run and with it CI.
        try:
            rc = subprocess.call([sys.executable, path], timeout=TEST_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            print(f"TIMEOUT after {TEST_TIMEOUT_SEC}s")
            rc = -1
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
