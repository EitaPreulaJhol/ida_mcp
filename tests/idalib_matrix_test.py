"""Opt-in IDA-version matrix for live idalib smoke checks.

Discovers installed IDA trees, then runs (in separate subprocesses, because
idalib can only load one major version per process):

1. the read-only all-tools sweep (``idalib_all_tools_test.py``);
2. the modern ``ida-mcp-bridge/`` folder-loader check
   (``idalib_folder_loader_test.py``) against the extracted release ZIP.

Opt-in. Skips green unless ``IDA_MCP_IDALIB=1``; set
``IDA_MCP_IDALIB_BINARY`` to the sample binary, and either let discovery find
common install paths or pass an explicit list:

    IDA_MCP_IDALIB_MATRIX=/opt/ida-8.5:/opt/ida-9.5 make idalib-matrix

Entries may be ``label=/path``. On Linux/macOS the path separator is ``:``;
on Windows it is ``;``. This harness is intentionally not part of
``tests/run_all.py`` (CI has no IDA license); it is a local release gate.
"""
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SWEEP = os.path.join(HERE, "idalib_all_tools_test.py")
FOLDER_TEST = os.path.join(HERE, "idalib_folder_loader_test.py")
PACKAGE = os.path.join(ROOT, "scripts", "package.py")
TIMEOUT_SEC = 900


def _skip(reason):
    print(f"SKIP: {reason}")
    sys.exit(0)


def _read_version():
    text = open(os.path.join(ROOT, "ida_mcp", "__init__.py"), encoding="utf-8").read()
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("could not read ida_mcp.__version__")
    return match.group(1)


def _default_candidates():
    home = os.path.expanduser("~")
    patterns = [
        os.path.join(home, "Applications", "IDAPro*"),
        os.path.join(home, "Applications", "IDA*"),
        os.path.join(home, "ida*"),
        "/opt/ida*",
        "/opt/IDA*",
        "/Applications/IDA Pro*",
        "/Applications/IDA*",
        r"C:\Program Files\IDA*",
        r"C:\Program Files (x86)\IDA*",
    ]
    found = []
    for pattern in patterns:
        found.extend(glob.glob(pattern))
    return found


def _candidate_entries():
    raw = (os.environ.get("IDA_MCP_IDALIB_MATRIX", "").strip()
           or os.environ.get("IDA_MCP_IDA_INSTALLS", "").strip())
    if raw:
        entries = []
        for item in raw.split(os.pathsep):
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                label, path = item.split("=", 1)
            else:
                label, path = "", item
            entries.append((label.strip() or os.path.basename(path.rstrip(os.sep)), path))
        return entries
    return [("", path) for path in _default_candidates()]


def _installs():
    """Deduplicated (label, path) for trees carrying idalib/python."""
    seen = set()
    out = []
    for label, path in _candidate_entries():
        path = os.path.abspath(os.path.expanduser(path))
        python_dir = os.path.join(path, "idalib", "python")
        if not os.path.isdir(python_dir):
            continue
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        out.append((label or os.path.basename(path.rstrip(os.sep)), path))
    return sorted(out, key=lambda item: item[1])


def _subprocess_env(install):
    """Environment for one idalib version, without inheriting another's paths."""
    env = os.environ.copy()
    env["IDA_MCP_IDALIB"] = "1"
    py_path = os.path.join(install, "idalib", "python")
    env["PYTHONPATH"] = py_path
    lib_dirs = [install, os.path.join(install, "plugins")]
    for name in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        old = [p for p in env.get(name, "").split(os.pathsep) if p]
        env[name] = os.pathsep.join(lib_dirs + old)
    return env


def _binary():
    binary = os.environ.get("IDA_MCP_IDALIB_BINARY", "").strip()
    if not binary:
        binary = "/bin/ls" if os.path.isfile("/bin/ls") else sys.executable
    return binary


def _build_folder(tmp):
    """Build the modern ZIP and extract its one top-level plugin folder."""
    result = subprocess.run(
        [sys.executable, PACKAGE], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    if result.returncode != 0:
        print(result.stdout)
        raise SystemExit("package build failed")
    version = _read_version()
    archive = os.path.join(ROOT, "dist", f"ida_mcp-{version}.zip")
    if not os.path.isfile(archive):
        raise SystemExit(f"modern ZIP not found after build: {archive}")
    plugins = os.path.join(tmp, "plugins")
    os.makedirs(plugins)
    with zipfile.ZipFile(archive) as z:
        z.extractall(plugins)
    folder = os.path.join(plugins, "ida-mcp-bridge")
    required = ("ida-plugin.json", "ida_mcp_loader.py", "ida_mcp")
    missing = [name for name in required if not os.path.exists(os.path.join(folder, name))]
    if missing:
        raise SystemExit(f"modern folder incomplete: {missing}")
    return folder


def _run(label, stage, cmd, env, cwd):
    print(f"\n--- {label}: {stage} ---")
    try:
        result = subprocess.run(
            cmd, cwd=cwd, env=env, text=True, timeout=TIMEOUT_SEC,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT after {TIMEOUT_SEC}s")
        return False, "timeout"
    output = result.stdout or ""
    print(output, end="" if output.endswith("\n") else "\n")
    skipped = "SKIP:" in output
    if result.returncode != 0:
        return False, "failed"
    return (False, "skipped") if skipped else (True, "passed")


def main():
    if os.environ.get("IDA_MCP_IDALIB", "").strip() not in ("1", "true", "yes"):
        _skip("IDA_MCP_IDALIB not set (local-only idalib matrix gate).")

    installs = _installs()
    if not installs:
        _skip("no IDA installs with idalib/python found; set "
              "IDA_MCP_IDALIB_MATRIX=/path/to/ida[:/path/to/other-ida]")

    binary = _binary()
    if not os.path.isfile(binary):
        _skip(f"IDA_MCP_IDALIB_BINARY is not a file: {binary!r}")

    tmp = tempfile.mkdtemp(prefix="ida_mcp_matrix_")
    results = []
    try:
        folder = _build_folder(tmp)
        print(f"matrix sample: {binary}")
        print(f"matrix installs: {', '.join(label for label, _ in installs)}")
        for label, install in installs:
            env = _subprocess_env(install)
            env["IDA_MCP_IDALIB_BINARY"] = binary
            ok, state = _run(
                label, "safe-tool sweep",
                [sys.executable, SWEEP], env, ROOT)
            results.append((label, "sweep", state))
            if ok:
                env = _subprocess_env(install)
                env["IDA_MCP_FOLDER_ROOT"] = folder
                ok2, state2 = _run(
                    label, "folder loader",
                    [sys.executable, FOLDER_TEST], env, tmp)
                results.append((label, "folder", state2))
            else:
                results.append((label, "folder", "not-run"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    failures = [(label, stage) for label, stage, state in results if state == "failed"]
    skipped = [(label, stage) for label, stage, state in results if state == "skipped"]
    passed = [(label, stage) for label, stage, state in results if state == "passed"]
    for label, stage, state in results:
        print(f"{state:8} {label}: {stage}")
    print(f"\npassed={len(passed)} skipped={len(skipped)} failed={len(failures)}")
    if failures:
        print("FAILED matrix entries: " + ", ".join(f"{l}/{s}" for l, s in failures))
        return 1
    if not passed:
        print("SKIP: every matrix entry skipped (idalib/license unavailable).")
        return 0
    print("ALL IDALIB MATRIX CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
