"""Instance discovery (trimmed from ida-pro-mcp discovery.py).

IDA plugin instances register themselves by writing JSON files to
{ida_user_dir}/mcp/instances/. The MCP server discovers running instances by
reading these files and validating PID liveness + TCP reachability.
"""
import datetime
import glob
import json
import os
import socket
import sys
import tempfile


def _get_ida_user_dir() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def get_instances_dir() -> str:
    return os.path.join(_get_ida_user_dir(), "mcp", "instances")


def _instance_file_path(port: int) -> str:
    return os.path.join(get_instances_dir(), f"instance_{port}.json")


def register_instance(host, port, pid, binary, idb_path, backend="gui") -> str:
    """Write an instance registration file. Returns the file path."""
    info = {
        "host": host,
        "port": port,
        "pid": pid,
        "binary": binary,
        "idb_path": idb_path,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "backend": backend,
    }
    instances_dir = get_instances_dir()
    os.makedirs(instances_dir, exist_ok=True)
    file_path = _instance_file_path(port)
    # Atomic write.
    fd, tmp_path = tempfile.mkstemp(dir=instances_dir, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)
        os.replace(tmp_path, file_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return file_path


def unregister_instance(port: int) -> bool:
    """Remove an instance registration file. Returns True if removed."""
    file_path = _instance_file_path(port)
    try:
        os.unlink(file_path)
        return True
    except OSError:
        return False


def is_pid_alive(pid: int) -> bool:
    """Check if a process is still running."""
    if sys.platform == "win32":
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def probe_instance(host, port, timeout=2.0) -> bool:
    """Check if an instance is reachable via TCP."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def discover_instances():
    """Scan for registered instances, cleaning up stale entries."""
    instances_dir = get_instances_dir()
    if not os.path.isdir(instances_dir):
        return []
    result = []
    for file_path in glob.glob(os.path.join(instances_dir, "instance_*.json")):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                info = json.load(f)
        except (json.JSONDecodeError, OSError):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue
        if not all(k in info for k in ("host", "port", "pid")):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue
        if not is_pid_alive(info["pid"]):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue
        if not probe_instance(info["host"], info["port"], timeout=1.0):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue
        result.append(info)
    result.sort(key=lambda x: x.get("started_at", ""))
    return result
