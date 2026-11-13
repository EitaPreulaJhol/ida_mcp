"""Instance discovery (trimmed from ida-pro-mcp discovery.py).

IDA plugin instances register themselves by writing JSON files to
{ida_user_dir}/mcp/instances/. The MCP server discovers running instances by
reading these files and validating PID liveness + TCP reachability.
"""
import datetime
import glob
import ipaddress
import json
import os
import socket
import sys
import tempfile


def _get_ida_user_dir() -> str:
    if sys.platform == "win32":
        # APPDATA is absent in service contexts and stripped profiles;
        # a KeyError here broke discovery instead of using the real location.
        base = os.environ.get("APPDATA") or os.path.expanduser(
            os.path.join("~", "AppData", "Roaming"))
        return os.path.join(base, "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def get_instances_dir() -> str:
    return os.path.join(_get_ida_user_dir(), "mcp", "instances")


def _instance_file_path(port: int) -> str:
    return os.path.join(get_instances_dir(), f"instance_{port}.json")


def _quiet_unlink(path: str) -> bool:
    """Best-effort unlink; swallow OSError. Returns True if removed."""
    try:
        os.unlink(path)
        return True
    except OSError:
        return False


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
    return _quiet_unlink(_instance_file_path(port))


_WIN_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_WIN_ERROR_ACCESS_DENIED = 5
_WIN_STILL_ACTIVE = 259


def _is_pid_alive_windows(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    # HANDLE is pointer-sized: the default c_int restype truncates it on x64.
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(_WIN_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        # Access denied means the process exists but belongs to someone else.
        return ctypes.get_last_error() == _WIN_ERROR_ACCESS_DENIED  # type: ignore[attr-defined]
    try:
        code = wintypes.DWORD()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            # An exited process stays openable while anyone holds a handle.
            return code.value == _WIN_STILL_ACTIVE
        return True
    finally:
        kernel32.CloseHandle(handle)


def _valid_instance_info(info) -> bool:
    """Validate the untrusted JSON read from an instance file.

    The file is local, but it can be stale/corrupt.  A string pid used to
    raise TypeError from os.kill and abort discovery for every instance.
    """
    if not isinstance(info, dict):
        return False
    pid = info.get("pid")
    port = info.get("port")
    host = info.get("host")
    return (isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
            and isinstance(port, int) and not isinstance(port, bool)
            and 0 < port <= 65535
            and isinstance(host, str))


def is_pid_alive(pid: int) -> bool:
    """Check if a process is still running (owned by any user)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if sys.platform == "win32":
        return _is_pid_alive_windows(pid)
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        # EPERM: the process exists but belongs to another user. Treating it
        # as dead made discovery delete that live instance's registration.
        return True
    except (ProcessLookupError, OSError):
        return False


# Bind hosts that mean "this machine" and the loopback address they map to.
_PROBE_ALIASES = {"0.0.0.0": "127.0.0.1", "::": "::1", "": "127.0.0.1",
                  "localhost": "127.0.0.1"}

_LOCAL_ADDRESSES: set[str] | None = None


def _local_addresses() -> set[str]:
    """Addresses that name this machine (resolved once, cached)."""
    global _LOCAL_ADDRESSES
    if _LOCAL_ADDRESSES is None:
        addrs = {"127.0.0.1", "::1", "localhost"}
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                addrs.add(str(info[4][0]).lower())
        except OSError:
            pass
        _LOCAL_ADDRESSES = addrs
    return _LOCAL_ADDRESSES


def probe_target(host) -> str | None:
    """Host to probe for a discovery entry, or None when it must not be probed.

    The instance file is local, but the ``host`` inside it is data: without this
    a file naming any address made the IDA process open a TCP connection there
    (a port scanner driven by whoever can write to the instances dir). A local
    instance is reachable on loopback or on one of this machine's own
    addresses, so anything else is reported as ``unverified`` and not probed.
    Hostnames are never resolved, on purpose.
    """
    name = str(host or "").strip().lower().strip("[]")
    name = _PROBE_ALIASES.get(name, name)
    if not name:
        return "127.0.0.1"
    if name in _local_addresses():
        return name
    try:
        if ipaddress.ip_address(name).is_loopback:
            return name
    except ValueError:
        pass  # a hostname: not something we resolve
    return None


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
            _quiet_unlink(file_path)
            continue
        if not _valid_instance_info(info):
            _quiet_unlink(file_path)
            continue
        if not is_pid_alive(info["pid"]):
            _quiet_unlink(file_path)
            continue
        target = probe_target(info.get("host"))
        if target is None:
            # Not reachable from here, or not something we probe: keep the entry
            # (it is a real, running instance) but say it is unverified.
            info["unverified"] = True
            result.append(info)
            continue
        if not probe_instance(target, info["port"], timeout=1.0):
            _quiet_unlink(file_path)
            continue
        result.append(info)
    result.sort(key=lambda x: str(x.get("started_at", "")))
    return result
