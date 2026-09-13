"""Minimal JSON-RPC 2.0 registry (trimmed from zeromcp 1.3.0).

Supports method dispatch, structured error mapping, and request cancellation
tracking used by the IDA sync layer.
"""
import json
import logging
import threading
import time
import traceback
from typing import Any, Callable, TypedDict, TypeAlias, NotRequired

JsonRpcId: TypeAlias = str | int | float | None

_current_request = threading.local()
_pending_requests_lock = threading.Lock()
_pending_requests: dict[int | str, threading.Event] = {}

logger = logging.getLogger(__name__)


def get_current_request_id() -> JsonRpcId:
    return getattr(_current_request, "id", None)


def get_current_cancel_event() -> "threading.Event | None":
    return getattr(_current_request, "cancel_event", None)


def register_pending_request(request_id: int | str) -> threading.Event:
    event = threading.Event()
    with _pending_requests_lock:
        _pending_requests[request_id] = event
    _current_request.cancel_event = event
    return event


def unregister_pending_request(request_id: int | str) -> None:
    with _pending_requests_lock:
        _pending_requests.pop(request_id, None)
    _current_request.cancel_event = None


def cancel_request(request_id: int | str) -> bool:
    with _pending_requests_lock:
        event = _pending_requests.get(request_id)
        if event is not None:
            event.set()
            return True
    return False


class JsonRpcRequest(TypedDict):
    jsonrpc: str
    method: str
    params: NotRequired[Any]
    id: NotRequired[JsonRpcId]


class JsonRpcError(TypedDict):
    code: int
    message: str
    data: NotRequired[Any]


class JsonRpcResponse(TypedDict):
    jsonrpc: str
    result: NotRequired[Any]
    error: NotRequired[JsonRpcError]
    id: NotRequired[JsonRpcId]


class JsonRpcException(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data


class RequestCancelledError(Exception):
    """Raised when a request is cancelled (LSP error code -32800)."""


class JsonRpcRegistry:
    def __init__(self) -> None:
        self.methods: dict[str, Callable] = {}
        self.redact_exceptions = False

    def method(self, func: Callable, name: str | None = None) -> Callable:
        self.methods[name or func.__name__] = func
        return func

    def dispatch(self, request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        try:
            if not isinstance(request, dict):
                request = json.loads(request)
            if not isinstance(request, dict):
                return self._error(None, -32600, "Invalid request: must be a JSON object")
        except Exception as e:
            return self._error(None, -32700, "JSON parse error", str(e))

        if request.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "Invalid request: 'jsonrpc' must be '2.0'")

        method = request.get("method")
        if method is None:
            return self._error(None, -32600, "Invalid request: 'method' is required")
        if not isinstance(method, str):
            return self._error(None, -32600, "Invalid request: 'method' must be a string")

        request_id: JsonRpcId = request.get("id")
        is_notification = "id" not in request
        params = request.get("params")

        _current_request.id = request_id
        start = time.perf_counter()
        try:
            result = self._call(method, params)
            elapsed = (time.perf_counter() - start) * 1000
            logger.debug("[MCP] << %s (%.1fms)", method, elapsed)
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "result": result, "id": request_id}
        except JsonRpcException as e:
            if is_notification:
                return None
            return self._error(request_id, e.code, e.message, e.data)
        except RequestCancelledError as e:
            if is_notification:
                return None
            return self._error(request_id, -32800, str(e) or "Request cancelled")
        except Exception as e:
            if is_notification:
                return None
            error = self.map_exception(e)
            return self._error(request_id, error["code"], error["message"], error.get("data"))
        finally:
            _current_request.id = None

    def _call(self, method: str, params: Any) -> Any:
        func = self.methods.get(method)
        if func is None:
            raise JsonRpcException(-32601, f"Method not found: {method}")
        if params is None:
            return func()
        if isinstance(params, dict):
            return func(**params)
        if isinstance(params, list):
            return func(*params)
        return func(params)

    def map_exception(self, e: Exception) -> JsonRpcError:
        if self.redact_exceptions:
            return {"code": -32603, "message": f"Internal Error: {str(e)}"}
        return {
            "code": -32603,
            "message": "\n".join(traceback.format_exception(e)).strip(),
        }

    def _error(self, request_id: JsonRpcId, code: int, message: str, data: Any = None) -> JsonRpcResponse:
        error: JsonRpcError = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": "2.0", "error": error, "id": request_id}
