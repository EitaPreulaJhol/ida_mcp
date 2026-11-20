# MCP transport architecture and threading invariants

`ida_mcp/zeromcp` is a small, stdlib-only transport. Keep protocol behavior
stable while changing internals; the harnesses in `tests/transport_test.py`,
`tests/session_test.py`, `tests/gate_test.py`, `tests/metrics_audit_test.py`,
`tests/robustness_test.py` and `tests/fuzz_conformance_test.py` are its
behavioral contract.

## Request path

1. `McpHttpRequestHandler` reads and bounds HTTP bodies, parses route/query
   flags, validates origin/token requirements, then dispatches JSON-RPC. The
   auth token is read from `X-IDA-MCP-Token`; the legacy `?token=` spelling is
   accepted only on loopback binds and is refused off-loopback.
2. Request-scoped state (`unsafe`, profile, extension groups, auth token,
   progress token) is stored in thread-local slots for that handler thread.
   `jsonrpc.py` separately scopes request IDs and cancellation events by MCP
   session so one client cannot cancel another client's call.
3. `McpServer` applies tool/resource access gates and output limits. Tool calls
   enter `_ToolAdmission`; reads that touch IDA use its fail-fast admission
   path. The handler thread then waits for the registered function to return.
4. `ida_mcp.sync.idasync` marshals IDA SDK work to IDA's main thread. Transport
   threads must not call IDA APIs directly. After dispatch, the server records
   metrics and, for mutating/extension calls only, appends the optional audit
   record.

```text
HTTP worker -> request context/access gate -> JSON-RPC registry
           -> bounded tool admission -> registered callable
           -> @idasync -> IDA main thread -> result -> metrics/audit
```

## Module ownership

| Module | Owns | Must not own |
|---|---|---|
| `jsonrpc.py` | JSON-RPC dispatch, request IDs, session-scoped cancellation | HTTP sockets, IDA SDK calls |
| `metrics.py` | Bounded counters, rolling timings, JSON-able metric snapshots | Server lifecycle, HTTP state, IDA APIs |
| `mcp.py` | MCP registries, HTTP routes/handlers, session/stream lifecycle, access gates, admission, audit | Direct IDA SDK work |

`McpServer` composes these pieces: metrics are held by one `McpMetrics`
instance, while request/session state stays in the transport owner. Keep helper
modules independent of IDA and avoid circular imports back to `mcp.py`.

## Shared state and lock ownership

| Lock / synchronization | Protects | Release before |
|---|---|---|
| `_ToolAdmission._cond` | Active slots, queue length and queue configuration | Running a registered tool or waiting on IDA |
| `_http_sessions_lock` | Session timestamps, TTL pruning and session cap | Stream closure or response/socket work |
| `_http_streams_lock` | Per-session Streamable HTTP stream sets | Sending events or closing streams; copy the set first |
| `_sse_lock` | Legacy SSE connection map | Sending events or writing to the client |
| `jsonrpc._pending_requests_lock` | `(scope, request_id) -> cancellation event` map | JSON-RPC/tool dispatch; setting an `Event` is the only in-lock action |
| `McpMetrics` internal locks | Counters and fixed-size duration/queue samples | Dispatch, callbacks, audit or IDA work |
| `_audit_lock` | Audit append/rotation for the configured JSONL files | Tool dispatch and IDA calls |
| `_McpThreadingHTTPServer._active_lock` | Accepted socket count for connection admission | Request handling or thread creation work |

Avoid nested acquisition across these owners. Under a lock, update or snapshot
small in-memory state; perform network I/O, callbacks, file I/O, and IDA calls
after releasing it. Metric and audit failures must never change a tool result.

## Safe refactoring checklist

- Preserve Streamable HTTP and legacy SSE routes and session headers.
- Do not move IDA-facing code into the transport; only `@idasync` crosses the
  main-thread boundary.
- Keep server-facing methods and response shapes stable when extracting
  implementation helpers.
- Add or extend a contract test before moving a responsibility; run
  `python tests/run_all.py`, `python -m mypy`, and `ruff check .` after each
  extraction.
- Keep the package dependency-free at runtime.
