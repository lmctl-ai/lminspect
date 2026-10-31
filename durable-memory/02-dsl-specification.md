# 02 - lmcode DSL Specification for lminspect

## Overview

`lminspect` integrates `lmcode` via `github.com/lmctl-ai/lmcode-go`. Traffic scripts are authored using `lmscript` syntax (`.lms`) and compiled into `.dslb` bytecode.

Addon scripts can be executed in two modes:
1. **Live Proxy Daemon Mode**: Loaded into the proxy server pipeline using `--script build/addon.dslb`.
2. **Standalone Execution Mode**: Executed directly via `lminspect --dsl script.dslb` for offline testing, verification, and flow simulation.

---

## Type Registry & Schema

### Root Contexts
- `inspect: Inspector`: Global factory for creating and parsing HTTP flows.
- `flow: Flow`: Currently active flow context (during hook execution).

### Interfaces
- `RequestHook`: `fn(f: Flow) -> void`
- `ResponseHook`: `fn(f: Flow) -> void`
- `FlowHook`: `fn(f: Flow) -> void`

### Object: `Inspector`
- `new_flow(method: string, url: string) -> Flow`: Constructs a synthetic HTTP flow.
- `parse_flow(json_str: string) -> Flow`: Reconstitutes a flow from its serialized JSON string.

### Object: `Flow`
- `id() -> string`: Returns the unique 16-character hexadecimal flow ID.
- `request() -> Request`: Returns the mutable request object.
- `response() -> Response`: Returns the mutable response object.
- `has_response() -> bool`: Returns `true` if a response has been received or mocked.
- `error() -> string`: Returns any error message recorded during processing.
- `duration_ms() -> int`: Returns request duration in milliseconds.
- `client_addr() -> string`: Returns client IP:port string.
- `intercept() -> void`: Pauses flow for inspection.
- `is_intercepted() -> bool`: Checks if flow is intercepted.
- `resume() -> void`: Resumes intercepted flow.
- `kill() -> void`: Drops connection and kills the flow immediately.
- `is_killed() -> bool`: Returns `true` if the flow was killed.
- `respond(status_code: int, body: string, content_type: string) -> void`: Generates a synthetic response and terminates upstream forwarding.
- `to_json() -> string`: Serializes flow to JSON.

### Object: `Request`
- `method() -> string`: HTTP method (GET, POST, etc.).
- `set_method(method: string) -> void`: Sets HTTP method.
- `url() -> string`: Full URL string.
- `set_url(url: string) -> void`: Updates full URL and automatically adjusts host, port, path, and scheme.
- `scheme() -> string`: URL scheme (`http` or `https`).
- `set_scheme(scheme: string) -> void`: Sets scheme.
- `host() -> string`: Request destination host.
- `set_host(host: string) -> void`: Sets host.
- `port() -> int`: Destination port.
- `set_port(port: int) -> void`: Sets destination port.
- `path() -> string`: Path and query (`/path?foo=bar`).
- `set_path(path: string) -> void`: Sets path and query.
- `header(name: string) -> string`: Returns first header value matching name (case-insensitive).
- `set_header(name: string, val: string) -> void`: Sets header value.
- `remove_header(name: string) -> void`: Deletes header.
- `header_names() -> StrList`: Returns list of all header names.
- `query(param: string) -> string`: Returns query parameter value.
- `set_query(param: string, val: string) -> void`: Sets or appends query parameter.
- `query_names() -> StrList`: Returns list of all query parameter keys.
- `text() -> string`: Body content as a string.
- `set_text(body: string) -> void`: Sets body content and updates `Content-Length`.

### Object: `Response`
- `status_code() -> int`: HTTP status code (200, 404, 500, etc.).
- `set_status_code(code: int) -> void`: Sets status code.
- `reason() -> string`: HTTP status reason string ("OK", "Not Found").
- `set_reason(reason: string) -> void`: Sets reason phrase.
- `header(name: string) -> string`: Gets header value.
- `set_header(name: string, val: string) -> void`: Sets header value.
- `remove_header(name: string) -> void`: Deletes header.
- `header_names() -> StrList`: Returns list of header names.
- `text() -> string`: Response body text.
- `set_text(body: string) -> void`: Sets response body text and synchronizes `Content-Length`.

### Functions
- `println(msg: string) -> void`: Prints to stdout.
- `assert(condition: bool, msg: string) -> void`: Fails execution with error if condition is false.
