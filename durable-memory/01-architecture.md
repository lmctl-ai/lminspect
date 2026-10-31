# 01 - lminspect Architecture & Proxy Engine

## Overview

`lminspect` is designed as a standalone, zero-dependency, pure-Go HTTP/HTTPS intercepting proxy and manipulation engine. It provides the core inspection and mutation capabilities of `mitmproxy` without any Python runtime dependency, while exposing the scriptable `lmcode` DSL for fast, deterministic traffic scripting.

```
+---------------------------------------------------------------------------------+
|                                 lminspect Engine                                |
|                                                                                 |
|  +--------------------+      +--------------------+      +-------------------+  |
|  |  Client HTTP/TLS   | ---> |  Proxy Dispatcher  | ---> |  Upstream Target  |  |
|  +--------------------+      +---------+----------+      +-------------------+  |
|                                        |                                        |
|                          +-------------+-------------+                          |
|                          | Addon & Interception Core |                          |
|                          +-------------+-------------+                          |
|                                        |                                        |
|             +-----------------+--------+--------+-----------------+             |
|             |                 |                 |                 |             |
|      +------+------+   +------+------+   +------+------+   +------+------+      |
|      |  Tap Addon  |   | Record/Rep  |   | Rule Engine |   |  lmcode VM  |      |
|      |  (Console)  |   |  (JSONL)    |   |  (Static)   |   | (.dslb LMS) |      |
|      +-------------+   +-------------+   +-------------+   +-------------+      |
+---------------------------------------------------------------------------------+
```

## Key Architectural Subsystems

### 1. Connection Hijacking & Dynamic TLS MITM (`pkg/proxy/server.go`, `pkg/proxy/cert.go`)
- **Forward Proxy (HTTP)**: Normal HTTP requests (`GET http://target/path`) are intercepted, passed through request addons, forwarded upstream using Go's `http.Transport`, and passed through response addons before returning to the client.
- **Forward Proxy (HTTPS CONNECT)**:
  - When a client issues `CONNECT target:443 HTTP/1.1`, the proxy hijacks the underlying socket via `http.Hijacker`.
  - It writes `HTTP/1.1 200 Connection Established\r\n\r\n`.
  - If `--ssl-bump` is active:
    1. Extracts SNI (or target host).
    2. Dynamically mints a leaf TLS certificate signed by the Root CA (or pulls an existing certificate from the in-memory cache).
    3. Completes the TLS server handshake with the client.
    4. Decrypts the inner HTTP/1.1 traffic in a keep-alive loop and passes it through the standard HTTP inspection pipeline.
  - If `--ssl-bump` is inactive:
    - Sockets are bridged via bidirectional raw TCP copying (`io.Copy`).
- **Reverse Proxy**: When invoked with `--mode reverse:<target_url>`, incoming requests are transparently routed to `<target_url>` with rewritten Host and URI headers.

### 2. Flow Data Model (`pkg/proxy/flow.go`)
- `HTTPFlow`: Encapsulates an end-to-end request/response cycle, containing:
  - `ID`: Unique random 16-character identifier.
  - `ClientAddr`: Client network address.
  - `Request`: Full HTTP request metadata (Method, URL, Scheme, Host, Port, Path, Headers, Body content).
  - `Response`: HTTP response metadata (StatusCode, Reason, Headers, Body content).
  - `DurationMs`: Total round-trip latency in milliseconds.
  - `Interception & Control State`: `Intercept()`, `Resume()`, `Kill()`, `Respond()`.
- Thread-safe serialization to JSON for `.jsonl` logging and replaying.

### 3. Addon Pipeline (`pkg/proxy/addon.go`, `pkg/proxy/addons.go`)
- Addons implement hook interfaces:
  - `RequestHook`: executed before sending request upstream.
  - `ResponseHook`: executed after receiving response from upstream.
  - `ErrorHook`: executed on upstream or network failures.
- Built-in Addons:
  - `TapAddon`: Pretty-prints transiting traffic lines to terminal stderr.
  - `RecordAddon`: Atomically streams flows into a `.jsonl` file.
  - `ReplayServerAddon`: Matches incoming requests against recorded flows and serves cached responses.
  - `RuleAddon`: Fast CLI-specified flags (`--redirect`, `--route`, `--header`, `--mock`).
  - `DslAddon`: Executes bytecode programs compiled from `.lms` scripts.

### 4. Zero-Dependency Static Build
- Built with `CGO_ENABLED=0`.
- Native Go standard library cryptography (`crypto/rsa`, `crypto/x509`, `crypto/tls`).
- Fast compilation (< 1 second) and tiny binary footprint (~12MB).
