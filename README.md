# lminspect

[![CI](https://github.com/lmctl-ai/lminspect/actions/workflows/ci.yml/badge.svg)](https://github.com/lmctl-ai/lminspect/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lmctl-ai/lminspect?color=blue)](https://github.com/lmctl-ai/lminspect/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**lminspect** is a high-performance, single-binary HTTP/HTTPS proxy and traffic manipulation engine written in pure Go, ported from the core capabilities of **mitmproxy** and supercharged with **lmcode** DSL programmability.

Designed specifically for automated testing, API reverse engineering, microservice mocking, and security analysis, `lminspect` eliminates Python runtime overhead while providing a statically compiled proxy with live scriptable interception hooks.

---

## Key Features

- **Pure Go & 100% Statically Linked**: Single binary with zero external C/runtime dependencies (`CGO_ENABLED=0`).
- **Dynamic TLS Decryption (SSL-Bump / MITM)**: On-the-fly leaf certificate minting with SAN (Subject Alternative Names) signed by a local Root CA.
- **lmcode DSL Scripting Engine**: First-class bytecode-compiled script addons (`.lms` compiled to `.dslb`) executing natively inside the request/response pipeline.
- **Flow Interception & Tampering**: Inspect and rewrite HTTP methods, URLs, paths, query parameters, headers, and request/response payloads in real time.
- **Synthetic Response Mocking**: Return mock responses directly from the proxy without forwarding upstream (`flow.respond(...)`).
- **Traffic Recording & Replay**: Stream captured flows to JSONL format (`--record`) and replay captured flows against target hosts (`replay --client`).
- **Reverse Proxy & Forward Proxy**: Seamless support for both standard forward proxy (`-x http://127.0.0.1:8080`) and reverse proxy modes (`--mode reverse:http://backend:8000`).
- **Zero UI Overhead**: Designed for headless CLI, CI/CD pipelines, container sidecars, and automated testing suites.

---

## Mitmproxy vs lminspect Comparison

| Feature | `mitmproxy` | `lminspect` |
| :--- | :--- | :--- |
| **Language** | Python 3 | Pure Go (1.26 toolchain) |
| **Binary** | Heavy bundle / Python venv | Single standalone static binary (~12MB) |
| **Scripting Engine** | Python scripts (`addons`) | Bytecode-compiled `lmcode` DSL (`.dslb`) |
| **Startup Time** | ~1000ms | < 10ms |
| **TLS MITM Decryption** | OpenSSL / Cryptography | Native Go `crypto/tls` dynamic cert cache |
| **Live Traffic Tap** | TUI (curses) or Web UI | Fast CLI stream `--tap` to stderr / stdout |
| **Flow Serialization** | Proprietary Python pickle format | Universal newline-delimited JSON (`.jsonl`) |
| **Deterministic Sandboxing** | Arbitrary Python host access | Safe, auditable DSL bytecode execution |

---

## Installation

### Prebuilt Binaries

Prebuilt standalone static binaries for Linux and macOS (x64 and ARM64) are available on [GitHub Releases](https://github.com/lmctl-ai/lminspect/releases).

```bash
# Example: Download and extract for linux-x64
curl -sSL https://github.com/lmctl-ai/lminspect/releases/latest/download/lminspect-linux-x64.tar.gz | tar -xz
sudo mv lminspect /usr/local/bin/
```

### Build from Source

Requirements: Go 1.25+ or 1.26+.

```bash
git clone https://github.com/lmctl-ai/lminspect.git
cd lminspect
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/lminspect main.go
```

---

## Quick Start

### 1. Generate Local Root CA
Generate a self-signed Root CA for TLS decryption:
```bash
lminspect certgen --cert ca.crt --key ca.key
```

### 2. Start Forward Proxy with SSL-Bump
```bash
lminspect run --port 8080 --ssl-bump --ca-cert ca.crt --ca-key ca.key --tap
```

### 3. Send Intercepted Traffic
```bash
# Plain HTTP:
curl -x http://127.0.0.1:8080 http://httpbin.org/get

# Decrypted HTTPS:
curl -x http://127.0.0.1:8080 --cacert ca.crt https://httpbin.org/get
```

### 4. Record and Replay Flows
Record traffic transiting through the proxy:
```bash
lminspect run --port 8080 --record flows.jsonl
curl -x http://127.0.0.1:8080 http://example.com/api/v1/resource
```

Replay recorded flows against a local staging target:
```bash
lminspect replay --client flows.jsonl --target 127.0.0.1:9000
```

---

## DSL Addon Scripting (lmcode)

`lminspect` integrates the **lmcode** virtual machine. Addons are written in `lmscript` syntax (`.lms`) and compiled into compact bytecode (`.dslb`).

### Example Addon (`add-header.lms`)

```lmcode
p = _dsl_ cli="lminspect";

# Request hook: executes before forwarding upstream
@request
fn on_request(f: Flow) -> void implements RequestHook {
    f.request().set_header("X-Proxy-By", "lminspect");
}

# Response hook: executes before returning to client
@response
fn on_response(f: Flow) -> void implements ResponseHook {
    f.response().set_header("X-Powered-By", "lminspect");
}

end _dsl_
savedsl(p, ARGV[0]);
```

### Compiling and Running an Addon

```bash
# 1. Compile script to bytecode
lmscript examples/add-header.lms build/add-header.dslb

# 2. Run proxy with compiled addon
lminspect run --port 8080 --script build/add-header.dslb
```

---

## Ported Mitmproxy Examples

All common mitmproxy addon patterns are ported under the [`examples/`](file:///home/ubuntu/repos/lmctl-ai/lminspect/examples) directory:

| Example | Description | Mitmproxy Original |
| :--- | :--- | :--- |
| [`add-header.lms`](file:///home/ubuntu/repos/lmctl-ai/lminspect/examples/add-header.lms) | Injects custom headers on requests and responses | `addons/add-header.py` |
| [`redirect-requests.lms`](file:///home/ubuntu/repos/lmctl-ai/lminspect/examples/redirect-requests.lms) | Rewrites request destination host, port, or path | `addons/redirect-requests.py` |
| [`custom-response.lms`](file:///home/ubuntu/repos/lmctl-ai/lminspect/examples/custom-response.lms) | Intercepts matching routes and serves synthetic responses | `addons/custom-response.py` |
| [`modify-response-body.lms`](file:///home/ubuntu/repos/lmctl-ai/lminspect/examples/modify-response-body.lms) | Performs string substitution on response bodies | `addons/modify-response-body.py` |
| [`modify-querystring.lms`](file:///home/ubuntu/repos/lmctl-ai/lminspect/examples/modify-querystring.lms) | Inspects and mutates URL query parameters | `addons/modify-querystring.py` |
| [`filter-flows.lms`](file:///home/ubuntu/repos/lmctl-ai/lminspect/examples/filter-flows.lms) | Filters and blocks unwanted requests (e.g. telemetry) | `addons/filter-flows.py` |
| [`dump-flows.lms`](file:///home/ubuntu/repos/lmctl-ai/lminspect/examples/dump-flows.lms) | Formats and logs transited flows to standard out | `addons/dump.py` |
| [`replay-flow.lms`](file:///home/ubuntu/repos/lmctl-ai/lminspect/examples/replay-flow.lms) | Deserializes, mutates, and replays recorded flows | `addons/replay.py` |

---

## CLI Reference

```
usage: lminspect --version | --dsl-schema [--json] | --dsl-signatures | --dsl FILE.dslb [FILE...]
       lminspect run [--listen ADDR] [--mode MODE] [--ssl-bump] [--tap] [--record FILE] [--script FILE.dslb]
       lminspect replay --client FILE.jsonl [--target URL]
       lminspect certgen [--cert FILE] [--key FILE]

Global commands:
  --version          Print lminspect version and exit
  --dsl-schema       Print JSON schema describing lmcode types & methods
  --dsl-signatures   Print human-readable signatures of all DSL methods
  --dsl FILE.dslb    Execute standalone lmcode bytecode file directly

Proxy commands ('run' or 'proxy'):
  --listen ADDR      Address and port to bind proxy (default "127.0.0.1:8080")
  --port INT         Port to listen on (overrides listen port)
  --bind IP          Bind IP address (overrides listen host)
  --mode MODE        Proxy mode: regular | reverse:<target_url> (default "regular")
  --ssl-bump         Enable dynamic TLS decryption (MITM)
  --ca-cert PATH     Path to custom Root CA certificate
  --ca-key PATH      Path to custom Root CA private key
  --tap              Print real-time flow summary to stderr
  --record PATH      Append transited flows to JSONL file
  --script PATH      Path to compiled .dslb addon script
  --redirect RULE    Redirect rule (pattern=target_url)
  --route RULE       Route rule (pattern=host:port)
  --header RULE      Header injection rule (pattern=key:val)
  --mock RULE        Mock synthetic response rule (pattern=status_code:body)

Replay commands ('replay'):
  --client PATH      Replay recorded requests from JSONL file
  --target ADDR      Override destination host:port for replayed requests

Certgen commands ('certgen'):
  --cert PATH        Output Root CA certificate file (default "ca.crt")
  --key PATH         Output Root CA private key file (default "ca.key")
```

---

## Testing

Run the full end-to-end test suite (Go unit tests, example compilation, standalone DSL executions, HTTP proxy verification, HTTPS SSL-Bump MITM verification, and flow recording/replay):

```bash
./test.sh
```

---

## License

Apache-2.0. See [LICENSE](file:///home/ubuntu/repos/lmctl-ai/lminspect/LICENSE) for details.
