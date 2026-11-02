# Case Study: Reverse-Engineering GitHub Copilot CLI with lminspect

This document details the practical workflow, protocol discoveries, and proxy enhancements made while using **lminspect** to intercept, inspect, and reverse-engineer the official `@github/copilot` CLI (`v1.0.105`).

---

## 1. Objective and Problem Statement

GitHub Copilot CLI is a hybrid Node.js and Rust-based terminal coding agent. To enable offline testing and deterministic integration suites (such as in `lmctl-ai/lmmock`), the exact wire formats, handshake procedures, and internal endpoint requirements needed to be extracted from real runtime traffic.

Using `lminspect`, we:
1. Minted on-the-fly Root CA certificates.
2. Intercepted and terminated TLS sessions transparently with `--ssl-bump`.
3. Captured, structured, and recorded every flow into JSONL via `--record` and real-time `--tap`.
4. Routed decrypted HTTPS requests to a local mock server using `--route`.

---

## 2. Interception Setup

### A. Dynamic CA Generation
`lminspect certgen` was used to mint a Root CA certificate and private key:
```bash
lminspect certgen --cert build/ca.crt --key build/ca.key
```

### B. Starting lminspect Proxy
`lminspect run` was executed with dynamic TLS decryption and logging:
```bash
lminspect run \
  --port 18080 \
  --ssl-bump \
  --ca-cert build/ca.crt \
  --ca-key build/ca.key \
  --tap \
  --record build/copilot-flows.jsonl
```

### C. Client Configuration
Because `@github/copilot` is packaged as a Node.js CLI executing an internal native engine, standard proxy environment variables and Node's extra CA trust store were injected:
```bash
export HTTP_PROXY="http://127.0.0.1:18080"
export HTTPS_PROXY="http://127.0.0.1:18080"
export NODE_EXTRA_CA_CERTS="$PWD/build/ca.crt"
```

---

## 3. Wire Protocol Discoveries

By analyzing the intercepted flows in `copilot-flows.jsonl`, five distinct communication patterns were cataloged:

### 1. Model Discovery & Catalog (`GET /models`, `GET /v1/models`)
- Copilot queries `/models` at startup to validate capabilities before issuing completions.
- **Critical Requirement:** Models in the returned list MUST include:
  ```json
  {
    "id": "gpt-5.3-codex",
    "name": "GPT-5.3 Codex",
    "capabilities": {
      "type": "chat",
      "family": "gpt-5.3-codex",
      "limits": { "max_prompt_tokens": 128000, "max_output_tokens": 8192 }
    },
    "is_chat_default": true,
    "is_chat_fallback": true,
    "model_picker_enabled": true,
    "supported_endpoints": ["/responses", "/chat/completions", "/v1/messages"]
  }
  ```
  If `is_chat_default` or `model_picker_enabled` are omitted, Copilot halts with `Error: No supported model available`.

### 2. Auto Routing Model Selector (`POST /auto`)
- When model is unset or set to `auto`, Copilot queries `/auto` with client context.
- The response must return `{"selected_model": { ... }}` wrapping the target model object.

### 3. OpenAI Streaming Responses API (`POST /v1/responses`, `POST /responses`)
- Copilot CLI's default agent mode uses OpenAI's streaming Responses API rather than standard Chat Completions.
- Copilot's Rust SSE parser is strictly sequential and requires:
  1. Sequential monotonic integer `sequence_number` (starting at 1) on every event.
  2. The exact event transition sequence:
     - `event: response.created`
     - `event: response.in_progress`
     - `event: response.output_item.added`
     - `event: response.content_part.added`
     - `event: response.output_text.delta` (with `{"delta": "text"}`)
     - `event: response.output_text.done`
     - `event: response.content_part.done`
     - `event: response.output_item.done`
     - `event: response.completed`
  3. Every JSON payload must include `"type": "<event_name>"` matching the SSE event header.

### 4. Anthropic Messages API (`POST /v1/messages`)
- When configured for Claude models, Copilot uses the Anthropic streaming wire API:
  - `event: message_start`
  - `event: content_block_start`
  - `event: content_block_delta` (`{"type": "content_block_delta", "delta": {"type": "text_delta", "text": "..."}}`)
  - `event: content_block_stop`
  - `event: message_delta`
  - `event: message_stop`

### 5. Internal Platform & Telemetry Endpoints
- Telemetry: `POST /telemetry`, `POST https://cafe.github.com/.../SubmitMetrics`
- Metadata: `GET /copilot_internal/team_customizations`, `GET /copilot_internal/managed_settings`
- MCP Registry: `POST /mcp/readonly`
- Agent Profiles: `GET /agents/swe/custom-agents/*`
- Update Checker: `GET https://api.github.com/repos/github/copilot-cli/releases`
All of these expect `200 OK` or graceful `404 Not Found` without failing the main execution pipeline.

---

## 4. lminspect Core Engine Enhancement: Scheme Rewrite in RuleRoute

### The Issue
When testing the transparent redirect of decrypted HTTPS traffic from `https://api.githubcopilot.com` to a local `http://127.0.0.1:19095` mock server using `--route`:
```bash
--route "https://api.githubcopilot.com/*=http://127.0.0.1:19095"
```
The client connection was HTTPS (terminated by `lminspect`). When `RuleRoute.OnRequest` rewrote the host and port, `flow.Request.Scheme` remained `"https"`. As a result, `lminspect` attempted a TLS handshake with the local HTTP server, failing with:
```
[ERROR] GET https://127.0.0.1:19095/... -> http: server gave HTTP response to HTTPS client
```

### The Fix
In [`pkg/proxy/addons.go`](file:///home/ubuntu/repos/lmctl-ai/lminspect/pkg/proxy/addons.go):
- Updated `RuleRoute` parsing logic to inspect the destination URL scheme.
- If the destination target specifies `http://`, `flow.Request.Scheme` is updated to `"http"` and port defaulted to `80`.
- If the destination target specifies `https://`, `flow.Request.Scheme` is preserved/updated to `"https"` and port defaulted to `443`.

This allows `lminspect` to act as an SSL-offloading transparent gateway between TLS clients and plain HTTP development/mock servers.

---

## 5. GitHub Actions Verification

Synthetic loopback tests and private live captures have different secret boundaries:
- **Self-contained E2E Interception:** Runs `lminspect run --ssl-bump --route ...=http://...` in front of `lmmock`, proving that dynamic TLS minting, CONNECT tunneling, payload logging, and routing work end-to-end on CI runners without external secrets.
- **Private Live Capture:** A real-key capture must run in a private Actions repository with the organization secret scoped only to the capture step. Build the repaired recorder from its tested commit; do not assume an older release contains this fix. Only sanitized exports may become artifacts. Never use shell tracing or write raw request/header dumps. This case study supplies no real keys and is not permission to capture against a vendor.


## Credential redaction boundary

Historical recording examples above predate the mandatory sanitizer. Current
record/JSON, tap/error and lmcode printing paths pass through one sanitized output
snapshot. Routing and on-wire authentication remain intact; only exported copies
change. The policy discovers credentials in both request and response, including
encoded query names, headers, cookies, URL userinfo, JSON/form/text, environment
keys and split SSE deltas. `<redacted:credential>` preserves the lmmock import
contract without retaining secret lengths. Unsupported opaque bodies are withheld,
so those payloads need synthetic fixtures rather than an assumed exact replay.

Before any private live capture, require the synthetic redaction matrix and the
removed-boundary mutation to pass. The tests scan output bytes and decoded body
bytes for fake credentials, their percent/base64 encodings and reassembled SSE
text. A real pinned lmmock importer also checks import/reimport stability. Old
recordings are not repaired in place and must not be uploaded as newly safe data.
