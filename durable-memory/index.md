# lminspect Durable Memory

Welcome to the internal engineering documentation and architecture record for **lminspect**.

## Document Index

1. [Architecture & Proxy Engine](file:///home/ubuntu/repos/lmctl-ai/lminspect/durable-memory/01-architecture.md)
   - Core proxy server design: forward proxy, reverse proxy, transparent mode.
   - TLS interception (SSL-Bump) with dynamic leaf certificate minting.
   - Addon pipeline lifecycle and event dispatcher.
   - Streaming JSONL flow recorder and client replay engine.

2. [lmcode DSL Specification](file:///home/ubuntu/repos/lmctl-ai/lminspect/durable-memory/02-dsl-specification.md)
   - Host registry, contexts (`inspect`, `flow`), and interfaces (`RequestHook`, `ResponseHook`, `FlowHook`).
   - Object models: `Inspector`, `Flow`, `Request`, `Response`.
   - Bytecode lifecycle: compilation from `.lms` to `.dslb` and execution via `lmcode` VM.

3. [Mitmproxy Feature Parity & Mapping](file:///home/ubuntu/repos/lmctl-ai/lminspect/durable-memory/03-mitmproxy-parity.md)
   - Structural comparison between Python mitmproxy and Go lminspect.
   - Event mapping (`request`, `response`, `error`).
   - Detailed mapping of all 8 ported example scripts.

4. [Case Study: Reverse-Engineering GitHub Copilot CLI](file:///home/ubuntu/repos/lmctl-ai/lminspect/durable-memory/04-copilot-case-study.md)
   - Step-by-step workflow for intercepting and inspecting `@github/copilot` live traffic.
   - Full protocol analysis: OpenAI Responses streaming, Anthropic Messages, and Model catalog discovery.
   - Core engine enhancement: `RuleRoute` scheme rewriting for TLS offloading to local mock servers.
   - GitHub Actions CI implementation patterns.
