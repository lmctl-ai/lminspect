# 05 - Standard `lmcode` REST Endpoints & Stateless CLI Interfaces

## Summary

`lminspect` upgrades its `github.com/lmctl-ai/lmcode-go` runtime dependency to `2027887` (`lmcode_std_v3` 226 canonical signatures) and `@lmctl-ai/lmctl@0.2.482`:
- **Standard Interfaces**: Supports `RestGet`, `RestPost`, `RestPut`, `RestDelete`, `RestPatch`, `RestHead`, `RestOptions`, `RestHandler`, `CliCommand`, and `CliOption` alongside `RequestHook`, `ResponseHook`, and `FlowHook`.
- **Standard Functions & Methods**: Exposes `rest_config`, `rest_route`, `rest_serve`, `rest_stop`, `rest_cli`, and the 15 `RestExchange` methods (`method`, `path`, `query`, `has_query`, `param`, `header`, `has_header`, `body`, `status`, `set_header`, `send`, `json`, `get`, `set`, `increment`).
- **Host CLI Compatibility**: Supports `--lmcode-schema [--json]`, `--lmcode-signatures`, and `--lmcode FILE.dslb [--save OUT.dslb]` (with `LMCODE_INVOCATION_FILE` manifest v1 support) in addition to `--dsl-schema`, `--dsl-signatures`, and `--dsl`.
- **Verification**: Covered by `TestDslStdRestAndCliInterfaces` in `pkg/dsl/host_test.go` and Section 4b of `test.sh`.
