# 03 - Mitmproxy Feature Parity & Mapping

## Conceptual Mapping

| Mitmproxy Python Concept | `lminspect` Go / `lmcode` Equivalent |
| :--- | :--- |
| `mitmproxy.http.HTTPFlow` | `proxy.HTTPFlow` / `Flow` in DSL |
| `mitmproxy.http.Request` | `proxy.Request` / `Request` in DSL |
| `mitmproxy.http.Response` | `proxy.Response` / `Response` in DSL |
| `addon.request(flow)` | `@request fn on_request(f: Flow) -> void implements RequestHook` |
| `addon.response(flow)` | `@response fn on_response(f: Flow) -> void implements ResponseHook` |
| `addon.error(flow)` | `proxy.Addon.OnError(flow, err)` |
| `flow.intercept()` | `flow.intercept()` |
| `flow.resume()` | `flow.resume()` |
| `flow.kill()` | `flow.kill()` |
| `flow.response = http.Response.make(code, body, headers)` | `flow.respond(code, body, content_type)` |
| `flow.request.query["k"] = "v"` | `flow.request().set_query("k", "v")` |
| `mitmdump -w flows.mitm` | `lminspect run --record flows.jsonl` |
| `mitmdump -r flows.mitm` | `lminspect replay --client flows.jsonl` |
| `mitmproxy --server-replay flows.mitm` | `lminspect run --replay-server flows.jsonl` |
| `mitmproxy --mode reverse:http://host:port` | `lminspect run --mode reverse:http://host:port` |
| `mitmproxy -s script.py` | `lminspect run --script script.dslb` |

---

## Ported Examples Detailed Map

### 1. `add-header`
- **Mitmproxy:**
  ```python
  class AddHeader:
      def response(self, flow: http.HTTPFlow):
          flow.response.headers["newheader"] = "foo"
  ```
- **lminspect:**
  ```lmcode
  @response
  fn on_response(f: Flow) -> void implements ResponseHook {
      f.response().set_header("X-Powered-By", "lminspect");
  }
  ```

### 2. `redirect-requests`
- **Mitmproxy:**
  ```python
  def request(flow: http.HTTPFlow) -> None:
      if flow.request.pretty_host == "example.com":
          flow.request.host = "mitmproxy.org"
  ```
- **lminspect:**
  ```lmcode
  @request
  fn on_request(f: Flow) -> void implements RequestHook {
      if (f.request().host() == "example.com") {
          f.request().set_host("mitmproxy.org");
      }
  }
  ```

### 3. `custom-response`
- **Mitmproxy:**
  ```python
  def request(flow: http.HTTPFlow) -> None:
      if flow.request.path.startswith("/mock"):
          flow.response = http.Response.make(200, b"Hello World", {"Content-Type": "text/plain"})
  ```
- **lminspect:**
  ```lmcode
  @request
  fn on_request(f: Flow) -> void implements RequestHook {
      if (str_starts_with(f.request().path(), "/mock")) {
          f.respond(200, "{\"mocked\": true}", "application/json");
      }
  }
  ```

### 4. `modify-response-body`
- **Mitmproxy:**
  ```python
  def response(flow: http.HTTPFlow) -> None:
      flow.response.text = flow.response.text.replace("foo", "bar")
  ```
- **lminspect:**
  ```lmcode
  @response
  fn on_response(f: Flow) -> void implements ResponseHook {
      if (str_contains(f.response().text(), "foo")) {
          f.response().set_text(str_replace(f.response().text(), "foo", "bar"));
      }
  }
  ```

### 5. `modify-querystring`
- **Mitmproxy:**
  ```python
  def request(flow: http.HTTPFlow) -> None:
      flow.request.query["mitmproxy"] = "rocks"
  ```
- **lminspect:**
  ```lmcode
  @request
  fn on_request(f: Flow) -> void implements RequestHook {
      f.request().set_query("mitmproxy", "rocks");
  }
  ```

### 6. `filter-flows`
- **Mitmproxy:**
  ```python
  def request(flow: http.HTTPFlow) -> None:
      if "analytics" in flow.request.host:
          flow.kill()
  ```
- **lminspect:**
  ```lmcode
  @request
  fn on_request(f: Flow) -> void implements RequestHook {
      if (str_contains(f.request().host(), "analytics")) {
          f.kill();
      }
  }
  ```

### 7. `dump-flows`
- **Mitmproxy:**
  ```python
  def response(flow: http.HTTPFlow) -> None:
      print(f">> {flow.request.method} {flow.request.url} -> {flow.response.status_code}")
  ```
- **lminspect:**
  ```lmcode
  @response
  fn on_response(f: Flow) -> void implements ResponseHook {
      println("[<< RES] " + str(f.response().status_code()) + " " + f.request().url() + " (" + str(f.duration_ms()) + "ms)");
  }
  ```

### 8. `replay-flow`
- **Mitmproxy:** Client replay reads dumped flows and re-executes them against target.
- **lminspect:**
  - Standalone parsing & mutation in DSL: `inspect.parse_flow(json_str)`
  - Native CLI command: `lminspect replay --client flows.jsonl --target 127.0.0.1:9000`
