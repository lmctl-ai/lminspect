package dsl

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/lmctl-ai/lmcode-go"
	"github.com/lmctl-ai/lminspect/pkg/proxy"
)

func TestDslHostDirectFlowExecution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lminspect-dsl-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	schemaFile := filepath.Join(tempDir, "lminspect.dsl.json")
	schemaBytes, err := os.ReadFile("../../schema/lminspect.dsl.json")
	if err != nil {
		t.Fatalf("failed to read schema: %v", err)
	}
	if err := os.WriteFile(schemaFile, schemaBytes, 0644); err != nil {
		t.Fatal(err)
	}

	lmsSource := `
p = _lmcode_ schema="` + filepath.ToSlash(schemaFile) + `";

let f = inspect.new_flow("POST", "https://api.internal:8443/v1/resource?action=create");
assert(f.request().method() == "POST", "method mismatch");
assert(f.request().scheme() == "https", "scheme mismatch");
assert(f.request().host() == "api.internal", "host mismatch");
assert(f.request().port() == 8443, "port mismatch");
assert(f.request().query("action") == "create", "query mismatch");

f.request().set_header("X-Custom", "Val123");
assert(f.request().header("x-custom") == "Val123", "header set mismatch");

f.respond(201, "{\"created\": true}", "application/json");
assert(f.has_response(), "expected response");
assert(f.response().status_code() == 201, "status code mismatch");
assert(f.response().text() == "{\"created\": true}", "response text mismatch");
assert(f.response().header("content-type") == "application/json", "content type mismatch");

end _lmcode_
savedsl(p, "` + filepath.ToSlash(filepath.Join(tempDir, "test.dslb")) + `");
`
	lmsFile := filepath.Join(tempDir, "test.lms")
	dslbFile := filepath.Join(tempDir, "test.dslb")
	if err := os.WriteFile(lmsFile, []byte(lmsSource), 0644); err != nil {
		t.Fatal(err)
	}

	absBin, err := filepath.Abs("../../bin")
	if err != nil {
		t.Fatal(err)
	}

	cmd := compilerCommand(lmsFile, dslbFile)
	cmd.Env = append(os.Environ(), "PATH="+absBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lmscript compilation failed: %v, output: %s", err, string(out))
	}

	bytecode, err := os.ReadFile(dslbFile)
	if err != nil {
		t.Fatal(err)
	}

	host := NewHost()
	prog, err := lmcode.Load(bytecode, schemaBytes, host.Registry)
	if err != nil {
		t.Fatalf("lmcode.Load failed: %v", err)
	}

	ctx := lmcode.NewContext()
	ctx.Set("inspect", host.Inspector)
	if err := prog.Run(ctx, host.Registry); err != nil {
		t.Fatalf("prog.Run failed: %v", err)
	}
}

func TestDslAddonHooks(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lminspect-addon-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	schemaFile := filepath.Join(tempDir, "lminspect.dsl.json")
	schemaBytes, err := os.ReadFile("../../schema/lminspect.dsl.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(schemaFile, schemaBytes, 0644); err != nil {
		t.Fatal(err)
	}

	lmsSource := `
p = _lmcode_ schema="` + filepath.ToSlash(schemaFile) + `";

@request
fn on_request(f: Flow) -> void implements RequestHook {
	f.request().set_header("X-Injected-By", "dsl-addon");
	if (f.request().path() == "/mock-target") {
		f.respond(200, "HELLO_FROM_DSL_ADDON", "text/plain");
	}
}

@response
fn on_response(f: Flow) -> void implements ResponseHook {
	if (f.response().status_code() == 404) {
		f.response().set_status_code(200);
		f.response().set_text("OVERRIDDEN_404");
	}
}

end _lmcode_
savedsl(p, "` + filepath.ToSlash(filepath.Join(tempDir, "hooks.dslb")) + `");
`
	lmsFile := filepath.Join(tempDir, "hooks.lms")
	dslbFile := filepath.Join(tempDir, "hooks.dslb")
	if err := os.WriteFile(lmsFile, []byte(lmsSource), 0644); err != nil {
		t.Fatal(err)
	}

	absBin, err := filepath.Abs("../../bin")
	if err != nil {
		t.Fatal(err)
	}

	cmd := compilerCommand(lmsFile, dslbFile)
	cmd.Env = append(os.Environ(), "PATH="+absBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lmscript compile error: %v, out: %s", err, string(out))
	}

	addon, err := NewDslAddon(dslbFile, schemaBytes)
	if err != nil {
		t.Fatalf("NewDslAddon error: %v", err)
	}

	// 1. Test on_request modification
	req := &proxy.Request{
		Method:  "GET",
		Path:    "/normal",
		Headers: make(map[string][]string),
	}
	flow1 := proxy.NewFlow(req, "127.0.0.1:1000")
	if err := addon.OnRequest(flow1); err != nil {
		t.Fatal(err)
	}
	if flow1.Request.Header("X-Injected-By") != "dsl-addon" {
		t.Fatalf("header not injected: %s", flow1.Request.Header("X-Injected-By"))
	}
	if flow1.Response != nil {
		t.Fatal("normal flow should not have response")
	}

	// 2. Test on_request synthetic respond
	reqMock := &proxy.Request{
		Method:  "GET",
		Path:    "/mock-target",
		Headers: make(map[string][]string),
	}
	flow2 := proxy.NewFlow(reqMock, "127.0.0.1:1000")
	if err := addon.OnRequest(flow2); err != nil {
		t.Fatal(err)
	}
	if flow2.Response == nil || flow2.Response.Text() != "HELLO_FROM_DSL_ADDON" {
		t.Fatalf("expected synthetic response from on_request")
	}

	// 3. Test on_response override
	req3 := &proxy.Request{Method: "GET", Path: "/not-found", Headers: make(map[string][]string)}
	flow3 := proxy.NewFlow(req3, "127.0.0.1:1000")
	flow3.Response = proxy.MakeResponse(404, "Not Found", "text/plain")
	if err := addon.OnResponse(flow3); err != nil {
		t.Fatal(err)
	}
	if flow3.Response.StatusCode != 200 || flow3.Response.Text() != "OVERRIDDEN_404" {
		t.Fatalf("response not overridden: %d %s", flow3.Response.StatusCode, flow3.Response.Text())
	}
}

// Invoke the private package's JS entry directly, including on Windows where
// exec.Command cannot execute an npm .cmd shim as a native process.
func compilerCommand(args ...string) *exec.Cmd {
	if entry := os.Getenv("LMSCRIPT_COMPILER_JS"); entry != "" {
		return exec.Command("node", append([]string{entry}, args...)...)
	}
	return exec.Command("lmscript", args...)
}
