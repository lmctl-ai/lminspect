package dsl

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/lmctl-ai/lmcode-go"
	"github.com/lmctl-ai/lminspect/pkg/proxy"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialPrintOutput(t *testing.T) {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		t.Fatal(e)
	}
	key := "synthetic-" + hex.EncodeToString(b)
	t.Setenv("PRINT_VENDOR_API_KEY", key)
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old; r.Close(); w.Close() }()
	h := NewHost()
	_, e = h.Registry.FunctionBySignature("fn println(string) -> void").Fn([]lmcode.Value{lmcode.Str("echo " + key)})
	w.Close()
	out, readErr := io.ReadAll(r)
	if e != nil || readErr != nil {
		t.Fatal("print fixture failed")
	}
	if strings.Contains(string(out), key) {
		t.Fatal("lmcode print leaked credential")
	}
}

func TestCredentialAddonPrintOutput(t *testing.T) {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		t.Fatal(e)
	}
	key := "synthetic-" + hex.EncodeToString(b)
	dir := t.TempDir()
	schema, e := os.ReadFile("../../schema/lminspect.dsl.json")
	if e != nil {
		t.Fatal(e)
	}
	schemaPath := filepath.Join(dir, "schema.json")
	if os.WriteFile(schemaPath, schema, 0600) != nil {
		t.Fatal("schema fixture failed")
	}
	bytecode := filepath.Join(dir, "addon.bin")
	source := fmt.Sprintf("p = _lmcode_ schema=%q;\n@request\nfn on_request(f: Flow) -> void implements RequestHook { println(f.request().header(\"Authorization\")); }\nend _lmcode_\nsavedsl(p, %q);\n", filepath.ToSlash(schemaPath), filepath.ToSlash(bytecode))
	input := filepath.Join(dir, "addon.lms")
	if os.WriteFile(input, []byte(source), 0600) != nil {
		t.Fatal("source fixture failed")
	}
	if output, e := compilerCommand(input).CombinedOutput(); e != nil {
		t.Fatalf("fixture compilation failed: %s", output)
	}
	addon, e := NewDslAddon(bytecode, schema)
	if e != nil {
		t.Fatal(e)
	}
	flow := proxy.NewFlow(&proxy.Request{Method: "GET", Path: "/", Headers: map[string][]string{"Authorization": {"Bearer " + key}}}, "")
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old; r.Close(); w.Close() }()
	e = addon.OnRequest(flow)
	w.Close()
	out, readErr := io.ReadAll(r)
	if e != nil || readErr != nil {
		t.Fatal("addon output failed")
	}
	if strings.Contains(string(out), key) {
		t.Fatal("lmcode print leaked credential")
	}
	if flow.Request.Header("Authorization") != "Bearer "+key {
		t.Fatal("addon print altered upstream authentication")
	}
}
