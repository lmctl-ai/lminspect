package proxy

import (
	"net/http"
	"strings"
	"testing"
)

func TestRequestAndResponse(t *testing.T) {
	httpReq, err := http.NewRequest("GET", "http://example.com:8080/path/test?q=1&foo=bar", strings.NewReader("sample payload"))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("User-Agent", "TestClient")
	httpReq.Header.Set("X-Custom", "Val1")

	req := NewRequest(httpReq, []byte("sample payload"))

	if req.Method != "GET" {
		t.Fatalf("expected GET, got %s", req.Method)
	}
	if req.Host != "example.com" {
		t.Fatalf("expected example.com, got %s", req.Host)
	}
	if req.Port != 8080 {
		t.Fatalf("expected 8080, got %d", req.Port)
	}
	if req.Path != "/path/test?q=1&foo=bar" {
		t.Fatalf("expected path, got %s", req.Path)
	}
	if req.URL() != "http://example.com:8080/path/test?q=1&foo=bar" {
		t.Fatalf("expected full URL, got %s", req.URL())
	}
	if req.Header("user-agent") != "TestClient" {
		t.Fatalf("case-insensitive header failed: %s", req.Header("user-agent"))
	}
	if req.Query("q") != "1" || req.Query("foo") != "bar" {
		t.Fatalf("query lookup failed")
	}

	req.SetQuery("q", "2")
	if req.Query("q") != "2" {
		t.Fatalf("query mutation failed: %s", req.Query("q"))
	}

	req.SetHeader("x-custom", "Val2")
	if req.Header("X-Custom") != "Val2" {
		t.Fatalf("header mutation failed: %s", req.Header("X-Custom"))
	}

	req.SetText("updated body")
	if req.Text() != "updated body" {
		t.Fatalf("text mutation failed: %s", req.Text())
	}
	if req.Header("Content-Length") != "12" {
		t.Fatalf("content-length update failed: %s", req.Header("Content-Length"))
	}

	// Test Response
	resp := MakeResponse(200, "{\"status\": \"ok\"}", "application/json")
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header("content-type") != "application/json" {
		t.Fatalf("expected application/json, got %s", resp.Header("content-type"))
	}
	if resp.Text() != "{\"status\": \"ok\"}" {
		t.Fatalf("expected json body, got %s", resp.Text())
	}

	resp.SetHeader("X-Added", "True")
	if resp.Header("x-added") != "True" {
		t.Fatalf("response header failed")
	}

	resp.SetText("new content")
	if resp.Text() != "new content" {
		t.Fatalf("response set_text failed")
	}
	if resp.Header("Content-Length") != "11" {
		t.Fatalf("response content length failed: %s", resp.Header("Content-Length"))
	}
}

func TestFlowLifecycle(t *testing.T) {
	req := &Request{
		Method:  "POST",
		Scheme:  "https",
		Host:    "api.internal",
		Port:    443,
		Path:    "/v1/auth",
		Headers: make(map[string][]string),
		Content: []byte("creds"),
	}

	flow := NewFlow(req, "192.168.1.1:1234")
	if flow.ID == "" {
		t.Fatal("expected flow ID")
	}
	if flow.IsIntercepted() {
		t.Fatal("expected not intercepted initially")
	}

	flow.Intercept()
	if !flow.IsIntercepted() {
		t.Fatal("expected intercepted")
	}

	flow.Resume()
	if flow.IsIntercepted() {
		t.Fatal("expected resumed")
	}

	flow.Respond(200, "{\"token\": \"abc\"}", "application/json")
	if flow.Response == nil || flow.Response.StatusCode != 200 {
		t.Fatal("expected synthetic response")
	}

	flow.Kill()
	if !flow.IsKilled() {
		t.Fatal("expected killed")
	}

	data, err := flow.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := FlowFromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID != flow.ID || restored.Request.URL() != flow.Request.URL() {
		t.Fatal("JSON round-trip mismatch")
	}
}
