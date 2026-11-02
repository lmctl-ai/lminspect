package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal("random fixture failed")
	}
	return "synthetic-" + hex.EncodeToString(b)
}
func percentAll(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}
func checkAbsent(t *testing.T, b []byte, keys ...string) {
	t.Helper()
	for _, k := range keys {
		for _, s := range []string{k, url.QueryEscape(k), percentAll(k), strings.ToLower(percentAll(k)), base64.StdEncoding.EncodeToString([]byte(k)), base64.StdEncoding.EncodeToString([]byte("Bearer " + k)), base64.RawURLEncoding.EncodeToString([]byte(k))} {
			if bytes.Contains(b, []byte(s)) {
				t.Fatal("credential survived output sanitization")
			}
		}
	}
}
func inspectCapture(t *testing.T, b []byte, keys ...string) *HTTPFlow {
	t.Helper()
	checkAbsent(t, b, keys...)
	f, e := FlowFromJSON(bytes.TrimSpace(b))
	if e != nil {
		t.Fatal("capture must remain decodable")
	}
	checkAbsent(t, f.Request.Content, keys...)
	if f.Response != nil {
		checkAbsent(t, f.Response.Content, keys...)
	}
	return f
}
func TestCredentialOutputBoundary(t *testing.T) {
	for _, kind := range []string{"json", "form", "text", "sse"} {
		t.Run(kind, func(t *testing.T) {
			header, query, body, envKey, user, cookie := syntheticKey(t), syntheticKey(t), syntheticKey(t), syntheticKey(t), syntheticKey(t), syntheticKey(t)
			t.Setenv("TEST_VENDOR_API_KEY", envKey)
			req := &Request{Method: "POST", Scheme: "https", Host: "vendor.invalid", Port: 443, Path: "/v1/messages?%61pi%5fkey=" + percentAll(query) + "&tokenizer=keep", Headers: map[string][]string{"Authorization": {"Bearer " + header}, "x-api-key": {header}, "api-key": {header}, "Cookie": {"sid=" + cookie}}, Content: []byte(`{"password":"` + body + `","echo":"` + envKey + `","tokenizer":"keep","usage":{"input_tokens":12}}`)}
			content := []byte(`{"access_token":"` + body + `","echo":"` + header + `","encoded":"` + base64.StdEncoding.EncodeToString([]byte("Bearer "+header)) + `","url":"https://` + user + `:pass@vendor.invalid/x?key=` + query + `"}`)
			ct := "application/json"
			switch kind {
			case "form":
				ct = "application/x-www-form-urlencoded"
				content = []byte("client_secret=" + percentAll(body) + "&echo=" + envKey)
			case "text":
				ct = "text/plain"
				content = []byte("password=" + body + "\nAuthorization: Bearer " + header + "\nhttps://" + user + ":pass@vendor.invalid/?key=" + query + "\n" + envKey)
			case "sse":
				ct = "text/event-stream"
				half := len(header) / 2
				content = []byte("event: delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"" + header[:half] + "\"}}\n\nevent: delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"" + header[half:] + "\"}}\n\ndata: [DONE]\n\n")
			}
			flow := NewFlow(req, "127.0.0.1")
			flow.Response = MakeResponse(200, string(content), ct)
			flow.Response.Headers["Set-Cookie"] = []string{"sid=" + cookie + "; HttpOnly"}
			flow.Response.Headers["Location"] = []string{"https://" + user + ":pass@vendor.invalid/?key=" + query}
			flow.Error = "echo " + envKey
			original := append([]byte(nil), flow.Response.Content...)
			recordPath := filepath.Join(t.TempDir(), "capture.jsonl")
			r, e := NewRecordAddon(recordPath)
			if e != nil {
				t.Fatal(e)
			}
			if e = r.OnResponse(flow); e != nil {
				t.Fatal(e)
			}
			r.Close()
			recorded, e := os.ReadFile(recordPath)
			if e != nil {
				t.Fatal(e)
			}
			clean := inspectCapture(t, recorded, header, query, body, envKey, user, cookie)
			if kind == "sse" {
				var joined string
				for _, line := range strings.Split(string(clean.Response.Content), "\n") {
					if strings.HasPrefix(line, "data: {") {
						var v map[string]any
						if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &v) != nil {
							t.Fatal("SSE structure lost")
						}
						d := v["delta"].(map[string]any)
						joined += d["text"].(string)
					}
				}
				checkAbsent(t, []byte(joined), header)
				if strings.Contains(string(clean.Response.Content), header[:len(header)/2]) {
					t.Fatal("split SSE credential fragment persisted")
				}
				if !strings.Contains(string(clean.Response.Content), "[DONE]") {
					t.Fatal("SSE terminal lost")
				}
			}
			if !strings.Contains(clean.Request.Path, "tokenizer=keep") {
				t.Fatal("noncredential query lost")
			}
			if !bytes.Equal(flow.Response.Content, original) || flow.Request.Header("Authorization") != "Bearer "+header {
				t.Fatal("sanitizer modified live traffic")
			}
			raw, e := json.Marshal(flow)
			if e != nil {
				t.Fatal(e)
			}
			inspectCapture(t, raw, header, query, body, envKey, user, cookie)
			var tap bytes.Buffer
			NewTapAddon(&tap).OnResponse(flow)
			NewTapAddon(&tap).OnError(flow, fmt.Errorf("upstream URL https://%s:pass@vendor.invalid/?token=%s", user, envKey))
			checkAbsent(t, tap.Bytes(), query, user, envKey)
		})
	}
}
func TestCredentialRecordingThroughRoutedProxy(t *testing.T) {
	key := syntheticKey(t)
	received := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream")
		half := len(key) / 2
		fmt.Fprint(w, "data: "+key[:half])
		w.(http.Flusher).Flush()
		fmt.Fprint(w, key[half:]+"\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()
	path := filepath.Join(t.TempDir(), "capture.jsonl")
	rec, e := NewRecordAddon(path)
	if e != nil {
		t.Fatal(e)
	}
	defer rec.Close()
	mgr := NewAddonManager()
	mgr.Register(rec)
	server, e := NewProxyServer(ServerConfig{Mode: "reverse:" + upstream.URL, Addons: mgr})
	if e != nil {
		t.Fatal(e)
	}
	request := httptest.NewRequest("GET", "http://vendor.invalid/?key="+url.QueryEscape(key), nil)
	request.Header.Set("Authorization", "Bearer "+key)
	reply := httptest.NewRecorder()
	server.ServeHTTP(reply, request)
	if <-received != "Bearer "+key {
		t.Fatal("routing authentication changed")
	}
	if !strings.Contains(reply.Body.String(), key) {
		t.Fatal("client stream changed")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	f := inspectCapture(t, b, key)
	if !strings.Contains(string(f.Response.Content), "[DONE]") {
		t.Fatal("stream framing changed")
	}
}
func TestCredentialJSONStructureAndIdempotence(t *testing.T) {
	key := syntheticKey(t)
	f := NewFlow(&Request{Method: "POST", Path: "/", Headers: map[string][]string{}, Content: []byte(`{"api_key":"` + key + `","tokenizer":"safe","usage":{"input_tokens":17},"ok":true}`)}, "")
	f.Response = MakeResponse(200, "{}", "application/json")
	b, e := f.ToJSON()
	if e != nil {
		t.Fatal(e)
	}
	g := inspectCapture(t, b, key)
	var tree map[string]any
	if json.Unmarshal(g.Request.Content, &tree) != nil {
		t.Fatal("JSON structure lost")
	}
	if tree["tokenizer"] != "safe" || tree["ok"] != true || tree["usage"].(map[string]any)["input_tokens"] != float64(17) {
		t.Fatal("noncredential JSON changed")
	}
	again, e := g.ToJSON()
	if e != nil || !bytes.Equal(b, again) {
		t.Fatal("redaction is not idempotent")
	}
}

func TestCredentialEncodedDiscoveryBeforeEchoes(t *testing.T) {
	for _, kind := range []string{"opaque-header", "opaque-response", "double-query", "split-bearer", "userinfo", "host-userinfo", "form", "text-auth-position"} {
		t.Run(kind, func(t *testing.T) {
			key := syntheticKey(t)
			f := NewFlow(&Request{Method: "POST", Scheme: "https", Host: "vendor.invalid", Port: 443, Path: "/capture", Headers: map[string][]string{}, Content: []byte(`{"echo":"` + key + `"}`)}, "")
			f.Response = MakeResponse(200, `{"echo":"`+key+`"}`, "application/json")
			switch kind {
			case "opaque-header":
				f.Request.Headers["Authorization"] = []string{base64.StdEncoding.EncodeToString([]byte("Bearer " + key))}
			case "opaque-response":
				f.Response.Content = []byte(`{"data":"` + base64.StdEncoding.EncodeToString([]byte("api_key="+key)) + `"}`)
			case "double-query":
				f.Request.Path = "/capture?%2561pi%255fkey=" + url.QueryEscape(percentAll(key))
			case "split-bearer":
				half := len(key) / 2
				f.Response = MakeResponse(200, "data: {\"delta\":{\"text\":\"Bearer "+key[:half]+"\",\"type\":\"text_delta\"}}\n\ndata: {\"delta\":{\"text\":\""+key[half:]+"\",\"type\":\"text_delta\"}}\n\ndata: [DONE]\n\n", "text/event-stream")
			case "host-userinfo":
				f.Request.Host = "user:" + key + "@vendor.invalid"
			case "userinfo":
				f.Response.Headers["Location"] = []string{"https://user:" + key + "@vendor.invalid/next"}
			case "form":
				f.Response = MakeResponse(200, "%61pi_key="+percentAll(key), "application/x-www-form-urlencoded")
			case "text-auth-position":
				f.Response = MakeResponse(200, "X-Custom-Auth: "+key, "text/plain")
			}
			b, e := f.ToJSON()
			if e != nil {
				t.Fatal(e)
			}
			inspectCapture(t, b, key)
		})
	}
}

func TestCredentialMarkerRemainsStable(t *testing.T) {
	t.Setenv("SYNTHETIC_API_KEY", "credential")
	f := NewFlow(&Request{Method: "POST", Path: "/", Headers: map[string][]string{}, Content: []byte(`{"api_key":"credential","echo":"credential"}`)}, "")
	f.Response = MakeResponse(200, "{}", "application/json")
	b, e := f.ToJSON()
	if e != nil {
		t.Fatal(e)
	}
	g, e := FlowFromJSON(b)
	if e != nil {
		t.Fatal(e)
	}
	again, e := g.ToJSON()
	if e != nil || !bytes.Equal(b, again) {
		t.Fatal("reserved redaction marker changed on re-export")
	}
	var body map[string]any
	if json.Unmarshal(g.Request.Content, &body) != nil || body["api_key"] != RedactedCredential {
		t.Fatal("credential marker lost")
	}
}

func TestCredentialCompressedAndLargeBodies(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate", "unsupported", "invalid"} {
		t.Run(encoding, func(t *testing.T) {
			key := syntheticKey(t)
			text := strings.Repeat("harmless-", 20000)
			raw := []byte(`{"api_key":"` + key + `","text":"` + text + `","tokenizer":"TokenizerPublicConfigurationAlpha-12345"}`)
			var compressed bytes.Buffer
			if encoding == "gzip" {
				w := gzip.NewWriter(&compressed)
				w.Write(raw)
				w.Close()
			} else if encoding == "deflate" {
				w := zlib.NewWriter(&compressed)
				w.Write(raw)
				w.Close()
			} else {
				compressed.Write(raw)
			}
			f := NewFlow(&Request{Method: "GET", Path: "/", Headers: map[string][]string{}}, "")
			f.Response = MakeResponse(200, compressed.String(), "application/json")
			f.Response.Headers["Content-Encoding"] = []string{encoding}
			if encoding == "invalid" {
				f.Response.Headers["Content-Encoding"] = []string{"gzip"}
			}
			out, e := f.ToJSON()
			if e != nil {
				t.Fatal(e)
			}
			g := inspectCapture(t, out, key)
			if g.Response.Header("Content-Encoding") != "" {
				t.Fatal("stale encoding persisted")
			}
			if encoding == "gzip" || encoding == "deflate" {
				var tree map[string]any
				if json.Unmarshal(g.Response.Content, &tree) != nil || tree["text"] != text || tree["tokenizer"] != "TokenizerPublicConfigurationAlpha-12345" {
					t.Fatal("ordinary large payload was lost or clipped")
				}
			} else if string(g.Response.Content) != RedactedCredential {
				t.Fatal("opaque body must fail closed")
			}
		})
	}
}

type credentialErrorAddon struct{ key string }

func (a credentialErrorAddon) Name() string { return "synthetic-route-error" }
func (a credentialErrorAddon) OnRequest(*HTTPFlow) error {
	return fmt.Errorf("route error echo %s", a.key)
}
func TestCredentialProxyErrorOutput(t *testing.T) {
	key := syntheticKey(t)
	addons := NewAddonManager()
	addons.Register(credentialErrorAddon{key})
	server, e := NewProxyServer(ServerConfig{Addons: addons})
	if e != nil {
		t.Fatal(e)
	}
	request := httptest.NewRequest("GET", "http://vendor.invalid/", nil)
	request.Header.Set("Authorization", "Bearer "+key)
	out := httptest.NewRecorder()
	server.ServeHTTP(out, request)
	if out.Code != 500 {
		t.Fatal("expected route error")
	}
	checkAbsent(t, out.Body.Bytes(), key)
}

func TestCredentialEarlierFlowEcho(t *testing.T) {
	key := syntheticKey(t)
	path := filepath.Join(t.TempDir(), "capture.jsonl")
	record, e := NewRecordAddon(path)
	if e != nil {
		t.Fatal(e)
	}
	defer record.Close()
	first := NewFlow(&Request{Method: "GET", Path: "/", Headers: map[string][]string{"Authorization": {"Bearer " + key}}}, "")
	first.Response = MakeResponse(200, "ok", "text/plain")
	second := NewFlow(&Request{Method: "GET", Path: "/", Headers: map[string][]string{}}, "")
	second.Response = MakeResponse(200, "unlabelled earlier credential echo "+key, "text/plain")
	for _, f := range []*HTTPFlow{first, second} {
		if record.OnResponse(f) != nil {
			t.Fatal("record failed")
		}
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	checkAbsent(t, b, key)
	decoder := json.NewDecoder(bytes.NewReader(b))
	for i := 0; i < 2; i++ {
		var f HTTPFlow
		if decoder.Decode(&f) != nil {
			t.Fatal("record framing lost")
		}
		checkAbsent(t, f.Response.Content, key)
	}
}

type removingCredentialAddon struct{}

func (removingCredentialAddon) Name() string { return "synthetic-auth-removal" }
func (removingCredentialAddon) OnRequest(f *HTTPFlow) error {
	key := f.Request.Header("Authorization")
	f.Request.RemoveHeader("Authorization")
	f.Respond(200, key, "text/plain")
	return nil
}
func TestCredentialRememberedBeforeMutableHook(t *testing.T) {
	key := syntheticKey(t)
	path := filepath.Join(t.TempDir(), "capture.jsonl")
	record, e := NewRecordAddon(path)
	if e != nil {
		t.Fatal(e)
	}
	defer record.Close()
	manager := NewAddonManager()
	manager.Register(removingCredentialAddon{})
	manager.Register(record)
	server, e := NewProxyServer(ServerConfig{Addons: manager})
	if e != nil {
		t.Fatal(e)
	}
	request := httptest.NewRequest("GET", "http://vendor.invalid/", nil)
	request.Header.Set("Authorization", key)
	reply := httptest.NewRecorder()
	server.ServeHTTP(reply, request)
	if reply.Body.String() != key {
		t.Fatal("live response changed")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	inspectCapture(t, b, key)
}

func TestCredentialKnownFieldsDoNotRequireEntropy(t *testing.T) {
	for _, name := range []string{"X-APIKey", "Auth", "Session_Key"} {
		t.Run(name, func(t *testing.T) {
			b := make([]byte, 2)
			if _, e := rand.Read(b); e != nil {
				t.Fatal(e)
			}
			key := "fake-" + hex.EncodeToString(b)
			f := NewFlow(&Request{Method: "GET", Path: "/", Headers: map[string][]string{name: {key}}}, "")
			f.Response = MakeResponse(200, "echo "+key, "text/plain")
			out, e := f.ToJSON()
			if e != nil {
				t.Fatal(e)
			}
			inspectCapture(t, out, key)
		})
	}
}

func TestCredentialPreserveOrdinaryURLBytes(t *testing.T) {
	path := "/models/a%2Fb?z=%20&a=%2f&b=plain"
	f := NewFlow(&Request{Method: "GET", Path: path, Headers: map[string][]string{}}, "")
	f.Response = MakeResponse(200, "ok", "text/plain")
	out, e := f.ToJSON()
	if e != nil {
		t.Fatal(e)
	}
	g, e := FlowFromJSON(out)
	if e != nil || g.Request.Path != path {
		t.Fatal("ordinary encoded path or query ordering changed")
	}
}
func TestCredentialKnownValueInQueryName(t *testing.T) {
	key := syntheticKey(t)
	t.Setenv("SYNTHETIC_VENDOR_API_KEY", key)
	f := NewFlow(&Request{Method: "GET", Path: "/capture?" + url.QueryEscape(key) + "=ordinary", Headers: map[string][]string{}}, "")
	f.Response = MakeResponse(200, "ok", "text/plain")
	out, e := f.ToJSON()
	if e != nil {
		t.Fatal(e)
	}
	inspectCapture(t, out, key)
}
