package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A model API streams hundreds of kilobytes of server-sent events per turn. The recorder must
// keep such a flow (sanitized, in full) and do so in reasonable time.
func TestRecordLargeStreamingFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := strings.Repeat("lorem ipsum dolor sit amet ", 40)
		for i := 0; i < 400; i++ {
			fmt.Fprintf(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":%d,\"delta\":\"%s\"}\n\n", i, chunk)
			w.(http.Flusher).Flush()
		}
		fmt.Fprint(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":34}}}\n\n")
	}))
	defer upstream.Close()
	path := filepath.Join(t.TempDir(), "capture.jsonl")
	rec, err := NewRecordAddon(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	mgr := NewAddonManager()
	mgr.Register(rec)
	server, err := NewProxyServer(ServerConfig{Mode: "reverse:" + upstream.URL, Addons: mgr})
	if err != nil {
		t.Fatal(err)
	}
	reply := httptest.NewRecorder()
	started := time.Now()
	server.ServeHTTP(reply, httptest.NewRequest("POST", "http://vendor.invalid/v1/responses", strings.NewReader(`{"input":"hi"}`)))
	elapsed := time.Since(started)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("streamed %d bytes, recorded %d bytes in %s", reply.Body.Len(), len(b), elapsed)
	if len(b) == 0 {
		t.Fatal("the streaming flow was not recorded")
	}
	if !strings.Contains(string(b), "response.completed") && !strings.Contains(string(b), "cmVzcG9uc2UuY29tcGxldGVk") {
		t.Fatal("the recording lost the end of the stream")
	}
	if elapsed > 30*time.Second {
		t.Fatalf("recording a %d byte stream took %s", reply.Body.Len(), elapsed)
	}
}
