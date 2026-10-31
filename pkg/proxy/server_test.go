package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxyServerForwardHTTP(t *testing.T) {
	// Upstream origin server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Header", "Hello")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ORIGIN_RESPONSE"))
	}))
	defer upstream.Close()

	proxySrv, err := NewProxyServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Mode:       "regular",
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	proxySrv.listener = ln
	go func() { _ = proxySrv.httpServer.Serve(ln) }()
	defer func() { _ = proxySrv.Shutdown(context.Background()) }()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("client.Get through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ORIGIN_RESPONSE" {
		t.Fatalf("expected ORIGIN_RESPONSE, got: %s", string(body))
	}
	if resp.Header.Get("X-Upstream-Header") != "Hello" {
		t.Fatalf("missing upstream header")
	}
}

func TestProxyServerRulesAndMock(t *testing.T) {
	rules := NewRuleAddon()
	_ = rules.AddMock("/mock", 200, "MOCKED_SUCCESS", "text/plain")
	_ = rules.AddRedirect("/redirect-me", "http://example.com/dest")
	_ = rules.AddHeader(".*", "X-Added-Key", "AddedVal")

	addonMgr := NewAddonManager()
	addonMgr.Register(rules)

	proxySrv, err := NewProxyServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Mode:       "regular",
		Addons:     addonMgr,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	proxySrv.listener = ln
	go func() { _ = proxySrv.httpServer.Serve(ln) }()
	defer func() { _ = proxySrv.Shutdown(context.Background()) }()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	// 1. Test Mock rule
	resp, err := client.Get("http://any-domain.org/mock")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "MOCKED_SUCCESS" {
		t.Fatalf("expected MOCKED_SUCCESS, got: %s", string(body))
	}

	// 2. Test Redirect rule
	respRedir, err := client.Get("http://any-domain.org/redirect-me")
	if err != nil {
		t.Fatal(err)
	}
	defer respRedir.Body.Close()
	if respRedir.StatusCode != 307 {
		t.Fatalf("expected 307, got %d", respRedir.StatusCode)
	}
	if respRedir.Header.Get("Location") != "http://example.com/dest" {
		t.Fatalf("redirect location mismatch: %s", respRedir.Header.Get("Location"))
	}
}

func TestProxyServerSSLBumpHTTPS(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lminspect-ssl-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	caCertPath := filepath.Join(tempDir, "ca.crt")
	caKeyPath := filepath.Join(tempDir, "ca.key")

	// Upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-TLS-Origin", "True")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SECURE_UPSTREAM_RESPONSE"))
	}))
	defer upstream.Close()

	rules := NewRuleAddon()
	_ = rules.AddMock(".*/swap-secret", 200, "MOCKED_HTTPS_SWAP", "text/plain")

	addonMgr := NewAddonManager()
	addonMgr.Register(rules)

	proxySrv, err := NewProxyServer(ServerConfig{
		ListenAddr:         "127.0.0.1:0",
		Mode:               "regular",
		SSLBump:            true,
		CACertPath:         caCertPath,
		CAKeyPath:          caKeyPath,
		InsecureSkipVerify: true,
		Addons:             addonMgr,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	proxySrv.listener = ln
	go func() { _ = proxySrv.httpServer.Serve(ln) }()
	defer func() { _ = proxySrv.Shutdown(context.Background()) }()

	caPEM := proxySrv.ca.CACertPEM()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
		},
		Timeout: 5 * time.Second,
	}

	// 1. Normal HTTPS passthrough with TLS decryption
	resp, err := client.Get(upstream.URL + "/normal")
	if err != nil {
		t.Fatalf("HTTPS GET through proxy failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "SECURE_UPSTREAM_RESPONSE" {
		t.Fatalf("expected SECURE_UPSTREAM_RESPONSE, got: %s", string(body))
	}

	// 2. HTTPS intercepted mock swap
	respSwap, err := client.Get(upstream.URL + "/swap-secret")
	if err != nil {
		t.Fatalf("HTTPS swap GET through proxy failed: %v", err)
	}
	defer respSwap.Body.Close()
	bodySwap, _ := io.ReadAll(respSwap.Body)
	if string(bodySwap) != "MOCKED_HTTPS_SWAP" {
		t.Fatalf("expected MOCKED_HTTPS_SWAP, got: %s", string(bodySwap))
	}
}

func TestRecordAndReplayAddons(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lminspect-record-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	recordFile := filepath.Join(tempDir, "flows.jsonl")

	// Upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ORIGIN_SAVED_" + r.URL.Path))
	}))
	defer upstream.Close()

	recAddon, err := NewRecordAddon(recordFile)
	if err != nil {
		t.Fatal(err)
	}

	addonMgr := NewAddonManager()
	addonMgr.Register(recAddon)

	proxySrv, err := NewProxyServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Mode:       "regular",
		Addons:     addonMgr,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxySrv.listener = ln
	go func() { _ = proxySrv.httpServer.Serve(ln) }()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	r1, err := client.Get(upstream.URL + "/path1")
	if err != nil {
		t.Fatal(err)
	}
	r1.Body.Close()

	r2, err := client.Get(upstream.URL + "/path2")
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()

	_ = recAddon.Close()
	_ = proxySrv.Shutdown(context.Background())
	ln.Close()

	// Verify recorded file
	content, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 recorded lines, got %d", len(lines))
	}

	// Now start a new proxy with ReplayServerAddon and shutdown upstream
	upstream.Close() // Upstream is dead!

	repAddon, err := NewReplayServerAddon(recordFile)
	if err != nil {
		t.Fatal(err)
	}

	replayAddonMgr := NewAddonManager()
	replayAddonMgr.Register(repAddon)

	replayProxy, err := NewProxyServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Mode:       "regular",
		Addons:     replayAddonMgr,
	})
	if err != nil {
		t.Fatal(err)
	}

	replayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	replayProxy.listener = replayLn
	go func() { _ = replayProxy.httpServer.Serve(replayLn) }()
	defer func() {
		_ = replayProxy.Shutdown(context.Background())
		replayLn.Close()
	}()

	replayClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: replayLn.Addr().String()}),
		},
		Timeout: 5 * time.Second,
	}

	// Request should be served from recording without upstream!
	repResp, err := replayClient.Get(fmt.Sprintf("http://dead-upstream.test/path1"))
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	defer repResp.Body.Close()
	repBody, _ := io.ReadAll(repResp.Body)
	if string(repBody) != "ORIGIN_SAVED_/path1" {
		t.Fatalf("replay response mismatch: %s", string(repBody))
	}
}
