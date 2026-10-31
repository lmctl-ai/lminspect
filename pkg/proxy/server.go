package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ServerConfig configures proxy runtime parameters.
type ServerConfig struct {
	ListenAddr         string
	Mode               string // "regular", "reverse:<url>", "transparent"
	CACertPath         string
	CAKeyPath          string
	SSLBump            bool
	InsecureSkipVerify bool
	Addons             *AddonManager
}

// ProxyServer is the core intercepting HTTP/HTTPS proxy daemon.
type ProxyServer struct {
	config     ServerConfig
	ca         *CertAuthority
	addons     *AddonManager
	httpServer *http.Server
	listener   net.Listener
	client     *http.Client
	reverseURL *url.URL
	running    bool
	mu         sync.Mutex
}

// NewProxyServer instantiates a ProxyServer.
func NewProxyServer(cfg ServerConfig) (*ProxyServer, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:8080"
	}
	if cfg.Addons == nil {
		cfg.Addons = NewAddonManager()
	}

	var ca *CertAuthority
	if cfg.SSLBump {
		var err error
		ca, err = NewCertAuthority(cfg.CACertPath, cfg.CAKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize CA: %w", err)
		}
	}

	var reverseURL *url.URL
	if strings.HasPrefix(cfg.Mode, "reverse:") {
		target := strings.TrimPrefix(cfg.Mode, "reverse:")
		var err error
		reverseURL, err = url.Parse(target)
		if err != nil {
			return nil, fmt.Errorf("invalid reverse proxy target URL: %w", err)
		}
	}

	tr := &http.Transport{
		Proxy: nil, // Direct connection to destination
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects automatically; let client handle
		},
	}

	s := &ProxyServer{
		config:     cfg,
		ca:         ca,
		addons:     cfg.Addons,
		client:     client,
		reverseURL: reverseURL,
	}

	s.httpServer = &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: http.HandlerFunc(s.ServeHTTP),
	}

	return s, nil
}

// Start begins listening and serving traffic.
func (s *ProxyServer) Start() error {
	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.running = true
	s.mu.Unlock()

	return s.httpServer.Serve(ln)
}

// Addr returns the bound listener address.
func (s *ProxyServer) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.config.ListenAddr
}

// Shutdown gracefully stops the proxy.
func (s *ProxyServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
	return s.httpServer.Shutdown(ctx)
}

// ServeHTTP routes plain HTTP and CONNECT tunneling requests.
func (s *ProxyServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		s.handleConnect(w, req)
		return
	}
	s.handleHTTP(w, req, false)
}

func (s *ProxyServer) handleHTTP(w http.ResponseWriter, req *http.Request, isTLS bool) {
	startTime := time.Now()

	// Read client body
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	flowReq := NewRequest(req, body)
	if isTLS {
		flowReq.Scheme = "https"
	}

	// Apply reverse proxy rewrite if in reverse mode
	if s.reverseURL != nil {
		flowReq.Scheme = s.reverseURL.Scheme
		flowReq.Host = s.reverseURL.Hostname()
		if s.reverseURL.Port() != "" {
			_, flowReq.Port, _ = parseHostPort(":" + s.reverseURL.Port())
		} else if flowReq.Scheme == "https" {
			flowReq.Port = 443
		} else {
			flowReq.Port = 80
		}
	}

	flow := NewFlow(flowReq, req.RemoteAddr)

	// Trigger Request Addons
	if err := s.addons.TriggerRequest(flow); err != nil {
		s.addons.TriggerError(flow, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Handle Killed flow
	if flow.IsKilled() {
		flow.DurationMs = time.Since(startTime).Milliseconds()
		_ = s.addons.TriggerResponse(flow)
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		return
	}

	// Handle Synthetic / Mocked Response
	if flow.Response != nil {
		flow.DurationMs = time.Since(startTime).Milliseconds()
		_ = s.addons.TriggerResponse(flow)
		s.writeResponse(w, flow.Response)
		return
	}

	// Forward upstream
	outReq, err := flow.Request.ToHTTPRequest()
	if err != nil {
		s.addons.TriggerError(flow, err)
		http.Error(w, fmt.Sprintf("Failed to construct upstream request: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.client.Do(outReq)
	if err != nil {
		flow.Error = err.Error()
		s.addons.TriggerError(flow, err)
		http.Error(w, fmt.Sprintf("Upstream connection error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		s.addons.TriggerError(flow, err)
		http.Error(w, fmt.Sprintf("Error reading upstream response: %v", err), http.StatusBadGateway)
		return
	}

	flow.Response = NewResponse(resp, respBody)
	flow.DurationMs = time.Since(startTime).Milliseconds()

	// Trigger Response Addons
	if err := s.addons.TriggerResponse(flow); err != nil {
		s.addons.TriggerError(flow, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if flow.IsKilled() {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		return
	}

	s.writeResponse(w, flow.Response)
}

func (s *ProxyServer) writeResponse(w http.ResponseWriter, resp *Response) {
	resp.mu.RLock()
	defer resp.mu.RUnlock()

	for k, vv := range resp.Headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	if len(resp.Content) > 0 {
		_, _ = w.Write(resp.Content)
	}
}

// handleConnect handles HTTPS CONNECT tunnels.
func (s *ProxyServer) handleConnect(w http.ResponseWriter, req *http.Request) {
	targetHost := req.Host

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Send 200 Connection Established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		_ = clientConn.Close()
		return
	}

	// If SSL Bump is disabled, tunnel raw TCP
	if !s.config.SSLBump || s.ca == nil {
		s.tunnelTCP(clientConn, targetHost)
		return
	}

	// SSL Bump: Decrypt TLS and inspect inner HTTP/1.1 traffic
	serverName := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		serverName = h
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sn := info.ServerName
			if sn == "" {
				sn = serverName
			}
			return s.ca.GetCertificate(sn)
		},
		NextProtos: []string{"http/1.1"},
	})

	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return
	}
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)
	for {
		innerReq, err := http.ReadRequest(reader)
		if err != nil {
			break // Connection closed or keepalive timeout
		}

		// Ensure scheme and host are populated from CONNECT context if not in inner request
		if innerReq.URL.Host == "" {
			innerReq.URL.Host = targetHost
			innerReq.Host = targetHost
		}
		innerReq.URL.Scheme = "https"

		rw := &tlsResponseWriter{
			conn:   tlsConn,
			header: make(http.Header),
		}

		s.handleHTTP(rw, innerReq, true)
		if rw.closeNotify || innerReq.Close || strings.EqualFold(innerReq.Header.Get("Connection"), "close") {
			break
		}
	}
}

func (s *ProxyServer) tunnelTCP(clientConn net.Conn, targetHost string) {
	defer clientConn.Close()

	destConn, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		return
	}
	defer destConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(destConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()
	<-done
}

// tlsResponseWriter implements http.ResponseWriter over an intercepted TLS connection.
type tlsResponseWriter struct {
	conn        net.Conn
	header      http.Header
	wroteHeader bool
	closeNotify bool
}

func (w *tlsResponseWriter) Header() http.Header {
	return w.header
}

func (w *tlsResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	statusText := http.StatusText(statusCode)
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", statusCode, statusText)

	if w.header.Get("Connection") == "close" {
		w.closeNotify = true
	}

	for k, vv := range w.header {
		for _, v := range vv {
			fmt.Fprintf(w.conn, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(w.conn, "\r\n")
}

func (w *tlsResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(data)
}
