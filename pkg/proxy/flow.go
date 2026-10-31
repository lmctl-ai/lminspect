package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Request represents an HTTP request within an intercepted flow.
type Request struct {
	Method  string              `json:"method"`
	Scheme  string              `json:"scheme"`
	Host    string              `json:"host"`
	Port    int                 `json:"port"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Content []byte              `json:"content"`
	mu      sync.RWMutex
}

// NewRequest creates a new Request from an http.Request.
func NewRequest(req *http.Request, body []byte) *Request {
	scheme := "http"
	if req.TLS != nil || req.URL.Scheme == "https" {
		scheme = "https"
	}

	host := req.Host
	port := 80
	if scheme == "https" {
		port = 443
	}

	if h, p, err := parseHostPort(req.Host); err == nil {
		host = h
		if p > 0 {
			port = p
		}
	}

	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}

	headers := make(map[string][]string)
	for k, vv := range req.Header {
		headers[k] = append([]string(nil), vv...)
	}

	return &Request{
		Method:  req.Method,
		Scheme:  scheme,
		Host:    host,
		Port:    port,
		Path:    path,
		Headers: headers,
		Content: body,
	}
}

// URL returns the full request URL string.
func (r *Request) URL() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.buildURL()
}

func (r *Request) buildURL() string {
	var hostPort string
	if (r.Scheme == "http" && r.Port == 80) || (r.Scheme == "https" && r.Port == 443) || r.Port == 0 {
		hostPort = r.Host
	} else {
		hostPort = fmt.Sprintf("%s:%d", r.Host, r.Port)
	}
	path := r.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("%s://%s%s", r.Scheme, hostPort, path)
}

// SetURL parses and replaces scheme, host, port, and path from a new URL string.
func (r *Request) SetURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if u.Scheme != "" {
		r.Scheme = strings.ToLower(u.Scheme)
	}
	if u.Host != "" {
		h, p, err := parseHostPort(u.Host)
		if err == nil {
			r.Host = h
			if p > 0 {
				r.Port = p
			} else if r.Scheme == "https" {
				r.Port = 443
			} else {
				r.Port = 80
			}
		}
	}
	r.Path = u.RequestURI()
	if r.Path == "" {
		r.Path = "/"
	}
	return nil
}

// Header returns the first value associated with the given key (case-insensitive).
func (r *Request) Header(key string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for k, vv := range r.Headers {
		if strings.EqualFold(k, key) && len(vv) > 0 {
			return vv[0]
		}
	}
	return ""
}

// SetHeader sets the header entries associated with key to the single element value.
func (r *Request) SetHeader(key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.Headers {
		if strings.EqualFold(k, key) {
			delete(r.Headers, k)
		}
	}
	r.Headers[key] = []string{value}
}

// RemoveHeader deletes all header entries associated with key (case-insensitive).
func (r *Request) RemoveHeader(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.Headers {
		if strings.EqualFold(k, key) {
			delete(r.Headers, k)
		}
	}
}

// HeaderNames returns a sorted list of unique header keys.
func (r *Request) HeaderNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var names []string
	for k := range r.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Query returns the first query parameter associated with the given key.
func (r *Request) Query(key string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, err := url.Parse(r.Path)
	if err != nil {
		return ""
	}
	return u.Query().Get(key)
}

// SetQuery sets the query parameter key to value.
func (r *Request) SetQuery(key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, err := url.Parse(r.Path)
	if err != nil {
		return
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	r.Path = u.RequestURI()
}

// QueryNames returns a sorted list of query parameter names.
func (r *Request) QueryNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, err := url.Parse(r.Path)
	if err != nil {
		return nil
	}
	var names []string
	for k := range u.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Text returns the request body content as a UTF-8 string.
func (r *Request) Text() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return string(r.Content)
}

// SetText sets the request body content from a string and updates Content-Length.
func (r *Request) SetText(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Content = []byte(text)
	r.setHeaderLocked("Content-Length", strconv.Itoa(len(r.Content)))
}

func (r *Request) setHeaderLocked(key, value string) {
	for k := range r.Headers {
		if strings.EqualFold(k, key) {
			delete(r.Headers, k)
		}
	}
	r.Headers[key] = []string{value}
}

// ToHTTPRequest reconstructs an *http.Request suitable for upstream forwarding.
func (r *Request) ToHTTPRequest() (*http.Request, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reqURL, err := url.Parse(r.buildURL())
	if err != nil {
		return nil, err
	}

	var body io.Reader
	if len(r.Content) > 0 {
		body = bytes.NewReader(r.Content)
	}

	req, err := http.NewRequest(r.Method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Host = reqURL.Host
	for k, vv := range r.Headers {
		// Skip hop-by-hop connection headers
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Proxy-Connection") {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	if len(r.Content) > 0 {
		req.ContentLength = int64(len(r.Content))
	}

	return req, nil
}

// Response represents an HTTP response within an intercepted flow.
type Response struct {
	StatusCode int                 `json:"status_code"`
	Reason     string              `json:"reason"`
	Headers    map[string][]string `json:"headers"`
	Content    []byte              `json:"content"`
	mu         sync.RWMutex
}

// NewResponse creates a new Response from an *http.Response.
func NewResponse(resp *http.Response, body []byte) *Response {
	headers := make(map[string][]string)
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		headers[k] = append([]string(nil), vv...)
	}
	headers["Content-Length"] = []string{strconv.Itoa(len(body))}

	return &Response{
		StatusCode: resp.StatusCode,
		Reason:     resp.Status,
		Headers:    headers,
		Content:    body,
	}
}

// MakeResponse creates a synthetic response with the given status code, body, and content type.
func MakeResponse(statusCode int, body string, contentType string) *Response {
	headers := make(map[string][]string)
	if contentType != "" {
		headers["Content-Type"] = []string{contentType}
	}
	headers["Content-Length"] = []string{strconv.Itoa(len(body))}

	return &Response{
		StatusCode: statusCode,
		Reason:     http.StatusText(statusCode),
		Headers:    headers,
		Content:    []byte(body),
	}
}

// Header returns the first value associated with the given key (case-insensitive).
func (resp *Response) Header(key string) string {
	resp.mu.RLock()
	defer resp.mu.RUnlock()
	for k, vv := range resp.Headers {
		if strings.EqualFold(k, key) && len(vv) > 0 {
			return vv[0]
		}
	}
	return ""
}

// SetHeader sets the response header key to value.
func (resp *Response) SetHeader(key, value string) {
	resp.mu.Lock()
	defer resp.mu.Unlock()
	for k := range resp.Headers {
		if strings.EqualFold(k, key) {
			delete(resp.Headers, k)
		}
	}
	resp.Headers[key] = []string{value}
}

// RemoveHeader removes the response header key (case-insensitive).
func (resp *Response) RemoveHeader(key string) {
	resp.mu.Lock()
	defer resp.mu.Unlock()
	for k := range resp.Headers {
		if strings.EqualFold(k, key) {
			delete(resp.Headers, k)
		}
	}
}

// HeaderNames returns a sorted list of unique response header names.
func (resp *Response) HeaderNames() []string {
	resp.mu.RLock()
	defer resp.mu.RUnlock()
	var names []string
	for k := range resp.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Text returns the response body content as a UTF-8 string.
func (resp *Response) Text() string {
	resp.mu.RLock()
	defer resp.mu.RUnlock()
	return string(resp.Content)
}

// SetText sets the response body content from a string and updates Content-Length.
func (resp *Response) SetText(text string) {
	resp.mu.Lock()
	defer resp.mu.Unlock()
	resp.Content = []byte(text)
	for k := range resp.Headers {
		if strings.EqualFold(k, "Content-Length") {
			delete(resp.Headers, k)
		}
	}
	resp.Headers["Content-Length"] = []string{strconv.Itoa(len(resp.Content))}
}

// HTTPFlow encapsulates a full HTTP request/response exchange along with metadata.
type HTTPFlow struct {
	ID          string    `json:"id"`
	Request     *Request  `json:"request"`
	Response    *Response `json:"response,omitempty"`
	Error       string    `json:"error,omitempty"`
	Intercepted bool      `json:"intercepted"`
	Killed      bool      `json:"killed"`
	Marked      bool      `json:"marked"`
	Timestamp   int64     `json:"timestamp"`
	DurationMs  int64     `json:"duration_ms"`
	ClientAddr  string    `json:"client_addr"`
	ServerAddr  string    `json:"server_addr"`
	mu          sync.RWMutex
}

// NewFlow creates a new HTTPFlow initialized with a unique ID and timestamp.
func NewFlow(req *Request, clientAddr string) *HTTPFlow {
	return &HTTPFlow{
		ID:         generateFlowID(),
		Request:    req,
		Timestamp:  time.Now().UnixMilli(),
		ClientAddr: clientAddr,
	}
}

// Intercept marks the flow as intercepted.
func (f *HTTPFlow) Intercept() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Intercepted = true
}

// Resume clears the intercepted state of the flow.
func (f *HTTPFlow) Resume() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Intercepted = false
}

// Kill terminates the flow, preventing it from forwarding or returning responses.
func (f *HTTPFlow) Kill() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Killed = true
}

// IsKilled returns whether the flow was killed.
func (f *HTTPFlow) IsKilled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Killed
}

// IsIntercepted returns whether the flow is currently intercepted.
func (f *HTTPFlow) IsIntercepted() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Intercepted
}

// Respond attaches an immediate synthetic response to the flow.
func (f *HTTPFlow) Respond(statusCode int, body string, contentType string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Response = MakeResponse(statusCode, body, contentType)
}

// ToJSON serializes the flow into JSON bytes.
func (f *HTTPFlow) ToJSON() ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return json.Marshal(f)
}

// FlowFromJSON deserializes a flow from JSON bytes.
func FlowFromJSON(data []byte) (*HTTPFlow, error) {
	var f HTTPFlow
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func generateFlowID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func parseHostPort(hostPort string) (string, int, error) {
	colon := strings.LastIndex(hostPort, ":")
	if colon == -1 {
		return hostPort, 0, nil
	}
	port, err := strconv.Atoi(hostPort[colon+1:])
	if err != nil {
		return hostPort, 0, nil
	}
	return hostPort[:colon], port, nil
}
