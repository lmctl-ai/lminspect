package proxy

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
)

// TapAddon logs transited flows to a writer (default stderr) in real-time.
type TapAddon struct {
	Out          io.Writer
	outputMemory outputMemory
	mu           sync.Mutex
}

func NewTapAddon(out io.Writer) *TapAddon {
	if out == nil {
		out = os.Stderr
	}
	return &TapAddon{Out: out}
}

func (t *TapAddon) Name() string { return "tap" }

func (t *TapAddon) OnRequest(flow *HTTPFlow) error {
	return nil
}

func (t *TapAddon) OnResponse(flow *HTTPFlow) error {
	flow.useOutputMemory(&t.outputMemory)
	flow, _ = SanitizeOutput(flow)
	t.mu.Lock()
	defer t.mu.Unlock()

	tag := "HTTP"
	if flow.Request.Scheme == "https" {
		tag = "HTTPS"
	}
	if flow.IsKilled() {
		fmt.Fprintf(t.Out, "[%s:KILL] %s %s (Killed)\n", tag, flow.Request.Method, flow.Request.URL())
		return nil
	}

	status := 0
	if flow.Response != nil {
		status = flow.Response.StatusCode
	}
	size := 0
	if flow.Response != nil {
		size = len(flow.Response.Content)
	}

	fmt.Fprintf(t.Out, "[%s] %s %s -> %d (%d bytes, %d ms)\n",
		tag, flow.Request.Method, flow.Request.URL(), status, size, flow.DurationMs)
	return nil
}

func (t *TapAddon) OnError(flow *HTTPFlow, err error) {
	flow.useOutputMemory(&t.outputMemory)
	flow, messages := SanitizeOutput(flow, err.Error())
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.Out, "[ERROR] %s %s -> %v\n", flow.Request.Method, flow.Request.URL(), messages[0])
}

// RecordAddon appends structured JSON lines for every completed flow.
type RecordAddon struct {
	outputMemory outputMemory
	filePath     string
	file         *os.File
	mu           sync.Mutex
}

func NewRecordAddon(filePath string) (*RecordAddon, error) {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &RecordAddon{
		filePath: filePath,
		file:     f,
	}, nil
}

func (r *RecordAddon) Name() string { return "record" }

func (r *RecordAddon) OnResponse(flow *HTTPFlow) error {
	flow.useOutputMemory(&r.outputMemory)
	data, err := flow.ToJSON()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err = r.file.Write(append(data, '\n'))
	return err
}

func (r *RecordAddon) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// ReplayServerAddon matches incoming requests against pre-recorded flows and serves recorded responses.
type ReplayServerAddon struct {
	flows []*HTTPFlow
	mu    sync.RWMutex
}

func NewReplayServerAddon(filePath string) (*ReplayServerAddon, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var flows []*HTTPFlow
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		flow, err := FlowFromJSON(line)
		if err == nil && flow.Response != nil {
			flows = append(flows, flow)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &ReplayServerAddon{flows: flows}, nil
}

func (r *ReplayServerAddon) Name() string { return "replay-server" }

func (r *ReplayServerAddon) OnRequest(flow *HTTPFlow) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reqPath := flow.Request.Path
	reqMethod := flow.Request.Method

	for _, recorded := range r.flows {
		if recorded.Request.Method == reqMethod && recorded.Request.Path == reqPath {
			// Found match! Serve recorded response
			flow.Response = &Response{
				StatusCode: recorded.Response.StatusCode,
				Reason:     recorded.Response.Reason,
				Headers:    make(map[string][]string),
				Content:    append([]byte(nil), recorded.Response.Content...),
			}
			for k, vv := range recorded.Response.Headers {
				flow.Response.Headers[k] = append([]string(nil), vv...)
			}
			return nil
		}
	}
	return nil
}

// RuleType defines the rule operation.
type RuleType int

const (
	RuleRedirect RuleType = iota
	RuleRoute
	RuleHeader
	RuleMock
)

// Rule represents a traffic manipulation rule.
type Rule struct {
	Type        RuleType
	Pattern     string
	regex       *regexp.Regexp
	Target      string
	HeaderKey   string
	HeaderVal   string
	StatusCode  int
	ContentType string
}

// RuleAddon evaluates configured CLI manipulation rules.
type RuleAddon struct {
	rules []*Rule
	mu    sync.RWMutex
}

func NewRuleAddon() *RuleAddon {
	return &RuleAddon{}
}

func (r *RuleAddon) Name() string { return "rules" }

func (r *RuleAddon) AddRedirect(pattern, targetURL string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	r.rules = append(r.rules, &Rule{
		Type:    RuleRedirect,
		Pattern: pattern,
		regex:   re,
		Target:  targetURL,
	})
	return nil
}

func (r *RuleAddon) AddRoute(pattern, hostPort string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	r.rules = append(r.rules, &Rule{
		Type:    RuleRoute,
		Pattern: pattern,
		regex:   re,
		Target:  hostPort,
	})
	return nil
}

func (r *RuleAddon) AddHeader(pattern, key, val string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	r.rules = append(r.rules, &Rule{
		Type:      RuleHeader,
		Pattern:   pattern,
		regex:     re,
		HeaderKey: key,
		HeaderVal: val,
	})
	return nil
}

func (r *RuleAddon) AddMock(pattern string, statusCode int, body, contentType string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	r.rules = append(r.rules, &Rule{
		Type:        RuleMock,
		Pattern:     pattern,
		regex:       re,
		StatusCode:  statusCode,
		Target:      body,
		ContentType: contentType,
	})
	return nil
}

func (r *RuleAddon) OnRequest(flow *HTTPFlow) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	urlStr := flow.Request.URL()
	pathStr := flow.Request.Path

	for _, rule := range r.rules {
		matched := rule.regex.MatchString(urlStr) || rule.regex.MatchString(pathStr)
		if !matched {
			continue
		}

		switch rule.Type {
		case RuleRedirect:
			flow.Respond(307, "", "")
			flow.Response.SetHeader("Location", rule.Target)
			return nil

		case RuleMock:
			ct := rule.ContentType
			if ct == "" {
				ct = "text/plain"
			}
			flow.Respond(rule.StatusCode, rule.Target, ct)
			return nil

		case RuleRoute:
			target := rule.Target
			if strings.HasPrefix(target, "http://") {
				flow.Request.Scheme = "http"
				target = strings.TrimPrefix(target, "http://")
			} else if strings.HasPrefix(target, "https://") {
				flow.Request.Scheme = "https"
				target = strings.TrimPrefix(target, "https://")
			}
			h, p, err := parseHostPort(target)
			if err == nil {
				flow.Request.Host = h
				if p > 0 {
					flow.Request.Port = p
				}
			}

		case RuleHeader:
			flow.Request.SetHeader(rule.HeaderKey, rule.HeaderVal)
		}
	}
	return nil
}

func (r *RuleAddon) OnResponse(flow *HTTPFlow) error {
	return nil
}
