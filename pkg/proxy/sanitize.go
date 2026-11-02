package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Matches lmmock/internal/scenario's idempotent credential marker (17db1c3).
const RedactedCredential = "<redacted:credential>"

var bearerPattern = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]+)`)
var vendorPattern = regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
var assignmentPattern = regexp.MustCompile(`([A-Za-z0-9_.%/-]+)["']?\s*[:=]\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s&;,}\r\n]+))`)
var encodedPattern = regexp.MustCompile(`[A-Za-z0-9+/_=-]{12,}`)
var urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)

func fieldName(s string) string {
	for {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	var b strings.Builder
	var prev rune
	for _, r := range s {
		if unicode.IsUpper(r) && unicode.IsLower(prev) {
			b.WriteByte('-')
		}
		if r == '_' {
			r = '-'
		}
		b.WriteRune(unicode.ToLower(r))
		prev = r
	}
	return b.String()
}
func credentialField(s string) bool {
	if markerForms[s] {
		return false
	}
	k := fieldName(s)
	compact := strings.ReplaceAll(k, "-", "")
	return k == "sig" || k == "signature" || strings.HasSuffix(k, "-signature") || k == "csrf" || strings.HasSuffix(k, "-csrf") || k == "xsrf" || strings.HasSuffix(k, "-xsrf") || k == "sid" || k == "key" || strings.HasSuffix(compact, "apikey") || k == "auth" || k == "x-auth" || k == "session-key" || k == "signing-key" || k == "token" || strings.HasSuffix(k, "-token") || strings.HasSuffix(k, "-api-key") || strings.Contains(k, "password") || strings.Contains(k, "passwd") || k == "pwd" || strings.Contains(k, "secret") || strings.Contains(k, "private-key") || strings.Contains(k, "access-key") || strings.Contains(k, "credential") || k == "authorization" || k == "proxy-authorization" || k == "authentication" || k == "cookie" || k == "set-cookie"
}
func authLike(s string) bool {
	k := fieldName(s)
	if k == "tokenizer" || k == "tokens" || k == "input-tokens" || k == "output-tokens" || k == "total-tokens" || k == "max-tokens" || k == "token-count" {
		return false
	}
	return strings.Contains(k, "auth") || strings.Contains(k, "token") || strings.Contains(k, "session") || strings.Contains(k, "key") || strings.Contains(k, "signatur")
}
func highEntropy(s string) bool {
	if len(s) < 16 {
		return false
	}
	counts := map[rune]int{}
	for _, c := range s {
		counts[c]++
	}
	var entropy float64
	for _, n := range counts {
		p := float64(n) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy >= 3.2
}
func sensitiveValue(k, v string) bool { return credentialField(k) || (authLike(k) && highEntropy(v)) }

// Credential memory belongs to an observation pipeline, never to disk or a
// process-wide global. Later flows can safely redact earlier credential echoes.
type outputMemory struct {
	sync.Mutex
	secrets map[string]bool
}

func (f *HTTPFlow) useOutputMemory(memory *outputMemory) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outputMemory == nil {
		f.outputMemory = memory
	}
}

type outputSanitizer struct{ secrets map[string]bool }

func (n *outputSanitizer) add(s string) {
	if s == "" || markerForms[s] {
		return
	}
	n.secrets[s] = true
}
func (n *outputSanitizer) learnValue(v string) {
	n.add(v)
	if scheme, rest, ok := strings.Cut(v, " "); ok && (strings.EqualFold(scheme, "Bearer") || strings.EqualFold(scheme, "Basic")) {
		n.add(strings.TrimSpace(rest))
	}
	if trimmed := strings.Trim(v, `"'.,;)]}`); trimmed != v {
		n.add(trimmed)
	}
	if decoded, e := url.QueryUnescape(v); e == nil && decoded != v {
		n.learnValue(decoded)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := enc.DecodeString(v); e == nil && len(b) < len(v) && utf8.Valid(b) {
			n.learnValue(string(b))
		}
	}
	for _, m := range bearerPattern.FindAllStringSubmatch(v, -1) {
		n.add(m[1])
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, e := enc.DecodeString(m[1]); e == nil {
				n.add(string(b))
				if a, b, ok := strings.Cut(string(b), ":"); ok {
					n.add(a)
					n.add(b)
				}
			}
		}
	}
	for _, p := range strings.Split(v, ";") {
		if _, value, ok := strings.Cut(p, "="); ok {
			n.add(strings.TrimSpace(value))
		}
	}
}
func (n *outputSanitizer) variants() []string {
	all := map[string]bool{}
	for s := range n.secrets {
		all[s] = true
		all[url.QueryEscape(s)] = true
		all[url.PathEscape(s)] = true
		var upper, lower, unicodeEsc strings.Builder
		for _, c := range []byte(s) {
			const hex = "0123456789ABCDEF"
			upper.WriteByte('%')
			upper.WriteByte(hex[c>>4])
			upper.WriteByte(hex[c&15])
		}
		lower.WriteString(strings.ToLower(upper.String()))
		all[upper.String()] = true
		all[lower.String()] = true
		for _, c := range s {
			if c <= 0xffff {
				unicodeEsc.WriteString("\\u" + strings.Repeat("0", 4-len(strconv.FormatInt(int64(c), 16))) + strconv.FormatInt(int64(c), 16))
			} else {
				unicodeEsc.Reset()
				break
			}
		}
		if unicodeEsc.Len() > 0 {
			all[unicodeEsc.String()] = true
		}
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			all[enc.EncodeToString([]byte(s))] = true
		}
	}
	out := make([]string, 0, len(all))
	for s := range all {
		if s != "" {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) == len(out[j]) {
			return out[i] < out[j]
		}
		return len(out[i]) > len(out[j])
	})
	return out
}

// Protect reserved markers even when a username or short credential is a
// substring of the marker. Encoded markers must remain stable on re-import too.
var markerForms = func() map[string]bool {
	n := &outputSanitizer{secrets: map[string]bool{RedactedCredential: true, "<redacted:secret>": true}}
	out := map[string]bool{}
	for _, s := range n.variants() {
		out[s] = true
	}
	return out
}()
var protectedMarkers = func() *regexp.Regexp {
	forms := make([]string, 0, len(markerForms))
	for s := range markerForms {
		forms = append(forms, regexp.QuoteMeta(s))
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return regexp.MustCompile(strings.Join(forms, "|"))
}()

func replaceOutsideMarkers(s, secret string) string {
	var out strings.Builder
	at := 0
	for _, span := range protectedMarkers.FindAllStringIndex(s, -1) {
		out.WriteString(strings.ReplaceAll(s[at:span[0]], secret, RedactedCredential))
		out.WriteString(s[span[0]:span[1]])
		at = span[1]
	}
	out.WriteString(strings.ReplaceAll(s[at:], secret, RedactedCredential))
	return out.String()
}
func (n *outputSanitizer) discoverText(s string) {
	if decoded, e := url.QueryUnescape(s); e == nil && decoded != s {
		n.discoverText(decoded)
	}
	for _, token := range encodedPattern.FindAllString(s, -1) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, e := enc.DecodeString(token); e == nil && len(b) < len(token) && utf8.Valid(b) {
				n.discoverText(string(b))
			}
		}
	}
	for _, u := range urlPattern.FindAllString(s, -1) {
		_ = n.cleanURL(u)
	}
	for _, m := range bearerPattern.FindAllStringSubmatch(s, -1) {
		n.learnValue(m[0])
	}
	for _, m := range vendorPattern.FindAllString(s, -1) {
		n.add(m)
	}
	for _, m := range assignmentPattern.FindAllStringSubmatch(s, -1) {
		v := m[2]
		if v == "" {
			v = m[3]
		}
		if v == "" {
			v = m[4]
		}
		key, _ := url.QueryUnescape(m[1])
		if sensitiveValue(key, v) {
			n.learnValue(v)
		}
	}
}
func decodeTree(b []byte) (any, bool) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return nil, false
	}
	var extra any
	return v, d.Decode(&extra) == io.EOF
}
func (n *outputSanitizer) discoverTree(v any, named bool) {
	switch x := v.(type) {
	case string:
		if named {
			n.learnValue(x)
		}
		n.discoverText(x)
	case []any:
		for _, e := range x {
			n.discoverTree(e, named)
		}
	case map[string]any:
		for k, v := range x {
			sv, _ := v.(string)
			n.discoverTree(v, named || sensitiveValue(k, sv))
		}
	}
}
func (n *outputSanitizer) text(s string) string {
	n.discoverText(s)
	for _, v := range n.variants() {
		s = replaceOutsideMarkers(s, v)
	}
	s = vendorPattern.ReplaceAllString(s, RedactedCredential)
	// Decode enclosing encodings, sanitize, then retain the encoding rather than
	// emitting the original opaque blob. Each recursive input is strictly shorter.
	if d, e := url.QueryUnescape(s); e == nil && d != s {
		if clean := n.text(d); clean != d {
			s = url.QueryEscape(clean)
		}
	}
	s = encodedPattern.ReplaceAllStringFunc(s, func(token string) string {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, e := enc.DecodeString(token); e == nil && len(b) < len(token) && utf8.Valid(b) {
				if clean := n.text(string(b)); clean != string(b) {
					return enc.EncodeToString([]byte(clean))
				}
			}
		}
		return token
	})
	s = urlPattern.ReplaceAllStringFunc(s, n.cleanURL)
	return s
}
func (n *outputSanitizer) cleanURL(s string) string {
	u, e := url.Parse(s)
	if e != nil {
		return RedactedCredential
	}
	if u.User != nil {
		n.add(u.User.Username())
		if p, ok := u.User.Password(); ok {
			n.add(p)
		}
		u.User = nil
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		u.RawQuery = "redacted=" + url.QueryEscape(RedactedCredential)
	} else {
		changed := false
		cleanQuery := url.Values{}
		for k, vs := range q {
			cleanKey := n.text(k)
			changed = changed || cleanKey != k
			for i, v := range vs {
				clean := v
				if sensitiveValue(k, v) {
					n.learnValue(v)
					clean = RedactedCredential
				} else {
					clean = n.text(v)
				}
				changed = changed || clean != v
				vs[i] = clean
			}
			cleanQuery[cleanKey] = append(cleanQuery[cleanKey], vs...)
		}
		if changed {
			u.RawQuery = cleanQuery.Encode()
		}
	}
	path := n.text(u.Path)
	if path != u.Path {
		u.Path = path
		u.RawPath = ""
	}
	fragment := n.text(u.Fragment)
	if fragment != u.Fragment {
		u.Fragment = fragment
		u.RawFragment = ""
	}
	u.Host = n.text(u.Host)
	u.Opaque = n.text(u.Opaque)
	return u.String()
}
func (n *outputSanitizer) tree(v any, named bool) any {
	switch x := v.(type) {
	case string:
		if named {
			return RedactedCredential
		}
		return n.text(x)
	case json.Number:
		if named {
			return json.Number("0")
		}
	case bool:
		if named {
			return false
		}
	case []any:
		for i, e := range x {
			x[i] = n.tree(e, named)
		}
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			sv, _ := v.(string)
			out[n.text(k)] = n.tree(v, named || sensitiveValue(k, sv))
		}
		return out
	}
	return v
}
func getHeader(h map[string][]string, k string) string {
	for key, vs := range h {
		if strings.EqualFold(k, key) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}
func deleteHeader(h map[string][]string, k string) {
	for key := range h {
		if strings.EqualFold(k, key) {
			delete(h, key)
		}
	}
}
func decodeContent(b []byte, h map[string][]string) []byte {
	encoding := strings.ToLower(strings.TrimSpace(getHeader(h, "Content-Encoding")))
	if encoding == "" || encoding == "identity" {
		return b
	}
	var r io.ReadCloser
	var e error
	switch encoding {
	case "gzip":
		r, e = gzip.NewReader(bytes.NewReader(b))
	case "deflate":
		r, e = zlib.NewReader(bytes.NewReader(b))
	default:
		e = io.ErrUnexpectedEOF
	}
	deleteHeader(h, "Content-Encoding")
	if e != nil {
		return []byte(RedactedCredential)
	}
	defer r.Close()
	plain, e := io.ReadAll(r)
	if e != nil {
		return []byte(RedactedCredential)
	}
	return plain
}

type ssePart struct {
	prefix, ending, plain string
	tree                  any
	json                  bool
}

func parseSSE(b []byte) []ssePart {
	var parts []ssePart
	for _, line := range strings.SplitAfter(string(b), "\n") {
		p := ssePart{plain: line}
		if strings.HasPrefix(line, "data:") {
			p.prefix = "data:"
			p.plain = strings.TrimPrefix(line, p.prefix)
			if strings.HasPrefix(p.plain, " ") {
				p.prefix += " "
				p.plain = p.plain[1:]
			}
			if strings.HasSuffix(p.plain, "\r\n") {
				p.ending = "\r\n"
			} else if strings.HasSuffix(p.plain, "\n") {
				p.ending = "\n"
			}
			p.plain = strings.TrimSuffix(p.plain, p.ending)
			p.tree, p.json = decodeTree([]byte(p.plain))
		}
		parts = append(parts, p)
	}
	return parts
}

type textRef struct {
	text string
	set  func(string)
}

func contentRefs(v any, refs *[]textRef) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "type" || k == "id" || k == "model" || k == "role" || k == "event" || k == "object" {
				continue
			}
			if s, ok := x[k].(string); ok {
				*refs = append(*refs, textRef{s, func(v string) { x[k] = v }})
			} else {
				contentRefs(x[k], refs)
			}
		}
	case []any:
		for i, v := range x {
			if s, ok := v.(string); ok {
				*refs = append(*refs, textRef{s, func(v string) { x[i] = v }})
			} else {
				contentRefs(v, refs)
			}
		}
	}
}
func (n *outputSanitizer) redactAcross(refs []textRef) {
	var joined strings.Builder
	for _, r := range refs {
		joined.WriteString(r.text)
	}
	_ = n.text(joined.String())
	for _, secret := range n.variants() {
		joined.Reset()
		for _, r := range refs {
			joined.WriteString(r.text)
		}
		whole := joined.String()
		var starts []int
		for at := 0; at < len(whole); {
			i := strings.Index(whole[at:], secret)
			if i < 0 {
				break
			}
			protected := false
			for _, span := range protectedMarkers.FindAllStringIndex(whole, -1) {
				if at+i < span[1] && at+i+len(secret) > span[0] {
					protected = true
					break
				}
			}
			if !protected {
				starts = append(starts, at+i)
			}
			at += i + len(secret)
		}
		offset := 0
		for i := range refs {
			s := refs[i].text
			end := offset + len(s)
			for j := len(starts) - 1; j >= 0; j-- {
				lo, hi := starts[j], starts[j]+len(secret)
				if lo < offset {
					lo = offset
				}
				if hi > end {
					hi = end
				}
				if lo < hi {
					s = s[:lo-offset] + RedactedCredential + s[hi-offset:]
				}
			}
			offset = end
			refs[i].text = s
			refs[i].set(s)
		}
	}
}
func (n *outputSanitizer) body(b []byte, h map[string][]string) []byte {
	if len(b) == 0 {
		return b
	}
	if !utf8.Valid(b) {
		return []byte(RedactedCredential)
	}
	ct := strings.ToLower(getHeader(h, "Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		parts := parseSSE(b)
		var refs []textRef
		for i := range parts {
			p := &parts[i]
			if p.json {
				n.discoverTree(p.tree, false)
				contentRefs(p.tree, &refs)
			} else if p.prefix != "" && p.plain != "[DONE]" {
				refs = append(refs, textRef{p.plain, func(s string) { p.plain = s }})
			}
		}
		n.redactAcross(refs)
		var out strings.Builder
		for _, p := range parts {
			if p.json {
				clean, _ := json.Marshal(n.tree(p.tree, false))
				p.plain = string(clean)
			} else if p.plain != "[DONE]" {
				p.plain = n.text(p.plain)
			}
			out.WriteString(p.prefix + p.plain + p.ending)
		}
		return []byte(out.String())
	}
	if tree, ok := decodeTree(b); ok {
		n.discoverTree(tree, false)
		out, _ := json.Marshal(n.tree(tree, false))
		return out
	}
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		q, e := url.ParseQuery(string(b))
		if e != nil {
			return []byte(RedactedCredential)
		}
		for k, vs := range q {
			for _, v := range vs {
				if sensitiveValue(k, v) {
					n.learnValue(v)
				}
			}
		}
		for k, vs := range q {
			for i, v := range vs {
				if sensitiveValue(k, v) {
					vs[i] = RedactedCredential
				} else {
					vs[i] = n.text(v)
				}
			}
		}
		return []byte(q.Encode())
	}
	return []byte(n.text(string(b)))
}

// SanitizeOutput is the sole credential policy boundary for exported flow copies
// and free-form output. It never mutates the flow used for network forwarding.
func SanitizeOutput(flow *HTTPFlow, extra ...string) (*HTTPFlow, []string) {
	n := &outputSanitizer{secrets: map[string]bool{}}
	if flow != nil {
		flow.mu.RLock()
		memory := flow.outputMemory
		flow.mu.RUnlock()
		if memory != nil {
			memory.Lock()
			defer memory.Unlock()
			if memory.secrets == nil {
				memory.secrets = map[string]bool{}
			}
			n.secrets = memory.secrets
		}
	}
	for _, entry := range os.Environ() {
		k, v, _ := strings.Cut(entry, "=")
		if sensitiveValue(k, v) {
			n.learnValue(v)
		}
		n.discoverText(v)
	}
	f := &HTTPFlow{}
	if flow != nil {
		flow.mu.RLock()
		f.ID = flow.ID
		f.Error = flow.Error
		f.Intercepted = flow.Intercepted
		f.Killed = flow.Killed
		f.Marked = flow.Marked
		f.Timestamp = flow.Timestamp
		f.DurationMs = flow.DurationMs
		f.ClientAddr = flow.ClientAddr
		f.ServerAddr = flow.ServerAddr
		if r := flow.Request; r != nil {
			r.mu.RLock()
			f.Request = &Request{Method: r.Method, Scheme: r.Scheme, Host: r.Host, Port: r.Port, Path: r.Path, Headers: cloneHeaders(r.Headers), Content: append([]byte(nil), r.Content...)}
			r.mu.RUnlock()
		}
		if r := flow.Response; r != nil {
			r.mu.RLock()
			f.Response = &Response{StatusCode: r.StatusCode, Reason: r.Reason, Headers: cloneHeaders(r.Headers), Content: append([]byte(nil), r.Content...)}
			r.mu.RUnlock()
		}
		flow.mu.RUnlock()
	}
	// Discover both directions first, then scrub echoes in either direction.
	if f.Request != nil {
		if at := strings.LastIndex(f.Request.Host, "@"); at >= 0 {
			info := f.Request.Host[:at]
			if decoded, e := url.QueryUnescape(info); e == nil {
				info = decoded
			}
			n.learnValue(info)
			if user, password, ok := strings.Cut(info, ":"); ok {
				n.learnValue(user)
				n.learnValue(password)
			}
			f.Request.Host = f.Request.Host[at+1:]
		}
	}
	var bodies []*[]byte
	var headers []map[string][]string
	if f.Request != nil {
		bodies = append(bodies, &f.Request.Content)
		headers = append(headers, f.Request.Headers)
		_ = n.cleanURL(f.Request.Path)
	}
	if f.Response != nil {
		bodies = append(bodies, &f.Response.Content)
		headers = append(headers, f.Response.Headers)
	}
	for i, h := range headers {
		*bodies[i] = decodeContent(*bodies[i], h)
		for k, vs := range h {
			for _, v := range vs {
				if sensitiveValue(k, v) {
					n.learnValue(v)
				}
				_ = n.text(v)
			}
		}
		if tree, ok := decodeTree(*bodies[i]); ok {
			n.discoverTree(tree, false)
		} else {
			_ = n.body(*bodies[i], h)
		}
	}
	for i, h := range headers {
		*bodies[i] = n.body(*bodies[i], h)
		clean := map[string][]string{}
		for k, vs := range h {
			out := make([]string, len(vs))
			for j, v := range vs {
				if sensitiveValue(k, v) {
					out[j] = RedactedCredential
				} else {
					out[j] = n.text(v)
				}
			}
			clean[n.text(k)] = out
		}
		deleteHeader(clean, "Content-Length")
		clean["Content-Length"] = []string{strconv.Itoa(len(*bodies[i]))}
		if i == 0 && f.Request != nil {
			f.Request.Headers = clean
		} else if f.Response != nil {
			f.Response.Headers = clean
		}
	}
	if f.Request != nil {
		r := f.Request
		r.Method = n.text(r.Method)
		r.Scheme = n.text(r.Scheme)
		r.Host = n.text(r.Host)
		r.Path = n.cleanURL(r.Path)
	}
	if f.Response != nil {
		f.Response.Reason = n.text(f.Response.Reason)
	}
	f.ID = n.text(f.ID)
	f.Error = n.text(f.Error)
	f.ClientAddr = n.text(f.ClientAddr)
	f.ServerAddr = n.text(f.ServerAddr)
	out := make([]string, len(extra))
	for i, s := range extra {
		out[i] = n.text(s)
	}
	return f, out
}
func cloneHeaders(h map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// MarshalJSON also protects callers that bypass ToJSON and marshal a flow directly.
func (f *HTTPFlow) MarshalJSON() ([]byte, error) {
	clean, _ := SanitizeOutput(f)
	type wireFlow HTTPFlow
	return json.Marshal((*wireFlow)(clean))
}
