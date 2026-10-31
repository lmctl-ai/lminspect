#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

echo "=== 1. Running Go Unit Tests ==="
export CGO_ENABLED=0
export PATH="${ROOT_DIR}/bin:${PATH}"

go test -v ./...

echo "=== 2. Building lminspect Static Binary ==="
mkdir -p "${ROOT_DIR}/bin" "${ROOT_DIR}/build"
go build -trimpath -ldflags="-s -w" -o "${ROOT_DIR}/bin/lminspect" main.go

echo "=== 3. Testing CLI Standard Flags ==="
"${ROOT_DIR}/bin/lminspect" --version
"${ROOT_DIR}/bin/lminspect" --dsl-signatures | grep -q "method Flow.respond"
"${ROOT_DIR}/bin/lminspect" --dsl-schema | grep -q '"name": "lminspect"'
echo "CLI flag tests passed."

echo "=== 4. Compiling Ported Mitmproxy Examples (lmscript -> dslb) ==="
EXAMPLES=(
    "add-header"
    "redirect-requests"
    "custom-response"
    "modify-response-body"
    "modify-querystring"
    "filter-flows"
    "dump-flows"
    "replay-flow"
)

for ex in "${EXAMPLES[@]}"; do
    echo "Compiling examples/${ex}.lms -> build/${ex}.dslb..."
    lmscript "examples/${ex}.lms" "build/${ex}.dslb"
    echo "Running standalone verification for build/${ex}.dslb..."
    "${ROOT_DIR}/bin/lminspect" --dsl "build/${ex}.dslb"
done
echo "All 8 Mitmproxy examples compiled and verified."

echo "=== 5. Testing Certgen Command ==="
CA_CERT="${ROOT_DIR}/build/ca.crt"
CA_KEY="${ROOT_DIR}/build/ca.key"
rm -f "${CA_CERT}" "${CA_KEY}"
"${ROOT_DIR}/bin/lminspect" certgen --cert "${CA_CERT}" --key "${CA_KEY}"
openssl x509 -in "${CA_CERT}" -text -noout | grep -q "lminspect Root CA"
echo "Certgen verified."

echo "=== 6. Live E2E Integration: HTTP Proxy & DSL Addon ==="
# Start upstream HTTP test server
UPSTREAM_HTTP_PORT=19081
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'HELLO_HTTP_UPSTREAM')

server = HTTPServer(('127.0.0.1', ${UPSTREAM_HTTP_PORT}), Handler)
server.serve_forever()
" &
HTTP_PID=$!
trap "kill -9 ${HTTP_PID} 2>/dev/null || true" EXIT

sleep 0.5

PROXY_HTTP_PORT=18081
RECORD_FILE="${ROOT_DIR}/build/flows.jsonl"
rm -f "${RECORD_FILE}"

"${ROOT_DIR}/bin/lminspect" run \
    --listen "127.0.0.1:${PROXY_HTTP_PORT}" \
    --script "${ROOT_DIR}/build/add-header.dslb" \
    --record "${RECORD_FILE}" \
    --tap &
PROXY_HTTP_PID=$!

sleep 0.8

# Test 1: Forward HTTP traffic through proxy and verify DSL injected header
HTTP_RES=$(curl -sSi -x "http://127.0.0.1:${PROXY_HTTP_PORT}" "http://127.0.0.1:${UPSTREAM_HTTP_PORT}/api/test")
echo "${HTTP_RES}" | grep -q "HELLO_HTTP_UPSTREAM"
echo "${HTTP_RES}" | grep -qi "X-Powered-By: lminspect"
echo "HTTP forward proxy with DSL addon verified."

kill -TERM ${PROXY_HTTP_PID} 2>/dev/null || true
kill -TERM ${HTTP_PID} 2>/dev/null || true
wait ${PROXY_HTTP_PID} 2>/dev/null || true
wait ${HTTP_PID} 2>/dev/null || true

echo "=== 7. Live E2E Integration: HTTPS SSL-Bump MITM & DSL Addon ==="
# Generate upstream TLS cert
UPSTREAM_KEY="${ROOT_DIR}/build/upstream.key"
UPSTREAM_CRT="${ROOT_DIR}/build/upstream.crt"
openssl req -x509 -newkey rsa:2048 -keyout "${UPSTREAM_KEY}" -out "${UPSTREAM_CRT}" -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

UPSTREAM_HTTPS_PORT=19443
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'HELLO_HTTPS_SECURE')

httpd = HTTPServer(('127.0.0.1', ${UPSTREAM_HTTPS_PORT}), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('${UPSTREAM_CRT}', '${UPSTREAM_KEY}')
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
" &
HTTPS_PID=$!
trap "kill -9 ${HTTPS_PID} 2>/dev/null || true" EXIT

sleep 0.5

PROXY_HTTPS_PORT=18443
"${ROOT_DIR}/bin/lminspect" run \
    --listen "127.0.0.1:${PROXY_HTTPS_PORT}" \
    --ssl-bump \
    --ca-cert "${CA_CERT}" \
    --ca-key "${CA_KEY}" \
    --script "${ROOT_DIR}/build/add-header.dslb" &
PROXY_HTTPS_PID=$!

sleep 0.8

# Test 2: Decrypt HTTPS traffic and verify injected header
HTTPS_RES=$(curl -sSi -x "http://127.0.0.1:${PROXY_HTTPS_PORT}" --cacert "${CA_CERT}" "https://127.0.0.1:${UPSTREAM_HTTPS_PORT}/secure-endpoint")
echo "${HTTPS_RES}" | grep -q "HELLO_HTTPS_SECURE"
echo "${HTTPS_RES}" | grep -qi "X-Powered-By: lminspect"
echo "HTTPS SSL-Bump MITM with DSL addon verified."

kill -TERM ${PROXY_HTTPS_PID} 2>/dev/null || true
kill -TERM ${HTTPS_PID} 2>/dev/null || true
wait ${PROXY_HTTPS_PID} 2>/dev/null || true
wait ${HTTPS_PID} 2>/dev/null || true

echo "=== 8. Testing Replay Command ==="
test -s "${RECORD_FILE}"
# Start target server for replay
REPLAY_TARGET_PORT=19082
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'REPLAY_TARGET_ACK')

server = HTTPServer(('127.0.0.1', ${REPLAY_TARGET_PORT}), Handler)
server.serve_forever()
" &
REPLAY_PID=$!
trap "kill -TERM ${REPLAY_PID} 2>/dev/null || true; wait ${REPLAY_PID} 2>/dev/null || true" EXIT

sleep 0.5

"${ROOT_DIR}/bin/lminspect" replay --client "${RECORD_FILE}" --target "127.0.0.1:${REPLAY_TARGET_PORT}"
kill -TERM ${REPLAY_PID} 2>/dev/null || true
wait ${REPLAY_PID} 2>/dev/null || true

trap - EXIT

echo ""
echo "================================================="
echo "  ALL LMINSPECT TESTS PASSED SUCCESSFULLY!       "
echo "================================================="
