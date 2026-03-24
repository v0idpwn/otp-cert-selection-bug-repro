#!/usr/bin/env bash
set -euo pipefail

OPENSSL_PORT=14433
ERLANG_PORT=14434

cleanup() {
    [ -n "${OPENSSL_PID:-}" ] && kill "$OPENSSL_PID" 2>/dev/null || true
    [ -n "${ERLANG_PID:-}" ]  && kill "$ERLANG_PID"  2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

echo "--- Generating certificates ---"
escript ssl_gen_test_certs.escript

# --- OpenSSL s_server (reference) ---
openssl s_server \
    -cert test_certs/ecdsa_cert.pem -key test_certs/ecdsa_key.pem \
    -dcert test_certs/rsa_cert.pem  -dkey test_certs/rsa_key.pem \
    -CAfile test_certs/ca.pem \
    -tls1_3 -accept "$OPENSSL_PORT" -www \
    >/dev/null 2>&1 &
OPENSSL_PID=$!
sleep 1

echo ""
echo "--- Client vs OpenSSL s_server (port $OPENSSL_PORT) ---"
escript ssl_test_client.escript localhost "$OPENSSL_PORT" || true

kill "$OPENSSL_PID" 2>/dev/null; wait "$OPENSSL_PID" 2>/dev/null || true
OPENSSL_PID=""

# --- Erlang SSL server ---
escript ssl_erlang_server.escript "$ERLANG_PORT" >/dev/null 2>&1 &
ERLANG_PID=$!
sleep 2

echo ""
echo "--- Client vs Erlang SSL server (port $ERLANG_PORT) ---"
escript ssl_test_client.escript localhost "$ERLANG_PORT" || true
