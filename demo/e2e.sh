#!/usr/bin/env bash
# End-to-end demo: serve sites/example over NXP/TCP and fetch it back.
#
# Usage (from the repo root, after building):
#   cargo build -p nexus-server -p nexus-browser
#   ./demo/e2e.sh
#
# The script starts nexus-server on a free loopback port, fetches the
# `home` and `about` pages with nexus-browser (both must succeed and
# render expected text), then fetches a missing page (must fail with a
# 404). It then restarts the server with a fresh site key and checks the
# signed flow: verified fetch with the right pin, refusal with the wrong
# pin, and a full `nexus sync` mirror. Finally it stops the server. Any
# unexpected result exits nonzero.

set -u

# Always operate from the repo root regardless of where we are invoked.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SERVER_BIN="./target/debug/nexus-server"
BROWSER_BIN="./target/debug/nexus-browser"
NEXUS_BIN="./target/debug/nexus"
SITE_DIR="sites/example"
SITE="example"

fail() {
    echo "e2e: FAIL: $*" >&2
    exit 1
}

pass() {
    echo "e2e: ok: $*"
}

# --- prereqs ---------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || fail "python3 is required (free-port selection)"
[[ -x "$SERVER_BIN" ]] || fail "missing $SERVER_BIN (run: cargo build -p nexus-server -p nexus-browser)"
[[ -x "$BROWSER_BIN" ]] || fail "missing $BROWSER_BIN (run: cargo build -p nexus-server -p nexus-browser)"
[[ -x "$NEXUS_BIN" ]] || fail "missing $NEXUS_BIN (run: cargo build -p nexus-server -p nexus-browser)"
[[ -d "$SITE_DIR" ]] || fail "missing $SITE_DIR (run from the repo root)"

# --- free port -------------------------------------------------------------
PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
[[ "$PORT" =~ ^[0-9]+$ ]] || fail "could not pick a free port"
ENDPOINT="127.0.0.1:$PORT"

# --- start server ----------------------------------------------------------
SERVER_LOG="$(mktemp -t nexus-e2e-server.XXXXXX.log)"
"$SERVER_BIN" --port "$PORT" --site "$SITE" --dir "$SITE_DIR" 2>"$SERVER_LOG" &
SERVER_PID=$!

cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    rm -f "$SERVER_LOG"
}
trap cleanup EXIT

# Wait until the server accepts a fetch (or time out).
READY=0
for _ in $(seq 1 50); do
    if "$BROWSER_BIN" --server "$ENDPOINT" --site "$SITE" --path home >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.1
done
[[ "$READY" -eq 1 ]] || { cat "$SERVER_LOG" >&2; fail "server did not become ready on $ENDPOINT"; }
pass "server up on $ENDPOINT (pid $SERVER_PID)"

# --- home page -------------------------------------------------------------
HOME_OUT="$("$BROWSER_BIN" --server "$ENDPOINT" --site "$SITE" --path home 2>/dev/null)" \
    || fail "fetch $SITE/home exited $?"
[[ "$HOME_OUT" == *"Hello, Nexus"* ]] || fail "$SITE/home did not render 'Hello, Nexus'"
pass "$SITE/home renders"

# --- about page ------------------------------------------------------------
ABOUT_OUT="$("$BROWSER_BIN" --server "$ENDPOINT" --site "$SITE" --path about 2>/dev/null)" \
    || fail "fetch $SITE/about exited $?"
[[ "$ABOUT_OUT" == *"What is Nexus?"* ]] || fail "$SITE/about did not render 'What is Nexus?'"
pass "$SITE/about renders"

# --- missing page (expect 404) ---------------------------------------------
MISSING_ERR="$(mktemp -t nexus-e2e-missing.XXXXXX.log)"
if "$BROWSER_BIN" --server "$ENDPOINT" --site "$SITE" --path does-not-exist >/dev/null 2>"$MISSING_ERR"; then
    rm -f "$MISSING_ERR"
    fail "fetch $SITE/does-not-exist unexpectedly succeeded (expected 404)"
fi
grep -q "404" "$MISSING_ERR" || { cat "$MISSING_ERR" >&2; rm -f "$MISSING_ERR"; fail "missing page error did not mention 404"; }
rm -f "$MISSING_ERR"
pass "$SITE/does-not-exist fails with 404 as expected"

echo "e2e: PASS: home + about render, missing page 404s"

# --- signed flow ---------------------------------------------------------
# Restart with a fresh site key; the unsigned server above stays down via
# cleanup ordering (kill first so the port is free to reuse).
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
KEY_FILE="$(mktemp -t nexus-e2e-key.XXXXXX)"
rm -f "$KEY_FILE"
"$SERVER_BIN" --port "$PORT" --site "$SITE" --dir "$SITE_DIR" --key "$KEY_FILE" 2>"$SERVER_LOG" &
SERVER_PID=$!

READY=0
for _ in $(seq 1 50); do
    if "$BROWSER_BIN" --server "$ENDPOINT" --site "$SITE" --path home >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.1
done
[[ "$READY" -eq 1 ]] || { cat "$SERVER_LOG" >&2; fail "signed server did not become ready"; }
SITE_ID="$(grep -a -o -m1 "site identity: [0-9a-f]*" "$SERVER_LOG" | awk '{print $3}')"
[[ "$SITE_ID" =~ ^[0-9a-f]{64}$ ]] || { cat "$SERVER_LOG" >&2; fail "could not read site identity"; }
pass "signed server up, site identity $SITE_ID"
rm -f "$KEY_FILE"

# Verified fetch with the right pin renders.
PINNED_OUT="$("$BROWSER_BIN" --server "$ENDPOINT" --site "$SITE" --path home --pin "$SITE_ID" 2>/dev/null)" \
    || fail "verified fetch exited $?"
[[ "$PINNED_OUT" == *"Hello, Nexus"* ]] || fail "verified fetch did not render"
pass "verified fetch with correct pin renders"

# Wrong pin fails closed (nonzero exit).
if "$BROWSER_BIN" --server "$ENDPOINT" --site "$SITE" --path home --pin "0000000000000000000000000000000000000000000000000000000000000000" >/dev/null 2>&1; then
    fail "verified fetch with wrong pin unexpectedly succeeded"
fi
pass "verified fetch with wrong pin refused"

# Full verified mirror via `nexus sync`.
SYNC_DIR="$(mktemp -d -t nexus-e2e-sync.XXXXXX)"
"$NEXUS_BIN" sync --server "$ENDPOINT" --site "$SITE" --dir "$SYNC_DIR" --pin "$SITE_ID" >/dev/null 2>&1 \
    || fail "nexus sync exited $?"
[[ -f "$SYNC_DIR/home.json" ]] || fail "sync did not write home.json"
[[ -f "$SYNC_DIR/about.json" ]] || fail "sync did not write about.json"
rm -rf "$SYNC_DIR"
pass "verified nexus sync mirrors the site"

echo "e2e: PASS: full suite incl. signed flow and sync"
