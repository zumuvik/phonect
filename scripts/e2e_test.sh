#!/usr/bin/env bash
set -euo pipefail

# End-to-end test of the phonect handshake
# Runs PC server and mobile emulator in parallel

ROOT="$(dirname "$(realpath "$0")")/.."
VENV="$ROOT/.venv"
PHONECT="$VENV/bin/python -m phonect.cli"

# Temp dir for test artifacts
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "=== Generating mobile key pair ==="
MOBILE_KEY="$WORKDIR/mobile"
$PHONECT gen-keys \
    --private-key "$MOBILE_KEY.pem" \
    --public-key "$MOBILE_KEY.pub"

MOBILE_FP=$(grep -oP 'Fingerprint: \K[0-9a-f]+' <<< "$($PHONECT gen-keys --private-key "$WORKDIR/_tmp.pem" --public-key "$WORKDIR/_tmp.pub")")
# Actually get real fingerprint from the generated key
MOBILE_FP=$(grep 'Fingerprint:' < <($PHONECT gen-keys --private-key "$WORKDIR/_m.pem" --public-key "$WORKDIR/_m.pub") | awk '{print $2}')

# Read the actual fingerprint from the key file
# Let's use python for that
MOBILE_FP=$($VENV/bin/python3 -c "
from phonect.crypto import load_public_key, fingerprint_from_public_key
pub = load_public_key(open('$MOBILE_KEY.pub','rb').read())
print(fingerprint_from_public_key(pub))
")

echo "Mobile public key fingerprint: ${MOBILE_FP:0:16}…"

echo ""
echo "=== Starting PC server (background) ==="
$PHONECT server "$MOBILE_KEY.pub" --port 9999 --timeout 15 > "$WORKDIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

echo ""
echo "=== Running mobile emulator ==="
$PHONECT client "$MOBILE_KEY.pem" 127.0.0.1 9999 \
    --device-name "e2e-test-phone" \
    --timeout 10 > "$WORKDIR/client.log" 2>&1 && CLIENT_OK=true || CLIENT_OK=false

wait $SERVER_PID 2>/dev/null || true

echo ""
echo "--- Server log ---"
cat "$WORKDIR/server.log"
echo ""
echo "--- Client log ---"
cat "$WORKDIR/client.log"

if $CLIENT_OK; then
    echo ""
    echo "✓ E2E TEST PASSED"
    exit 0
else
    echo ""
    echo "✗ E2E TEST FAILED"
    exit 1
fi
