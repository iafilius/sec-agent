#!/usr/bin/env bash
set -euo pipefail

echo "========================================================================"
echo "🛡️  sec-agent Pre-Release Privacy & Secret Leakage Audit"
echo "========================================================================"

TARGET_DIR="${1:-publish}"

ERRORS=0

echo "🔍 1. Checking for hardcoded absolute user home paths (/Users/ or /home/)..."
FOUND_PATHS=$(grep -rnEI "/Users/[a-zA-Z0-9_-]+/\.config|/home/[a-zA-Z0-9_-]+/\.config" "$TARGET_DIR" --exclude-dir=".git" --exclude-dir=".logs" --exclude="privacy_audit.sh" --binary-files=without-match || true)

if [ -n "$FOUND_PATHS" ]; then
    echo "❌ PRIVACY VIOLATION: Found hardcoded user home path in publish files:"
    echo "$FOUND_PATHS"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ No hardcoded user home config paths found."
fi

echo "🔍 2. Checking for specific master seed mnemonics..."
FOUND_MNEMONIC=$(grep -rn "doctor coin soft cube" "$TARGET_DIR" --exclude-dir=".git" --exclude="privacy_audit.sh" || true)
if [ -n "$FOUND_MNEMONIC" ]; then
    echo "❌ PRIVACY VIOLATION: Found production seed mnemonic string:"
    echo "$FOUND_MNEMONIC"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ No production seed mnemonics found."
fi

echo "🔍 3. Checking for active WireGuard / NordVPN private keys..."
FOUND_WG_KEY=$(grep -rn "zX4bwmdLgegUGYY4rJFEjMPn7VrH1aBMPnBLlvqqrSQ" "$TARGET_DIR" --exclude-dir=".git" --exclude="privacy_audit.sh" || true)
if [ -n "$FOUND_WG_KEY" ]; then
    echo "❌ PRIVACY VIOLATION: Found live WireGuard private key:"
    echo "$FOUND_WG_KEY"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ No live WireGuard private keys found."
fi

echo "🔍 4. Checking for unredacted RSA/Ed25519 private key blocks (outside unit tests)..."
FOUND_SSH_KEY=$(grep -rn "BEGIN OPENSSH PRIVATE KEY" "$TARGET_DIR" --exclude-dir=".git" --exclude="*_test.go" --exclude="privacy_audit.sh" || true)
if [ -n "$FOUND_SSH_KEY" ]; then
    echo "❌ PRIVACY VIOLATION: Found unredacted SSH private key block:"
    echo "$FOUND_SSH_KEY"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ No SSH private key blocks found."
fi

echo "========================================================================"
if [ "$ERRORS" -gt 0 ]; then
    echo "❌ AUDIT FAILED: $ERRORS privacy violation(s) detected. Release blocked!"
    exit 1
else
    echo "✨ AUDIT PASSED: 100% Privacy & Secret Isolation Clean!"
    exit 0
fi
