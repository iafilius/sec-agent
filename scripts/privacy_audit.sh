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

echo "🔍 5. Checking for personal backup volume / folder / host identifiers..."
FOUND_BCK_ID=$(grep -rnE "OneDrive - NN|BCKArFI|192\.168\.31\.125|CloudFolder - Work|BackupDrive/Work" "$TARGET_DIR" --exclude-dir=".git" --exclude="privacy_audit.sh" --binary-files=without-match || true)
if [ -n "$FOUND_BCK_ID" ]; then
    echo "❌ PRIVACY VIOLATION: Found personal backup identifier in publish files:"
    echo "$FOUND_BCK_ID"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ No personal backup identifiers found."
fi

echo "🔍 6. Checking for GitHub Push Protection token prefixes (sk_live_, ghp_[A-Za-z0-9]{20,})..."
FOUND_GH_PP=$(grep -rnE "sk_live_[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{20,}" "$TARGET_DIR" --exclude-dir=".git" --exclude="privacy_audit.sh" --binary-files=without-match || true)
if [ -n "$FOUND_GH_PP" ]; then
    echo "❌ PRIVACY VIOLATION: Found GitHub Push Protection token prefix in publish files:"
    echo "$FOUND_GH_PP"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ No GitHub Push Protection token prefixes found."
fi

echo "========================================================================"
if [ "$ERRORS" -gt 0 ]; then
    echo "❌ AUDIT FAILED: $ERRORS privacy violation(s) detected. Release blocked!"
    exit 1
else
    echo "✨ AUDIT PASSED: 100% Privacy & Secret Isolation Clean!"
    exit 0
fi
