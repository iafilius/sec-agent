package main

import (
	"bytes"
	"testing"
	"time"
)

func TestLongestSecretPrefixSuffix(t *testing.T) {
	secrets := []string{
		"azure_devops_pat_secret_123456789012345678901234567890",
		"super_secret_token",
	}
	maxLen := len(secrets[0])

	// 1. Text has no suffix matching any secret prefix
	prompt := "Apply to 3 item(s)? [y/N] "
	L := longestSecretPrefixSuffix(prompt, secrets, maxLen)
	if L != 0 {
		t.Fatalf("expected L=0 for interactive prompt, got %d", L)
	}

	// 2. Text ends with exact prefix "azure_" (6 chars)
	textWithPrefix := "Some output before azure_"
	L = longestSecretPrefixSuffix(textWithPrefix, secrets, maxLen)
	if L != 6 {
		t.Fatalf("expected L=6 for prefix 'azure_', got %d", L)
	}

	// 3. Text ends with "s" matching prefix of "super_secret_token"
	textEndsWithS := "Enter choice s"
	L = longestSecretPrefixSuffix(textEndsWithS, secrets, maxLen)
	if L != 1 {
		t.Fatalf("expected L=1 for trailing 's', got %d", L)
	}
}

func TestRedactWriterImmediatePromptFlush(t *testing.T) {
	var buf bytes.Buffer
	// 52-char secret token
	azurePAT := "oiv45abcdefghijklmnopqrstuvwxyz1234567890abcdefghij"
	w := newRedactWriter(&buf, []string{azurePAT})

	prompt := "Apply to 3 item(s)? [y/N] "
	n, err := w.Write([]byte(prompt))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(prompt) {
		t.Fatalf("expected n=%d, got %d", len(prompt), n)
	}

	// Because prompt does not end with any prefix of azurePAT,
	// it MUST be flushed immediately to buf without waiting for Flush()!
	if buf.String() != prompt {
		t.Fatalf("expected prompt to flush immediately, got %q in buffer", buf.String())
	}
}

func TestRedactWriterBoundaryCrossingRedaction(t *testing.T) {
	var buf bytes.Buffer
	secret := "TOP_SECRET_API_KEY_12345"
	w := newRedactWriter(&buf, []string{secret})

	// Chunk 1: partial prefix
	chunk1 := "Header: TOP_SEC"
	_, _ = w.Write([]byte(chunk1))

	// Should flush "Header: " immediately, retaining "TOP_SEC"
	if buf.String() != "Header: " {
		t.Fatalf("expected buf to have 'Header: ', got %q", buf.String())
	}

	// Chunk 2: rest of secret + trailing message
	chunk2 := "RET_API_KEY_12345 -- finished."
	_, _ = w.Write([]byte(chunk2))

	expected := "Header: [REDACTED_BY_SEC] -- finished."
	if buf.String() != expected {
		t.Fatalf("expected %q, got %q", expected, buf.String())
	}
}

func TestRedactWriterIdleTimerFlush(t *testing.T) {
	var buf bytes.Buffer
	secret := "SECRET_TOKEN"
	w := newRedactWriter(&buf, []string{secret})
	w.idleTimeout = 10 * time.Millisecond

	// Writes text that ends with "S", matching the prefix of "SECRET_TOKEN"
	_, _ = w.Write([]byte("Target: S"))

	// "Target: " should be flushed immediately, "S" buffered
	if buf.String() != "Target: " {
		t.Fatalf("expected 'Target: ', got %q", buf.String())
	}

	// Wait for idle timer
	time.Sleep(30 * time.Millisecond)

	// Now "Target: S" should be fully flushed
	if buf.String() != "Target: S" {
		t.Fatalf("expected 'Target: S' after idle timeout, got %q", buf.String())
	}
}

func TestRecoverySeedWarningBanner(t *testing.T) {
	if !bytes.Contains([]byte(recoverySeedWarningBanner), []byte("CRITICAL SECURITY WARNING")) {
		t.Errorf("expected recoverySeedWarningBanner to contain 'CRITICAL SECURITY WARNING'")
	}
	if !bytes.Contains([]byte(recoverySeedWarningBanner), []byte("NEVER paste this recovery seed phrase")) {
		t.Errorf("expected recoverySeedWarningBanner to contain 'NEVER paste this recovery seed phrase'")
	}
	if !bytes.Contains([]byte(recoverySeedWarningBanner), []byte("chat, AI prompt")) {
		t.Errorf("expected recoverySeedWarningBanner to warn about chat and AI prompts")
	}
}
