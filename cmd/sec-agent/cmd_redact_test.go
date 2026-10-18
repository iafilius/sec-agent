package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactWriterBasic(t *testing.T) {
	var out bytes.Buffer
	secrets := []string{"SUPER_SECRET_KEY_123", "ANOTHER_SECRET"}
	w := newRedactWriter(&out, secrets)

	input := "Connecting to server with SUPER_SECRET_KEY_123 in payload. Also ANOTHER_SECRET is here.\n"
	n, err := w.Write([]byte(input))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(input) {
		t.Errorf("expected %d bytes written, got %d", len(input), n)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	result := out.String()
	if strings.Contains(result, "SUPER_SECRET_KEY_123") {
		t.Errorf("SUPER_SECRET_KEY_123 was not redacted: %s", result)
	}
	if strings.Contains(result, "ANOTHER_SECRET") {
		t.Errorf("ANOTHER_SECRET was not redacted: %s", result)
	}
	if !strings.Contains(result, "[REDACTED_BY_SEC]") {
		t.Errorf("expected [REDACTED_BY_SEC] placeholder in output: %s", result)
	}
}

func TestRedactWriterSlidingWindowChunkSplit(t *testing.T) {
	var out bytes.Buffer
	secret := "MY_HIGHLY_SENSITIVE_API_TOKEN_XYZ"
	w := newRedactWriter(&out, []string{secret})

	fullMessage := "The token is: " + secret + " and process exited."

	// Write in small 3-byte chunks to intentionally split the secret across boundaries
	chunkSize := 3
	for i := 0; i < len(fullMessage); i += chunkSize {
		end := i + chunkSize
		if end > len(fullMessage) {
			end = len(fullMessage)
		}
		_, err := w.Write([]byte(fullMessage[i:end]))
		if err != nil {
			t.Fatalf("Write chunk failed at %d: %v", i, err)
		}
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	result := out.String()
	if strings.Contains(result, secret) {
		t.Fatalf("Secret leaked across sliding window chunks! Got: %s", result)
	}

	expected := "The token is: [REDACTED_BY_SEC] and process exited."
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestRedactWriterShortSecretsIgnored(t *testing.T) {
	var out bytes.Buffer
	// Secrets < 4 characters should be ignored to avoid over-redacting common words
	secrets := []string{"a", "to", "the"}
	w := newRedactWriter(&out, secrets)

	input := "Welcome to the application\n"
	_, _ = w.Write([]byte(input))
	_ = w.Flush()

	result := out.String()
	if result != input {
		t.Errorf("expected unmodified text %q, got %q", input, result)
	}
}

func TestRedactWriterEmptySecrets(t *testing.T) {
	var out bytes.Buffer
	w := newRedactWriter(&out, nil)

	input := "Hello World! No redaction needed."
	_, _ = w.Write([]byte(input))
	_ = w.Flush()

	if out.String() != input {
		t.Errorf("expected %q, got %q", input, out.String())
	}
}

func TestHexCollisionDetectionAndProtection(t *testing.T) {
	hexSecret := "a1b2c3d4"
	if !isPureHex(hexSecret) {
		t.Fatalf("expected %q to be pure hex", hexSecret)
	}

	// 1. 40-character Git commit hash containing hexSecret as a substring
	gitCommitSHA := "commit 7f8" + hexSecret + "e9045612347890abcdef1234567890ab is clean"
	if containsSecretValue(gitCommitSHA, hexSecret) {
		t.Errorf("expected git commit SHA to NOT trigger secret collision, but containsSecretValue returned true")
	}

	// replaceSecretMatches should preserve the commit SHA intact
	redactedLine := replaceSecretMatches(gitCommitSHA, hexSecret, "[REDACTED]")
	if redactedLine != gitCommitSHA {
		t.Errorf("expected git commit SHA to remain unchanged, got: %s", redactedLine)
	}

	// 2. 64-character SHA-256 digest in lockfile containing hexSecret as prefix
	sha256Digest := "sha256:" + hexSecret + "9876543210abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if containsSecretValue(sha256Digest, hexSecret) {
		t.Errorf("expected sha256 digest prefix to NOT trigger collision, got true")
	}

	// 3. Standalone hex secret should match and be redacted
	standaloneLine := "export TOKEN=\"a1b2c3d4\""
	if !containsSecretValue(standaloneLine, hexSecret) {
		t.Errorf("expected standalone hex secret to match, got false")
	}
	standaloneRedacted := replaceSecretMatches(standaloneLine, hexSecret, "[REDACTED]")
	expectedStandalone := "export TOKEN=\"[REDACTED]\""
	if standaloneRedacted != expectedStandalone {
		t.Errorf("expected %q, got %q", expectedStandalone, standaloneRedacted)
	}

	// 4. Line containing both a commit hash collision AND a standalone secret
	mixedLine := "checkout 7f8" + hexSecret + "e9045612347890abcdef1234567890ab; token=a1b2c3d4"
	if !containsSecretValue(mixedLine, hexSecret) {
		t.Errorf("expected mixed line to match due to standalone secret token, got false")
	}
	mixedRedacted := replaceSecretMatches(mixedLine, hexSecret, "[REDACTED]")
	expectedMixed := "checkout 7f8" + hexSecret + "e9045612347890abcdef1234567890ab; token=[REDACTED]"
	if mixedRedacted != expectedMixed {
		t.Errorf("expected %q, got %q", expectedMixed, mixedRedacted)
	}
}

func TestDerivedEncodingRedactionBase64AndURLEscaped(t *testing.T) {
	rawMap := map[string]string{
		"auth/token": "p@ss/word+123=",
	}
	expanded := expandDerivedSecrets(rawMap)

	// Check raw
	if _, ok := expanded["p@ss/word+123="]; !ok {
		t.Errorf("raw secret missing from expanded map")
	}

	// Check base64
	b64Expected := "cEBzcy93b3JkKzEyMz0="
	if name, ok := expanded[b64Expected]; !ok || !strings.Contains(name, "(base64)") {
		t.Errorf("base64 encoding missing or unlabelled in expanded map: got %v", name)
	}

	// Check url-encoded (query or path escape)
	urlExpected := "p%40ss%2Fword%2B123%3D"
	if name, ok := expanded[urlExpected]; !ok || !strings.Contains(name, "(url-encoded)") {
		t.Errorf("url-encoded form missing or unlabelled in expanded map: got %v", name)
	}
}

func TestRedactWriterWithDerivedEncodingsAndHexCollisions(t *testing.T) {
	var out bytes.Buffer
	secrets := []string{"p@ss/word+123=", "a1b2c3d4"}
	w := newRedactWriter(&out, secrets)

	input := "Header Authorization: Basic cEBzcy93b3JkKzEyMz0=\n" +
		"URL query: https://api.internal/v1?token=p%40ss%2Fword%2B123%3D\n" +
		"Git commit: f81" + "a1b2c3d4" + "99887766554433221100aabbccddeeff\n" +
		"Standalone hex token: a1b2c3d4\n"

	_, err := w.Write([]byte(input))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	result := out.String()
	// Base64 and URL-encoded forms should be redacted
	if strings.Contains(result, "cEBzcy93b3JkKzEyMz0=") {
		t.Errorf("Base64 token was not redacted in output: %s", result)
	}
	if strings.Contains(result, "p%40ss%2Fword%2B123%3D") {
		t.Errorf("URL-encoded token was not redacted in output: %s", result)
	}
	// Git commit hash should remain intact
	expectedGitHash := "f81" + "a1b2c3d4" + "99887766554433221100aabbccddeeff"
	if !strings.Contains(result, expectedGitHash) {
		t.Errorf("Git commit SHA was improperly corrupted: %s", result)
	}
	// Standalone hex token should be redacted
	if strings.Contains(result, "Standalone hex token: a1b2c3d4") {
		t.Errorf("Standalone hex token was not redacted: %s", result)
	}
	if !strings.Contains(result, "Standalone hex token: [REDACTED_BY_SEC]") {
		t.Errorf("Expected [REDACTED_BY_SEC] placeholder for standalone hex token: %s", result)
	}
}

