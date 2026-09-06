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
