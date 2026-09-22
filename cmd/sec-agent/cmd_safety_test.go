package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"secure_secrets/internal/config"
	"testing"
)

func TestProductionMutationSafety(t *testing.T) {
	// Clean environment variables before and after
	origConfirm := os.Getenv("SEC_CONFIRM_PROD")
	origAI := os.Getenv("AI_AGENT")
	origCI := os.Getenv("CI")
	origTier := activeEnvTier
	defer func() {
		_ = os.Setenv("SEC_CONFIRM_PROD", origConfirm)
		_ = os.Setenv("AI_AGENT", origAI)
		_ = os.Setenv("CI", origCI)
		activeEnvTier = origTier
	}()

	// Ensure non-interactive mode for automated testing
	_ = os.Setenv("CI", "1")
	_ = os.Unsetenv("SEC_CONFIRM_PROD")

	// Intercept safetyExitFn
	var capturedExitCode int
	safetyExitFn = func(code int) {
		capturedExitCode = code
		panic(fmt.Sprintf("exit-%d", code))
	}
	defer func() { safetyExitFn = os.Exit }()

	// 1. Read-only command on prod profile: should pass freely
	activeEnvTier = config.TierProd
	err := validateProdMutationSafety("xuntos-prod", false, false)
	if err != nil {
		t.Errorf("expected read-only operation to pass freely on prod, got: %v", err)
	}

	// 2. Mutation on dev profile: should pass freely
	activeEnvTier = config.TierDev
	err = validateProdMutationSafety("xuntos-dev", true, false)
	if err != nil {
		t.Errorf("expected mutation on dev profile to pass freely, got: %v", err)
	}

	// 3. Non-interactive mutation on prod profile without confirm-prod: must abort with exit code 2
	activeEnvTier = config.TierProd
	capturedExitCode = 0
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic/abort from safetyExitFn(2), but function returned normally")
			}
		}()
		_ = validateProdMutationSafety("xuntos-prod", true, false)
	}()

	if capturedExitCode != 2 {
		t.Errorf("expected exit code 2 for unconfirmed prod mutation, got %d", capturedExitCode)
	}

	// 4. Non-interactive mutation on prod profile WITH confirm-prod: should succeed
	capturedExitCode = 0
	err = validateProdMutationSafety("xuntos-prod", true, true)
	if err != nil {
		t.Errorf("expected mutation with confirmProd=true to succeed, got: %v", err)
	}
	if capturedExitCode != 0 {
		t.Errorf("expected exit code 0 when confirmProd is true, got %d", capturedExitCode)
	}

	// 5. Non-interactive mutation on prod profile WITH SEC_CONFIRM_PROD=1 env var: should succeed
	_ = os.Setenv("SEC_CONFIRM_PROD", "1")
	capturedExitCode = 0
	err = validateProdMutationSafety("xuntos-prod", true, false)
	if err != nil {
		t.Errorf("expected mutation with SEC_CONFIRM_PROD=1 to succeed, got: %v", err)
	}
	if capturedExitCode != 0 {
		t.Errorf("expected exit code 0 with SEC_CONFIRM_PROD=1, got %d", capturedExitCode)
	}
}

func TestProductionMutationSafetyJSONError(t *testing.T) {
	origJSON := jsonErrors
	origCI := os.Getenv("CI")
	origTier := activeEnvTier
	defer func() {
		jsonErrors = origJSON
		_ = os.Setenv("CI", origCI)
		activeEnvTier = origTier
	}()

	_ = os.Setenv("CI", "1")
	jsonErrors = true
	activeEnvTier = config.TierProd

	var capturedExitCode int
	safetyExitFn = func(code int) {
		capturedExitCode = code
		panic(fmt.Sprintf("exit-%d", code))
	}
	defer func() { safetyExitFn = os.Exit }()

	// Intercept stderr
	r, w, _ := os.Pipe()
	oldStderr := os.Stderr
	os.Stderr = w

	func() {
		defer func() {
			_ = recover()
		}()
		_ = validateProdMutationSafety("xuntos-prod", true, false)
	}()

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if capturedExitCode != 2 {
		t.Errorf("expected exit code 2, got %d", capturedExitCode)
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &jsonResp); err != nil {
		t.Fatalf("expected valid JSON error output, got: %s (err: %v)", out, err)
	}

	if jsonResp["code"] != "PROD_MUTATION_CONFIRMATION_REQUIRED" {
		t.Errorf("expected code PROD_MUTATION_CONFIRMATION_REQUIRED, got %v", jsonResp["code"])
	}
	if jsonResp["success"] != false {
		t.Errorf("expected success false, got %v", jsonResp["success"])
	}
}
