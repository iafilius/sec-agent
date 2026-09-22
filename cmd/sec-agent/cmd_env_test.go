package main

import (
	"bytes"
	"encoding/json"
	"os"
	"secure_secrets/internal/config"
	"secure_secrets/internal/store"
	"strings"
	"testing"
)

func TestWorkspaceConfigV1V2Deserialization(t *testing.T) {
	// Test v1 legacy schema deserialization
	v1JSON := `{"profile": "legacy-vault", "ttl": "4h", "grace": "15m"}`
	var cfgV1 WorkspaceConfig
	if err := json.Unmarshal([]byte(v1JSON), &cfgV1); err != nil {
		t.Fatalf("failed to unmarshal v1 config: %v", err)
	}
	normalizeWorkspaceConfig(&cfgV1)

	if cfgV1.Profile != "legacy-vault" {
		t.Errorf("expected Profile 'legacy-vault', got %q", cfgV1.Profile)
	}
	if cfgV1.Default != "dev" {
		t.Errorf("expected synthesized Default 'dev', got %q", cfgV1.Default)
	}
	devEnv, ok := cfgV1.Environments["dev"]
	if !ok {
		t.Fatalf("expected synthesized 'dev' environment in Environments map")
	}
	if devEnv.Profile != "legacy-vault" {
		t.Errorf("expected devEnv.Profile 'legacy-vault', got %q", devEnv.Profile)
	}
	if devEnv.ParsedTier() != config.TierDev {
		t.Errorf("expected devEnv.ParsedTier() 'dev', got %q", devEnv.ParsedTier())
	}

	// Test v2 schema deserialization
	v2JSON := `{
		"version": 2,
		"default": "dev",
		"environments": {
			"dev": {
				"profile": "xuntos-dev",
				"tier": "dev",
				"description": "Local development"
			},
			"sandbox": {
				"profile": "xuntos-prod",
				"tier": "prod",
				"description": "Production sandbox"
			}
		}
	}`
	var cfgV2 WorkspaceConfig
	if err := json.Unmarshal([]byte(v2JSON), &cfgV2); err != nil {
		t.Fatalf("failed to unmarshal v2 config: %v", err)
	}
	normalizeWorkspaceConfig(&cfgV2)

	if cfgV2.Version != 2 {
		t.Errorf("expected Version 2, got %d", cfgV2.Version)
	}
	if cfgV2.Profile != "xuntos-dev" {
		t.Errorf("expected synthesized Profile 'xuntos-dev' from default, got %q", cfgV2.Profile)
	}
	if len(cfgV2.Environments) != 2 {
		t.Fatalf("expected 2 environments, got %d", len(cfgV2.Environments))
	}
	sandboxEnv, ok := cfgV2.Environments["sandbox"]
	if !ok {
		t.Fatalf("expected 'sandbox' environment in Environments map")
	}
	if sandboxEnv.Profile != "xuntos-prod" {
		t.Errorf("expected sandbox Profile 'xuntos-prod', got %q", sandboxEnv.Profile)
	}
	if !sandboxEnv.ParsedTier().IsProduction() {
		t.Errorf("expected sandbox tier to be production, got %q", sandboxEnv.ParsedTier())
	}
}

func TestResolveWorkspaceEnvironmentPrecedence(t *testing.T) {
	// Clean environment variables before and after test
	origSecEnv := os.Getenv("SEC_ENV")
	origSecProf := os.Getenv("SEC_PROFILE")
	defer func() {
		_ = os.Setenv("SEC_ENV", origSecEnv)
		_ = os.Setenv("SEC_PROFILE", origSecProf)
	}()

	_ = os.Unsetenv("SEC_ENV")
	_ = os.Unsetenv("SEC_PROFILE")

	wsCfg := &WorkspaceConfig{
		Version: 2,
		Default: "dev",
		Environments: map[string]WorkspaceEnvironment{
			"dev": {
				Profile: store.ProfileName("xuntos-dev"),
				Tier:    "dev",
			},
			"sandbox": {
				Profile: store.ProfileName("xuntos-prod"),
				Tier:    "prod",
			},
		},
	}
	normalizeWorkspaceConfig(wsCfg)

	// Precedence 5: Global fallback "default" when wsCfg is nil
	ctx5, err := ResolveWorkspaceEnvironment("", "", nil)
	if err != nil {
		t.Fatalf("Rule 5 resolution failed: %v", err)
	}
	if ctx5.Profile != "default" || ctx5.Source != "global_default" {
		t.Errorf("expected global_default 'default', got %+v", ctx5)
	}

	// Precedence 4: Workspace default when no flags or env vars are set
	ctx4, err := ResolveWorkspaceEnvironment("", "", wsCfg)
	if err != nil {
		t.Fatalf("Rule 4 resolution failed: %v", err)
	}
	if ctx4.Profile != "xuntos-dev" || ctx4.EnvAlias != "dev" || ctx4.Source != "secrc_default" {
		t.Errorf("expected secrc_default 'xuntos-dev', got %+v", ctx4)
	}

	// Precedence 3: Shell environment variable SEC_ENV overrides .secrc default
	_ = os.Setenv("SEC_ENV", "sandbox")
	ctx3, err := ResolveWorkspaceEnvironment("", "", wsCfg)
	if err != nil {
		t.Fatalf("Rule 3 resolution failed: %v", err)
	}
	if ctx3.Profile != "xuntos-prod" || ctx3.EnvAlias != "sandbox" || ctx3.Source != "sec_env" {
		t.Errorf("expected sec_env 'xuntos-prod', got %+v", ctx3)
	}
	if !ctx3.Tier.IsProduction() {
		t.Errorf("expected tier prod for sandbox, got %q", ctx3.Tier)
	}

	// Precedence 2: CLI environment alias flag (-E / --env) overrides SEC_ENV
	ctx2, err := ResolveWorkspaceEnvironment("", "dev", wsCfg)
	if err != nil {
		t.Fatalf("Rule 2 resolution failed: %v", err)
	}
	if ctx2.Profile != "xuntos-dev" || ctx2.EnvAlias != "dev" || ctx2.Source != "cli_env" {
		t.Errorf("expected cli_env 'xuntos-dev', got %+v", ctx2)
	}

	// Precedence 1: Explicit CLI profile flag (-P / --profile) overrides CLI env flag and SEC_ENV
	ctx1, err := ResolveWorkspaceEnvironment("custom-profile", "dev", wsCfg)
	if err != nil {
		t.Fatalf("Rule 1 resolution failed: %v", err)
	}
	if ctx1.Profile != "custom-profile" || ctx1.Source != "cli_profile" {
		t.Errorf("expected cli_profile 'custom-profile', got %+v", ctx1)
	}

	// Rule 2 error: Unknown environment alias returns actionable error
	_, errUnknown := ResolveWorkspaceEnvironment("", "nonexistent-env", wsCfg)
	if errUnknown == nil {
		t.Errorf("expected error for nonexistent environment alias, got nil")
	}
}

func TestHandleUseAndHandleEnv(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tmpDir: %v", err)
	}

	secrcContent := `{
		"version": 2,
		"default": "dev",
		"environments": {
			"dev": {
				"profile": "xuntos-dev",
				"tier": "dev",
				"description": "Local dev"
			},
			"sandbox": {
				"profile": "xuntos-prod",
				"tier": "prod",
				"description": "Prod sandbox"
			}
		}
	}`
	if err := os.WriteFile(".secrc", []byte(secrcContent), 0600); err != nil {
		t.Fatalf("failed to write .secrc: %v", err)
	}

	// 1. Test handleUse with valid environment
	{
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w

		handleUse("", []string{"sandbox", "--export"})

		_ = w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()

		if !strings.Contains(out, `export SEC_ENV="sandbox";`) {
			t.Errorf("expected export SEC_ENV=\"sandbox\", got:\n%s", out)
		}
		if !strings.Contains(out, `export SEC_PROFILE="xuntos-prod";`) {
			t.Errorf("expected export SEC_PROFILE=\"xuntos-prod\", got:\n%s", out)
		}
	}

	// 2. Test handleUse --clear
	{
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w

		handleUse("", []string{"--clear", "--export"})

		_ = w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()

		if !strings.Contains(out, "unset SEC_ENV;") {
			t.Errorf("expected unset SEC_ENV;, got:\n%s", out)
		}
		if !strings.Contains(out, "unset SEC_PROFILE;") {
			t.Errorf("expected unset SEC_PROFILE;, got:\n%s", out)
		}
	}

	// 3. Test handleEnv --json
	{
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w

		handleEnv("", []string{"--json"})

		_ = w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()

		var entries []EnvironmentListEntry
		if err := json.Unmarshal([]byte(out), &entries); err != nil {
			t.Fatalf("failed to unmarshal handleEnv JSON: %v, output: %s", err, out)
		}
		if len(entries) != 2 {
			t.Fatalf("expected 2 environments in JSON, got %d", len(entries))
		}
		if entries[0].Alias != "dev" || entries[1].Alias != "sandbox" {
			t.Errorf("unexpected aliases: %+v", entries)
		}
		if entries[1].Tier != "prod" {
			t.Errorf("expected sandbox tier 'prod', got %q", entries[1].Tier)
		}
	}

	// 4. Test handleEnv text table
	{
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w

		handleEnv("", []string{"ls"})

		_ = w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()

		if !strings.Contains(out, "ACTIVE") || !strings.Contains(out, "ALIAS") {
			t.Errorf("expected table header in output, got:\n%s", out)
		}
		if !strings.Contains(out, "dev") || !strings.Contains(out, "sandbox") {
			t.Errorf("expected dev and sandbox in table, got:\n%s", out)
		}
		if !strings.Contains(out, "prod 🔴") {
			t.Errorf("expected prod 🔴 tier badge in table, got:\n%s", out)
		}
	}
}

func TestPromptMultiEnvironment(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tmpDir: %v", err)
	}

	secrcContent := `{
		"version": 2,
		"default": "dev",
		"environments": {
			"dev": {
				"profile": "xuntos-dev",
				"tier": "dev"
			},
			"sandbox": {
				"profile": "xuntos-prod",
				"tier": "prod"
			}
		}
	}`
	if err := os.WriteFile(".secrc", []byte(secrcContent), 0600); err != nil {
		t.Fatalf("failed to write .secrc: %v", err)
	}

	origSecEnv := os.Getenv("SEC_ENV")
	defer func() { _ = os.Setenv("SEC_ENV", origSecEnv) }()

	// 1. In dev environment
	_ = os.Setenv("SEC_ENV", "dev")
	{
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w

		handlePrompt("xuntos-dev", []string{"--format", "plain"})

		_ = w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()

		if !strings.Contains(out, "sec: dev (xuntos-dev") {
			t.Errorf("expected prompt output for dev to contain 'sec: dev (xuntos-dev', got: %s", out)
		}
	}

	// 2. In sandbox environment (prod tier)
	_ = os.Setenv("SEC_ENV", "sandbox")
	{
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w

		handlePrompt("xuntos-prod", []string{"--format", "plain"})

		_ = w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()

		if !strings.Contains(out, "sec: sandbox (xuntos-prod 🔴") {
			t.Errorf("expected prompt output for sandbox to contain 'sec: sandbox (xuntos-prod 🔴', got: %s", out)
		}
	}
}


