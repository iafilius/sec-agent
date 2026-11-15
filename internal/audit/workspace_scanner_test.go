package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secure_secrets/internal/store"
)

func TestScanDomainPrimitiveValidation(t *testing.T) {
	if err := SeverityCritical.Validate(); err != nil {
		t.Fatalf("expected valid severity, got %v", err)
	}
	if err := ScanSeverity("INVALID").Validate(); !errors.Is(err, ErrInvalidScanSeverity) {
		t.Fatalf("expected ErrInvalidScanSeverity, got %v", err)
	}
	if err := FeasibilityReadyNow.Validate(); err != nil {
		t.Fatalf("expected valid feasibility, got %v", err)
	}
	if err := IntegrationFeasibility("UNKNOWN").Validate(); !errors.Is(err, ErrInvalidIntegrationFeasibility) {
		t.Fatalf("expected ErrInvalidIntegrationFeasibility, got %v", err)
	}
	if err := (ScanOptions{TargetPath: ""}).Validate(); !errors.Is(err, ErrInvalidScanTarget) {
		t.Fatalf("expected ErrInvalidScanTarget, got %v", err)
	}
}

func TestRunWorkspaceScanAndThreeTierAdvisor(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Unmigrated .env file (Tier 1: READY_NOW)
	dotenvContent := "DATABASE_PASSWORD=\"super_secret_db_12345\"\nSAFE_MIGRATED=\"<migrated_to_sec>\"\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(dotenvContent), 0600); err != nil {
		t.Fatal(err)
	}

	// 2. Shell script with insecure --password flag (Tier 2: NEEDS_WORKSPACE_ADAPTATION)
	scriptContent := "#!/bin/sh\ncurl --password=my_cli_flag_secret_99 https://internal.example.com\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "deploy.sh"), []byte(scriptContent), 0700); err != nil {
		t.Fatal(err)
	}

	// 3. Static config file with active vault secret match + extension idea
	cfgContent := "mqtt_bridge_pass: \"vault_master_secret_xyz987\"\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "mosquitto.conf"), []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}

	// 4. Ecosystem dotfile (.netrc) -> Tier 3: SEC_AGENT_EXTENSION_OPPORTUNITY
	netrcContent := "machine api.example.com login admin password netrc_token_abcdef123\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".netrc"), []byte(netrcContent), 0600); err != nil {
		t.Fatal(err)
	}

	// 5. Skipped directory (Library) should NOT be scanned
	libDir := filepath.Join(tmpDir, "Library")
	_ = os.MkdirAll(libDir, 0700)
	_ = os.WriteFile(filepath.Join(libDir, "ignored.env"), []byte("SKIPPED_SECRET=\"should_not_appear_12345\"\n"), 0600)

	vaultSecrets := map[string]store.SecretEntry{
		"mqtt/bridge_pass": {Value: "vault_master_secret_xyz987"},
	}

	report, err := RunWorkspaceScan(ScanOptions{
		TargetPath:   tmpDir,
		Profile:      "my-app",
		VaultSecrets: vaultSecrets,
	})
	if err != nil {
		t.Fatalf("RunWorkspaceScan failed: %v", err)
	}

	if report.Summary.TotalFindings < 4 {
		t.Fatalf("expected at least 4 findings, got %d: %+v", report.Summary.TotalFindings, report.ActionItems)
	}
	if report.Summary.ReadyNowCount < 1 {
		t.Errorf("expected at least 1 READY_NOW finding, got %d", report.Summary.ReadyNowCount)
	}
	if report.Summary.NeedsAdaptationCount < 2 {
		t.Errorf("expected at least 2 NEEDS_WORKSPACE_ADAPTATION findings, got %d", report.Summary.NeedsAdaptationCount)
	}
	if report.Summary.ExtensionOpportunityCount < 1 {
		t.Errorf("expected at least 1 SEC_AGENT_EXTENSION_OPPORTUNITY finding, got %d", report.Summary.ExtensionOpportunityCount)
	}
	if len(report.ExtensionIdeas) == 0 {
		t.Errorf("expected discovered sec-agent extension ideas to be populated")
	}

	// Verify zero plaintext secret exposure in any RedactedSnippet
	rawSecrets := []string{
		"super_secret_db_12345",
		"my_cli_flag_secret_99",
		"vault_master_secret_xyz987",
		"netrc_token_abcdef123",
		"should_not_appear_12345",
	}
	foundVaultMatch := false
	foundDotenvCmd := false

	for _, item := range report.ActionItems {
		if err := item.Validate(); err != nil {
			t.Errorf("action item %s failed validation: %v", item.ID, err)
		}
		for _, raw := range rawSecrets {
			if strings.Contains(item.RedactedSnippet, raw) {
				t.Errorf("SECURITY VIOLATION: raw secret %q leaked in RedactedSnippet of %s: %s", raw, item.ID, item.RedactedSnippet)
			}
		}
		if strings.Contains(item.FilePath, "Library") {
			t.Errorf("SafeSkipDirs violation: scanned file inside skipped Library dir: %s", item.FilePath)
		}
		if item.MatchedVaultKey == "mqtt/bridge_pass" {
			foundVaultMatch = true
		}
		if item.Category == "UNMIGRATED_DOTENV" && strings.Contains(item.IntegrationStrategy.SuggestedCommand, "sec migrate-local .env --profile my-app") {
			foundDotenvCmd = true
		}
	}

	if !foundVaultMatch {
		t.Errorf("expected exact match against active vault key 'mqtt/bridge_pass'")
	}
	if !foundDotenvCmd {
		t.Errorf("expected 'sec migrate-local .env --profile my-app' command on dotenv finding")
	}
}

func TestExternalScannerParsersAndBrewHints(t *testing.T) {
	origLookup := ToolLookupFunc
	origInstall := BrewInstallFunc
	defer func() {
		ToolLookupFunc = origLookup
		BrewInstallFunc = origInstall
	}()

	installedTools := map[string]bool{}
	ToolLookupFunc = func(name string) (string, string, bool) {
		if installedTools[name] {
			return "/opt/homebrew/bin/" + name, "1.0.0-mock", true
		}
		return "", "", false
	}
	var brewInstallCalls []string
	BrewInstallFunc = func(name string) error {
		brewInstallCalls = append(brewInstallCalls, name)
		installedTools[name] = true
		return nil
	}

	tmpDir := t.TempDir()
	// 1. Test missing tool hints without --install-tools
	_, statuses, hints := RunExternalScanners(tmpDir, true, ScanOptions{
		TargetPath: tmpDir,
		Deep:       true,
	}, "default", nil, nil)

	if statuses["gitleaks"].Installed || statuses["trufflehog"].Installed {
		t.Fatalf("expected mock tools to be reported as not installed initially")
	}
	if len(hints) < 2 {
		t.Fatalf("expected brew install hints for gitleaks and trufflehog, got %v", hints)
	}

	// 2. Test --install-tools auto-provisioning via Homebrew
	_, statusesAfter, _ := RunExternalScanners(tmpDir, true, ScanOptions{
		TargetPath:   tmpDir,
		Deep:         true,
		InstallTools: true,
	}, "default", nil, nil)

	if len(brewInstallCalls) != 2 {
		t.Fatalf("expected 2 brew install calls, got %v", brewInstallCalls)
	}
	if !statusesAfter["gitleaks"].Installed || !statusesAfter["trufflehog"].Installed {
		t.Fatalf("expected tools to be marked installed after --install-tools")
	}

	// 3. Test Gitleaks JSON parser and redaction
	mockGitleaksJSON := []byte(`[
		{
			"Description": "GitHub Personal Access Token",
			"StartLine": 12,
			"File": "config/auth.yaml",
			"Match": "token: REDACTED",
			"Secret": "mock_pat_token_1234567890abcdef",
			"RuleID": "github-pat",
			"Commit": ""
		}
	]`)
	glItems := ParseGitleaksJSONOutput(mockGitleaksJSON, "dir", tmpDir, "default", nil, nil)
	if len(glItems) != 1 {
		t.Fatalf("expected 1 parsed gitleaks item, got %d", len(glItems))
	}
	if strings.Contains(glItems[0].RedactedSnippet, "mock_pat_token_1234567890") {
		t.Errorf("expected secret to be redacted from gitleaks snippet")
	}

	// 4. Test TruffleHog JSONL parser
	mockTrufflehogJSONL := []byte(`{"DetectorName":"Stripe","Verified":true,"Raw":"mock_stripe_val_999","SourceMetadata":{"Data":{"Filesystem":{"file":"payments.py","line":44}}}}` + "\n")
	thItems := ParseTrufflehogJSONLines(mockTrufflehogJSONL, tmpDir, "default", nil, nil)
	if len(thItems) != 1 {
		t.Fatalf("expected 1 parsed trufflehog item, got %d", len(thItems))
	}
	if !thItems[0].VerifiedLive || thItems[0].Severity != SeverityCritical {
		t.Errorf("expected verified live trufflehog item to have CRITICAL severity")
	}
}

