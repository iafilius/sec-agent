package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"secure_secrets/internal/store"
)

var (
	// ErrInvalidScanSeverity indicates an unrecognized ScanSeverity value.
	ErrInvalidScanSeverity = errors.New("invalid scan severity")
	// ErrInvalidIntegrationFeasibility indicates an unrecognized IntegrationFeasibility value.
	ErrInvalidIntegrationFeasibility = errors.New("invalid integration feasibility")
	// ErrInvalidScanTarget indicates an empty or invalid scan target path.
	ErrInvalidScanTarget = errors.New("invalid scan target path")
)

// ScanSeverity defines strongly typed priority levels for discovered security action items.
type ScanSeverity string

const (
	SeverityCritical ScanSeverity = "CRITICAL"
	SeverityHigh     ScanSeverity = "HIGH"
	SeverityMedium   ScanSeverity = "MEDIUM"
	SeverityLow      ScanSeverity = "LOW"
)

// Validate ensures the ScanSeverity matches a valid domain constant.
func (s ScanSeverity) Validate() error {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidScanSeverity, string(s))
	}
}

// IntegrationFeasibility classifies how a detected plaintext credential can be bridged to sec-agent.
type IntegrationFeasibility string

const (
	FeasibilityReadyNow              IntegrationFeasibility = "READY_NOW"
	FeasibilityNeedsAdaptation       IntegrationFeasibility = "NEEDS_WORKSPACE_ADAPTATION"
	FeasibilityExtensionOpportunity  IntegrationFeasibility = "SEC_AGENT_EXTENSION_OPPORTUNITY"
)

// Validate ensures the IntegrationFeasibility matches a valid domain constant.
func (f IntegrationFeasibility) Validate() error {
	switch f {
	case FeasibilityReadyNow, FeasibilityNeedsAdaptation, FeasibilityExtensionOpportunity:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidIntegrationFeasibility, string(f))
	}
}

// WorkspaceAdaptationAdvice provides concrete steps for refactoring a workspace file or tool invocation.
type WorkspaceAdaptationAdvice struct {
	Summary string   `json:"summary"`
	Steps   []string `json:"steps"`
}

// SecAgentExtensionIdea proposes a new sec-agent capability when a target tool lacks direct injection hooks.
type SecAgentExtensionIdea struct {
	Applicable  bool   `json:"applicable"`
	FeatureSlug string `json:"feature_slug"`
	Proposal    string `json:"proposal"`
}

// IntegrationStrategy describes how to remediate a finding via direct drop-in, workspace refactoring, or sec-agent extension.
type IntegrationStrategy struct {
	Feasibility      IntegrationFeasibility     `json:"feasibility"`
	CurrentBlocker   string                     `json:"current_blocker,omitempty"`
	SuggestedCommand string                     `json:"suggested_command"`
	WorkspaceAdvice  *WorkspaceAdaptationAdvice `json:"workspace_advice,omitempty"`
	ExtensionIdea    *SecAgentExtensionIdea     `json:"sec_agent_extension_idea,omitempty"`
}

// Validate checks the invariants of an IntegrationStrategy.
func (s IntegrationStrategy) Validate() error {
	if err := s.Feasibility.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(s.SuggestedCommand) == "" {
		return fmt.Errorf("%w: empty suggested_command", ErrInvalidIntegrationFeasibility)
	}
	return nil
}

// ScanActionItem represents a deduplicated, redacted security finding and its actionable remediation plan.
type ScanActionItem struct {
	ID                  string              `json:"id"`
	Severity            ScanSeverity        `json:"severity"`
	Category            string              `json:"category"`
	Engines             []string            `json:"engines"`
	FilePath            string              `json:"file_path"`
	LineNumber          int                 `json:"line_number"`
	RuleID              string              `json:"rule_id"`
	Description         string              `json:"description"`
	MatchedVaultKey     string              `json:"matched_vault_key,omitempty"`
	RedactedSnippet     string              `json:"redacted_snippet"`
	VerifiedLive        bool                `json:"verified_live,omitempty"`
	Fingerprint         string              `json:"fingerprint"`
	IntegrationStrategy IntegrationStrategy `json:"integration_strategy"`
}

// Validate verifies all invariants on a ScanActionItem.
func (item ScanActionItem) Validate() error {
	if err := item.Severity.Validate(); err != nil {
		return err
	}
	return item.IntegrationStrategy.Validate()
}

// EngineStatus captures discovery and execution state for a scanner engine.
type EngineStatus struct {
	Name        string `json:"name"`
	Active      bool   `json:"active"`
	Installed   bool   `json:"installed"`
	Version     string `json:"version,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	InstallHint string `json:"install_hint,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

// ScanSummary aggregates counts by severity and integration tier.
type ScanSummary struct {
	TotalFindings             int            `json:"total_findings"`
	ScannedFiles              int            `json:"scanned_files"`
	BySeverity                map[string]int `json:"by_severity"`
	ByFeasibility             map[string]int `json:"by_feasibility"`
	ReadyNowCount             int            `json:"ready_now_count"`
	NeedsAdaptationCount      int            `json:"needs_adaptation_count"`
	ExtensionOpportunityCount int            `json:"extension_opportunity_count"`
}

// ScanReport is the top-level machine-readable Security Improvement Action List.
type ScanReport struct {
	SchemaVersion  string                    `json:"schema_version"`
	ScanTimestamp  string                    `json:"scan_timestamp"`
	TargetPath     string                    `json:"target_path"`
	Profile        string                    `json:"profile"`
	VaultUnlocked  bool                      `json:"vault_unlocked"`
	Engines        map[string]EngineStatus   `json:"engines"`
	ToolHints      []string                  `json:"tool_hints,omitempty"`
	Summary        ScanSummary               `json:"summary"`
	ActionItems    []ScanActionItem          `json:"action_items"`
	ExtensionIdeas []SecAgentExtensionIdea   `json:"discovered_extension_ideas,omitempty"`
}

// ScanOptions configures a workspace or directory security scan.
type ScanOptions struct {
	TargetPath   string
	Profile      string
	GitHistory   bool
	Deep         bool
	VerifyLive   bool
	InstallTools bool
	VaultSecrets map[string]store.SecretEntry
}

// Validate checks that ScanOptions has a valid target path.
func (o ScanOptions) Validate() error {
	if strings.TrimSpace(o.TargetPath) == "" {
		return fmt.Errorf("%w: target path cannot be empty", ErrInvalidScanTarget)
	}
	return nil
}

var (
	dotenvKeyValRegex     = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`)
	staticConfigAssignRe  = regexp.MustCompile(`(?i)["']?([a-z0-9_.\-]*?(?:password|passwd|secret|api_key|apikey|access_token|auth_token|private_key|client_secret|_authtoken)[a-z0-9_.\-]*)["']?\s*(?:[:=]|\s+)\s*["']?([^\s"',;#{}]+)["']?`)
	pgpassLineRe          = regexp.MustCompile(`^[^:#\s]+:[^:#\s]+:[^:#\s]+:[^:#\s]+:([^\s:#]+)$`)
	codeHardcodedAssignRe = regexp.MustCompile(`(?i)\b([a-z0-9_]*?(?:password|passwd|secret|api_key|apikey|access_token|auth_token|private_key|client_secret)[a-z0-9_]*)\b\s*(?::=|=)\s*["']([^"'\$\{\}\s]{6,})["']`)
)

// SafeSkipDirs lists directory names skipped during recursive workspace or $HOME scans to avoid TCC prompts and cache bloat.
var SafeSkipDirs = map[string]bool{
	"Library":            true,
	".Trash":             true,
	".cache":             true,
	".npm":               true,
	".yarn":              true,
	".pnpm-store":        true,
	".cargo":             true,
	".rustup":            true,
	".gradle":            true,
	".m2":                true,
	"node_modules":       true,
	"vendor":             true,
	"dist":               true,
	"build":              true,
	".git":               true,
	".hg":                true,
	".svn":               true,
	"__pycache__":        true,
	".venv":              true,
	"venv":               true,
	".tox":               true,
	".idea":              true,
	".vscode":            true,
	".gemini":            true,
	"OrbStack":           true,
	"Containers":         true,
	"Application Support": true,
}

// AllowedDotfiles lists dotfile names or directories in $HOME or workspaces that SHOULD be inspected for credential leaks.
var AllowedDotfiles = map[string]bool{
	".env":             true,
	".npmrc":           true,
	".netrc":           true,
	".pgpass":          true,
	".pypirc":          true,
	".git-credentials": true,
	".dockercfg":       true,
	".zsh_history":     true,
	".bash_history":    true,
	".aws":             true,
	".kube":            true,
	".docker":          true,
}

// IsAllowedHiddenEntry determines if a hidden file or directory should be traversed.
func IsAllowedHiddenEntry(name string) bool {
	if name == "." || name == ".." {
		return true
	}
	if strings.HasPrefix(name, ".env") {
		return true
	}
	return AllowedDotfiles[name]
}

// ComputeFindingFingerprint returns a deterministic SHA-256 fingerprint for an action item.
func ComputeFindingFingerprint(filePath string, lineNum int, category, ruleID string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s:%d:%s:%s", filepath.ToSlash(filePath), lineNum, category, ruleID)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// ScrubSecretLine replaces any occurrence of targetValue or known secret tokens in rawLine with [REDACTED_BY_SEC].
func ScrubSecretLine(rawLine, targetValue string) string {
	trimmed := strings.TrimSpace(rawLine)
	if targetValue != "" && len(targetValue) >= 3 {
		trimmed = strings.ReplaceAll(trimmed, targetValue, "[REDACTED_BY_SEC]")
	}
	for _, pat := range DefaultSecretPatterns {
		trimmed = pat.Regex.ReplaceAllString(trimmed, "[REDACTED_BY_SEC]")
	}
	if len(trimmed) > 160 {
		trimmed = trimmed[:160] + "..."
	}
	return trimmed
}

func isPlaceholderOrSafeValue(val string) bool {
	v := strings.Trim(strings.TrimSpace(val), `"'`)
	if v == "" || v == "<migrated_to_sec>" || v == "[REDACTED_BY_SEC]" || v == "REDACTED" {
		return true
	}
	if strings.HasPrefix(v, "$") || strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "<") || strings.HasPrefix(v, "your_") || strings.HasPrefix(v, "YOUR_") {
		return true
	}
	lower := strings.ToLower(v)
	switch lower {
	case "true", "false", "null", "none", "nil", "localhost", "127.0.0.1", "changeme", "example", "test", "dummy", "xxx", "todo":
		return true
	}
	if len(v) < 4 {
		return true
	}
	return false
}

// BuildIntegrationStrategy classifies a finding into one of the 3 Integration Feasibility Tiers and constructs remediation advice.
func BuildIntegrationStrategy(profile, relPath, category, keyName string) IntegrationStrategy {
	profFlag := ""
	if profile != "" && profile != "default" {
		profFlag = fmt.Sprintf(" --profile %s", profile)
	}
	cleanKey := strings.ToLower(strings.ReplaceAll(keyName, "_", "/"))
	if cleanKey == "" {
		cleanKey = "app/secret_key"
	}

	base := filepath.Base(relPath)
	ext := strings.ToLower(filepath.Ext(relPath))

	// Tier 1: Unmigrated .env or .env.* files -> Direct drop-in via sec migrate-local
	if category == "UNMIGRATED_DOTENV" || base == ".env" || strings.HasPrefix(base, ".env.") {
		return IntegrationStrategy{
			Feasibility:      FeasibilityReadyNow,
			SuggestedCommand: fmt.Sprintf("sec migrate-local %s%s", relPath, profFlag),
		}
	}

	// Tier 1 / Tier 2: CLI script flags (-p / --password)
	if category == "INSECURE_SCRIPT_FLAG" {
		return IntegrationStrategy{
			Feasibility:      FeasibilityNeedsAdaptation,
			CurrentBlocker:   "Script passes plaintext credential directly on the CLI flag (exposed in ps aux and shell history).",
			SuggestedCommand: fmt.Sprintf("sec set %s%s && sec run%s --redact -- %s", cleanKey, profFlag, profFlag, relPath),
			WorkspaceAdvice: &WorkspaceAdaptationAdvice{
				Summary: "Parameterize script to read from environment variable or stdin instead of a literal CLI flag",
				Steps: []string{
					fmt.Sprintf("Store the credential inside the Secure Enclave: sec set %s%s", cleanKey, profFlag),
					fmt.Sprintf("Replace the hardcoded flag value in %s with an environment variable reference (e.g. \"$%s\") or --password-stdin", relPath, strings.ToUpper(strings.ReplaceAll(cleanKey, "/", "_"))),
					fmt.Sprintf("Execute the script through sec-agent: sec run%s --redact -- %s", profFlag, relPath),
				},
			},
		}
	}

	// Tier 3: Home/Ecosystem Dotfiles (.netrc, .npmrc, .pgpass, .pypirc, .git-credentials)
	if base == ".netrc" || base == ".npmrc" || base == ".pgpass" || base == ".pypirc" || base == ".git-credentials" || strings.Contains(relPath, ".aws/credentials") {
		return IntegrationStrategy{
			Feasibility:      FeasibilityExtensionOpportunity,
			CurrentBlocker:   fmt.Sprintf("Ecosystem tool expects a fixed plaintext credential file (%s) on disk and does not natively query sec-agent.", base),
			SuggestedCommand: fmt.Sprintf("sec stream %s.tmpl > %s", relPath, relPath),
			WorkspaceAdvice: &WorkspaceAdaptationAdvice{
				Summary: fmt.Sprintf("Replace static %s with a template or ephemeral file wrapper", base),
				Steps: []string{
					fmt.Sprintf("Store the token in sec-agent: sec set %s%s", cleanKey, profFlag),
					fmt.Sprintf("Move %s to %s.tmpl and replace the secret with {{%s}}", relPath, relPath, cleanKey),
					fmt.Sprintf("Use 'sec run --temp-file' if the CLI supports a custom config path env var, or render on demand via 'sec stream %s.tmpl'", relPath),
				},
			},
			ExtensionIdea: &SecAgentExtensionIdea{
				Applicable:  true,
				FeatureSlug: "ephemeral-fixed-path-mount-and-cred-helpers",
				Proposal:    fmt.Sprintf("Extend sec-agent with 'sec run --ephemeral-file %s.tmpl:%s' (materializing the file only during process execution and 0x00-shredding on exit) or a native credential helper for %s.", relPath, relPath, base),
			},
		}
	}

	// Tier 2 + Tier 3: Static Configuration Files (.json, .yaml, .yml, .toml, .ini, .conf, .xml)
	switch ext {
	case ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".xml", ".properties":
		return IntegrationStrategy{
			Feasibility:      FeasibilityNeedsAdaptation,
			CurrentBlocker:   fmt.Sprintf("Static configuration file (%s) contains a literal credential; many parsers for %s do not expand $ENV_VAR natively.", relPath, ext),
			SuggestedCommand: fmt.Sprintf("sec set %s%s && sec stream %s.tmpl > %s", cleanKey, profFlag, relPath, relPath),
			WorkspaceAdvice: &WorkspaceAdaptationAdvice{
				Summary: "Convert static configuration file into a mustache template (.tmpl) or use --temp-file injection",
				Steps: []string{
					fmt.Sprintf("Store the secret in the vault: sec set %s%s", cleanKey, profFlag),
					fmt.Sprintf("Rename %s to %s.tmpl, replace the literal secret with {{%s}}, and add %s to .gitignore", relPath, relPath, cleanKey, relPath),
					fmt.Sprintf("If the consuming tool accepts a config path env var, run: sec run%s --temp-file CONFIG_FILE=%s.tmpl -- <cmd>", profFlag, relPath),
					fmt.Sprintf("Otherwise, stream the config in memory: sec stream%s %s.tmpl", profFlag, relPath),
				},
			},
			ExtensionIdea: &SecAgentExtensionIdea{
				Applicable:  true,
				FeatureSlug: "in-place-ephemeral-config-mount",
				Proposal:    fmt.Sprintf("Add 'sec run --mount-template %s.tmpl:%s -- <cmd>' to materialize fixed-path config files in-place before process start and securely zero-shred them on exit.", relPath, relPath),
			},
		}
	}

	// Tier 2: Source Code Files (.go, .py, .js, .ts, .rb, .sh, .zsh, etc.)
	return IntegrationStrategy{
		Feasibility:      FeasibilityNeedsAdaptation,
		CurrentBlocker:   fmt.Sprintf("Hardcoded secret literal inside %s; sec-agent injects via environment variables, stdin, or templates rather than rewriting source literals at runtime.", relPath),
		SuggestedCommand: fmt.Sprintf("sec set %s%s && sec run%s --redact -- <cmd>", cleanKey, profFlag, profFlag),
		WorkspaceAdvice: &WorkspaceAdaptationAdvice{
			Summary: "Refactor hardcoded source constant to read from an environment variable injected by 'sec run'",
			Steps: []string{
				fmt.Sprintf("Store the credential in sec-agent: sec set %s%s", cleanKey, profFlag),
				fmt.Sprintf("Update %s to read the environment variable %s from process environment (e.g. os.Getenv / os.environ / process.env)", relPath, strings.ToUpper(strings.ReplaceAll(cleanKey, "/", "_"))),
				fmt.Sprintf("Run your application or test suite with: sec run%s --redact -- <command>", profFlag),
			},
		},
	}
}

// RunWorkspaceScan executes the hybrid sec-native + external Homebrew scanner pipeline and returns a unified ScanReport.
func RunWorkspaceScan(opts ScanOptions) (*ScanReport, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	cleanTarget := expandHomePath(opts.TargetPath)
	info, err := os.Stat(cleanTarget)
	if err != nil {
		return nil, fmt.Errorf("target path %q not found or inaccessible: %w", opts.TargetPath, err)
	}

	profile := opts.Profile
	if profile == "" {
		profile = "default"
	}

	report := &ScanReport{
		SchemaVersion: "1.0",
		ScanTimestamp: time.Now().UTC().Format(time.RFC3339),
		TargetPath:    cleanTarget,
		Profile:       profile,
		VaultUnlocked: len(opts.VaultSecrets) > 0,
		Engines:       make(map[string]EngineStatus),
		Summary: ScanSummary{
			BySeverity:    map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
			ByFeasibility: map[string]int{"READY_NOW": 0, "NEEDS_WORKSPACE_ADAPTATION": 0, "SEC_AGENT_EXTENSION_OPPORTUNITY": 0},
		},
	}

	vaultNotes := "Locked (0 vault secrets loaded for exact-match comparison; run 'sec open' to enable exact vault value matching)"
	if report.VaultUnlocked {
		vaultNotes = fmt.Sprintf("Unlocked (%d vault secret(s) active for exact-match detection)", len(opts.VaultSecrets))
	}
	report.Engines["sec_native"] = EngineStatus{
		Name:      "sec-native",
		Active:    true,
		Installed: true,
		Version:   "built-in",
		Notes:     vaultNotes,
	}

	ignorePath := ".secignore"
	if info.IsDir() {
		candidateIgnore := filepath.Join(cleanTarget, ".secignore")
		if _, statErr := os.Stat(candidateIgnore); statErr == nil {
			ignorePath = candidateIgnore
		}
	}
	ignoreRules := LoadSecIgnoreRules(ignorePath)

	// Prepare active vault lookup map (value -> keyPath)
	vaultValToKey := make(map[string]string)
	for k, entry := range opts.VaultSecrets {
		if strings.HasPrefix(k, "__") {
			continue
		}
		v := strings.TrimSpace(entry.Value)
		if len(v) >= 6 && !isPlaceholderOrSafeValue(v) {
			vaultValToKey[v] = k
		}
	}

	var rawItems []ScanActionItem
	scannedCount := 0

	scanSingleFile := func(filePath string) {
		relPath := relativeDisplayPath(cleanTarget, filePath)
		if ShouldIgnoreFile(relPath, ignoreRules) || ShouldIgnoreFile(filePath, ignoreRules) {
			return
		}
		// Skip binary or huge files (> 2MB) to keep scans responsive
		fInfo, statErr := os.Stat(filePath)
		if statErr != nil || fInfo.IsDir() || fInfo.Size() > 2*1024*1024 {
			return
		}
		if isLikelyBinaryOrEncryptedFile(filePath) {
			return
		}

		scannedCount++
		items := scanFileNative(filePath, relPath, profile, vaultValToKey, ignoreRules)
		rawItems = append(rawItems, items...)
	}

	if !info.IsDir() {
		scanSingleFile(cleanTarget)
	} else {
		_ = filepath.WalkDir(cleanTarget, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				// Gracefully skip permission-denied directories (e.g. macOS TCC folders in ~)
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if path == cleanTarget {
					return nil
				}
				if SafeSkipDirs[name] {
					return filepath.SkipDir
				}
				if strings.HasPrefix(name, ".") && !IsAllowedHiddenEntry(name) {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") && !IsAllowedHiddenEntry(name) {
				// Also skip hidden non-credential files unless inside an allowed hidden directory
				parentBase := filepath.Base(filepath.Dir(path))
				if !AllowedDotfiles[parentBase] {
					return nil
				}
			}
			scanSingleFile(path)
			return nil
		})
	}

	// Execute external Homebrew scanners (gitleaks & optional trufflehog)
	extItems, extStatuses, extHints := RunExternalScanners(cleanTarget, info.IsDir(), opts, profile, vaultValToKey, ignoreRules)
	for k, st := range extStatuses {
		report.Engines[k] = st
	}
	report.ToolHints = append(report.ToolHints, extHints...)
	rawItems = append(rawItems, extItems...)

	// Deduplicate findings by (FilePath, LineNumber) and merge engine attributions
	deduped := deduplicateAndNumberActionItems(rawItems)
	report.ActionItems = deduped
	report.Summary.ScannedFiles = scannedCount
	report.Summary.TotalFindings = len(deduped)

	seenExtensions := make(map[string]bool)
	for _, item := range deduped {
		report.Summary.BySeverity[string(item.Severity)]++
		report.Summary.ByFeasibility[string(item.IntegrationStrategy.Feasibility)]++
		switch item.IntegrationStrategy.Feasibility {
		case FeasibilityReadyNow:
			report.Summary.ReadyNowCount++
		case FeasibilityNeedsAdaptation:
			report.Summary.NeedsAdaptationCount++
		case FeasibilityExtensionOpportunity:
			report.Summary.ExtensionOpportunityCount++
		}
		if item.IntegrationStrategy.ExtensionIdea != nil && item.IntegrationStrategy.ExtensionIdea.Applicable {
			slug := item.IntegrationStrategy.ExtensionIdea.FeatureSlug
			if !seenExtensions[slug] {
				seenExtensions[slug] = true
				report.ExtensionIdeas = append(report.ExtensionIdeas, *item.IntegrationStrategy.ExtensionIdea)
			}
		}
	}

	return report, nil
}

func expandHomePath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
	}
	return filepath.Clean(p)
}

func relativeDisplayPath(rootPath, filePath string) string {
	if rootPath == filePath {
		return filepath.Base(filePath)
	}
	if rel, err := filepath.Rel(rootPath, filePath); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return filePath
}

func isLikelyBinaryOrEncryptedFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".enc", ".kdbx", ".png", ".jpg", ".jpeg", ".gif", ".icns", ".ico", ".pdf", ".zip", ".tar", ".gz", ".tgz", ".wasm", ".so", ".dylib", ".a", ".o", ".exe", ".bin", ".sqlite", ".db", ".lock":
		return true
	}
	base := filepath.Base(filePath)
	if base == "go.sum" || base == "package-lock.json" || base == "yarn.lock" || base == "pnpm-lock.yaml" || strings.HasSuffix(base, "_test.go") {
		return true
	}
	// Check first 512 bytes for null byte
	// #nosec G304 G703
	f, err := os.Open(filePath)
	if err != nil {
		return true
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return true
		}
	}
	return false
}

func scanFileNative(filePath, relPath, profile string, vaultValToKey map[string]string, ignoreRules []string) []ScanActionItem {
	// #nosec G304 G703
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	base := filepath.Base(filePath)
	ext := strings.ToLower(filepath.Ext(filePath))
	isDotenv := base == ".env" || (strings.HasPrefix(base, ".env.") && !strings.HasSuffix(base, ".tmpl") && !strings.HasSuffix(base, ".example") && !strings.HasSuffix(base, ".sample"))
	isStaticCfg := ext == ".json" || ext == ".yaml" || ext == ".yml" || ext == ".toml" || ext == ".ini" || ext == ".conf" || ext == ".cfg" || base == ".npmrc" || base == ".netrc" || base == ".pgpass" || base == ".pypirc" || base == ".git-credentials"

	// First run script CLI flag scanner if applicable
	var items []ScanActionItem
	if IsScriptCandidate(filePath, false) && !isDotenv {
		if scriptFindings, sErr := ScanScriptFile(filePath); sErr == nil {
			for _, sf := range scriptFindings {
				strat := BuildIntegrationStrategy(profile, relPath, "INSECURE_SCRIPT_FLAG", "cli_password")
				items = append(items, ScanActionItem{
					Severity:            SeverityHigh,
					Category:            "INSECURE_SCRIPT_FLAG",
					Engines:             []string{"sec-native"},
					FilePath:            relPath,
					LineNumber:          sf.LineNumber,
					RuleID:              "sec-cli-password-flag",
					Description:         sf.Reason,
					RedactedSnippet:     ScrubSecretLine(sf.LineSnippet, sf.Match),
					Fingerprint:         ComputeFindingFingerprint(relPath, sf.LineNumber, "INSECURE_SCRIPT_FLAG", "sec-cli-password-flag"),
					IntegrationStrategy: strat,
				})
			}
		}
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if ShouldIgnoreLine(rawLine, ignoreRules) {
			continue
		}

		// 1. Check active vault exact match
		matchedVaultKey := ""
		matchedVaultVal := ""
		for vVal, vKey := range vaultValToKey {
			if strings.Contains(rawLine, vVal) {
				matchedVaultKey = vKey
				matchedVaultVal = vVal
				break
			}
		}

		// 2. If dotenv file, check for unmigrated KEY=VALUE entries
		if isDotenv {
			if m := dotenvKeyValRegex.FindStringSubmatch(rawLine); len(m) == 3 {
				envKey := m[1]
				envVal := strings.Trim(strings.TrimSpace(m[2]), `"'`)
				if !isPlaceholderOrSafeValue(envVal) {
					strat := BuildIntegrationStrategy(profile, relPath, "UNMIGRATED_DOTENV", envKey)
					desc := fmt.Sprintf("Plaintext dotenv variable %q is not migrated to sec-agent (<migrated_to_sec>)", envKey)
					if matchedVaultKey != "" {
						desc = fmt.Sprintf("Plaintext dotenv variable %q matches active vault secret %q", envKey, matchedVaultKey)
					}
					items = append(items, ScanActionItem{
						Severity:            SeverityCritical,
						Category:            "UNMIGRATED_DOTENV",
						Engines:             []string{"sec-native"},
						FilePath:            relPath,
						LineNumber:          lineNum,
						RuleID:              "sec-dotenv-plaintext",
						Description:         desc,
						MatchedVaultKey:     matchedVaultKey,
						RedactedSnippet:     fmt.Sprintf("%s=[REDACTED_BY_SEC]", envKey),
						Fingerprint:         ComputeFindingFingerprint(relPath, lineNum, "UNMIGRATED_DOTENV", "sec-dotenv-plaintext"),
						IntegrationStrategy: strat,
					})
					continue
				}
			}
		}

		// 3. Exact match against unlocked vault in any non-dotenv file
		if matchedVaultKey != "" {
			cat := "VAULT_SECRET_EXPOSED_IN_FILE"
			if isStaticCfg {
				cat = "STATIC_CONFIG_PLAINTEXT"
			}
			strat := BuildIntegrationStrategy(profile, relPath, cat, matchedVaultKey)
			items = append(items, ScanActionItem{
				Severity:            SeverityCritical,
				Category:            cat,
				Engines:             []string{"sec-native"},
				FilePath:            relPath,
				LineNumber:          lineNum,
				RuleID:              "sec-vault-exact-match",
				Description:         fmt.Sprintf("Plaintext value matches active vault secret %q in profile %q", matchedVaultKey, profile),
				MatchedVaultKey:     matchedVaultKey,
				RedactedSnippet:     ScrubSecretLine(rawLine, matchedVaultVal),
				Fingerprint:         ComputeFindingFingerprint(relPath, lineNum, cat, "sec-vault-exact-match"),
				IntegrationStrategy: strat,
			})
			continue
		}

		// 4. Built-in Known Token Regexes (AWS, GitHub, Stripe, Slack, DB URI, Private Key)
		matchedPattern := false
		for _, pat := range DefaultSecretPatterns {
			if found := pat.Regex.FindString(rawLine); found != "" {
				cat := "KNOWN_TOKEN_SIGNATURE"
				if isStaticCfg {
					cat = "STATIC_CONFIG_PLAINTEXT"
				}
				strat := BuildIntegrationStrategy(profile, relPath, cat, pat.Name)
				items = append(items, ScanActionItem{
					Severity:            SeverityHigh,
					Category:            cat,
					Engines:             []string{"sec-native"},
					FilePath:            relPath,
					LineNumber:          lineNum,
					RuleID:              "sec-pattern-" + strings.ToLower(strings.ReplaceAll(pat.Name, " ", "-")),
					Description:         fmt.Sprintf("Detected %s signature in plaintext file", pat.Name),
					RedactedSnippet:     ScrubSecretLine(rawLine, found),
					Fingerprint:         ComputeFindingFingerprint(relPath, lineNum, cat, pat.Name),
					IntegrationStrategy: strat,
				})
				matchedPattern = true
				break
			}
		}
		if matchedPattern {
			continue
		}

		// 5. Static config or source code password/secret/token assignment
		if isStaticCfg {
			if base == ".pgpass" {
				if m := pgpassLineRe.FindStringSubmatch(rawLine); len(m) == 2 && !isPlaceholderOrSafeValue(m[1]) {
					strat := BuildIntegrationStrategy(profile, relPath, "STATIC_CONFIG_PLAINTEXT", "pgpass_password")
					items = append(items, ScanActionItem{
						Severity:            SeverityHigh,
						Category:            "STATIC_CONFIG_PLAINTEXT",
						Engines:             []string{"sec-native"},
						FilePath:            relPath,
						LineNumber:          lineNum,
						RuleID:              "sec-pgpass-plaintext",
						Description:         "Plaintext PostgreSQL password in .pgpass file",
						RedactedSnippet:     ScrubSecretLine(rawLine, m[1]),
						Fingerprint:         ComputeFindingFingerprint(relPath, lineNum, "STATIC_CONFIG_PLAINTEXT", "sec-pgpass-plaintext"),
						IntegrationStrategy: strat,
					})
					continue
				}
			}
			if m := staticConfigAssignRe.FindStringSubmatch(rawLine); len(m) == 3 {
				kName := m[1]
				kVal := m[2]
				if !isPlaceholderOrSafeValue(kVal) {
					strat := BuildIntegrationStrategy(profile, relPath, "STATIC_CONFIG_PLAINTEXT", kName)
					items = append(items, ScanActionItem{
						Severity:            SeverityHigh,
						Category:            "STATIC_CONFIG_PLAINTEXT",
						Engines:             []string{"sec-native"},
						FilePath:            relPath,
						LineNumber:          lineNum,
						RuleID:              "sec-static-config-secret",
						Description:         fmt.Sprintf("Plaintext credential field %q in static configuration file", kName),
						RedactedSnippet:     ScrubSecretLine(rawLine, kVal),
						Fingerprint:         ComputeFindingFingerprint(relPath, lineNum, "STATIC_CONFIG_PLAINTEXT", "sec-static-config-secret"),
						IntegrationStrategy: strat,
					})
					continue
				}
			}
		} else if m := codeHardcodedAssignRe.FindStringSubmatch(rawLine); len(m) == 3 {
			kName := m[1]
			kVal := m[2]
			if !isPlaceholderOrSafeValue(kVal) {
				strat := BuildIntegrationStrategy(profile, relPath, "HARDCODED_SOURCE_SECRET", kName)
				items = append(items, ScanActionItem{
					Severity:            SeverityHigh,
					Category:            "HARDCODED_SOURCE_SECRET",
					Engines:             []string{"sec-native"},
					FilePath:            relPath,
					LineNumber:          lineNum,
					RuleID:              "sec-hardcoded-credential",
					Description:         fmt.Sprintf("Hardcoded credential assignment to %q in source/script file", kName),
					RedactedSnippet:     ScrubSecretLine(rawLine, kVal),
					Fingerprint:         ComputeFindingFingerprint(relPath, lineNum, "HARDCODED_SOURCE_SECRET", "sec-hardcoded-credential"),
					IntegrationStrategy: strat,
				})
			}
		}
	}

	return items
}

func deduplicateAndNumberActionItems(items []ScanActionItem) []ScanActionItem {
	type locKey struct {
		file string
		line int
	}
	byLoc := make(map[locKey]*ScanActionItem)
	var order []locKey

	for i := range items {
		it := items[i]
		k := locKey{file: it.FilePath, line: it.LineNumber}
		if existing, ok := byLoc[k]; ok {
			// Merge engine names
			for _, eng := range it.Engines {
				if !containsString(existing.Engines, eng) {
					existing.Engines = append(existing.Engines, eng)
				}
			}
			if it.VerifiedLive {
				existing.VerifiedLive = true
				existing.Severity = SeverityCritical
			}
			if it.MatchedVaultKey != "" && existing.MatchedVaultKey == "" {
				existing.MatchedVaultKey = it.MatchedVaultKey
				existing.Severity = SeverityCritical
			}
		} else {
			cloned := it
			byLoc[k] = &cloned
			order = append(order, k)
		}
	}

	// Sort deterministically: CRITICAL before HIGH before MEDIUM before LOW, then by file & line
	severityRank := map[ScanSeverity]int{
		SeverityCritical: 0,
		SeverityHigh:     1,
		SeverityMedium:   2,
		SeverityLow:      3,
	}
	sort.SliceStable(order, func(i, j int) bool {
		a := byLoc[order[i]]
		b := byLoc[order[j]]
		ra := severityRank[a.Severity]
		rb := severityRank[b.Severity]
		if ra != rb {
			return ra < rb
		}
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		return a.LineNumber < b.LineNumber
	})

	result := make([]ScanActionItem, 0, len(order))
	for idx, k := range order {
		it := byLoc[k]
		it.ID = fmt.Sprintf("ACT-%03d", idx+1)
		result = append(result, *it)
	}
	return result
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}
