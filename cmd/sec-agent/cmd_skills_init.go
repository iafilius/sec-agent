package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"secure_secrets/internal/config"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
	"strings"
	"syscall"
	"time"
)

type InstalledSkillEntry struct {
	Target  string `json:"target"`  // e.g. antigravity, copilot, cursor, claude, windsurf
	Scope   string `json:"scope"`   // global or workspace
	Path    string `json:"path"`    // path where skill was written
	Version string `json:"version"` // sec-agent binary version at install time
}

type SkillManifest struct {
	Version string                `json:"version"`
	Skills  []InstalledSkillEntry `json:"skills"`
}

func loadSkillManifest() (*SkillManifest, error) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(cfgDir, "skills_manifest.json")
	// #nosec G304 G703
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var m SkillManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func saveSkillManifest(m *SkillManifest) error {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(cfgDir, "skills_manifest.json")
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// #nosec G304 G703
	return os.WriteFile(manifestPath, data, 0600)
}

func resolveSkillPath(target, scope string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	cwd, _ := os.Getwd()

	switch target {
	case "antigravity":
		if scope == "workspace" {
			if cwd == "" {
				return "", fmt.Errorf("workspace scope requires active working directory")
			}
			return filepath.Join(cwd, ".agents", "skills", "sec-agent-integration", "SKILL.md"), nil
		}
		return filepath.Join(homeDir, ".gemini", "config", "skills", "sec-agent-integration", "SKILL.md"), nil
	case "copilot":
		if cwd == "" {
			return "", fmt.Errorf("copilot skill requires active working directory")
		}
		return filepath.Join(cwd, ".github", "copilot-instructions.md"), nil
	case "cursor":
		if scope == "workspace" {
			if cwd == "" {
				return "", fmt.Errorf("workspace scope requires active working directory")
			}
			return filepath.Join(cwd, ".cursor", "rules", "sec-agent.mdc"), nil
		}
		return filepath.Join(homeDir, ".cursor", "rules", "sec-agent.mdc"), nil
	case "claude":
		if scope == "workspace" {
			if cwd == "" {
				return "", fmt.Errorf("workspace scope requires active working directory")
			}
			return filepath.Join(cwd, ".claude", "skills", "sec-agent.md"), nil
		}
		return filepath.Join(homeDir, ".claude", "skills", "sec-agent.md"), nil
	case "windsurf":
		if cwd == "" {
			return "", fmt.Errorf("windsurf skill requires active working directory")
		}
		return filepath.Join(cwd, ".windsurfrules"), nil
	default:
		return "", fmt.Errorf("unknown skill target %q (supported: antigravity, copilot, cursor, claude, windsurf)", target)
	}
}

func writeSkillToFile(targetPath string) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// #nosec G304 G703
	return os.WriteFile(targetPath, embeddedSkillBytes, 0600)
}

func handleSkillInstallTarget(target, scope string) bool {
	targetPath, err := resolveSkillPath(target, scope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Skill error: %v\n", err)
		return false
	}
	if err := writeSkillToFile(targetPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write skill file to %s: %v\n", targetPath, err)
		return false
	}
	fmt.Printf("[✓] Installed %s skill (%s) -> %s\n", target, scope, targetPath)

	manifest, _ := loadSkillManifest()
	if manifest == nil {
		manifest = &SkillManifest{Version: Version, Skills: []InstalledSkillEntry{}}
	}

	found := false
	for i, entry := range manifest.Skills {
		if entry.Target == target && entry.Scope == scope {
			manifest.Skills[i].Path = targetPath
			manifest.Skills[i].Version = Version
			found = true
			break
		}
	}
	if !found {
		manifest.Skills = append(manifest.Skills, InstalledSkillEntry{
			Target:  target,
			Scope:   scope,
			Path:    targetPath,
			Version: Version,
		})
	}
	_ = saveSkillManifest(manifest)
	return true
}

func syncInstalledSkillsIfOutdated() {
	if !config.IsConfigDirInitialized() {
		return
	}
	manifest, err := loadSkillManifest()
	if err != nil || manifest == nil || len(manifest.Skills) == 0 {
		return
	}
	if manifest.Version == Version {
		return
	}
	updatedCount := 0
	for i, entry := range manifest.Skills {
		targetPath, err := resolveSkillPath(entry.Target, entry.Scope)
		if err == nil {
			if writeErr := writeSkillToFile(targetPath); writeErr == nil {
				manifest.Skills[i].Version = Version
				manifest.Skills[i].Path = targetPath
				updatedCount++
			}
		}
	}
	if updatedCount > 0 {
		manifest.Version = Version
		_ = saveSkillManifest(manifest)
		fmt.Fprintf(os.Stderr, "[sec-agent] Automatically upgraded AI agent skills (%s) across %d location(s).\n", Version, updatedCount)
	}
}

func detectIDEEnvironment() (target string, scope string, name string) {
	cwd, _ := os.Getwd()

	if cwd != "" {
		if _, err := os.Stat(filepath.Join(cwd, ".agents")); err == nil {
			return "antigravity", "global", "Antigravity IDE (Global ~/.gemini/ config)"
		}
		if _, err := os.Stat(filepath.Join(cwd, ".github", "copilot-instructions.md")); err == nil {
			return "copilot", "workspace", "VS Code + Copilot (Workspace .github/ detected)"
		}
		if _, err := os.Stat(filepath.Join(cwd, ".cursor")); err == nil {
			return "cursor", "workspace", "Cursor (Workspace .cursor/ detected)"
		}
		if _, err := os.Stat(filepath.Join(cwd, ".claude")); err == nil {
			return "claude", "workspace", "Claude Code (Workspace .claude/ detected)"
		}
		if _, err := os.Stat(filepath.Join(cwd, ".windsurfrules")); err == nil {
			return "windsurf", "workspace", "Windsurf (Workspace .windsurfrules detected)"
		}
	}

	if os.Getenv("ANTIGRAVITY_AGENT") != "" ||
		os.Getenv("__CFBundleIdentifier") == "com.google.antigravity-ide" ||
		strings.Contains(os.Getenv("ANTIGRAVITY_EDITOR_APP_ROOT"), "Antigravity") ||
		strings.Contains(os.Getenv("PATH"), ".gemini/antigravity-ide") {
		return "antigravity", "global", "Antigravity IDE (AGY Shell Environment)"
	}

	if os.Getenv("CURSOR_AGENT") != "" || strings.Contains(os.Getenv("PATH"), "Cursor") {
		return "cursor", "global", "Cursor (Shell Environment)"
	}

	if os.Getenv("CLAUDE_CODE") != "" || os.Getenv("CLAUDE") != "" {
		return "claude", "global", "Claude Code (Shell Environment)"
	}

	if os.Getenv("WINDSURF") != "" {
		return "windsurf", "workspace", "Windsurf (Shell Environment)"
	}

	if os.Getenv("VSCODE_PID") != "" && os.Getenv("ANTIGRAVITY_AGENT") == "" {
		return "copilot", "workspace", "VS Code + GitHub Copilot (Shell Environment)"
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		if _, err := os.Stat(filepath.Join(homeDir, ".gemini")); err == nil {
			return "antigravity", "global", "Antigravity IDE (Global ~/.gemini/ detected)"
		}
		if _, err := os.Stat(filepath.Join(homeDir, ".cursor")); err == nil {
			return "cursor", "global", "Cursor (Global ~/.cursor/ detected)"
		}
		if _, err := os.Stat(filepath.Join(homeDir, ".claude")); err == nil {
			return "claude", "global", "Claude Code (Global ~/.claude/ detected)"
		}
	}

	return "antigravity", "global", "Antigravity IDE (Default)"
}

func handleInit(profile string, args []string) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialization error: %v\n", err)
		os.Exit(1)
	}
	snapshotsDir := filepath.Join(cfgDir, "snapshots")
	_ = os.MkdirAll(snapshotsDir, 0700)

	fmt.Println("=== 🔑 sec-agent Vault Onboarding & Setup ===")
	fmt.Printf("[✓] Vault configuration directory initialized at %s\n", cfgDir)
	fmt.Printf("[✓] Automatic point-in-time snapshots folder initialized at %s\n", snapshotsDir)

	detectedTarget, detectedScope, detectedName := detectIDEEnvironment()
	fmt.Printf("[ℹ] Auto-detected Active Environment: %s\n", detectedName)

	syncInstalledSkillsIfOutdated()

	nonInteractive := false
	skillTarget := ""
	skillScope := "global"
	for i := 0; i < len(args); i++ {
		if args[i] == "--non-interactive" || args[i] == "-y" || args[i] == "--yes" {
			nonInteractive = true
		} else if args[i] == "--skill" && i+1 < len(args) {
			skillTarget = args[i+1]
			i++
		} else if args[i] == "--scope" && i+1 < len(args) {
			skillScope = args[i+1]
			i++
		}
	}

	if skillTarget != "" {
		handleSkillInstallTarget(skillTarget, skillScope)
		return
	}

	if nonInteractive || !isInteractiveTerminal() {
		handleSkillInstallTarget(detectedTarget, detectedScope)
		fmt.Println("\nInitialization complete.")
		return
	}

	fmt.Println("\nSelect AI Assistant environment(s) to install integration skills:")
	fmt.Println("  [1] Antigravity IDE (Global: ~/.gemini/config/skills/)")
	fmt.Println("  [2] Antigravity IDE (Workspace: .agents/skills/)")
	fmt.Println("  [3] VS Code + GitHub Copilot (.github/copilot-instructions.md)")
	fmt.Println("  [4] Cursor (Global: ~/.cursor/rules/ | Workspace: .cursor/rules/)")
	fmt.Println("  [5] Claude Code (Global: ~/.claude/skills/ | Workspace: .claude/skills/)")
	fmt.Println("  [6] Windsurf (.windsurfrules)")
	fmt.Println("  [7] Skip AI skill installation")

	fmt.Print("\nEnter selection (e.g. 1,3 or 'all' or '7'): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" || input == "7" || input == "skip" {
		fmt.Println("Skipped AI skill installation. Setup complete!")
		return
	}

	choices := strings.Split(input, ",")
	for _, choice := range choices {
		choice = strings.TrimSpace(choice)
		switch choice {
		case "1":
			handleSkillInstallTarget("antigravity", "global")
		case "2":
			handleSkillInstallTarget("antigravity", "workspace")
		case "3":
			handleSkillInstallTarget("copilot", "workspace")
		case "4":
			handleSkillInstallTarget("cursor", "global")
			handleSkillInstallTarget("cursor", "workspace")
		case "5":
			handleSkillInstallTarget("claude", "global")
			handleSkillInstallTarget("claude", "workspace")
		case "6":
			handleSkillInstallTarget("windsurf", "workspace")
		case "all":
			handleSkillInstallTarget("antigravity", "global")
			handleSkillInstallTarget("antigravity", "workspace")
			handleSkillInstallTarget("copilot", "workspace")
			handleSkillInstallTarget("cursor", "global")
			handleSkillInstallTarget("claude", "global")
			handleSkillInstallTarget("windsurf", "workspace")
		}
	}

	fmt.Println("\nSetup complete! You can re-run 'sec-agent init' anytime to update settings or install skills.")
}

func handleSkill(profile string, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sec-agent skill <install|status|update> [args]")
		os.Exit(1)
	}

	sub := args[0]
	switch sub {
	case "install":
		target := ""
		scope := "global"
		for i := 1; i < len(args); i++ {
			if (args[i] == "--target" || args[i] == "-t") && i+1 < len(args) {
				target = args[i+1]
				i++
			} else if (args[i] == "--scope" || args[i] == "-s") && i+1 < len(args) {
				scope = args[i+1]
				i++
			}
		}
		if target == "" {
			handleInit(profile, nil)
			return
		}
		handleSkillInstallTarget(target, scope)
	case "status", "list", "ls":
		manifest, err := loadSkillManifest()
		if err != nil || manifest == nil {
			fmt.Println("No skill manifest found. Run 'sec-agent init' or 'sec-agent skill install' to configure skills.")
			return
		}
		fmt.Println("=== 🤖 sec-agent AI Skill Installation Status ===")
		fmt.Printf("Binary Skill Version: %s\n\n", Version)
		if len(manifest.Skills) == 0 {
			fmt.Println("No skills currently tracked in manifest.")
			return
		}
		for _, s := range manifest.Skills {
			status := "[✓] Up to date"
			if s.Version != Version {
				status = fmt.Sprintf("[!] Outdated (installed %s)", s.Version)
			}
			fmt.Printf("  • %-15s (%-9s) %s\n", s.Target, s.Scope, status)
			fmt.Printf("    Path: %s\n", s.Path)
		}
	case "update":
		manifest, err := loadSkillManifest()
		if err != nil || manifest == nil || len(manifest.Skills) == 0 {
			fmt.Println("No skills tracked in manifest to update.")
			return
		}
		updated := 0
		for i, entry := range manifest.Skills {
			targetPath, err := resolveSkillPath(entry.Target, entry.Scope)
			if err == nil {
				if writeErr := writeSkillToFile(targetPath); writeErr == nil {
					manifest.Skills[i].Version = Version
					manifest.Skills[i].Path = targetPath
					updated++
					fmt.Printf("[✓] Updated %s (%s) -> %s\n", entry.Target, entry.Scope, targetPath)
				}
			}
		}
		manifest.Version = Version
		_ = saveSkillManifest(manifest)
		fmt.Printf("\nSuccessfully updated %d skill location(s) to %s.\n", updated, Version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown skill subcommand %q. Supported: install, status, update\n", sub)
		os.Exit(1)
	}
}

func handleInitShell(args []string) {
	targetShell := "zsh"
	if len(args) > 0 && args[0] != "" {
		targetShell = strings.ToLower(args[0])
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fail("HOME_DIR_NOT_FOUND", err, "")
	}

	rcFile := filepath.Join(homeDir, ".zshrc")
	if targetShell == "bash" {
		rcFile = filepath.Join(homeDir, ".bashrc")
		if _, err := os.Stat(rcFile); os.IsNotExist(err) {
			rcFile = filepath.Join(homeDir, ".bash_profile")
		}
	}

	existingContent := ""
	// #nosec G304 G703
	if data, err := os.ReadFile(rcFile); err == nil {
		existingContent = string(data)
	}

	aliasLine := "alias sec=sec-agent"
	compSnippet := fmt.Sprintf("if command -v sec-agent >/dev/null 2>&1; then eval \"$(sec-agent shell-completion %s)\"; fi", targetShell)
	// #nosec G101
	chpwdSnippet := `_sec_chpwd_hook() {
  if [ -f .secrc ]; then
    local prof
    prof=$(grep -o '"profile":[[:space:]]*"[^"]*"' .secrc 2>/dev/null | cut -d'"' -f4)
    if [ -n "$prof" ] && [ "$prof" != "$SEC_PROFILE" ]; then
      export SEC_PROFILE="$prof"
    fi
  fi
}
if [ -n "$ZSH_VERSION" ]; then
  autoload -U add-zsh-hook 2>/dev/null
  add-zsh-hook chpwd _sec_chpwd_hook 2>/dev/null
fi`

	if strings.Contains(existingContent, aliasLine) && strings.Contains(existingContent, "shell-completion") && strings.Contains(existingContent, "_sec_chpwd_hook") {
		fmt.Printf("✨ sec-agent shell integration and %s completions are already installed in %s\n", targetShell, rcFile)
		return
	}

	var builder strings.Builder
	if len(existingContent) > 0 && !strings.HasSuffix(existingContent, "\n") {
		builder.WriteString("\n")
	}
	builder.WriteString("\n# sec-agent Shell Integration & Autocompletions\n")
	if !strings.Contains(existingContent, aliasLine) {
		builder.WriteString(aliasLine + "\n")
	}
	if !strings.Contains(existingContent, "shell-completion") {
		builder.WriteString(compSnippet + "\n")
	}
	if !strings.Contains(existingContent, "_sec_chpwd_hook") {
		builder.WriteString(chpwdSnippet + "\n")
	}

	// #nosec G304 G703
	f, err := os.OpenFile(rcFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fail("FILE_WRITE_ERROR", fmt.Errorf("Failed opening %s for appending: %v", rcFile, err), "")
	}
	defer f.Close()

	if _, err := f.WriteString(builder.String()); err != nil {
		fail("FILE_WRITE_ERROR", fmt.Errorf("Failed appending shell integration to %s: %v", rcFile, err), "")
	}

	fmt.Printf("✅ Added 'alias sec=sec-agent' and %s completions to %s\n", targetShell, rcFile)
	fmt.Printf("💡 Run 'source %s' or open a new terminal tab to activate.\n", rcFile)
}

func handleFeedback(args []string) {
	showJSON := false
	showExample := false
	for _, a := range args {
		if a == "--json" {
			showJSON = true
		} else if a == "--example" || a == "-e" {
			showExample = true
		}
	}

// AgentExampleUseCaseDTO represents a structured feedback example item.
type AgentExampleUseCaseDTO struct {
	Component string `json:"component"`
	Example   string `json:"example"`
	Reason    string `json:"reason"`
}

// AgentRoadmapSuggestionDTO represents a roadmap suggestion item.
type AgentRoadmapSuggestionDTO struct {
	Feature string `json:"feature"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

// AgentFeedbackDTO represents structured agent feedback guidelines.
type AgentFeedbackDTO struct {
	Tool                      string                      `json:"tool"`
	DesiredFeedbackCategories []string                    `json:"desired_feedback_categories"`
	ExampleUsecases           []AgentExampleUseCaseDTO    `json:"example_usecases"`
	FutureRoadmapSuggestions  []AgentRoadmapSuggestionDTO `json:"future_roadmap_suggestions"`
}

	if showJSON {
		resp := AgentFeedbackDTO{
			Tool: "sec-agent",
			DesiredFeedbackCategories: []string{
				"operational_usecases_and_network_hardware",
				"missing_cli_flags_or_subcommands",
				"ai_skill_integration_friction",
				"security_and_compliance_gaps",
			},
			ExampleUsecases: []AgentExampleUseCaseDTO{
				{
					Component: "Network Hardware & Embedded Systems",
					Example:   "Xiaomi AX3600 OpenWrt SSH & LuCI admin notes preservation",
					Reason:    "Prevents losing Dropbear SSH flags (-o HostKeyAlgorithms=+ssh-rsa) and HTTPS port bindings (443/668).",
				},
				{
					Component: "Vault Migration",
					Example:   "KeePassXC .kdbx Full Metadata Import",
					Reason:    "Preserves custom string attributes (TOTP secrets, PINs, recovery codes) during vault consolidation.",
				},
			},
			FutureRoadmapSuggestions: []AgentRoadmapSuggestionDTO{
				{
					Feature: "Centralized Remote Vault Sync Adapter",
					Status:  "Optional Suggestion (Non-Binding / No Commitment)",
					Details: "Optional background OIDC/SSO sync module to mirror enterprise secrets from corporate vaults (HashiCorp Vault, AWS Secrets Manager, GCP) while preserving Touch ID offline security.",
				},
			},
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return
	}

	if showExample {
		fmt.Println(`=== sec-agent Feature Proposal & Feedback Example Template ===

# Proposal: [Feature Name]
**Target Repository:** secure_secrets
**Target Component:** sec-agent CLI & Embedded AI Skill
**Evaluation Date:** ` + time.Now().Format("2006-01-02") + `

## 1. Executive Summary & Operational Motivation
- **Problem Statement:** What friction or issue occurs in real-world usage?
- **Why Now:** Why is this enhancement required (lost context, security, automation ease)?

## 2. Proposed Architectural Enhancements
- Specific CLI subcommands, flags, or data structure changes.
- Example CLI commands and output formats.

## 3. Real-World Usecases & Impact
- Hardware/Network device management (routers, switches, firewalls).
- AI agent workflow integration ease.`)
		return
	}

	fmt.Println(`=== 🤖 sec-agent AI & User Feedback Guidance ===

sec-agent welcomes actionable feedback and feature proposals! To help us continuously improve sec-agent:

1. 🎯 What Information We Desire:
   • Operational Usecases: Real-world workflows (e.g. router SSH/HTTPS endpoints, Dropbear flags, KeePassXC custom fields).
   • Workflow Friction: Missing CLI flags, unexpected shell formatting, or AI skill integration gaps.
   • Security & Governance: Memory safety, session scoping, audit log requirements.

2. 💡 Why Feature Motivators Matter:
   • Documenting the exact problem, operational context, and business rationale ensures new features are built to high quality standards without scope drift.

3. 🛠️ Quick Commands:
   • sec-agent feedback --example  : View full markdown proposal template & examples
   • sec-agent feedback --json     : Output structured feedback schema for AI assistants`)
}

func handleBackupList(profile string) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	snapshotsDir := filepath.Join(cfgDir, "snapshots")
	prof := profile
	if prof == "" {
		prof = "default"
	}
	snapshotsDir = filepath.Join(snapshotsDir, prof)

	fmt.Println("=== 📁 sec-agent Vault Snapshots & Backups ===")
	fmt.Printf("Search Path: %s\n\n", snapshotsDir)

	entries, err := os.ReadDir(snapshotsDir)
	if err != nil || len(entries) == 0 {
		fmt.Println("  No automatic write snapshots found in snapshots directory.")
	} else {
		fmt.Println("Automatic Write Snapshots (.enc):")
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".enc") {
				info, _ := entry.Info()
				size := int64(0)
				modTime := ""
				if info != nil {
					size = info.Size()
					modTime = info.ModTime().Format("2006-01-02 15:04:05")
				}
				fullPath := filepath.Join(snapshotsDir, entry.Name())
				fmt.Printf("  • %s  (%d bytes, %s)\n", entry.Name(), size, modTime)
				fmt.Printf("    Path: %s\n", fullPath)
			}
		}
	}

	localEntries, err := os.ReadDir(".")
	if err == nil {
		fmt.Println("\nLocal KeePassXC Backup Files (.kdbx):")
		count := 0
		for _, entry := range localEntries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".kdbx") {
				info, _ := entry.Info()
				size := int64(0)
				modTime := ""
				if info != nil {
					size = info.Size()
					modTime = info.ModTime().Format("2006-01-02 15:04:05")
				}
				fmt.Printf("  • %s  (%d bytes, %s)\n", entry.Name(), size, modTime)
				count++
			}
		}
		if count == 0 {
			fmt.Println("  No .kdbx backup files in current directory.")
		}
	}
}

func handleUniversalDedupe(activeProfile string, args []string) {
	fromProfile := activeProfile
	if fromProfile == "" {
		fromProfile = "default"
	}
	toProfile := ""
	prefix := ""
	dryRun := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if (arg == "--from" || arg == "-f") && i+1 < len(args) {
			fromProfile = args[i+1]
			i++
		} else if (arg == "--to" || arg == "-t") && i+1 < len(args) {
			toProfile = args[i+1]
			i++
		} else if (arg == "--prefix" || arg == "-p") && i+1 < len(args) {
			prefix = args[i+1]
			i++
		} else if arg == "--dry-run" || arg == "--dryrun" {
			dryRun = true
		}
	}

	if toProfile == "" {
		fmt.Fprintln(os.Stderr, "❌ Error: Target profile '--to <profile>' is required.")
		fmt.Fprintln(os.Stderr, "Usage: sec dedupe [--from <src>] --to <dst> [--prefix <prefix>] [--dry-run]")
		fmt.Fprintln(os.Stderr, "Example: sec dedupe --from default --to dev --prefix aws/")
		os.Exit(1)
	}

	if fromProfile == toProfile {
		fmt.Fprintln(os.Stderr, "❌ Error: Source and target profiles cannot be identical.")
		os.Exit(1)
	}

	modeStr := ""
	if dryRun {
		modeStr = " (DRY-RUN PREVIEW)"
	}
	fmt.Printf("\n🔀 Running Secret Deduplication%s: [%s] ➔ [%s]\n", modeStr, fromProfile, toProfile)
	fmt.Println(strings.Repeat("─", 70))

	srcGetter, srcSetter := keychain.GetKeychainAccessPair(fromProfile)
	srcKey, err := store.InitializeMasterKey(fromProfile, srcGetter, srcSetter)
	if err != nil || len(srcKey) == 0 {
		fmt.Printf("  ⚠️ Source profile %q key unavailable or session locked. Please run 'sec open --profile %s' first.\n", fromProfile, fromProfile)
		return
	}

	dstGetter, dstSetter := keychain.GetKeychainAccessPair(toProfile)
	dstKey, err := store.InitializeMasterKey(toProfile, dstGetter, dstSetter)
	if err != nil || len(dstKey) == 0 {
		dstKey = srcKey
	}

	var prefixes []string
	if prefix != "" {
		prefixes = []string{prefix}
	}

	if dryRun {
		prefDesc := "all secrets"
		if len(prefixes) > 0 {
			prefDesc = fmt.Sprintf("prefix %q", prefix)
		}
		fmt.Printf("  • [DRY-RUN WOULD DEDUPLICATE] Matching %s from [%s] -> [%s]\n", prefDesc, fromProfile, toProfile)
		return
	}

	movedKeys, err := store.DeduplicateProfileSecrets(fromProfile, toProfile, prefixes, srcKey, dstKey)
	if err != nil {
		fmt.Printf("  ❌ Deduplication failed: %v\n", err)
	} else if len(movedKeys) == 0 {
		fmt.Printf("  ✨ Profile %q is clean (0 matching secret keys to deduplicate).\n", fromProfile)
	} else {
		fmt.Printf("  ✨ Successfully deduplicated %d secret key(s) from [%s] -> [%s]:\n", len(movedKeys), fromProfile, toProfile)
		for _, k := range movedKeys {
			fmt.Printf("    • [MOVED] %s -> %s\n", k, toProfile)
		}
	}
}

func handleCleanup(profile string, dryRun bool) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		fail("CONFIG_ERROR", err, "")
	}

	modeStr := "CLEANUP"
	if dryRun {
		modeStr = "CLEANUP (DRY-RUN PREVIEW)"
	}

	fmt.Printf("\n🧹 sec-agent Storage & Keychain %s\n", modeStr)
	fmt.Println(strings.Repeat("─", 70))

	var activeVaults []string
	var legacyBakFiles []string
	var orphanedLockFiles []string
	var freedBytes int64

	// #nosec G304 G703
	_ = filepath.Walk(cfgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		// Identify active main vault database files vs temporary test artifact files
		if name == "secrets.enc" || (strings.HasPrefix(name, "secrets_") && strings.HasSuffix(name, ".enc")) {
			isTestArtifact := strings.Contains(name, "copy-") || strings.Contains(name, "-test") || strings.Contains(name, "test-")
			if isTestArtifact {
				legacyBakFiles = append(legacyBakFiles, path)
				freedBytes += info.Size()
				return nil
			}
			schemaTag := "v1.0 Legacy Vault"
			if store.IsV2Vault(path) {
				schemaTag = "v2.0 Dual-Slot Vault"
			}
			activeVaults = append(activeVaults, fmt.Sprintf("%s (%s)", path, schemaTag))
			return nil
		}
		// Exclude active socket / pid files for running daemon processes
		if strings.HasSuffix(name, ".sock") || strings.HasSuffix(name, ".pid") {
			pidFile := strings.TrimSuffix(path, ".sock") + ".pid"
			if strings.HasSuffix(path, ".pid") {
				pidFile = path
			}
			// #nosec G122 G304 G703
			if pidData, err := os.ReadFile(pidFile); err == nil {
				var pid int
				if _, err := fmt.Sscanf(string(pidData), "%d", &pid); err == nil && pid > 0 {
					if process, err := os.FindProcess(pid); err == nil {
						if err := process.Signal(syscall.Signal(0)); err == nil {
							// Active running daemon process: preserve socket & pid file
							return nil
						}
					}
				}
			}
		}

		isBackupSnapshot := strings.Contains(name, ".bak.") || strings.HasSuffix(name, ".bak") ||
			(strings.HasPrefix(name, "secrets.enc.") && len(name) > len("secrets.enc.")) ||
			(strings.HasPrefix(name, "secrets_") && strings.Contains(name, ".enc."))

		isOrphanedLock := (strings.HasSuffix(name, ".sock") || strings.HasSuffix(name, ".pid") || strings.HasSuffix(name, ".tmp"))

		if isBackupSnapshot {
			legacyBakFiles = append(legacyBakFiles, path)
			freedBytes += info.Size()
		} else if isOrphanedLock {
			orphanedLockFiles = append(orphanedLockFiles, path)
			freedBytes += info.Size()
		}
		return nil
	})

	if len(activeVaults) > 0 {
		fmt.Printf("\n🛡️ Protected Active Vaults (Preserved — Never Deleted):\n")
		for _, v := range activeVaults {
			fmt.Printf("  • [✓ SAFE] %s\n", v)
		}
	}

	if len(legacyBakFiles) > 0 {
		fmt.Printf("\n📁 Legacy (v1.0) & Rolling Backup Snapshots Identified (%d items):\n", len(legacyBakFiles))
		for _, f := range legacyBakFiles {
			if dryRun {
				fmt.Printf("  • [DRY-RUN WOULD REMOVE] %s\n", f)
			} else {
				// #nosec G703
				if err := os.Remove(f); err == nil {
					fmt.Printf("  • [✓ REMOVED] %s\n", f)
				} else {
					fmt.Printf("  • [❌ FAILED TO REMOVE] %s: %v\n", f, err)
				}
			}
		}
	} else {
		fmt.Println("\n📁 Legacy (v1.0) & Rolling Backup Snapshots: None found (Clean).")
	}

	if len(orphanedLockFiles) > 0 {
		fmt.Printf("\n🔒 Orphaned Lock & Socket Files Identified (%d items):\n", len(orphanedLockFiles))
		for _, f := range orphanedLockFiles {
			if dryRun {
				fmt.Printf("  • [DRY-RUN WOULD REMOVE] %s\n", f)
			} else {
				// #nosec G703
				if err := os.Remove(f); err == nil {
					fmt.Printf("  • [✓ REMOVED] %s\n", f)
				} else {
					fmt.Printf("  • [❌ FAILED TO REMOVE] %s: %v\n", f, err)
				}
			}
		}
	} else {
		fmt.Println("\n🔒 Orphaned Sockets & Locks: None found (Clean).")
	}

	totalCount := len(legacyBakFiles) + len(orphanedLockFiles)
	fmt.Println("\n" + strings.Repeat("─", 70))
	if dryRun {
		fmt.Printf("Summary: %d item(s) would be deleted (approx. %s freed).\n", totalCount, formatBytes(freedBytes))
		fmt.Println("Active vaults remain 100% untouched.")
		fmt.Println("To perform actual deletion, run: 'sec cleanup'")
	} else {
		fmt.Printf("✨ Cleanup complete. %d item(s) removed (approx. %s freed).\n", totalCount, formatBytes(freedBytes))
	}
}

