package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"secure_secrets/internal/audit"
	"secure_secrets/internal/daemon"
)

func handleGitHookInstall(profile string, args []string) {
	global := false
	for _, arg := range args {
		if arg == "--global" {
			global = true
		}
	}

	hookPath := ""
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error determining user home directory: %v\n", err)
			os.Exit(1)
		}
		hooksDir := filepath.Join(home, ".config", "git", "hooks")
		if err := os.MkdirAll(hooksDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating global git hooks directory: %v\n", err)
			os.Exit(1)
		}
		hookPath = filepath.Join(hooksDir, "pre-commit")
		// #nosec G204
		_ = exec.Command("git", "config", "--global", "core.hooksPath", hooksDir).Run()
	} else {
		gitDirCmd := exec.Command("git", "rev-parse", "--git-dir")
		out, err := gitDirCmd.Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: Not a git repository (or any of the parent directories).")
			os.Exit(1)
		}
		gitDir := strings.TrimSpace(string(out))
		hooksDir := filepath.Join(gitDir, "hooks")
		if err := os.MkdirAll(hooksDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating git hooks directory: %v\n", err)
			os.Exit(1)
		}
		hookPath = filepath.Join(hooksDir, "pre-commit")
	}

	hookScript := `#!/bin/sh
# Installed by sec-agent (Phase 2 Privacy Guard)
sec-agent githook check "$@"
`
	// #nosec G306
	if err := os.WriteFile(hookPath, []byte(hookScript), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing pre-commit hook script to %s: %v\n", hookPath, err)
		os.Exit(1)
	}

	fmt.Printf("✅ Successfully installed sec-agent pre-commit privacy guard hook at: %s\n", hookPath)
}

func handleGitHookCheck(profile string, args []string) {
	gitDirCmd := exec.Command("git", "rev-parse", "--git-dir")
	if err := gitDirCmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error: Not a git repository.")
		os.Exit(1)
	}

	diffCmd := exec.Command("git", "diff", "--cached", "--name-only")
	out, err := diffCmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching staged git files: %v\n", err)
		os.Exit(1)
	}

	files := strings.Split(strings.TrimSpace(string(out)), "\n")
	var stagedFiles []string
	for _, f := range files {
		f = strings.TrimSpace(f)
		if f != "" {
			stagedFiles = append(stagedFiles, f)
		}
	}

	if len(stagedFiles) == 0 {
		os.Exit(0)
	}

	ignoreRules := audit.LoadSecIgnoreRules(".secignore")

	// Fetch active profile secrets for exact string matching
	vaultValues := make(map[string]string)
	req := daemon.IPCRequest{Action: "backup"}
	if resp, err := queryDaemon(profile, req); err == nil && resp != nil && resp.Success && resp.Secrets != nil {
		for k, entry := range resp.Secrets {
			v := strings.TrimSpace(entry.Value)
			if len(v) >= 6 {
				vaultValues[k] = v
			}
		}
	}

	violationsFound := false

	for _, file := range stagedFiles {
		if audit.ShouldIgnoreFile(file, ignoreRules) {
			continue
		}

		// #nosec G204
		diffFileCmd := exec.Command("git", "diff", "--cached", "-U0", "--", file)
		diffBytes, err := diffFileCmd.Output()
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(diffBytes)))
		lineNum := 0
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				addedContent := line[1:]
				lineNum++

				if audit.ShouldIgnoreLine(addedContent, ignoreRules) {
					continue
				}

				// 1. Check active vault value exact matches
				for vName, vVal := range vaultValues {
					if strings.Contains(addedContent, vVal) {
						fmt.Fprintf(os.Stderr, "❌ [sec Privacy Guard] Hardcoded Vault Secret Detected in staged file!\n")
						fmt.Fprintf(os.Stderr, "  • File: %s\n", file)
						fmt.Fprintf(os.Stderr, "  • Secret Name: %s\n", vName)
						fmt.Fprintf(os.Stderr, "  • Action: Please remove hardcoded secret before committing or use 'sec run -- ...'\n\n")
						violationsFound = true
					}
				}

				// 2. Check regex patterns
				for _, pattern := range audit.DefaultSecretPatterns {
					if pattern.Regex.MatchString(addedContent) {
						fmt.Fprintf(os.Stderr, "❌ [sec Privacy Guard] Potential Credentials / Key Detected!\n")
						fmt.Fprintf(os.Stderr, "  • File: %s\n", file)
						fmt.Fprintf(os.Stderr, "  • Pattern: %s\n", pattern.Name)
						fmt.Fprintf(os.Stderr, "  • Action: Remove sensitive credentials or add rule to .secignore\n\n")
						violationsFound = true
					}
				}

				// 3. High Entropy string detection
				if audit.IsHighEntropyString(addedContent) {
					fmt.Fprintf(os.Stderr, "⚠️  [sec Privacy Guard] Suspicious High-Entropy String Detected!\n")
					fmt.Fprintf(os.Stderr, "  • File: %s\n", file)
					fmt.Fprintf(os.Stderr, "  • Action: Review staged line to ensure no plaintext secret is leaked\n\n")
					violationsFound = true
				}
			}
		}
	}

	if violationsFound {
		fmt.Fprintln(os.Stderr, "🛑 Git pre-commit Privacy Guard check FAILED. Commit aborted to prevent secret leakage.")
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "✅ sec Privacy Guard: Staged files verified clean.")
}
