package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"secure_secrets/internal/audit"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
)

func handleScan(profile string, args []string) {
	targetPath := "."
	outputJSON := jsonErrors
	outputFile := ""
	gitHistory := false
	deep := false
	verifyLive := false
	installTools := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--json":
			outputJSON = true
		case arg == "--output" || arg == "-o":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--output="):
			outputFile = strings.TrimPrefix(arg, "--output=")
		case arg == "--git-history" || arg == "--history":
			gitHistory = true
		case arg == "--deep":
			deep = true
		case arg == "--verify-live":
			verifyLive = true
			deep = true
		case arg == "--install-tools":
			installTools = true
		case !strings.HasPrefix(arg, "-"):
			targetPath = arg
		}
	}

	// Opportunistically fetch active decrypted vault secrets if daemon is unlocked
	var vaultSecrets map[string]store.SecretEntry
	if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"}); err == nil && resp != nil && resp.Success && resp.Secrets != nil {
		vaultSecrets = resp.Secrets
	}

	report, err := audit.RunWorkspaceScan(audit.ScanOptions{
		TargetPath:   targetPath,
		Profile:      profile,
		GitHistory:   gitHistory,
		Deep:         deep,
		VerifyLive:   verifyLive,
		InstallTools: installTools,
		VaultSecrets: vaultSecrets,
	})
	if err != nil {
		fail("SCAN_ERROR", err, "Verify that the target path exists and is readable.")
	}

	if outputFile != "" {
		jsonBytes, mErr := json.MarshalIndent(report, "", "  ")
		if mErr != nil {
			fail("JSON_ENCODE_ERROR", mErr, "Failed to encode scan report as JSON.")
		}
		// #nosec G306 G703
		if wErr := os.WriteFile(outputFile, jsonBytes, 0600); wErr != nil {
			fail("FILE_WRITE_ERROR", wErr, fmt.Sprintf("Failed to write scan action list to %s.", outputFile))
		}
	}

	if outputJSON {
		jsonBytes, mErr := json.MarshalIndent(report, "", "  ")
		if mErr != nil {
			fail("JSON_ENCODE_ERROR", mErr, "Failed to encode scan report as JSON.")
		}
		fmt.Println(string(jsonBytes))
		if report.Summary.TotalFindings > 0 {
			os.Exit(1)
		}
		return
	}

	printScanReportHuman(report, outputFile)
	if report.Summary.TotalFindings > 0 {
		os.Exit(1)
	}
}

func printScanReportHuman(report *audit.ScanReport, savedFile string) {
	fmt.Printf("🛡️  sec-agent Workspace & Directory Security Scan: %s\n", report.TargetPath)

	var engBadges []string
	for _, key := range []string{"sec_native", "gitleaks", "trufflehog"} {
		if st, ok := report.Engines[key]; ok {
			if st.Active {
				ver := st.Version
				if ver == "" {
					ver = "active"
				}
				engBadges = append(engBadges, fmt.Sprintf("[✓ %s (%s)]", st.Name, ver))
			} else if st.Installed {
				engBadges = append(engBadges, fmt.Sprintf("[○ %s (installed, standby)]", st.Name))
			} else {
				engBadges = append(engBadges, fmt.Sprintf("[✗ %s (not installed)]", st.Name))
			}
		}
	}
	fmt.Printf("Engines: %s\n", strings.Join(engBadges, " "))
	if report.VaultUnlocked {
		fmt.Printf("Vault Exact-Match Engine: Unlocked (profile: %s)\n", report.Profile)
	} else {
		fmt.Printf("Vault Exact-Match Engine: Locked (profile: %s — run 'eval $(sec open)' to also detect custom vault passwords)\n", report.Profile)
	}
	fmt.Println(strings.Repeat("─", 88))

	for _, hint := range report.ToolHints {
		fmt.Printf("💡 Homebrew Tool Hint: %s\n", hint)
	}
	if len(report.ToolHints) > 0 {
		fmt.Println(strings.Repeat("─", 88))
	}

	if len(report.ActionItems) == 0 {
		fmt.Printf("\n\033[32m✅ [PASS] Scanned %d file(s): Zero plaintext credentials or unmigrated secrets detected!\033[0m\n", report.Summary.ScannedFiles)
		if savedFile != "" {
			fmt.Printf("💾 Machine-readable Security Improvement Action List saved to: %s\n", savedFile)
		}
		return
	}

	fmt.Printf("\n\033[1;31m🚨 SECURITY IMPROVEMENT ACTION LIST (%d Action Item(s) across %d Scanned File(s))\033[0m\n\n",
		report.Summary.TotalFindings, report.Summary.ScannedFiles)

	for _, item := range report.ActionItems {
		fmt.Printf("[%s] %s | %s (Tier: %s)\n",
			item.ID, item.Severity, item.Category, item.IntegrationStrategy.Feasibility)
		fmt.Printf("  • Location:          %s:%d (Engines: %s)\n",
			item.FilePath, item.LineNumber, strings.Join(item.Engines, ", "))
		fmt.Printf("  • Issue:             %s\n", item.Description)
		if item.MatchedVaultKey != "" {
			fmt.Printf("  • Vault Match:       Matches active secret %q in profile %q\n", item.MatchedVaultKey, report.Profile)
		}
		fmt.Printf("  • Redacted Snippet:  %s\n", item.RedactedSnippet)
		fmt.Printf("  • Suggested Command: %s\n", item.IntegrationStrategy.SuggestedCommand)

		if item.IntegrationStrategy.WorkspaceAdvice != nil {
			fmt.Printf("  • Workspace Advice:  %s\n", item.IntegrationStrategy.WorkspaceAdvice.Summary)
			for idx, step := range item.IntegrationStrategy.WorkspaceAdvice.Steps {
				fmt.Printf("      %d) %s\n", idx+1, step)
			}
		}
		if item.IntegrationStrategy.ExtensionIdea != nil && item.IntegrationStrategy.ExtensionIdea.Applicable {
			fmt.Printf("  • sec-agent Extend:  [%s] %s\n",
				item.IntegrationStrategy.ExtensionIdea.FeatureSlug,
				item.IntegrationStrategy.ExtensionIdea.Proposal)
		}
		fmt.Println()
	}

	if len(report.ExtensionIdeas) > 0 {
		fmt.Println("🧩 Discovered sec-agent Capability Extension Opportunities:")
		for _, idea := range report.ExtensionIdeas {
			fmt.Printf("  • [%s]: %s\n", idea.FeatureSlug, idea.Proposal)
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("─", 88))
	fmt.Printf("Summary: %d Total (%d READY_NOW, %d NEEDS_WORKSPACE_ADAPTATION, %d SEC_AGENT_EXTENSION_OPPORTUNITY)\n",
		report.Summary.TotalFindings,
		report.Summary.ReadyNowCount,
		report.Summary.NeedsAdaptationCount,
		report.Summary.ExtensionOpportunityCount)
	if savedFile != "" {
		fmt.Printf("💾 Machine-readable Security Improvement Action List saved to: %s\n", savedFile)
	} else {
		fmt.Println("💡 Tip: Re-run with '--json' or '--output .sec-audit-actions.json' for machine-readable processing.")
	}
}
