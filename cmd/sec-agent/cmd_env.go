package main

import (
	"encoding/json"
	"fmt"
	"os"
	"secure_secrets/internal/config"
	"sort"
	"strings"

	"golang.org/x/term"
)

func formatTierBadge(tier config.EnvironmentTier) string {
	switch tier {
	case config.TierProd:
		return "prod 🔴"
	case config.TierStaging:
		return "staging 🟡"
	case config.TierDev:
		return "dev"
	default:
		return tier.String()
	}
}

// handleUse implements process-scoped, zero-disk environment switching.
func handleUse(profile string, args []string) {
	clearContext := false
	forceExport := false
	var targetAlias string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--clear" || a == "-c" {
			clearContext = true
		} else if a == "--export" {
			forceExport = true
		} else if !strings.HasPrefix(a, "-") && targetAlias == "" {
			targetAlias = a
		}
	}

	isTTY := term.IsTerminal(int(os.Stdout.Fd())) && !forceExport

	if clearContext {
		if isTTY {
			fmt.Println("✨ Active workspace context cleared.")
			fmt.Println("💡 To apply to your current shell session, run:")
			fmt.Println("  eval $(sec use --clear)")
		} else {
			fmt.Println("unset SEC_ENV;")
			fmt.Println("unset SEC_PROFILE;")
		}
		return
	}

	wsCfg := loadWorkspaceConfig()
	if targetAlias == "" {
		if wsCfg == nil || len(wsCfg.Environments) == 0 {
			fail("NO_ENVIRONMENTS", fmt.Errorf("no workspace environments configured in .secrc"), "Add an 'environments' section to .secrc to enable environment contexts.")
		}
		currentEnv := os.Getenv("SEC_ENV")
		if currentEnv == "" {
			currentEnv = wsCfg.Default
		}
		if isTTY {
			fmt.Printf("Active Environment: %s\n", currentEnv)
			if env, ok := wsCfg.Environments[currentEnv]; ok {
				fmt.Printf("Active Profile:     %s\n", env.Profile)
				fmt.Printf("Tier:               %s\n", formatTierBadge(env.ParsedTier()))
			}
			fmt.Println("\nUsage:")
			fmt.Println("  eval $(sec use <alias>)   Switch active environment in current shell")
			fmt.Println("  eval $(sec use --clear)   Clear active environment context")
			fmt.Println("  sec env ls                List all available workspace environments")
		} else {
			if env, ok := wsCfg.Environments[currentEnv]; ok {
				fmt.Printf("export SEC_ENV=\"%s\";\n", currentEnv)
				fmt.Printf("export SEC_PROFILE=\"%s\";\n", env.Profile)
			}
		}
		return
	}

	if wsCfg == nil || len(wsCfg.Environments) == 0 {
		fail("NO_ENVIRONMENTS", fmt.Errorf("no workspace environments configured in .secrc"), "Add an 'environments' section to .secrc to enable environment contexts.")
	}

	targetEnv, ok := wsCfg.Environments[targetAlias]
	if !ok {
		var available []string
		for k := range wsCfg.Environments {
			available = append(available, k)
		}
		sort.Strings(available)
		fail("ENVIRONMENT_NOT_FOUND", fmt.Errorf("environment alias %q not found in .secrc", targetAlias), fmt.Sprintf("Available environments: %s. Run 'sec env ls' to view details.", strings.Join(available, ", ")))
	}

	if isTTY {
		fmt.Printf("Target Environment: %s\n", targetAlias)
		fmt.Printf("Target Profile:     %s\n", targetEnv.Profile)
		fmt.Printf("Tier:               %s\n", formatTierBadge(targetEnv.ParsedTier()))
		if targetEnv.Description != "" {
			fmt.Printf("Description:        %s\n", targetEnv.Description)
		}
		fmt.Println()
		fmt.Printf("💡 To activate '%s' in this shell session, run:\n", targetAlias)
		fmt.Printf("  eval $(sec use %s)\n", targetAlias)
	} else {
		fmt.Printf("export SEC_ENV=\"%s\";\n", targetAlias)
		fmt.Printf("export SEC_PROFILE=\"%s\";\n", targetEnv.Profile)
	}
}

// EnvironmentListEntry represents an environment in JSON or tabular introspection.
type EnvironmentListEntry struct {
	Alias       string `json:"alias"`
	Profile     string `json:"profile"`
	Tier        string `json:"tier"`
	Active      bool   `json:"active"`
	Description string `json:"description,omitempty"`
}

// handleEnv handles 'sec env' and 'sec env ls'.
func handleEnv(profile string, args []string) {
	isListSubcmd := len(args) > 0 && (args[0] == "ls" || args[0] == "list")
	hasJSONFlag := jsonErrors
	for _, a := range args {
		if a == "--json" {
			hasJSONFlag = true
		}
	}

	wsCfg := loadWorkspaceConfig()
	isMultiEnv := wsCfg != nil && (wsCfg.Version >= 2 || len(wsCfg.Environments) > 1)

	// If not explicitly asking to list environments (and not bare multi-env introspection),
	// preserve 100% backward-compatible secret export behavior.
	if !isListSubcmd && !(hasJSONFlag && len(args) == 1) && !(len(args) == 0 && isMultiEnv) {
		handleLegacyExportEnv(profile, args)
		return
	}

	if wsCfg == nil || len(wsCfg.Environments) == 0 {
		if hasJSONFlag {
			fmt.Println("[]")
			return
		}
		fmt.Println("No environments configured in workspace .secrc.")
		return
	}

	currentEnv := os.Getenv("SEC_ENV")
	if currentEnv == "" {
		currentEnv = wsCfg.Default
	}

	var aliases []string
	for a := range wsCfg.Environments {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)

	var entries []EnvironmentListEntry
	for _, alias := range aliases {
		env := wsCfg.Environments[alias]
		isActive := alias == currentEnv
		entries = append(entries, EnvironmentListEntry{
			Alias:       alias,
			Profile:     env.Profile.String(),
			Tier:        env.Tier,
			Active:      isActive,
			Description: env.Description,
		})
	}

	if hasJSONFlag {
		data, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println("  ACTIVE  ALIAS                 PROFILE              TIER         DESCRIPTION")
	for _, e := range entries {
		activeMarker := " "
		if e.Active {
			activeMarker = "*"
		}
		tierBadge := formatTierBadge(config.ParseEnvironmentTier(e.Tier))
		fmt.Printf("%-2s %-6s %-20s %-20s %-12s %s\n",
			activeMarker,
			"",
			e.Alias,
			e.Profile,
			tierBadge,
			e.Description,
		)
	}
}
