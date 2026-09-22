package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

var safetyExitFn = os.Exit

// isProfileProdTier checks whether the target profile is classified as production tier
// via active environment context, .secrc environment definitions, or profile naming conventions.
func isProfileProdTier(profile string) bool {
	// 1. Check if active environment tier was set to prod
	if activeEnvTier.IsProduction() {
		return true
	}

	// 2. Check workspace config environments
	if wsCfg := loadWorkspaceConfig(); wsCfg != nil && wsCfg.Environments != nil {
		for alias, env := range wsCfg.Environments {
			if env.Profile.String() == profile || alias == activeEnvAlias {
				if env.ParsedTier().IsProduction() {
					return true
				}
			}
		}
	}

	// 3. Check profile naming heuristics (e.g. ends with "-prod" or "production")
	lower := strings.ToLower(profile)
	if strings.HasSuffix(lower, "-prod") || strings.HasSuffix(lower, "_prod") || lower == "prod" || lower == "production" {
		return true
	}

	return false
}

// validateProdMutationSafety enforces blast-radius protection when mutating production vaults.
// In non-interactive mode: aborts with exit code 2 and structured error code PROD_MUTATION_CONFIRMATION_REQUIRED
// unless confirmProd is true or SEC_CONFIRM_PROD=1.
// In interactive mode: displays a warning banner and prompts for explicit user confirmation [y/N].
func validateProdMutationSafety(profile string, isMutating bool, confirmProd bool) error {
	if !isMutating {
		return nil
	}

	if !isProfileProdTier(profile) {
		return nil
	}

	if confirmProd || os.Getenv("SEC_CONFIRM_PROD") == "1" {
		return nil
	}

	if !isInteractiveTerminal() {
		if jsonErrors {
			data, _ := json.Marshal(map[string]interface{}{
				"success":     false,
				"error":       fmt.Sprintf("mutating production profile %q requires explicit confirmation via --confirm-prod or SEC_CONFIRM_PROD=1", profile),
				"code":        "PROD_MUTATION_CONFIRMATION_REQUIRED",
				"remediation": "Pass --confirm-prod or set SEC_CONFIRM_PROD=1 to authorize mutations in automated environments.",
				"profile":     profile,
			})
			fmt.Fprintln(os.Stderr, string(data))
		} else {
			fmt.Fprintf(os.Stderr, "Error: [PROD_MUTATION_CONFIRMATION_REQUIRED] mutating production profile %q requires explicit confirmation.\n", profile)
			fmt.Fprintln(os.Stderr, "Remediation: Pass --confirm-prod or set SEC_CONFIRM_PROD=1 to authorize mutation against production profiles.")
		}
		safetyExitFn(2)
		return fmt.Errorf("PROD_MUTATION_CONFIRMATION_REQUIRED")
	}

	fmt.Fprintf(os.Stderr, "\n⚠️  WARNING: You are about to mutate secrets in PRODUCTION profile %q 🔴.\n", profile)
	fmt.Fprintf(os.Stderr, "Are you sure you want to proceed? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed reading confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		return fmt.Errorf("production mutation aborted by user")
	}

	return nil
}
