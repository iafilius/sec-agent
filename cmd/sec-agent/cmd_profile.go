package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"secure_secrets/internal/biometrics"
	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const recoverySeedWarningBanner = `╔════════════════════════════════════════════════════════════════════════════╗
║ ⚠️  CRITICAL SECURITY WARNING:                                            ║
║ NEVER paste this recovery seed phrase into any chat, AI prompt, ticket,    ║
║ browser window, or shared document. Store it offline or in a vault.        ║
╚════════════════════════════════════════════════════════════════════════════╝`

func getProfileEnvTier(profile store.ProfileName) config.EnvironmentTier {
	resp, err := queryDaemonRaw(profile.String(), daemon.IPCRequest{
		Action: daemon.IPCActionGet,
		Path:   "__profile_env__",
	})
	if err == nil && resp.Success && resp.Value != "" {
		return config.ParseEnvironmentTier(resp.Value)
	}
	return config.ParseEnvironmentTier(profile.String())
}

func printEnvBadge(profile store.ProfileName) {
	tier := getProfileEnvTier(profile)
	switch tier {
	case config.TierDev:
		fmt.Println("\033[32m🟢 [ENV: DEV]\033[0m")
	case config.TierStaging:
		fmt.Println("\033[33m🟡 [ENV: STAGING]\033[0m")
	case config.TierProd:
		fmt.Println("\033[1;31m🔴 [ENV: PROD - CAUTION!]\033[0m")
	}
}

func checkProductionGuard(profile store.ProfileName, args []string) {
	tier := getProfileEnvTier(profile)
	if !tier.IsProduction() {
		return
	}

	for _, arg := range args {
		if arg == "--dry-run" {
			return // Dry-run is non-mutating and safe; bypass production guard
		}
	}

	hasConfirm := confirmProdFlag || os.Getenv("SEC_CONFIRM_PROD") == "1"
	for _, arg := range args {
		if arg == "--confirm-prod" {
			hasConfirm = true
			break
		}
	}

	if hasConfirm {
		// Propagate confirmation to background daemon session if available
		_, _ = queryDaemonRaw(profile.String(), daemon.IPCRequest{
			Action: daemon.IPCActionConfirmProd,
			Token:  os.Getenv("SEC_SESSION_TOKEN"),
		})
		return
	}

	// Check if the current daemon session has already been confirmed for production
	resp, err := queryDaemonRaw(profile.String(), daemon.IPCRequest{Action: daemon.IPCActionPing})
	if err == nil && resp != nil && resp.ProductionConfirmed {
		return // Already confirmed for this session
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fail("PRODUCTION_GUARD_BLOCKED", fmt.Errorf("command execution against PRODUCTION profile %q requires --confirm-prod flag in non-interactive mode", profile), "Pass --confirm-prod flag to confirm execution.")
	}

	fmt.Printf("\n\033[1;31m⚠️  WARNING: You are executing a command against PRODUCTION profile %q!\033[0m\n", profile)
	fmt.Print("Type 'prod' or press Enter to confirm execution: ")
	var input string
	_, _ = fmt.Scanln(&input)
	input = strings.ToLower(strings.TrimSpace(input))
	if input != "" && input != "prod" && input != "y" && input != "yes" {
		fmt.Fprintln(os.Stderr, "Execution cancelled by production safety guard.")
		os.Exit(1)
	}

	// Record confirmation in daemon session memory for subsequent invocations
	_, _ = queryDaemonRaw(profile.String(), daemon.IPCRequest{
		Action: daemon.IPCActionConfirmProd,
		Token:  os.Getenv("SEC_SESSION_TOKEN"),
	})
}

func checkExpirationWarnings(secrets map[string]store.SecretEntry) {
	now := time.Now()
	var expiringSoon []string
	for path, entry := range secrets {
		if strings.HasPrefix(path, "__") {
			continue
		}
		if !entry.Expires.IsZero() {
			until := entry.Expires.Sub(now)
			if until > 0 && until <= 7*24*time.Hour {
				days := int(until.Hours() / 24)
				expiringSoon = append(expiringSoon, fmt.Sprintf(" [!] %-30s -> Expires in %d day(s) (%s)", path, days, entry.Expires.Format(time.RFC3339)))
			}
		}
	}
	if len(expiringSoon) > 0 {
		fmt.Printf("\n\033[33m⚠️  EXPIRATION WARNING: %d secret key(s) expiring soon!\033[0m\n", len(expiringSoon))
		for _, msg := range expiringSoon {
			fmt.Println(msg)
		}
	}
}

func handleDiffProfiles(p1, p2 string, args []string) {
	prefix := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--prefix" && i+1 < len(args) {
			prefix = args[i+1]
			i++
		}
	}

	resp1, err1 := queryDaemon(p1, daemon.IPCRequest{Action: "backup"})
	if err1 != nil || !resp1.Success {
		failDaemonNotRunning(p1)
	}

	resp2, err2 := queryDaemon(p2, daemon.IPCRequest{Action: "backup"})
	if err2 != nil || !resp2.Success {
		failDaemonNotRunning(p2)
	}

	map1 := make(map[string]string)
	for path, entry := range resp1.Secrets {
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			continue
		}
		envKey := pathToEnvKeyWithEntry(path, entry)
		map1[envKey] = path
		map1[path] = path
	}

	map2 := make(map[string]string)
	for path, entry := range resp2.Secrets {
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			continue
		}
		envKey := pathToEnvKeyWithEntry(path, entry)
		map2[envKey] = path
		map2[path] = path
	}

	allKeysSet := make(map[string]bool)
	for k := range map1 {
		allKeysSet[k] = true
	}
	for k := range map2 {
		allKeysSet[k] = true
	}

	var allKeys []string
	for k := range allKeysSet {
		if !strings.HasPrefix(k, "__") {
			allKeys = append(allKeys, k)
		}
	}
	sort.Strings(allKeys)

	fmt.Printf("=== Profile Structural Matrix Diff: %q vs %q ===\n", p1, p2)
	fmt.Printf("%-32s %-16s %-16s %s\n", "KEY / ALIAS", fmt.Sprintf("[%s]", strings.ToUpper(p1)), fmt.Sprintf("[%s]", strings.ToUpper(p2)), "STATUS")
	fmt.Println(strings.Repeat("-", 80))

	for _, k := range allKeys {
		p1Path, in1 := map1[k]
		p2Path, in2 := map2[k]

		status := "[MATCH]"
		s1 := "Present"
		s2 := "Present"

		if in1 && !in2 {
			status = fmt.Sprintf("[%s ONLY]", strings.ToUpper(p1))
			s2 = "Missing"
		} else if !in1 && in2 {
			status = fmt.Sprintf("[%s ONLY]", strings.ToUpper(p2))
			s1 = "Missing"
		}

		_ = p1Path
		_ = p2Path
		fmt.Printf("%-32s %-16s %-16s %s\n", k, s1, s2, status)
	}
}

func handleProfile(profile string, args []string) {
	if len(args) == 0 {
		tier := getProfileEnvTier(store.ProfileName(profile))
		fmt.Printf("Profile: %s\n", profile)
		if tier != config.TierUnset {
			fmt.Printf("Environment Tier: %s\n", strings.ToUpper(tier.String()))
			printEnvBadge(store.ProfileName(profile))
		} else {
			fmt.Println("Environment Tier: Unset (Run 'sec profile set-env dev|dta|prod')")
		}
		return
	}

	subcmd := args[0]
	switch subcmd {
	case "new", "create", "init":
		handleProfileNew(args[1:])
		return
	case "ls", "list":
		handleProfileList(args[1:])
		return
	case "describe", "info":
		handleProfileDescribe(profile, args[1:])
		return
	case "enroll-recovery":
		handleEnrollRecovery(profile, args[1:])
		return
	case "which":
		handleWhich(profile, args[1:])
		return
	case "set-env":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: sec profile set-env <dev|dta|staging|prod> [--profile <name>]")
			os.Exit(1)
		}
		tier := strings.ToLower(strings.TrimSpace(args[1]))
		if tier != "dev" && tier != "dta" && tier != "test" && tier != "staging" && tier != "prod" && tier != "production" {
			fail("INVALID_ARGUMENT", fmt.Errorf("invalid environment tier %q", tier), "Supported tiers: dev, dta, staging, prod")
		}
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action:  "set",
			Path:    "__profile_env__",
			Value:   tier,
			Comment: "Profile Environment Tagging",
		})
		if err != nil {
			failDaemonNotRunning(profile)
		}
		if !resp.Success {
			code, rem := mapDaemonError(resp.Error)
			fail(code, fmt.Errorf("%s", resp.Error), rem)
		}
		fmt.Printf("Profile %q successfully bound to environment tier %q.\n", profile, strings.ToUpper(tier))
		printEnvBadge(store.ProfileName(profile))
		return
	}

	fmt.Fprintln(os.Stderr, "Usage: sec profile [new <name> [--summary <text>] [--comment <c>] [--seed <mnemonic>]] [ls [--long] [--json]] [describe <name> [--summary <text>] [--comment <c>] [--clear-summary] [--json]] [enroll-recovery] [which [<path>]] [set-env dev|dta|staging|prod]")
	os.Exit(1)
}

func handleProfileList(args []string) {
	longMode := false
	jsonMode := false
	for _, a := range args {
		if a == "--long" || a == "-l" {
			longMode = true
		} else if a == "--json" {
			jsonMode = true
		} else if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec profile ls [--long|-l] [--json]")
			fmt.Println("\nList all discovered vault profiles, formats, and summaries.")
			return
		}
	}

	vaults, err := store.ListVaultFiles()
	if err != nil {
		fail("LIST_PROFILES_ERROR", fmt.Errorf("failed to discover profiles: %w", err), "")
	}

	if jsonMode {
		type profileJSON struct {
			Profile  string `json:"profile"`
			Path     string `json:"path"`
			IsV2     bool   `json:"is_v2"`
			HasSlot1 bool   `json:"has_slot1"`
			Summary  string `json:"summary,omitempty"`
		}
		var list []profileJSON
		for _, v := range vaults {
			list = append(list, profileJSON{
				Profile:  v.Profile,
				Path:     v.Path,
				IsV2:     v.IsV2,
				HasSlot1: v.HasSlot1,
				Summary:  v.Summary,
			})
		}
		data, _ := json.MarshalIndent(list, "", "  ")
		fmt.Println(string(data))
		return
	}

	if len(vaults) == 0 {
		fmt.Println("No profiles discovered.")
		return
	}

	if longMode {
		fmt.Println("Discovered Profiles (Detailed):")
		fmt.Printf("  %-20s %-16s %-16s %-30s %s\n", "PROFILE", "SCHEMA", "SLOT 1 RECOVERY", "VAULT FILE", "SUMMARY / DESCRIPTION")
		for _, v := range vaults {
			schema := "v1.0 Legacy"
			recovery := "Missing ⚠️"
			if v.IsV2 {
				schema = "v2.0 Dual-Slot"
				if v.HasSlot1 {
					recovery = "Enrolled ✓"
				}
			}
			summary := v.Summary
			if summary == "" {
				summary = "-"
			}
			fmt.Printf("  • %-18s %-16s %-16s %-30s %s\n", v.Profile, schema, recovery, filepath.Base(v.Path), summary)
		}
		return
	}

	fmt.Println("Discovered Profiles:")
	hasAnySummary := false
	for _, v := range vaults {
		if v.Summary != "" {
			hasAnySummary = true
			break
		}
	}
	for _, v := range vaults {
		status := "v1.0"
		if v.IsV2 {
			if v.HasSlot1 {
				status = "v2.0 Dual-Slot"
			} else {
				status = "v2.0 (Slot 1 missing)"
			}
		}
		statusStr := fmt.Sprintf("[%s]", status)
		if hasAnySummary {
			if v.Summary != "" {
				fmt.Printf("  • %-20s %-16s  %s\n", v.Profile, statusStr, v.Summary)
			} else {
				fmt.Printf("  • %-20s %s\n", v.Profile, statusStr)
			}
		} else {
			fmt.Printf("  • %-20s [%s]\n", v.Profile, status)
		}
	}
}

func handleProfileDescribe(profile string, args []string) {
	var name string
	var summaryText string
	hasSummary := false
	clearSummary := false
	jsonOutput := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" || a == "help" {
			fmt.Println("Usage: sec profile describe <name> [--summary <text>] [--comment <text>] [--description <text>] [--clear-summary] [--json]")
			fmt.Println("\nInspect or update unencrypted profile metadata and summary without Touch ID biometrics.")
			return
		}
		if a == "--json" {
			jsonOutput = true
		} else if a == "--clear-summary" {
			clearSummary = true
		} else if (a == "--summary" || a == "--comment" || a == "--description") && i+1 < len(args) {
			summaryText = args[i+1]
			hasSummary = true
			i++
		} else if strings.HasPrefix(a, "--summary=") {
			summaryText = strings.TrimPrefix(a, "--summary=")
			hasSummary = true
		} else if strings.HasPrefix(a, "--comment=") {
			summaryText = strings.TrimPrefix(a, "--comment=")
			hasSummary = true
		} else if strings.HasPrefix(a, "--description=") {
			summaryText = strings.TrimPrefix(a, "--description=")
			hasSummary = true
		} else if a == "--profile" && i+1 < len(args) {
			name = args[i+1]
			i++
		} else if strings.HasPrefix(a, "--profile=") {
			name = strings.TrimPrefix(a, "--profile=")
		} else if !strings.HasPrefix(a, "-") && name == "" {
			name = a
		}
	}

	if name == "" {
		if profile != "" {
			name = profile
		} else {
			name = "default"
		}
	}

	pName := store.ProfileName(name)
	if err := pName.Validate(); err != nil {
		fail("INVALID_PROFILE_NAME", fmt.Errorf("invalid profile name %q: %w", name, err), "Profile names must contain only alphanumeric characters, dashes, and underscores.")
	}

	vaultPath := store.GetStorePathForProfile(pName.String())
	// #nosec G304 G703
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		fail("PROFILE_NOT_FOUND", fmt.Errorf("profile %q not found at %s", pName.String(), vaultPath), "Run 'sec profile ls' to view existing profiles or 'sec profile new "+pName.String()+"' to create it.")
	}

	if hasSummary && clearSummary {
		fail("INVALID_ARGUMENT", fmt.Errorf("cannot specify both --summary and --clear-summary"), "")
	}

	if clearSummary {
		if err := store.UpdateProfileSummary(pName.String(), ""); err != nil {
			fail("UPDATE_SUMMARY_FAILED", fmt.Errorf("failed to clear profile summary: %w", err), "")
		}
		if jsonOutput {
			fmt.Printf("{\"profile\":%q,\"summary\":\"\",\"status\":\"cleared\"}\n", pName.String())
		} else {
			fmt.Printf("✅ Summary cleared for profile %q.\n", pName.String())
		}
		return
	}

	if hasSummary {
		summaryText = strings.Trim(strings.TrimSpace(summaryText), `"'`)
		if err := store.UpdateProfileSummary(pName.String(), summaryText); err != nil {
			fail("UPDATE_SUMMARY_FAILED", fmt.Errorf("failed to update profile summary: %w", err), "")
		}
		if jsonOutput {
			fmt.Printf("{\"profile\":%q,\"summary\":%q,\"status\":\"updated\"}\n", pName.String(), summaryText)
		} else {
			if summaryText == "" {
				fmt.Printf("✅ Summary cleared for profile %q.\n", pName.String())
			} else {
				fmt.Printf("✅ Summary updated for profile %q: %s\n", pName.String(), summaryText)
			}
		}
		return
	}

	// Read and inspect profile envelope
	env, err := store.ReadVaultEnvelope(vaultPath)
	if err != nil {
		fail("VAULT_READ_ERROR", fmt.Errorf("failed to read vault envelope: %w", err), "")
	}

	status := "v1.0"
	isV2 := env != nil && env.SchemaVersion == store.SchemaV2
	hasSlot1 := env != nil && env.Slot1 != nil
	if isV2 {
		if hasSlot1 {
			status = "v2.0 Dual-Slot"
		} else {
			status = "v2.0 (Slot 1 missing)"
		}
	}

	summary := ""
	if env != nil {
		summary = env.Summary
	}

	if jsonOutput {
		type profileInfo struct {
			Profile  string `json:"profile"`
			Summary  string `json:"summary,omitempty"`
			Path     string `json:"path"`
			IsV2     bool   `json:"is_v2"`
			HasSlot1 bool   `json:"has_slot1"`
			Status   string `json:"status"`
		}
		info := profileInfo{
			Profile:  pName.String(),
			Summary:  summary,
			Path:     vaultPath,
			IsV2:     isV2,
			HasSlot1: hasSlot1,
			Status:   status,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return
	}

	fmt.Printf("Profile:    %s\n", pName.String())
	fmt.Printf("Vault Path: %s\n", vaultPath)
	fmt.Printf("Format:     %s\n", status)
	if summary != "" {
		fmt.Printf("Summary:    %s\n", summary)
	} else {
		fmt.Printf("Summary:    (none)\n")
	}
}

func handleProfileNew(args []string) {
	var name string
	seedInput := ""
	summaryInput := ""
	autoSecrc := false
	noSecrc := false
	reuseSeed := false
	noSingleLine := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" || a == "help" {
			fmt.Println("Usage: sec profile new <name> [--summary <text>] [--comment <text>] [--description <text>] [--seed <mnemonic>] [--reuse-seed|--existing-seed] [--secrc|--no-secrc] [--no-single-line]")
			fmt.Println("\nCreate a new named profile with Dual-Slot Touch ID (Slot 0) and BIP39 recovery seed (Slot 1).")
			return
		}
		if (a == "--summary" || a == "--comment" || a == "--description") && i+1 < len(args) {
			summaryInput = strings.Trim(args[i+1], `"'`)
			i++
		} else if strings.HasPrefix(a, "--summary=") {
			summaryInput = strings.Trim(strings.TrimPrefix(a, "--summary="), `"'`)
		} else if strings.HasPrefix(a, "--comment=") {
			summaryInput = strings.Trim(strings.TrimPrefix(a, "--comment="), `"'`)
		} else if strings.HasPrefix(a, "--description=") {
			summaryInput = strings.Trim(strings.TrimPrefix(a, "--description="), `"'`)
		} else if a == "--seed" && i+1 < len(args) {
			seedInput = strings.Trim(args[i+1], `"'`)
			i++
		} else if strings.HasPrefix(a, "--seed=") {
			seedInput = strings.Trim(strings.TrimPrefix(a, "--seed="), `"'`)
		} else if a == "--reuse-seed" || a == "--existing-seed" {
			reuseSeed = true
		} else if a == "--secrc" {
			autoSecrc = true
		} else if a == "--no-secrc" {
			noSecrc = true
		} else if a == "--no-single-line" {
			noSingleLine = true
		} else if !strings.HasPrefix(a, "-") && name == "" {
			name = a
		}
	}

	if name == "" {
		fmt.Fprintln(os.Stderr, "Usage: sec profile new <name> [--summary <text>] [--seed <mnemonic>] [--reuse-seed|--existing-seed] [--secrc|--no-secrc] [--no-single-line]")
		os.Exit(1)
	}

	pName := store.ProfileName(name)
	if err := pName.Validate(); err != nil {
		fail("INVALID_PROFILE_NAME", fmt.Errorf("invalid profile name %q: %w", name, err), "Profile names must contain only alphanumeric characters, dashes, and underscores.")
	}
	if pName.String() == "default" {
		fail("INVALID_PROFILE_NAME", fmt.Errorf("cannot create profile named 'default' (default profile already exists)"), "")
	}

	vaultPath := store.GetStorePathForProfile(pName.String())
	// #nosec G304 G703
	if _, err := os.Stat(vaultPath); err == nil {
		fail("PROFILE_EXISTS", fmt.Errorf("profile %q already exists at %s", pName.String(), vaultPath), "Use 'sec open --profile "+pName.String()+"' to unlock this profile.")
	}

	if !isInteractiveTerminal() && seedInput == "" && os.Getenv("SEC_TEST_MODE") != "1" {
		cmdStr := "sec-agent profile new " + pName.String()
		if reuseSeed {
			cmdStr += " --reuse-seed"
		}
		printInteractiveBlocker(cmdStr, "Profile creation enrolls Touch ID and a 24-word recovery seed")
		os.Exit(78)
	}

	if os.Getenv("SEC_TEST_MODE") != "1" {
		res := biometrics.AuthenticateWithTimeout(biometrics.FormatReason(Version, "create_profile", pName.String()), config.DefaultPromptTimeout)
		if res != biometrics.AuthSuccess {
			handleBiometricFailure(res, config.DefaultPromptTimeout)
		}
	}

	mnemonic := seedInput
	if mnemonic == "" {
		reader := bufio.NewReader(os.Stdin)
		choice := "1"

		if reuseSeed {
			choice = "2"
		} else {
			fmt.Printf("? Profile %q recovery seed setup:\n", pName.String())
			fmt.Println("  [1] Generate a new 24-word recovery seed (Default)")
			fmt.Println("  [2] Link an existing 24-word master recovery seed phrase")
			fmt.Print("\nEnter choice [1/2] (press Enter for default): ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))
			if input != "" {
				choice = input
			}
		}

		if choice == "2" || choice == "r" || choice == "reuse" || choice == "existing" || choice == "link" {
			fmt.Print("Enter your existing 24-word recovery seed phrase: ")
			existingSeed, _ := reader.ReadString('\n')
			existingSeed = strings.Trim(strings.TrimSpace(existingSeed), `"'`)
			if err := crypto.ValidateMnemonic(existingSeed); err != nil {
				fmt.Fprintf(os.Stderr, "\n❌ Provided seed phrase is not a valid 24-word BIP39 mnemonic: %v. Aborting.\n", err)
				os.Exit(1)
			}
			mnemonic = existingSeed
			fmt.Println("✅ Existing recovery seed phrase verified and linked.")
		} else if choice == "1" {
			m, err := crypto.GenerateMnemonic()
			if err != nil {
				fail("CRYPTO_ERROR", fmt.Errorf("failed to generate recovery mnemonic: %w", err), "")
			}
			mnemonic = m
			words := strings.Fields(mnemonic)
			printRecoveryMnemonic(mnemonic, fmt.Sprintf("\n🔑 Your 24-word recovery mnemonic for profile %q (WRITE THIS DOWN NOW):", pName.String()), noSingleLine)

			fmt.Println("To confirm you have saved the mnemonic, enter verification words (or enter 'r' to reuse an existing seed phrase instead):")
			verificationWords := []int{4, 12, 20}
			for _, pos := range verificationWords {
				fmt.Printf("  Word #%d: ", pos)
				entered, _ := reader.ReadString('\n')
				entered = strings.TrimSpace(strings.ToLower(entered))
				if entered == "r" || entered == "reuse" {
					fmt.Print("Enter your existing 24-word recovery seed phrase: ")
					existingSeed, _ := reader.ReadString('\n')
					existingSeed = strings.Trim(strings.TrimSpace(existingSeed), `"'`)
					if err := crypto.ValidateMnemonic(existingSeed); err != nil {
						fmt.Fprintf(os.Stderr, "\n❌ Provided seed phrase is not a valid 24-word BIP39 mnemonic: %v. Aborting.\n", err)
						os.Exit(1)
					}
					mnemonic = existingSeed
					fmt.Println("✅ Existing recovery seed phrase verified and linked.")
					break
				}
				expected := strings.ToLower(words[pos-1])
				if entered != expected {
					fmt.Fprintf(os.Stderr, "\n❌ Word #%d mismatch (expected %q, got %q). Aborting.\n", pos, expected, entered)
					os.Exit(1)
				}
			}
		} else {
			fail("INVALID_CHOICE", fmt.Errorf("invalid choice %q: must be 1 or 2", choice), "Select 1 to generate a new seed or 2 to link an existing seed.")
		}
	} else {
		if err := crypto.ValidateMnemonic(mnemonic); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Provided seed phrase is not a valid 24-word BIP39 mnemonic: %v\n", err)
			os.Exit(1)
		}
	}

	getter, setter := keychain.GetKeychainAccessPair(pName.String())
	masterKey, err := store.InitializeMasterKey(pName.String(), getter, setter)
	if err != nil {
		fail("KEYCHAIN_ERROR", fmt.Errorf("failed to initialize profile master key: %w", err), "")
	}

	slot1, wrapErr := store.WrapMasterKey(mnemonic, masterKey)
	if wrapErr != nil {
		store.ZeroBytes(masterKey)
		fail("WRAP_ERROR", fmt.Errorf("failed to wrap recovery key: %w", wrapErr), "")
	}

	// Ensure empty store is initialized on disk if not yet present
	// #nosec G304 G703
	if _, statErr := os.Stat(vaultPath); os.IsNotExist(statErr) {
		if saveErr := store.SaveStore(pName.String(), &store.EncryptedStore{Secrets: make(map[store.SecretKey]store.SecretEntry)}, masterKey); saveErr != nil {
			store.ZeroBytes(masterKey)
			fail("VAULT_INIT_ERROR", fmt.Errorf("failed to initialize vault file: %w", saveErr), "")
		}
	}

	env, readErr := store.ReadVaultEnvelope(vaultPath)
	if readErr != nil {
		store.ZeroBytes(masterKey)
		fail("VAULT_READ_ERROR", fmt.Errorf("failed to read created vault: %w", readErr), "")
	}
	env.Slot1 = slot1
	env.UpgradedAt = time.Now().UTC()
	if summaryInput != "" {
		env.Summary = summaryInput
	}
	if writeErr := store.WriteVaultEnvelope(vaultPath, env); writeErr != nil {
		store.ZeroBytes(masterKey)
		fail("VAULT_WRITE_ERROR", fmt.Errorf("failed to write complete Dual-Slot vault: %w", writeErr), "")
	}
	store.ZeroBytes(masterKey)
	fmt.Printf("✅ Profile %q successfully created with Dual-Slot Touch ID + BIP39 recovery key!\n", pName.String())

	if noSecrc {
		return
	}

	var existingCfg string
	for _, f := range []string{".secrc", ".secenv", ".sec.json"} {
		if _, err := os.Stat(f); err == nil {
			existingCfg = f
			break
		}
	}
	if existingCfg != "" {
		fmt.Printf("ℹ️  Workspace already contains %s. Skipping .secrc creation.\n", existingCfg)
		return
	}

	doWrite := autoSecrc
	if !doWrite && isInteractiveTerminal() {
		fmt.Printf("\nBind current workspace directory to profile %q via .secrc? [Y/n]: ", pName.String())
		reader := bufio.NewReader(os.Stdin)
		ans, _ := reader.ReadString('\n')
		ans = strings.ToLower(strings.TrimSpace(ans))
		if ans == "" || ans == "y" || ans == "yes" {
			doWrite = true
		}
	}

	if doWrite {
		cwd, _ := os.Getwd()
		absSecrc := filepath.Join(cwd, ".secrc")
		if cwd != "" {
			homeDir, _ := os.UserHomeDir()
			isSensitiveDir := false
			if homeDir != "" {
				evalHome, err1 := filepath.EvalSymlinks(homeDir)
				evalCwd, err2 := filepath.EvalSymlinks(cwd)
				if err1 == nil && err2 == nil {
					if evalCwd == evalHome || evalCwd == filepath.Join(evalHome, "bin") || strings.HasPrefix(evalCwd, filepath.Join(evalHome, "bin")+string(filepath.Separator)) {
						isSensitiveDir = true
					}
				}
				if cwd == homeDir || cwd == filepath.Join(homeDir, "bin") || strings.HasPrefix(cwd, filepath.Join(homeDir, "bin")+string(filepath.Separator)) {
					isSensitiveDir = true
				}
			}
			if cwd == "/usr/local/bin" || cwd == "/tmp" || cwd == "/var/tmp" || cwd == "/private/tmp" || cwd == "/private/var/tmp" {
				isSensitiveDir = true
			}

			if isSensitiveDir {
				fmt.Printf("⚠️  Notice: Creating .secrc in a home/system directory (%s).\n", cwd)
				fmt.Printf("   All child projects without their own .secrc will inherit profile %q via upward traversal!\n", pName.String())
				fmt.Printf("   Consider running 'sec profile new' inside your specific project repository.\n")
			} else if !hasProjectRootMarkers(cwd) {
				fmt.Printf("⚠️  Warning: Current directory (%s) does not appear to be a Git repository or project root.\n", cwd)
				fmt.Printf("   All child subdirectories will inherit profile %q via upward traversal!\n", pName.String())
			}
		}

		secrcData := fmt.Sprintf("{\n  \"profile\": %q\n}\n", pName.String())
		// #nosec G304 G703
		if err := os.WriteFile(filepath.Clean(".secrc"), []byte(secrcData), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Failed to write .secrc: %v\n", err)
		} else {
			fmt.Printf("📁 Bound workspace config: %s\n", absSecrc)
			fmt.Printf("   Scope: Active for this directory and all subdirectories.\n")
		}
	}
}

func hasProjectRootMarkers(dir string) bool {
	markers := []string{
		".git",
		".arjan",
		".agent",
		"config.yaml",
		"config.yml",
		"go.mod",
		"package.json",
		"Makefile",
		"pyproject.toml",
		"requirements.txt",
		"Cargo.toml",
		"docker-compose.yml",
		"compose.yaml",
		"README.md",
	}
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}

	// Check immediate subdirectories for .git (e.g. umbrella workspace with child sub-repository)
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				if _, err := os.Stat(filepath.Join(dir, entry.Name(), ".git")); err == nil {
					return true
				}
			}
		}
	}
	return false
}

func handleLegacyExportEnv(profile string, args []string) {
	prefix := ""
	if len(args) > 0 {
		prefix = args[0]
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	for path, entry := range resp.Secrets {
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			continue
		}
		envKey := pathToEnvKeyWithEntry(path, entry)
		fmt.Printf("export %s=%q\n", envKey, entry.Value)
	}
}

func handleLoad(profile string, args []string) {
	prefix := ""
	format := "env"

	for i := 0; i < len(args); i++ {
		if args[i] == "--format" || args[i] == "-f" {
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		} else if !strings.HasPrefix(args[i], "-") && prefix == "" {
			prefix = args[i]
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "get_group",
		Path:   prefix,
	})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(resp.Secrets); err != nil {
			fail("SERIALIZATION_FAILED", err, "")
		}
		return
	}

	for path, entry := range resp.Secrets {
		relPath := path
		if prefix != "" && strings.HasPrefix(path, prefix) {
			relPath = strings.TrimPrefix(path, prefix)
			relPath = strings.TrimPrefix(relPath, "/")
		}
		if relPath == "" {
			relPath = path
		}
		envKey := pathToEnvKeyWithEntry(relPath, entry)
		fmt.Printf("export %s=%q\n", envKey, entry.Value)
	}
}

type redactWriter struct {
	target      io.Writer
	secrets     []string
	buf         []byte
	maxLen      int
	mu          sync.Mutex
	flushTimer  *time.Timer
	idleTimeout time.Duration
}

func newRedactWriter(target io.Writer, secrets []string) *redactWriter {
	validSecrets := expandDerivedSecretList(secrets)
	max := 0
	for _, s := range validSecrets {
		if len(s) > max {
			max = len(s)
		}
	}
	return &redactWriter{
		target:      target,
		secrets:     validSecrets,
		maxLen:      max,
		idleTimeout: 25 * time.Millisecond,
	}
}

func (w *redactWriter) Write(p []byte) (n int, err error) {
	if len(w.secrets) == 0 {
		return w.target.Write(p)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.flushTimer != nil {
		w.flushTimer.Stop()
		w.flushTimer = nil
	}

	w.buf = append(w.buf, p...)
	out := string(w.buf)
	for _, sec := range w.secrets {
		out = replaceSecretMatches(out, sec, "[REDACTED_BY_SEC]")
	}

	L := longestSecretPrefixSuffix(out, w.secrets, w.maxLen)
	if L == 0 {
		w.buf = nil
		_, err = w.target.Write([]byte(out))
		return len(p), err
	}

	safeLen := len(out) - L
	toFlush := out[:safeLen]
	w.buf = []byte(out[safeLen:])
	if len(toFlush) > 0 {
		if _, err = w.target.Write([]byte(toFlush)); err != nil {
			return len(p), err
		}
	}

	w.flushTimer = time.AfterFunc(w.idleTimeout, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if len(w.buf) > 0 {
			toWrite := string(w.buf)
			for _, sec := range w.secrets {
				toWrite = replaceSecretMatches(toWrite, sec, "[REDACTED_BY_SEC]")
			}
			w.buf = nil
			_, _ = w.target.Write([]byte(toWrite))
		}
	})

	return len(p), nil
}

func (w *redactWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.flushTimer != nil {
		w.flushTimer.Stop()
		w.flushTimer = nil
	}

	if len(w.buf) == 0 {
		return nil
	}
	out := string(w.buf)
	for _, sec := range w.secrets {
		out = replaceSecretMatches(out, sec, "[REDACTED_BY_SEC]")
	}
	w.buf = nil
	_, err := w.target.Write([]byte(out))
	return err
}

func longestSecretPrefixSuffix(text string, secrets []string, maxLen int) int {
	maxCheck := maxLen - 1
	if len(text) < maxCheck {
		maxCheck = len(text)
	}
	for l := maxCheck; l >= 1; l-- {
		suffix := text[len(text)-l:]
		for _, sec := range secrets {
			if strings.HasPrefix(sec, suffix) {
				return l
			}
		}
	}
	return 0
}

func setupEphemeralSSHAgentFromBytes(keyBytes []byte, passphrase string) (socketPath string, cleanup func(), err error) {
	var rawKey interface{}
	if passphrase != "" {
		rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
	} else {
		rawKey, err = ssh.ParseRawPrivateKey(keyBytes)
	}
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: rawKey}); err != nil {
		return "", nil, fmt.Errorf("failed to add SSH key to ephemeral keyring: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "sec_ssh_agent_*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary socket directory: %w", err)
	}

	socketPath = filepath.Join(tmpDir, "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to listen on unix socket %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("failed to set 0600 perms on SSH agent socket: %w", err)
	}

	done := make(chan bool)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				_ = agent.ServeAgent(keyring, c)
				_ = c.Close()
			}(conn)
		}
	}()

	cleanup = func() {
		close(done)
		_ = listener.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return socketPath, cleanup, nil
}

func setupEphemeralSSHAgent(profile, keyPath, passphraseVaultKey string) (socketPath string, cleanup func(), err error) {
	// #nosec G304 G703
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read SSH private key file %s: %w", keyPath, err)
	}

	passphrase := ""
	if passphraseVaultKey != "" {
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: "get",
			Path:   passphraseVaultKey,
		})
		if err != nil || !resp.Success {
			return "", nil, fmt.Errorf("failed to retrieve SSH passphrase secret %q from vault: %v", passphraseVaultKey, err)
		}
		passphrase = resp.Value
	}

	return setupEphemeralSSHAgentFromBytes(keyBytes, passphrase)
}

func setupEphemeralSSHAgentFromVault(profile, keyVaultPath, passphraseVaultKey string) (socketPath string, cleanup func(), err error) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "get",
		Path:   keyVaultPath,
	})
	if err != nil || !resp.Success || resp.Value == "" {
		return "", nil, fmt.Errorf("failed to retrieve SSH private key secret %q from vault: %v", keyVaultPath, err)
	}

	passphrase := ""
	if passphraseVaultKey != "" {
		pResp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: "get",
			Path:   passphraseVaultKey,
		})
		if err != nil || !pResp.Success {
			return "", nil, fmt.Errorf("failed to retrieve SSH passphrase secret %q from vault: %v", passphraseVaultKey, err)
		}
		passphrase = pResp.Value
	}

	return setupEphemeralSSHAgentFromBytes([]byte(resp.Value), passphrase)
}

func handleRun(profile string, args []string) {
	groupPrefix := ""
	var allowedKeys []string
	dryRun := false
	noRedact := false
	autoExtend := false
	sshKeyPath := ""
	sshKeySecretPath := ""
	sshPassphraseVaultKey := ""
	stdinKeyPath := ""
	stdinRaw := false
	var tempFileSpecs []string

	cmdIndex := -1
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			cmdIndex = i + 1
			break
		}
		if (args[i] == "--group" || args[i] == "-g") && i+1 < len(args) {
			groupPrefix = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--group=") {
			groupPrefix = strings.TrimPrefix(args[i], "--group=")
		} else if args[i] == "--stdin-key" && i+1 < len(args) {
			stdinKeyPath = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--stdin-key=") {
			stdinKeyPath = strings.TrimPrefix(args[i], "--stdin-key=")
		} else if args[i] == "--stdin-raw" || args[i] == "--stdin-no-newline" {
			stdinRaw = true
		} else if (args[i] == "--temp-file") && i+1 < len(args) {
			tempFileSpecs = append(tempFileSpecs, args[i+1])
			i++
		} else if strings.HasPrefix(args[i], "--temp-file=") {
			tempFileSpecs = append(tempFileSpecs, strings.TrimPrefix(args[i], "--temp-file="))
		} else if args[i] == "--allow-keys" && i+1 < len(args) {
			allowedKeys = strings.Split(args[i+1], ",")
			i++
		} else if strings.HasPrefix(args[i], "--allow-keys=") {
			allowedKeys = strings.Split(strings.TrimPrefix(args[i], "--allow-keys="), ",")
		} else if args[i] == "--dry-run" {
			dryRun = true
		} else if args[i] == "--auto-extend" {
			autoExtend = true
		} else if args[i] == "--no-redact" {
			noRedact = true
		} else if args[i] == "--redact" {
			noRedact = false
		} else if (args[i] == "--ssh-key-secret" || args[i] == "--key-secret") && i+1 < len(args) {
			sshKeySecretPath = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--ssh-key-secret=") {
			sshKeySecretPath = strings.TrimPrefix(args[i], "--ssh-key-secret=")
		} else if strings.HasPrefix(args[i], "--key-secret=") {
			sshKeySecretPath = strings.TrimPrefix(args[i], "--key-secret=")
		} else if args[i] == "--ssh-key" && i+1 < len(args) {
			sshKeyPath = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--ssh-key=") {
			sshKeyPath = strings.TrimPrefix(args[i], "--ssh-key=")
		} else if args[i] == "--ssh-passphrase-key" && i+1 < len(args) {
			sshPassphraseVaultKey = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--ssh-passphrase-key=") {
			sshPassphraseVaultKey = strings.TrimPrefix(args[i], "--ssh-passphrase-key=")
		} else if args[i] == "--timeout" && i+1 < len(args) {
			timeoutVal := args[i+1]
			_ = os.Setenv("SEC_PROMPT_TIMEOUT", timeoutVal)
			i++
		} else if strings.HasPrefix(args[i], "--timeout=") {
			timeoutVal := strings.TrimPrefix(args[i], "--timeout=")
			_ = os.Setenv("SEC_PROMPT_TIMEOUT", timeoutVal)
		}
	}

	if cmdIndex == -1 || cmdIndex >= len(args) {
		fail("INVALID_ARGUMENTS", fmt.Errorf("no target command specified. Separate subagent flags and target command using '--'"), "Usage: sec run [--group <prefix>] [--stdin-key <key>] [--stdin-raw] [--temp-file <ENV>=<target>] [--ssh-key <path>] [--auto-extend] -- <cmd> [args...]")
	}

	targetCmd := args[cmdIndex]
	targetArgs := args[cmdIndex+1:]

	checkProductionGuard(store.ProfileName(profile), args)
	checkAndAutoExtendSession(profile, autoExtend)

	var stdinSecretBytes []byte
	if stdinKeyPath != "" {
		getResp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: "get",
			Path:   stdinKeyPath,
		})
		if err != nil {
			failDaemonNotRunning(profile)
		}
		if !getResp.Success {
			code, rem := mapDaemonError(getResp.Error)
			fail(code, fmt.Errorf("failed to fetch stdin key %q: %s", stdinKeyPath, getResp.Error), rem)
		}
		val := getResp.Value
		if !stdinRaw {
			val += "\n"
		}
		stdinSecretBytes = []byte(val)
	}
	defer func() {
		if len(stdinSecretBytes) > 0 {
			store.ZeroBytes(stdinSecretBytes)
		}
	}()

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "get_group",
		Path:   groupPrefix,
	})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	envMap := make(map[string]string)
	var secretValues []string

	allowedSet := make(map[string]bool)
	for _, k := range allowedKeys {
		allowedSet[strings.TrimSpace(k)] = true
	}

	for path, entry := range resp.Secrets {
		if strings.HasPrefix(path, "__") {
			continue
		}

		relPath := path
		if groupPrefix != "" && strings.HasPrefix(path, groupPrefix) {
			relPath = strings.TrimPrefix(path, groupPrefix)
			relPath = strings.TrimPrefix(relPath, "/")
		}
		if relPath == "" {
			relPath = path
		}

		envKey := pathToEnvKeyWithEntry(relPath, entry)
		if err := config.EnvVarKey(envKey).Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️ Skipping secret key %q: invalid environment variable name %q (%v)\n", path, envKey, err)
			continue
		}

		if len(allowedSet) > 0 && !allowedSet[envKey] && !allowedSet[path] && !allowedSet[relPath] {
			continue
		}

		envMap[envKey] = entry.Value
		if len(entry.Value) > 3 {
			secretValues = append(secretValues, entry.Value)
		}

		// Companion metadata injection: KEY_METAKEY=val
		if entry.Metadata != nil {
			for metaK, metaV := range entry.Metadata {
				if metaK == "alias" || metaK == "rotate_cmd" || metaK == "rotate_ttl" {
					continue
				}
				cleanMetaKey := strings.ToUpper(strings.Map(func(r rune) rune {
					if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
						return r
					}
					return '_'
				}, metaK))
				metaEnvKey := fmt.Sprintf("%s_%s", envKey, cleanMetaKey)
				if err := config.EnvVarKey(metaEnvKey).Validate(); err == nil {
					envMap[metaEnvKey] = metaV
				}
			}
		}
	}

	// Inline sec:// URI placeholder expansion in target command and arguments
	secURIRegex := regexp.MustCompile(`sec://([a-zA-Z0-9_\-\./:]+)`)
	for idx, arg := range targetArgs {
		if strings.Contains(arg, "sec://") {
			targetArgs[idx] = secURIRegex.ReplaceAllStringFunc(arg, func(match string) string {
				secretPath := strings.TrimPrefix(match, "sec://")
				targetProf := profile
				if strings.Contains(secretPath, ":") {
					parts := strings.SplitN(secretPath, ":", 2)
					targetProf = parts[0]
					secretPath = parts[1]
				}
				getResp, err := queryDaemon(targetProf, daemon.IPCRequest{
					Action: "get",
					Path:   secretPath,
				})
				if err == nil && getResp != nil && getResp.Success {
					if len(getResp.Value) > 3 {
						secretValues = append(secretValues, getResp.Value)
					}
					return getResp.Value
				}
				return match
			})
		}
	}
	if strings.Contains(targetCmd, "sec://") {
		targetCmd = secURIRegex.ReplaceAllStringFunc(targetCmd, func(match string) string {
			secretPath := strings.TrimPrefix(match, "sec://")
			getResp, err := queryDaemon(profile, daemon.IPCRequest{
				Action: "get",
				Path:   secretPath,
			})
			if err == nil && getResp != nil && getResp.Success {
				if len(getResp.Value) > 3 {
					secretValues = append(secretValues, getResp.Value)
				}
				return getResp.Value
			}
			return match
		})
	}

	var agentSocket string
	var agentCleanup func()
	if sshKeySecretPath != "" {
		sock, cleanup, err := setupEphemeralSSHAgentFromVault(profile, sshKeySecretPath, sshPassphraseVaultKey)
		if err != nil {
			fail("SSH_AGENT_FAILED", fmt.Errorf("failed to spin up ephemeral SSH agent from vault key %q: %v", sshKeySecretPath, err), "")
		}
		agentSocket = sock
		agentCleanup = cleanup
		defer agentCleanup()
		envMap["SSH_AUTH_SOCK"] = agentSocket
	} else if sshKeyPath != "" {
		sock, cleanup, err := setupEphemeralSSHAgent(profile, sshKeyPath, sshPassphraseVaultKey)
		if err != nil {
			fail("SSH_AGENT_FAILED", fmt.Errorf("failed to spin up ephemeral SSH agent: %v", err), "")
		}
		agentSocket = sock
		agentCleanup = cleanup
		defer agentCleanup()
		envMap["SSH_AUTH_SOCK"] = agentSocket
	}

	tempMgr := newTempFileManager()
	defer tempMgr.Cleanup()

	if len(tempFileSpecs) > 0 {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		go func() {
			<-sigChan
			tempMgr.Cleanup()
			os.Exit(1)
		}()

		wsCfg := loadWorkspaceConfig()
		for _, spec := range tempFileSpecs {
			parts := strings.SplitN(spec, "=", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				tempMgr.Cleanup()
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid --temp-file format %q, expected ENV=KEY_OR_TEMPLATE", spec), "Usage: sec run --temp-file <ENV_VAR>=<key_or_template> -- <cmd> [args...]")
			}
			tfEnvKey := strings.TrimSpace(parts[0])
			tfTarget := strings.TrimSpace(parts[1])
			if err := config.EnvVarKey(tfEnvKey).Validate(); err != nil {
				tempMgr.Cleanup()
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid environment variable name %q in --temp-file: %v", tfEnvKey, err), "Environment variable names must contain only alphanumeric characters and underscores.")
			}

			content, rErr := resolveTempFileTarget(profile, tfEnvKey, tfTarget, wsCfg)
			if rErr != nil {
				tempMgr.Cleanup()
				fail("TEMP_FILE_RESOLUTION_FAILED", rErr, "Verify that the secret key exists in the vault or the template file is valid.")
			}

			tempPath, cErr := tempMgr.CreateTempFile(tfEnvKey, content)
			if cErr != nil {
				tempMgr.Cleanup()
				fail("TEMP_FILE_CREATE_FAILED", cErr, "Verify disk space and permissions in temporary directory.")
			}

			envMap[tfEnvKey] = tempPath
			if len(content) > 3 {
				secretValues = append(secretValues, content)
			}
		}
	}

	if dryRun {
		tempMgr.Cleanup()
		fmt.Println("=== Dry-Run: Subprocess Secret Injection Plan ===")
		fmt.Printf("Target Command:     %s %s\n", targetCmd, strings.Join(targetArgs, " "))
		tier := getProfileEnvTier(store.ProfileName(profile))
		if tier == config.TierUnset {
			tier = config.TierDev
		}
		fmt.Printf("Vault Profile:      %s (Tier: %s)\n", profile, strings.ToUpper(tier.String()))
		if stdinKeyPath != "" {
			fmt.Printf("Stdin Injection:    %s (append newline: %t)\n", stdinKeyPath, !stdinRaw)
		}
		fmt.Printf("Redaction Enabled:  true\n\n")
		fmt.Printf("%-24s %-36s %s\n", "INJECTED ENV VAR", "VAULT KEY PATH", "VALUE PREVIEW")
		fmt.Println(strings.Repeat("-", 80))

		count := 0
		var keys []string
		for k := range envMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			count++
			val := envMap[k]
			fmt.Printf("%-24s %-36s [REDACTED_BY_SEC] (%d chars)\n", k, k, len(val))
		}
		fmt.Printf("\n[INFO] Dry-run completed. %d secret(s) ready to inject. No process executed.\n", count)
		return
	}

	currentEnv := os.Environ()
	finalEnv := make([]string, 0, len(currentEnv)+len(envMap))

	overrideSet := make(map[string]bool)
	for k := range envMap {
		overrideSet[k] = true
	}

	for _, e := range currentEnv {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 && overrideSet[parts[0]] {
			continue
		}
		finalEnv = append(finalEnv, e)
	}
	for k, v := range envMap {
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
	}

	// #nosec G204 G702
	subProcess := exec.Command(targetCmd, targetArgs...)
	subProcess.Env = finalEnv
	subProcess.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var stdoutRedact, stderrRedact *redactWriter
	if noRedact {
		subProcess.Stdout = os.Stdout
		subProcess.Stderr = os.Stderr
	} else {
		stdoutRedact = newRedactWriter(os.Stdout, secretValues)
		stderrRedact = newRedactWriter(os.Stderr, secretValues)
		subProcess.Stdout = stdoutRedact
		subProcess.Stderr = stderrRedact
	}
	if len(stdinSecretBytes) > 0 {
		subProcess.Stdin = bytes.NewReader(stdinSecretBytes)
	} else {
		subProcess.Stdin = os.Stdin
	}

	isTerm := term.IsTerminal(int(os.Stdin.Fd()))
	var origPgid int
	if isTerm {
		origPgid, _ = unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
		signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
		defer func() {
			if origPgid > 0 {
				_ = unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCSPGRP, origPgid)
			}
			signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)
		}()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)
	go func() {
		for sig := range sigChan {
			if subProcess.Process != nil && subProcess.Process.Pid > 0 {
				pgid := -subProcess.Process.Pid
				if sysSig, ok := sig.(syscall.Signal); ok {
					_ = syscall.Kill(pgid, sysSig)
				} else {
					_ = subProcess.Process.Signal(sig)
				}
			}
		}
	}()

	startErr := subProcess.Start()
	if startErr != nil {
		fail("SUBPROCESS_EXEC_FAILED", fmt.Errorf("failed executing command %q: %v", targetCmd, startErr), "")
	}

	if isTerm && subProcess.Process != nil && subProcess.Process.Pid > 0 {
		_ = unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCSPGRP, subProcess.Process.Pid)
	}

	runErr := subProcess.Wait()
	if isTerm && origPgid > 0 {
		_ = unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCSPGRP, origPgid)
	}

	if stdoutRedact != nil {
		_ = stdoutRedact.Flush()
	}
	if stderrRedact != nil {
		_ = stderrRedact.Flush()
	}

	tempMgr.Cleanup()

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fail("SUBPROCESS_EXEC_FAILED", fmt.Errorf("failed executing command %q: %v", targetCmd, runErr), "")
	}
}

func handlePrompt(profile string, args []string) {
	format := "plain"
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) {
			format = strings.ToLower(args[i+1])
			i++
		}
	}

	wsCfg := loadWorkspaceConfig()
	envAlias := activeEnvAlias
	if envAlias == "" {
		envAlias = os.Getenv("SEC_ENV")
	}
	if envAlias == "" && wsCfg != nil {
		envAlias = wsCfg.Default
	}

	tier := activeEnvTier
	if tier == config.TierUnset && wsCfg != nil && wsCfg.Environments != nil && envAlias != "" {
		if env, ok := wsCfg.Environments[envAlias]; ok {
			tier = env.ParsedTier()
		}
	}

	isMultiEnv := wsCfg != nil && len(wsCfg.Environments) > 0 && envAlias != ""

	activeProfile := profile
	if activeProfile == "" {
		activeProfile = "default"
	}

	// High-speed non-blocking probe to daemon socket
	sockPath, err := config.GetSocketPath(activeProfile)
	if err != nil {
		printPromptFormat(format, activeProfile, envAlias, tier, isMultiEnv, "unknown", false)
		return
	}

	conn, err := net.DialTimeout("unix", sockPath, 10*time.Millisecond)
	if err != nil {
		printPromptFormat(format, activeProfile, envAlias, tier, isMultiEnv, "locked", false)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Millisecond))

	reqBytes, _ := json.Marshal(daemon.IPCRequest{Action: "ping"})
	reqBytes = append(reqBytes, '\n')
	_, _ = conn.Write(reqBytes)

	reader := bufio.NewReader(conn)
	respBytes, err := reader.ReadBytes('\n')
	_ = conn.Close()

	if err != nil {
		printPromptFormat(format, activeProfile, envAlias, tier, isMultiEnv, "locked", false)
		return
	}

	var resp daemon.IPCResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil || !resp.Success {
		printPromptFormat(format, activeProfile, envAlias, tier, isMultiEnv, "locked", false)
		return
	}

	printPromptFormat(format, activeProfile, envAlias, tier, isMultiEnv, "unlocked", true)
}

func printPromptFormat(format, profile, envAlias string, tier config.EnvironmentTier, isMultiEnv bool, status string, unlocked bool) {
	if isMultiEnv && envAlias != "" {
		tierBadge := ""
		if tier.IsProduction() {
			tierBadge = " 🔴"
		}
		statusSuffix := ""
		if !unlocked {
			statusSuffix = " (" + status + ")"
		}
		label := fmt.Sprintf("%s (%s%s)%s", envAlias, profile, tierBadge, statusSuffix)

		switch format {
		case "starship":
			color := "bold green"
			if !unlocked {
				color = "bold yellow"
			}
			if tier.IsProduction() {
				color = "bold red"
			}
			fmt.Printf("[ sec: %s ](%s)", label, color)
		case "p10k":
			color := "green"
			if !unlocked {
				color = "yellow"
			}
			if tier.IsProduction() {
				color = "red"
			}
			fmt.Printf("%%F{%s}sec: %s%%f", color, label)
		default:
			fmt.Printf("[sec: %s]\n", label)
		}
		return
	}

	badge := ""
	switch status {
	case "unlocked":
		badge = "🛡️ "
	case "locked":
		badge = "🔒 "
	case "expired":
		badge = "⚠️ "
	default:
		badge = "⚪ "
	}

	switch format {
	case "starship":
		if unlocked {
			fmt.Printf("[ %ssec:%s ](bold green)", badge, profile)
		} else {
			fmt.Printf("[ %ssec:%s ](bold yellow)", badge, profile)
		}
	case "p10k":
		if unlocked {
			fmt.Printf("%%F{green}%ssec:%s%%f", badge, profile)
		} else {
			fmt.Printf("%%F{yellow}%ssec:%s%%f", badge, profile)
		}
	default:
		if unlocked {
			fmt.Printf("%ssec:%s\n", badge, profile)
		} else {
			fmt.Printf("%ssec:%s (locked)\n", badge, profile)
		}
	}
}

func handleInitDirenv() {
	home, err := os.UserHomeDir()
	if err != nil {
		fail("HOME_DIR_ERROR", fmt.Errorf("failed to locate user home directory: %v", err), "")
	}

	direnvDir := filepath.Join(home, ".config", "direnv")
	_ = os.MkdirAll(direnvDir, 0700)
	direnvrcPath := filepath.Join(direnvDir, "direnvrc")

	snippet := `
# sec-agent direnv integration helper
use_sec_agent() {
  local profile="${1:-default}"
  if command -v sec-agent >/dev/null 2>&1; then
    eval "$(sec-agent load --format env --profile "$profile" 2>/dev/null)"
  fi
}
`

	// #nosec G304
	existing, _ := os.ReadFile(direnvrcPath)
	if strings.Contains(string(existing), "use_sec_agent()") {
		fmt.Printf("✨ sec-agent direnv integration is already installed in %s\n", direnvrcPath)
		return
	}

	// #nosec G304
	f, err := os.OpenFile(direnvrcPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fail("FILE_WRITE_ERROR", fmt.Errorf("failed writing to %s: %v", direnvrcPath, err), "")
	}
	defer f.Close()

	if _, err := f.WriteString(snippet); err != nil {
		fail("FILE_WRITE_ERROR", fmt.Errorf("failed writing to %s: %v", direnvrcPath, err), "")
	}

	fmt.Printf("✅ Added 'use_sec_agent [profile]' helper to %s\n", direnvrcPath)
	fmt.Println("💡 In any project directory, add 'use sec-agent [profile]' to your .envrc file.")
}

// handleWhich statelessly resolves workspace configuration for a target path or cwd.
func handleWhich(profile string, args []string) {
	jsonMode := false
	targetPath := ""

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" || a == "help" {
			if spec, ok := findCommandSpec("which"); ok {
				printCommandHelp(spec)
			} else {
				fmt.Println("Usage: sec which [<path>] [--json]")
				fmt.Println("\nStatelessly resolve and inspect workspace configuration for an arbitrary directory.")
			}
			return
		}
		if a == "--json" {
			jsonMode = true
		} else if !strings.HasPrefix(a, "-") && targetPath == "" {
			targetPath = a
		}
	}

	startDir := targetPath
	if startDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fail("IO_ERROR", fmt.Errorf("failed to get current working directory: %w", err), "")
		}
		startDir = cwd
	}

	absDir, err := filepath.Abs(startDir)
	if err != nil {
		fail("INVALID_PATH", fmt.Errorf("invalid path %q: %w", startDir, err), "")
	}

	// #nosec G703
	fi, err := os.Stat(absDir)
	if err != nil {
		fail("PATH_NOT_FOUND", fmt.Errorf("path does not exist: %s", absDir), "")
	}
	if !fi.IsDir() {
		absDir = filepath.Dir(absDir)
	}

	var foundCfg *WorkspaceConfig
	var foundConfigFile string
	var foundWorkspaceRoot string

	dir := absDir
	for {
		for _, name := range []string{".secenv", ".secrc", ".sec.json"} {
			cfgPath := filepath.Join(dir, name)
			// #nosec G304 G703
			if data, err := os.ReadFile(cfgPath); err == nil {
				var cfg WorkspaceConfig
				if err := json.Unmarshal(data, &cfg); err == nil {
					normalizeWorkspaceConfig(&cfg)
					foundCfg = &cfg
					foundConfigFile = cfgPath
					foundWorkspaceRoot = dir
					break
				}
			}
		}
		if foundCfg != nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	resProfile := "default"
	resEnv := ""
	resTier := ""
	if foundCfg != nil {
		if foundCfg.Profile != "" {
			resProfile = foundCfg.Profile.String()
		}
		if foundCfg.Default != "" {
			resEnv = foundCfg.Default
			if envDef, ok := foundCfg.Environments[resEnv]; ok {
				if envDef.Profile != "" {
					resProfile = envDef.Profile.String()
				}
				if envDef.Tier != "" {
					resTier = envDef.Tier
				}
			}
		}
	}

	if jsonMode {
		type whichJSON struct {
			TargetDir     string `json:"target_dir"`
			Profile       string `json:"profile"`
			ConfigFile    string `json:"config_file,omitempty"`
			WorkspaceRoot string `json:"workspace_root,omitempty"`
			Environment   string `json:"environment,omitempty"`
			Tier          string `json:"tier,omitempty"`
		}
		resp := whichJSON{
			TargetDir:     absDir,
			Profile:       resProfile,
			ConfigFile:    foundConfigFile,
			WorkspaceRoot: foundWorkspaceRoot,
			Environment:   resEnv,
			Tier:          resTier,
		}
		data, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(data))
		return
	}

	if foundCfg == nil {
		fmt.Printf("No workspace configuration detected for %s\n", absDir)
		fmt.Println("Default profile: default")
		return
	}

	fmt.Printf("📌 Resolved Profile: %s\n", resProfile)
	fmt.Printf("📄 Config File:      %s\n", foundConfigFile)
	fmt.Printf("📂 Workspace Root:   %s\n", foundWorkspaceRoot)
	if resEnv != "" {
		if resTier != "" {
			fmt.Printf("🏷️  Environment:     %s (Tier: %s)\n", resEnv, strings.ToUpper(resTier))
		} else {
			fmt.Printf("🏷️  Environment:     %s\n", resEnv)
		}
	}
}

