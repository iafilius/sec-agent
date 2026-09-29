package main

import (
	"encoding/json"
	"fmt"
	"os"

	"secure_secrets/internal/config"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
)

type KeychainStatusDTO struct {
	Profile             string `json:"profile"`
	Service             string `json:"service"`
	Account             string `json:"account"`
	Exists              bool   `json:"exists"`
	AccessControl       string `json:"access_control"`
	ActiveVersion       string `json:"active_version"`
	LastRecordedVersion string `json:"last_recorded_version"`
	IsSealedToActive    bool   `json:"is_sealed_to_active"`
	CreationDate        string `json:"creation_date,omitempty"`
	ModificationDate    string `json:"modification_date,omitempty"`
}

func handleKeychain(profile string, args []string) {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printKeychainUsage()
		return
	}

	subcmd := args[0]
	switch subcmd {
	case "prune":
		handleKeychainPrune(profile, args[1:])
	case "status", "info":
		handleKeychainStatus(profile, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown keychain command %q.\n\n", subcmd)
		printKeychainUsage()
		os.Exit(1)
	}
}

func printKeychainUsage() {
	fmt.Println("Usage: sec keychain <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  prune   Re-seal Keychain items to active binary, purging historical ACL authorizations")
	fmt.Println("  status  Inspect Keychain biometric binding, presence, and active version sealing")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -p, --profile <name>  Specify profile (default: active profile)")
	fmt.Println("  -a, --all             Apply to all discovered profiles (prune only)")
	fmt.Println("      --json            Output in JSON format (status only)")
}

func handleKeychainPrune(profile string, args []string) {
	allProfiles := false
	targetProfile := profile

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--all", "-a":
			allProfiles = true
		case "--profile", "-p":
			if i+1 < len(args) {
				targetProfile = args[i+1]
				i++
			}
		}
	}

	profilesToPrune := []string{targetProfile}
	if allProfiles {
		discovered, err := store.ListVaultFiles()
		if err == nil && len(discovered) > 0 {
			profilesToPrune = make([]string, 0, len(discovered))
			for _, v := range discovered {
				profilesToPrune = append(profilesToPrune, v.Profile)
			}
		}
	}

	curVer := keychain.GetVersion()
	successCount := 0

	for _, p := range profilesToPrune {
		getter, _ := keychain.GetKeychainAccessPair(p)
		masterKey, err := getter()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Profile %-20s: Failed to unlock master key via Touch ID (%v)\n", p, err)
			continue
		}

		if err := keychain.ResealKeychainForProfile(p, masterKey); err != nil {
			store.ZeroBytes(masterKey)
			fmt.Fprintf(os.Stderr, "[✗] Profile %-20s: Failed to re-seal Keychain item (%v)\n", p, err)
			continue
		}
		store.ZeroBytes(masterKey)

		fmt.Printf("[✓] Profile %-20s: Keychain item re-sealed to %s (historical authorizations purged).\n", p, curVer)
		successCount++
	}

	if successCount > 0 {
		_ = config.SetLastKnownVersion(curVer)
		fmt.Printf("\n[✓] Successfully re-sealed %d profile(s) to sec-agent %s.\n", successCount, curVer)
	} else if len(profilesToPrune) > 0 {
		os.Exit(1)
	}
}

func handleKeychainStatus(profile string, args []string) {
	targetProfile := profile
	jsonOutput := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOutput = true
		case "--profile", "-p":
			if i+1 < len(args) {
				targetProfile = args[i+1]
				i++
			}
		}
	}

	svc := "sec-session"
	if targetProfile != "" && targetProfile != "default" {
		svc = "sec-session:profile_" + targetProfile
	}
	acc := "master"

	meta, err := keychain.GetItemMetadata(svc, acc)
	if err != nil {
		fail("KEYCHAIN_ERROR", fmt.Errorf("failed to query keychain metadata: %w", err), "")
	}

	curVer := keychain.GetVersion()
	lastVer, _ := config.GetLastKnownVersion()
	isSealed := meta.Exists && (lastVer == curVer || lastVer == "")

	dto := KeychainStatusDTO{
		Profile:             targetProfile,
		Service:             svc,
		Account:             acc,
		Exists:              meta.Exists,
		AccessControl:       meta.AccessControl,
		ActiveVersion:       curVer,
		LastRecordedVersion: lastVer,
		IsSealedToActive:    isSealed,
	}
	if !meta.CreationDate.IsZero() {
		dto.CreationDate = meta.CreationDate.Format("2006-01-02 15:04:05 MST")
	}
	if !meta.ModificationDate.IsZero() {
		dto.ModificationDate = meta.ModificationDate.Format("2006-01-02 15:04:05 MST")
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(dto)
		return
	}

	fmt.Println("=== macOS Keychain Biometric Binding Status ===")
	fmt.Printf("  Profile:                %s\n", targetProfile)
	fmt.Printf("  Service Name:           %s\n", svc)
	fmt.Printf("  Account:                %s\n", acc)

	if meta.Exists {
		fmt.Printf("  Item Present:           Yes\n")
		fmt.Printf("  Access Control Mode:    %s (Hardware Enclave bound)\n", meta.AccessControl)
		if dto.CreationDate != "" {
			fmt.Printf("  Created:                %s\n", dto.CreationDate)
		}
		if dto.ModificationDate != "" {
			fmt.Printf("  Last Modified:          %s\n", dto.ModificationDate)
		}
	} else {
		fmt.Printf("  Item Present:           No (Not initialized or locked)\n")
	}

	fmt.Printf("  Active Executable:      %s\n", curVer)
	if lastVer != "" {
		fmt.Printf("  Last Sealed Version:    %s\n", lastVer)
	} else {
		fmt.Printf("  Last Sealed Version:    (Not recorded)\n")
	}

	if !meta.Exists {
		fmt.Printf("  Status:                 [!] Item not found in login.keychain-db\n")
	} else if lastVer != "" && lastVer != curVer {
		fmt.Printf("  Status:                 [⚠️] Version drift detected (Run 'sec keychain prune' to re-seal)\n")
	} else {
		fmt.Printf("  Status:                 [✓] Sealed to active binary\n")
	}
}
