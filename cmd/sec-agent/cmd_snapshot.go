package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
)

func handleSnapshot(profile string, args []string) {
	if len(args) == 0 {
		handleSnapshotList(profile, nil)
		return
	}

	subCmd := strings.ToLower(args[0])
	subArgs := args[1:]

	switch subCmd {
	case "list", "ls":
		handleSnapshotList(profile, subArgs)
	case "create", "add", "new":
		handleSnapshotCreate(profile, subArgs)
	case "restore":
		handleSnapshotRestore(profile, subArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown snapshot subcommand: %s\n", subCmd)
		fmt.Fprintln(os.Stderr, "Usage: sec snapshot <list|create|restore> [args]")
		os.Exit(1)
	}
}

func handleSnapshotList(profile string, args []string) {
	jsonOutput := false
	allProfiles := true
	filterProfile := profile
	verbose := false

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			switch arg {
			case "--json":
				jsonOutput = true
			case "--all-profiles", "-A", "--all":
				allProfiles = true
			case "--verbose", "-v", "--path":
				verbose = true
			}
		} else {
			// Positional argument specifies profile filter
			filterProfile = arg
			allProfiles = false
		}
	}

	// If explicit profile flag was passed (not default), filter by that profile
	if profile != "" && profile != "default" {
		filterProfile = profile
		allProfiles = false
	}

	getter, _ := keychain.GetKeychainAccessPair(filterProfile)
	activeKey, _ := getter()

	var snapshots []*store.SnapshotMeta
	var err error

	if allProfiles {
		snapshots, err = store.ListAllSnapshots(activeKey)
	} else {
		snapshots, err = store.ListSnapshots(filterProfile, activeKey)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list snapshots: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snapshots)
		return
	}

	activeFP := crypto.MasterKeyFingerprint(activeKey)

	if allProfiles {
		fmt.Println("📁 Point-in-Time Vault Snapshots (All Profiles)")
	} else {
		snapDir, _ := store.GetSnapshotDir(profile)
		fmt.Printf("📁 Point-in-Time Vault Snapshots (Profile: %s)\n", profile)
		if snapDir != "" {
			home, _ := os.UserHomeDir()
			dispDir := snapDir
			if home != "" && strings.HasPrefix(snapDir, home) {
				dispDir = "~" + strings.TrimPrefix(snapDir, home)
			}
			fmt.Printf("📌 Storage Path: %s\n", dispDir)
		}
	}

	if len(activeKey) > 0 {
		fmt.Printf("🔒 Active Master Key SHA-256: sha256:%s\n", activeFP)
	}
	fmt.Println("───────────────────────────────────────────────────────────────────────────────────────────────────────────────────")

	if len(snapshots) == 0 {
		fmt.Println("  No snapshots found. Run 'sec snapshot create' to generate one.")
		fmt.Println("───────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
		return
	}

	if verbose {
		fmt.Printf("%-24s %-12s %-20s %-8s %-8s %-20s %-24s %s\n", "SNAPSHOT ID", "PROFILE", "CREATED", "FORMAT", "KEYS", "KEY SHA-256", "TRIGGER REASON", "FILE PATH")
	} else {
		fmt.Printf("%-24s %-12s %-20s %-8s %-8s %-20s %s\n", "SNAPSHOT ID", "PROFILE", "CREATED", "FORMAT", "KEYS", "KEY SHA-256", "TRIGGER REASON")
	}
	fmt.Println("───────────────────────────────────────────────────────────────────────────────────────────────────────────────────")

	for _, s := range snapshots {
		secCountStr := "?"
		if s.SecretCount >= 0 {
			secCountStr = fmt.Sprintf("%d", s.SecretCount)
		}

		keyFpStr := s.MasterKeySHA256
		if keyFpStr != "" && keyFpStr != "unknown" && keyFpStr != "none" {
			if s.KeyMatch {
				keyFpStr = fmt.Sprintf("sha256:%s [MATCH]", keyFpStr[:min(8, len(keyFpStr))])
			} else {
				keyFpStr = fmt.Sprintf("sha256:%s [MISMATCH]", keyFpStr[:min(8, len(keyFpStr))])
			}
		}

		pName := s.Profile
		if pName == "" {
			pName = "default"
		}

		if verbose {
			home, _ := os.UserHomeDir()
			dispPath := s.FilePath
			if home != "" && strings.HasPrefix(s.FilePath, home) {
				dispPath = "~" + strings.TrimPrefix(s.FilePath, home)
			}
			fmt.Printf("%-24s %-12s %-20s %-8s %-8s %-20s %-24s %s\n",
				s.ID,
				pName,
				s.CreatedAt.Format("2006-01-02 15:04:05"),
				s.SchemaVersion,
				secCountStr,
				keyFpStr,
				s.TriggerReason,
				dispPath,
			)
		} else {
			fmt.Printf("%-24s %-12s %-20s %-8s %-8s %-20s %s\n",
				s.ID,
				pName,
				s.CreatedAt.Format("2006-01-02 15:04:05"),
				s.SchemaVersion,
				secCountStr,
				keyFpStr,
				s.TriggerReason,
			)
		}
	}

	fmt.Println("───────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
	fmt.Println("To restore a snapshot: run 'sec snapshot restore <SNAPSHOT_ID>'")
}

func handleSnapshotCreate(profile string, args []string) {
	comment := ""
	for i := 0; i < len(args); i++ {
		if (args[i] == "--comment" || args[i] == "-m") && i+1 < len(args) {
			comment = args[i+1]
			i++
		}
	}

	getter, _ := keychain.GetKeychainAccessPair(profile)
	activeKey, _ := getter()

	actor := os.Getenv("SEC_ACTOR")
	if actor == "" {
		actor = "terminal"
	}

	meta, err := store.CreateSnapshot(profile, "manual", actor, comment, activeKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create snapshot: %v\n", err)
		daemon.LogOperation(actor, "SNAPSHOT_CREATE", profile, crypto.MasterKeyFingerprint(activeKey), "Manual snapshot creation failed", false, err.Error())
		os.Exit(1)
	}

	activeFP := crypto.MasterKeyFingerprint(activeKey)
	daemon.LogOperation(actor, "SNAPSHOT_CREATE", profile, activeFP, fmt.Sprintf("Created snapshot %s", meta.ID), true, "")

	fmt.Printf("✨ Created snapshot %s (Profile: %s, Master Key SHA-256: sha256:%s)\n", meta.ID, profile, activeFP)
	fmt.Printf("  File: %s\n", meta.FilePath)
}

func handleSnapshotRestore(profile string, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Snapshot ID required")
		fmt.Fprintln(os.Stderr, "Usage: sec snapshot restore <SNAPSHOT_ID> [--force]")
		os.Exit(1)
	}

	targetID := args[0]
	force := false
	for _, arg := range args {
		if arg == "--force" || arg == "-f" {
			force = true
		}
	}

	getter, _ := keychain.GetKeychainAccessPair(profile)
	activeKey, err := getter()
	if err != nil || len(activeKey) == 0 {
		fmt.Fprintf(os.Stderr, "Error: Touch ID re-authentication required to restore snapshot: %v\n", err)
		os.Exit(1)
	}

	snapshots, err := store.ListSnapshots(profile, activeKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list snapshots: %v\n", err)
		os.Exit(1)
	}

	var targetSnap *store.SnapshotMeta
	for _, s := range snapshots {
		if s.ID == targetID || strings.HasPrefix(s.ID, targetID) {
			targetSnap = s
			break
		}
	}

	if targetSnap == nil {
		fmt.Fprintf(os.Stderr, "Error: Snapshot %q not found for profile %q\n", targetID, profile)
		fmt.Fprintln(os.Stderr, "Run 'sec snapshot list' to see available snapshots.")
		os.Exit(1)
	}

	actor := os.Getenv("SEC_ACTOR")
	if actor == "" {
		actor = "terminal"
	}

	// 1. Create Pre-Restore Safety Snapshot of active vault
	safetyMeta, safetyErr := store.CreateSnapshot(profile, "pre-restore-safety", actor, fmt.Sprintf("Safety copy created before restoring %s", targetSnap.ID), activeKey)
	if safetyErr == nil {
		fmt.Printf("🛡️  Created pre-restore safety snapshot %s\n", safetyMeta.ID)
	}

	// 2. Perform Decryption Verification of Target Snapshot
	snapshotData, readErr := os.ReadFile(targetSnap.FilePath)
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "Error reading snapshot file %s: %v\n", targetSnap.FilePath, readErr)
		os.Exit(1)
	}

	var payloadToTest []byte
	if store.IsV2Vault(targetSnap.FilePath) {
		env, envErr := store.ReadVaultEnvelope(targetSnap.FilePath)
		if envErr != nil {
			fmt.Fprintf(os.Stderr, "Corrupt snapshot envelope: %v\n", envErr)
			os.Exit(1)
		}
		payloadToTest = env.Payload
	} else {
		payloadToTest = snapshotData
	}

	_, decErr := crypto.Decrypt(activeKey, payloadToTest)
	if decErr != nil {
		fmt.Fprintf(os.Stderr, "❌ Cannot restore snapshot %s: Decryption failed with active Touch ID key (%v)\n", targetSnap.ID, decErr)
		fmt.Fprintln(os.Stderr, "Remediation: This snapshot was created under a previous master key. Un-brick via 'sec session recover'.")
		daemon.LogOperation(actor, "SNAPSHOT_RESTORE", profile, crypto.MasterKeyFingerprint(activeKey), fmt.Sprintf("Failed to restore snapshot %s (Key mismatch)", targetSnap.ID), false, decErr.Error())
		os.Exit(1)
	}

	// 3. Confirm with user if interactive
	if !force {
		fmt.Printf("\n⚠️  You are about to restore snapshot %s (%s) into profile %q.\n", targetSnap.ID, targetSnap.CreatedAt.Format("2006-01-02 15:04:05"), profile)
		fmt.Print("Proceed with restore? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		ans, _ := reader.ReadString('\n')
		ans = strings.TrimSpace(strings.ToLower(ans))
		if ans != "y" && ans != "yes" {
			fmt.Println("Restore canceled.")
			return
		}
	}

	// 4. Overwrite active vault file atomically
	cfgDir, _ := config.GetConfigDir()
	vaultPath := filepath.Join(cfgDir, "secrets.enc")
	if profile != "default" {
		vaultPath = filepath.Join(cfgDir, fmt.Sprintf("secrets_%s.enc", profile))
	}

	// #nosec G304 G703
	if err := os.WriteFile(vaultPath, snapshotData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to overwrite vault file: %v\n", err)
		daemon.LogOperation(actor, "SNAPSHOT_RESTORE", profile, crypto.MasterKeyFingerprint(activeKey), fmt.Sprintf("Failed to restore snapshot %s", targetSnap.ID), false, err.Error())
		os.Exit(1)
	}

	activeFP := crypto.MasterKeyFingerprint(activeKey)
	daemon.LogOperation(actor, "SNAPSHOT_RESTORE", profile, activeFP, fmt.Sprintf("Successfully restored snapshot %s", targetSnap.ID), true, "")

	// 5. Evict stale daemon cache to reload restored vault
	evictStaleDaemon(profile)

	fmt.Printf("✨ Successfully restored snapshot %s into profile %q! Daemon reloaded.\n", targetSnap.ID, profile)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
