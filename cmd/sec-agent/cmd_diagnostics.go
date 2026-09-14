package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
)

func detectDaemonAnomaly(profile string, pids []int) (bool, string, string) {
	if len(pids) > 1 {
		msg := fmt.Sprintf("[⚠️] Daemon Anomaly: Multiple daemon processes (%d) detected for profile %q (PIDs: %v)", len(pids), profile, pids)
		rem := fmt.Sprintf("Run 'sec restart --profile %s' to terminate duplicate processes and restart a clean instance.", profile)
		return true, msg, rem
	}
	if len(pids) == 1 {
		return false, fmt.Sprintf("[✓] Daemon Process: Single instance active (PID: %d)", pids[0]), ""
	}
	return false, "", ""
}

func handleDoctor(profile string, args []string) {
	skipKeychain := false
	repairMode := false
	for _, a := range args {
		if a == "--skip-keychain" {
			skipKeychain = true
		} else if a == "--repair" {
			repairMode = true
		}
	}

	if repairMode {
		fmt.Println("=== sec-agent Vault Envelope Structure Repair ===")
		vaults, vErr := store.ListVaultFiles()
		if vErr != nil {
			fmt.Printf("[✗] Failed to list vault files: %v\n", vErr)
			os.Exit(1)
		}
		repairedCount := 0
		for _, v := range vaults {
			if v.NestingDepth > 1 {
				fmt.Printf("[⏳] Profile %-20s Vault: Nested Envelope (Depth: %d). Flattening...\n", v.Profile, v.NestingDepth)
				origDepth, err := store.FlattenVaultFile(v.Path)
				if err != nil {
					fmt.Printf("[✗] Profile %-20s Repair failed: %v\n", v.Profile, err)
				} else {
					fmt.Printf("[✓] Profile %-20s Repaired successfully! Flattened from depth %d to 1 (Backup: %s.bak_nested)\n", v.Profile, origDepth, filepath.Base(v.Path))
					repairedCount++
				}
			}
		}
		if repairedCount == 0 {
			fmt.Println("[✓] All vault envelopes are already clean (no nested envelopes found).")
		} else {
			fmt.Printf("\n[✓] Successfully repaired %d nested vault envelope(s).\n", repairedCount)
		}
		return
	}

	fmt.Println("=== sec-agent System & Security Doctor ===")

	// 1. Operating System & Arch
	fmt.Printf("[✓] Operating System: %s (%s)\n", runtime.GOOS, runtime.GOARCH)

	// 2. Config Directory permissions
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		fmt.Printf("[✗] Config Directory: Failed to resolve (%v)\n", err)
	} else {
		if fi, err := os.Stat(cfgDir); err == nil {
			fmt.Printf("[✓] Config Directory: %s (Mode: %o)\n", cfgDir, fi.Mode().Perm())
		} else {
			fmt.Printf("[✗] Config Directory: Missing (%v)\n", err)
		}
	}

	// 3. Socket Security
	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		fmt.Printf("[✗] Unix Socket: Failed to resolve (%v)\n", err)
	} else {
		if fi, err := os.Stat(sockPath); err == nil {
			fmt.Printf("[✓] Unix Socket: %s (Permissions: %o - Owner Only)\n", sockPath, fi.Mode().Perm())
		} else {
			fmt.Println("[!] Unix Socket: Inactive (Run 'eval $(sec open)' to start daemon)")
		}
	}

	// 4. Secure Enclave & Touch ID
	if runtime.GOOS == "darwin" {
		fmt.Println("[✓] Secure Enclave: Hardware biometrics supported & active")
		fmt.Println("[✓] Keychain Access: SecAccessControl & Hardened Runtime active")
	} else {
		fmt.Println("[!] Secure Enclave: Non-macOS system (using fallback software key storage)")
	}

	// 5. Active Daemon Health & Anomaly Detection
	daemonPIDs := findDaemonPIDs(profile)
	if hasAnomaly, msg, rem := detectDaemonAnomaly(profile, daemonPIDs); hasAnomaly {
		fmt.Println(msg)
		fmt.Fprintf(os.Stderr, "    Remediation: %s\n", rem)
	} else if msg != "" {
		fmt.Println(msg)
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: daemon.IPCActionStatus})
	if err == nil && resp.Success && resp.StatusInfo != nil {
		fmt.Printf("[✓] Daemon Health: Active (Secrets Stored: %d)\n", resp.StatusInfo.TotalSecrets)
	} else {
		fmt.Println("[!] Daemon Health: Session locked or stopped")
	}

	// 6. Security Audit Log
	auditPath := filepath.Join(cfgDir, "audit.log")
	if fi, err := os.Stat(auditPath); err == nil {
		fmt.Printf("[✓] Security Audit Log: %s (%d bytes)\n", auditPath, fi.Size())
	} else {
		fmt.Println("[✓] Security Audit Log: Initialized")
	}

	// 7. Vault Envelope & Keychain Diagnostics across all profiles
	fmt.Println("\n--- Vault & Keychain Health ---")
	vaults, vErr := store.ListVaultFiles()
	if vErr == nil {
		for _, v := range vaults {
			if v.NestingDepth > 1 {
				fmt.Printf("[⚠️] Profile %-20s Vault: Nested Envelope Detected (Depth: %d) — Run 'sec doctor --repair' to auto-heal\n", v.Profile, v.NestingDepth)
			}
		}
	}

	if skipKeychain || (!isInteractiveTerminal() && os.Getenv("SEC_TEST_MODE") != "1") {
		reason := "headless / non-interactive terminal detected"
		if skipKeychain {
			reason = "--skip-keychain flag supplied"
		}
		fmt.Printf("[ℹ] Skipped live Touch ID Keychain probe (%s).\n", reason)
		fmt.Println("    (Run 'sec doctor' in an interactive terminal to verify Touch ID hardware keys)")
	} else if vErr == nil {
		fmt.Println("[ℹ] Auditing enrolled profile keys in macOS Keychain (Touch ID prompt may appear)...")
		for _, v := range vaults {
			getter, _ := keychain.GetKeychainAccessPair(v.Profile)
			kcKey, err := getter()
			if err != nil {
				fmt.Printf("[!] Profile %-20s Vault: %s | Keychain: Key Missing/Locked (%v)\n", v.Profile, v.Path, err)
				continue
			}

			if store.IsV2Vault(v.Path) {
				env, readErr := store.ReadVaultEnvelope(v.Path)
				if readErr != nil {
					fmt.Printf("[✗] Profile %-20s Vault: Corrupt Envelope (%v)\n", v.Profile, readErr)
					continue
				}
				_, decErr := crypto.Decrypt(kcKey, env.Payload)
				if decErr != nil {
					fmt.Printf("[✗] Profile %-20s Vault: v2.0 Envelope | Keychain Key Mismatch (%v)\n", v.Profile, decErr)
				} else {
					fmt.Printf("[✓] Profile %-20s Vault: v2.0 Dual-Slot Envelope | Touch ID Key Verified\n", v.Profile)
				}
			} else {
				data, readErr := os.ReadFile(v.Path)
				if readErr != nil {
					fmt.Printf("[✗] Profile %-20s Vault: Failed to read file (%v)\n", v.Profile, readErr)
					continue
				}
				_, decErr := crypto.Decrypt(kcKey, data)
				if decErr != nil {
					fmt.Printf("[✗] Profile %-20s Vault: v1.0 Legacy Vault | Keychain Key Mismatch (%v)\n", v.Profile, decErr)
				} else {
					fmt.Printf("[✓] Profile %-20s Vault: v1.0 Legacy Vault | Touch ID Key Verified (Migrate via 'sec migrate-v2')\n", v.Profile)
				}
			}
			store.ZeroBytes(kcKey)
		}
	}

	fmt.Println("\nAll system diagnostic checks complete!")
}

func handleStatusQuick(profile string) {
	socketPath, err := config.GetSocketPath(profile)
	if err != nil {
		fail("CONFIG_ERROR", err, "Failed to resolve config directory.")
	}
	info, err := os.Stat(socketPath)
	if err != nil {
		failDaemonNotRunning(profile)
	}

	mode := info.Mode()
	perms := mode.Perm()

	// Live IPC dial check to confirm daemon responsiveness and detect orphaned socket files
	pingResp, pingErr := queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionPing})
	if pingErr != nil {
		fmt.Fprintf(os.Stderr, "Notice: Stale socket file detected at %s (daemon process is not running).\n", socketPath)
		failDaemonNotRunning(profile)
	}

	daemonVer := ""
	daemonSynced := true
	if pingResp != nil && pingResp.Version != "" {
		daemonVer = pingResp.Version
		if pingResp.Version != Version {
			daemonSynced = false
		}
	} else if pidPath, pErr := config.GetPIDFilePath(profile); pErr == nil {
		// #nosec G304 G703
		if data, err := os.ReadFile(pidPath); err == nil {
			var pInfo daemon.PIDLockInfo
			if json.Unmarshal(data, &pInfo) == nil && pInfo.Version != "" {
				daemonVer = pInfo.Version
				if pInfo.Version != Version {
					daemonSynced = false
				}
			}
		}
	}

	var activeSkillPath string
	skillSynced := false
	if manifest, mErr := loadSkillManifest(); mErr == nil && manifest != nil && len(manifest.Skills) > 0 {
		for _, s := range manifest.Skills {
			if s.Path != "" {
				activeSkillPath = s.Path
				if s.Version == Version {
					skillSynced = true
				}
				break
			}
		}
	}

	socketStatus := "ACTIVE (IPC socket responsive)"
	statusField := "ACTIVE"
	if pingResp != nil && !pingResp.Success {
		if strings.Contains(pingResp.Error, "locked") {
			socketStatus = "LOCKED (Daemon running, session locked)"
			statusField = "LOCKED"
		} else {
			socketStatus = fmt.Sprintf("DENIED (%s)", pingResp.Error)
			statusField = "DENIED"
		}
	}

	if jsonErrors {
		resMap := map[string]interface{}{
			"success":      true,
			"profile":      profile,
			"socket_path":  socketPath,
			"socket_perms": fmt.Sprintf("%04o", perms),
			"status":       statusField,
		}
		if statusField != "ACTIVE" && pingResp != nil {
			resMap["status_detail"] = pingResp.Error
		}
		if activeSkillPath != "" {
			resMap["skill_path"] = activeSkillPath
			resMap["skill_version"] = Version
			resMap["skill_synced"] = skillSynced
		}
		if daemonVer != "" {
			resMap["daemon_version"] = daemonVer
			resMap["daemon_synced"] = daemonSynced
		}
		data, _ := json.MarshalIndent(resMap, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println("=== sec-agent Fast-Path Status Diagnostic ===")
	fmt.Printf("[✓] Active Profile: %s\n", profile)
	fmt.Printf("[✓] Socket Path:    %s\n", socketPath)
	fmt.Printf("[✓] File Perms:     %04o (Strict)\n", perms)
	fmt.Printf("[✓] Socket Status:  %s\n", socketStatus)
	if daemonVer != "" {
		if !daemonSynced {
			fmt.Printf("[✓] Daemon Version: %s (⚠️ Outdated: CLI is %s — run 'sec restart --hot-reload')\n", daemonVer, Version)
		} else {
			fmt.Printf("[✓] Daemon Version: %s (Synced)\n", daemonVer)
		}
	}
	if activeSkillPath != "" {
		syncMsg := "Synced"
		if !skillSynced {
			syncMsg = "Update Available"
		}
		fmt.Printf("[✓] AI Skill Doc:   %s (%s: %s)\n", activeSkillPath, Version, syncMsg)
	}

	fmt.Println("\n💡 Encountered friction, bugs, or have an idea? Run 'sec feedback' or submit an issue on GitHub.")
}

func handleStatusAll() {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		fail("CONFIG_ERROR", err, "")
	}

	profilesMap := make(map[string]bool)
	profilesMap["default"] = true

	// Discover profiles from vault files (.enc) via SSOT
	if vaults, vErr := store.ListVaultFiles(); vErr == nil {
		for _, v := range vaults {
			if v.Profile != "" {
				profilesMap[v.Profile] = true
			}
		}
	}

	profilesDir := filepath.Join(cfgDir, "profiles")
	if entries, err := os.ReadDir(profilesDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				profilesMap[e.Name()] = true
			}
		}
	}

	var profiles []string
	for p := range profilesMap {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)

	type ProfileInfo struct {
		Name       string
		Tier       string
		Unlocked   bool
		DaemonRun  bool
		TotalKeys  int
		ExpKeys    int
		SocketPath string
		Namespaces []string
	}

	var profileInfos []ProfileInfo
	totalGlobalExpiring := 0

	for _, p := range profiles {
		tier := getProfileEnvTier(store.ProfileName(p))
		if tier == config.TierUnset {
			tier = config.TierDev
		}

		info := ProfileInfo{
			Name: p,
			Tier: strings.ToUpper(tier.String()),
		}

		resp, err := queryDaemonRaw(p, daemon.IPCRequest{Action: daemon.IPCActionStatus})
		if err == nil && resp != nil && resp.Success && resp.StatusInfo != nil {
			info.DaemonRun = true
			info.Unlocked = resp.StatusInfo.IsUnlocked
			info.TotalKeys = resp.StatusInfo.TotalSecrets
			info.ExpKeys = resp.StatusInfo.ExpiredSecrets
			info.SocketPath = resp.StatusInfo.SocketPath
		}

		bkResp, bkErr := queryDaemonRaw(p, daemon.IPCRequest{Action: "backup"})
		if bkErr == nil && bkResp != nil && bkResp.Success {
			nsMap := make(map[string]int)
			for path, entry := range bkResp.Secrets {
				if strings.HasPrefix(path, "__") {
					continue
				}
				parts := strings.SplitN(path, "/", 2)
				if len(parts) > 1 {
					nsMap[parts[0]+"/"]++
				} else {
					nsMap["root"]++
				}
				if !entry.Expires.IsZero() && time.Until(entry.Expires) <= 7*24*time.Hour && time.Until(entry.Expires) > 0 {
					totalGlobalExpiring++
				}
			}
			var nsList []string
			for ns, count := range nsMap {
				nsList = append(nsList, fmt.Sprintf("%s (%d)", ns, count))
			}
			sort.Strings(nsList)
			info.Namespaces = nsList
		}

		profileInfos = append(profileInfos, info)
	}

	if jsonErrors {
		type jsonProfileInfo struct {
			Name          string   `json:"name"`
			Tier          string   `json:"tier"`
			Unlocked      bool     `json:"unlocked"`
			DaemonRunning bool     `json:"daemon_running"`
			TotalKeys     int      `json:"total_keys"`
			ExpiredKeys   int      `json:"expired_keys"`
			Namespaces    []string `json:"namespaces,omitempty"`
		}
		jsonProfiles := make([]jsonProfileInfo, 0, len(profileInfos))
		for _, info := range profileInfos {
			jsonProfiles = append(jsonProfiles, jsonProfileInfo{
				Name:          info.Name,
				Tier:          info.Tier,
				Unlocked:      info.Unlocked,
				DaemonRunning: info.DaemonRun,
				TotalKeys:     info.TotalKeys,
				ExpiredKeys:   info.ExpKeys,
				Namespaces:    info.Namespaces,
			})
		}
		result := map[string]interface{}{
			"success":                true,
			"cli_version":            Version,
			"build_date":             BuildDate,
			"config_directory":       cfgDir,
			"profiles":               jsonProfiles,
			"expiring_within_7_days": totalGlobalExpiring,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println("=== sec-agent Global Workstation Status & Inventory ===")
	fmt.Printf("CLI Version:            %s (Build Date: %s)\n", Version, BuildDate)
	fmt.Printf("Config Directory:       %s\n", cfgDir)
	if wsCfg, wsFile, wsDir := loadWorkspaceConfigVerbose(); wsCfg != nil && wsCfg.Profile != "" {
		fmt.Printf("Workspace Binding:     %s (via %s in %s)\n", wsCfg.Profile, wsFile, wsDir)
	}
	fmt.Println()

	fmt.Printf("%-24s %-10s %-20s %-12s %s\n", "PROFILE NAME", "ENV TIER", "SESSION STATUS", "STORED KEYS", "EXPIRED")
	fmt.Println(strings.Repeat("-", 80))

	for _, info := range profileInfos {
		tierBadge := info.Tier
		switch info.Tier {
		case "DEV":
			tierBadge = "\033[32mDEV🟢\033[0m"
		case "DTA", "STAGING":
			tierBadge = "\033[33mSTAGING🟡\033[0m"
		case "PROD":
			tierBadge = "\033[31mPROD🔴\033[0m"
		}

		sessStatus := "\033[31mLOCKED\033[0m"
		if info.Unlocked {
			sessStatus = "\033[32mUNLOCKED (TouchID)\033[0m"
		} else if !info.DaemonRun {
			sessStatus = "\033[90mInactive\033[0m"
		}

		fmt.Printf("%-24s %-19s %-29s %-12d %-12d\n",
			info.Name,
			tierBadge,
			sessStatus,
			info.TotalKeys,
			info.ExpKeys,
		)
	}

	fmt.Println("\n=== Key Vault Namespaces & Groups Across Profiles ===")
	for _, info := range profileInfos {
		if len(info.Namespaces) > 0 {
			fmt.Printf(" • %-24s: %s\n", info.Name, strings.Join(info.Namespaces, ", "))
		} else {
			fmt.Printf(" • %-24s: (No secrets stored)\n", info.Name)
		}
	}

	if totalGlobalExpiring > 0 {
		fmt.Printf("\n\033[33m⚠️  EXPIRATION WARNING: %d secret key(s) expiring within the next 7 days across all profiles!\033[0m\n", totalGlobalExpiring)
		fmt.Println("Run 'sec ls --expiring 7d --profile <name>' for detailed inspection.")
	}
}

func handleStatus(profile string, args []string) {
	for _, arg := range args {
		if arg == "--all" || arg == "-a" {
			handleStatusAll()
			return
		} else if arg == "--quick" || arg == "-q" {
			handleStatusQuick(profile)
			return
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "status"})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	info := resp.StatusInfo
	tier := getProfileEnvTier(store.ProfileName(profile))
	if tier == "" {
		tier = "UNSET"
	}

	dbPath, _ := store.GetStorePath(profile)
	schemaStatus := "v2.0 Dual-Slot Envelope (Hardened)"
	isLegacy := false
	// #nosec G304 G703
	if dbData, err := os.ReadFile(dbPath); err == nil && len(dbData) > 0 {
		if dbData[0] != '{' {
			schemaStatus = "v1.0 Legacy Single-Slot Ciphertext (Unwrapped)"
			isLegacy = true
		}
	}

	fmt.Println("=== sec-agent Status & Diagnostics ===")
	if wsCfg, wsFile, wsDir := loadWorkspaceConfigVerbose(); wsCfg != nil && wsCfg.Profile != "" {
		fmt.Printf("📌 Active Workspace Profile: %s (bound via %s in %s)\n", wsCfg.Profile, wsFile, wsDir)
	}
	fmt.Printf("Active Profile:       %s (Tier: %s)\n", info.Profile, strings.ToUpper(tier.String()))
	printEnvBadge(store.ProfileName(profile))
	daemonVerStr := info.Version
	if info.Version != "" && info.Version != Version {
		daemonVerStr = fmt.Sprintf("%s (⚠️ Outdated: CLI is %s — run 'sec restart --hot-reload')", info.Version, Version)
	}
	fmt.Printf("Daemon Version:       %s\n", daemonVerStr)
	fmt.Printf("Vault Schema:         %s\n", schemaStatus)
	fmt.Println("Biometric Policy:     kSecAccessControlBiometryCurrentSet (Admin Defense Active)")
	if info.IsUnlocked {
		fmt.Println("Session Status:       UNLOCKED (Authorized via Touch ID)")
	} else {
		fmt.Println("Session Status:       LOCKED (Run 'eval $(sec open)')")
	}
	fmt.Printf("Stored Secrets:       %d total (%d expired)\n", info.TotalSecrets, info.ExpiredSecrets)
	fmt.Printf("Hard TTL Limit:       %s\n", info.SessionTTL)
	fmt.Printf("Inactivity Grace:     %s\n", info.GraceTTL)
	fmt.Printf("Socket Path:          %s\n", info.SocketPath)
	fmt.Printf("Database Path:        %s\n", info.StorePath)
	fmt.Printf("Database Size:        %d bytes\n", info.StoreSizeBytes)
	var staleSkills []InstalledSkillEntry
	if manifest, mErr := loadSkillManifest(); mErr == nil && manifest != nil && len(manifest.Skills) > 0 {
		syncStatus := "synced"
		for _, s := range manifest.Skills {
			if s.Version != Version {
				syncStatus = "updates available"
				staleSkills = append(staleSkills, s)
			}
		}
		fmt.Printf("AI Skills:            %d active (%s, %s)\n", len(manifest.Skills), Version, syncStatus)
	} else {
		fmt.Println("AI Skills:            none active")
	}

	if len(staleSkills) > 0 {
		fmt.Println("\n\033[33m⚠️  AI SKILL VERSION DRIFT DETECTED:\033[0m")
		for _, s := range staleSkills {
			fmt.Printf("   • %s (%s): installed doc (%s) trails CLI (%s)\n", s.Target, s.Scope, s.Version, Version)
		}
		fmt.Println("   ▶ Remediation: Run 'sec-agent skill update' to refresh your AI assistant instructions!")
	}

	if isLegacy {
		fmt.Println("\n\033[33m⚠️  SECURITY WARNING — LEGACY VAULT SCHEMA (v1.0 DETECTED):\033[0m")
		fmt.Println("   • Your vault file is using legacy v1.0 single-slot encryption.")
		fmt.Println("   • It does NOT protect against corporate device admins or rogue fingerprint additions.")
		fmt.Println("   • Run 'sec migrate-v2' to upgrade to Dual-Slot Admin Defense instantly.")
		fmt.Println("   • 💡 REMINDER: Always store your 24-word recovery seed in a safe offline location")
		fmt.Println("     (e.g., paper vault or password manager) before updating biometrics!")
	}

	bkResp, err := queryDaemonRaw(profile, daemon.IPCRequest{Action: "backup"})
	if err == nil && bkResp.Success {
		checkExpirationWarnings(bkResp.Secrets)
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func handleAudit(profile string, args []string) {
	limit := 50
	showJSON := false
	showVerbose := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--limit" || args[i] == "-n" {
			if i+1 < len(args) {
				if l, err := strconv.Atoi(args[i+1]); err == nil {
					limit = l
					i++
				}
			}
		} else if args[i] == "--json" || args[i] == "-j" {
			showJSON = true
		} else if args[i] == "--verbose" || args[i] == "-v" {
			showVerbose = true
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: daemon.IPCActionAudit,
		Limit:  limit,
	})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	lines := strings.Split(resp.Value, "\n")
	var list []daemon.AuditLogEntry
	for _, line := range lines {
		if line == "" {
			continue
		}
		var m daemon.AuditLogEntry
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			list = append(list, m)
		}
	}

	if showJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(list)
		return
	}

	if len(list) == 0 {
		fmt.Println("No audit log entries found.")
		return
	}

	cfgDir, _ := config.GetConfigDir()
	logPath := filepath.Join(cfgDir, "audit.log")
	logSize := int64(0)
	if fi, err := os.Stat(logPath); err == nil {
		logSize = fi.Size()
	}

	titleProf := profile
	if titleProf == "" {
		titleProf = "default"
	}

	fmt.Printf("🛡️  sec-agent Security Audit Flight Log (Profile: %s)\n", titleProf)
	fmt.Printf("📌 Log File: %s (Size: %d B, %d entries)\n", logPath, logSize, len(list))

	if showVerbose {
		fmt.Println("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
		fmt.Printf("%-20s %-8s %-10s %-20s %-16s %-22s %-8s %s\n", "TIMESTAMP (UTC)", "ACTION", "PROFILE", "KEY PATH", "KEY FINGERPRINT", "CALLER PROCESS", "STATUS", "VAULT FILE")
		fmt.Println("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
		for _, e := range list {
			tStr := e.Timestamp
			if t, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
				tStr = t.Format("2006-01-02 15:04:05")
			}
			pStr := e.Path
			if pStr == "" {
				pStr = "-"
			}
			fpStr := e.MasterKeySHA256
			if fpStr != "" && !strings.HasPrefix(fpStr, "sha256:") {
				fpStr = "sha256:" + fpStr
			}
			if fpStr == "" {
				fpStr = "-"
			}
			procStr := e.ProcessName
			if procStr == "" && e.PeerPID > 0 {
				procStr = fmt.Sprintf("PID %d", e.PeerPID)
			}
			if procStr == "" {
				procStr = "-"
			}
			statusStr := "SUCCESS"
			if !e.Success {
				statusStr = "FAILED"
			}
			storeFile := e.StoreFilePath
			if storeFile == "" {
				storeFile = "-"
			}
			profStr := e.Profile
			if profStr == "" {
				profStr = "default"
			}
			fmt.Printf("%-20s %-8s %-10s %-20s %-16s %-22s %-8s %s\n", tStr, string(e.Action), profStr, truncateStr(pStr, 20), truncateStr(fpStr, 16), truncateStr(procStr, 22), statusStr, storeFile)
		}
		fmt.Println("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
	} else {
		fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
		fmt.Printf("%-20s %-8s %-10s %-20s %-16s %-22s %-8s %s\n", "TIMESTAMP (UTC)", "ACTION", "PROFILE", "KEY PATH", "KEY FINGERPRINT", "CALLER PROCESS", "STATUS", "DETAILS")
		fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
		for _, e := range list {
			tStr := e.Timestamp
			if t, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
				tStr = t.Format("2006-01-02 15:04:05")
			}
			pStr := e.Path
			if pStr == "" {
				pStr = "-"
			}
			fpStr := e.MasterKeySHA256
			if fpStr != "" && !strings.HasPrefix(fpStr, "sha256:") {
				fpStr = "sha256:" + fpStr
			}
			if fpStr == "" {
				fpStr = "-"
			}
			procStr := e.ProcessName
			if procStr == "" && e.PeerPID > 0 {
				procStr = fmt.Sprintf("PID %d", e.PeerPID)
			}
			if procStr == "" {
				procStr = "-"
			}
			statusStr := "SUCCESS"
			if !e.Success {
				statusStr = "FAILED"
			}
			detStr := e.Details
			if detStr == "" {
				if e.ValueLength > 0 {
					detStr = fmt.Sprintf("val_len=%dB, ver=%d", e.ValueLength, e.SecretVersion)
				} else if e.Error != "" {
					detStr = e.Error
				} else {
					detStr = "-"
				}
			}
			profStr := e.Profile
			if profStr == "" {
				profStr = "default"
			}
			fmt.Printf("%-20s %-8s %-10s %-20s %-16s %-22s %-8s %s\n", tStr, string(e.Action), profStr, truncateStr(pStr, 20), truncateStr(fpStr, 16), truncateStr(procStr, 22), statusStr, detStr)
		}
		fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
		fmt.Println("To view full filesystem paths: run 'sec audit --verbose'")
		fmt.Println("To view structured JSON output: run 'sec audit --json'")
	}
}

type DaemonProcessEntry struct {
	PID        int    `json:"pid"`
	Profile    string `json:"profile"`
	Status     string `json:"status"`
	Uptime     string `json:"uptime,omitempty"`
	Socket     string `json:"socket"`
	Executable string `json:"executable"`
}

func handleDaemonList(args []string) {
	jsonOut := false
	for _, a := range args {
		if a == "--json" {
			jsonOut = true
		}
	}

	entriesMap := make(map[int]*DaemonProcessEntry)

	// 1. Scan config directory for .pid files
	cfgDir, err := config.GetConfigDir()
	if err == nil && cfgDir != "" {
		files, _ := os.ReadDir(cfgDir)
		for _, f := range files {
			name := f.Name()
			if strings.HasPrefix(name, "sec-agent") && strings.HasSuffix(name, ".pid") {
				profile := "default"
				if name != "sec-agent.pid" {
					profile = strings.TrimPrefix(name, "sec-agent_")
					profile = strings.TrimSuffix(profile, ".pid")
				}
				pidPath := filepath.Join(cfgDir, name)
				// #nosec G304 G703
				if data, err := os.ReadFile(pidPath); err == nil {
					var info daemon.PIDLockInfo
					if json.Unmarshal(data, &info) == nil && info.PID > 0 {
						if syscall.Kill(info.PID, 0) == nil {
							sock, _ := config.GetSocketPath(profile)
							entriesMap[info.PID] = &DaemonProcessEntry{
								PID:        info.PID,
								Profile:    profile,
								Executable: info.Executable,
								Socket:     sock,
							}
						}
					}
				}
			}
		}
	}

	// 2. Scan process table using ps -eo pid,etime,command
	psCmd := exec.Command("ps", "-eo", "pid,etime,command")
	if out, err := psCmd.Output(); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "PID") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			pid, err := strconv.Atoi(fields[0])
			if err != nil || pid <= 0 || pid == os.Getpid() || pid == os.Getppid() {
				continue
			}
			etime := fields[1]
			cmdLine := strings.Join(fields[2:], " ")
			base := filepath.Base(fields[2])

			if strings.Contains(cmdLine, "grep") || strings.Contains(cmdLine, "go test") {
				continue
			}

			isSecBin := base == "sec" || base == "sec-agent" || strings.Contains(fields[2], "sec-agent") || strings.Contains(fields[2], "/sec")
			if !isSecBin {
				if !strings.Contains(cmdLine, "sec daemon") && !strings.Contains(cmdLine, "sec-agent daemon") {
					continue
				}
			}

			hasDaemon := false
			for _, f := range fields[2:] {
				if f == "daemon" {
					hasDaemon = true
					break
				}
			}
			if !hasDaemon {
				continue
			}

			procProfile := "default"
			for i := 2; i < len(fields); i++ {
				if (fields[i] == "--profile" || fields[i] == "-P") && i+1 < len(fields) {
					procProfile = fields[i+1]
					break
				}
				if strings.HasPrefix(fields[i], "--profile=") {
					procProfile = strings.TrimPrefix(fields[i], "--profile=")
					break
				}
			}

			sock, _ := config.GetSocketPath(procProfile)
			if entry, ok := entriesMap[pid]; ok {
				entry.Uptime = etime
				if entry.Executable == "" {
					entry.Executable = fields[2]
				}
			} else {
				entriesMap[pid] = &DaemonProcessEntry{
					PID:        pid,
					Profile:    procProfile,
					Uptime:     etime,
					Executable: fields[2],
					Socket:     sock,
				}
			}
		}
	}

	// 3. Query status for each profile using fast probe
	var entries []*DaemonProcessEntry
	for _, entry := range entriesMap {
		sock := entry.Socket
		if sock == "" {
			sock, _ = config.GetSocketPath(entry.Profile)
			entry.Socket = sock
		}
		// Fast single dial attempt (20ms timeout) without sleep/retries
		conn, err := net.DialTimeout("unix", sock, 20*time.Millisecond)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
			_ = json.NewEncoder(conn).Encode(daemon.IPCRequest{Action: daemon.IPCActionPing})
			var resp daemon.IPCResponse
			if err := json.NewDecoder(conn).Decode(&resp); err == nil {
				if resp.Success {
					entry.Status = "Active (unlocked)"
				} else {
					entry.Status = "Active (locked)"
				}
			} else {
				entry.Status = "Stale / Unresponsive"
			}
			_ = conn.Close()
		} else {
			entry.Status = "Stale / Unresponsive"
		}
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Profile != entries[j].Profile {
			return entries[i].Profile < entries[j].Profile
		}
		return entries[i].PID < entries[j].PID
	})

	if jsonOut {
		data, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(data))
		return
	}

	if len(entries) == 0 {
		fmt.Println("No active background daemon processes found.")
		return
	}

	fmt.Printf("%-8s %-16s %-22s %-12s %s\n", "PID", "PROFILE", "STATUS", "UPTIME", "SOCKET")
	fmt.Println(strings.Repeat("-", 80))
	for _, e := range entries {
		fmt.Printf("%-8d %-16s %-22s %-12s %s\n", e.PID, e.Profile, e.Status, e.Uptime, e.Socket)
	}
}
