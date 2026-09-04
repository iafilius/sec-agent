package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"secure_secrets/internal/audit"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
)

func handleCheck(profile string, args []string) {
	var requiredKeys []string
	templateFile := ""
	pingHost := ""
	remoteHost := ""
	var uciChecks []string
	var envChecks []string
	scanLeaks := false
	scanWeak := false
	scanScripts := false
	scriptsPath := "."

	for i := 0; i < len(args); i++ {
		if args[i] == "--scan-weak" || args[i] == "-w" {
			scanWeak = true
		} else if args[i] == "--leaks" || args[i] == "--scan-leaks" || args[i] == "-l" || args[i] == "--history" {
			scanLeaks = true
		} else if args[i] == "--scripts" || args[i] == "--scan-scripts" {
			scanScripts = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				scriptsPath = args[i+1]
				i++
			}
		} else if args[i] == "--remote" && i+1 < len(args) {
			remoteHost = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--remote=") {
			remoteHost = strings.TrimPrefix(args[i], "--remote=")
		} else if args[i] == "--uci" && i+1 < len(args) {
			uciChecks = append(uciChecks, args[i+1])
			i++
		} else if strings.HasPrefix(args[i], "--uci=") {
			uciChecks = append(uciChecks, strings.TrimPrefix(args[i], "--uci="))
		} else if args[i] == "--env" && i+1 < len(args) {
			envChecks = append(envChecks, args[i+1])
			i++
		} else if strings.HasPrefix(args[i], "--env=") {
			envChecks = append(envChecks, strings.TrimPrefix(args[i], "--env="))
		} else if args[i] == "--template" || args[i] == "-t" {
			if i+1 < len(args) {
				templateFile = args[i+1]
				i++
			}
		} else if args[i] == "--ping-host" {
			if i+1 < len(args) {
				pingHost = args[i+1]
				i++
			}
		} else if args[i] == "--required" || args[i] == "-r" {
			if i+1 < len(args) {
				requiredKeys = strings.Split(args[i+1], ",")
				i++
			}
		} else if !strings.HasPrefix(args[i], "-") {
			requiredKeys = append(requiredKeys, args[i])
		}
	}

	if remoteHost != "" && (len(uciChecks) > 0 || len(envChecks) > 0) {
		handleCheckRemote(profile, remoteHost, uciChecks, envChecks)
		return
	}

	if scanLeaks {
		handleCheckLeaks(profile)
		return
	}

	if scanScripts {
		handleCheckScripts(scriptsPath)
		return
	}

	if scanWeak {
		resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
		if err != nil || !resp.Success {
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running or locked for profile %q", profile), "Run 'eval $(sec open)' to unlock.")
		}

		fmt.Println("=== Vault Secret Password Entropy & Weakness Scan ===")
		fmt.Printf("%-36s %s\n", "KEY PATH", "STATUS")
		fmt.Println(strings.Repeat("-", 60))

		weakCount := 0
		passCount := 0

		var paths []string
		for p := range resp.Secrets {
			if !strings.HasPrefix(p, "__") {
				paths = append(paths, p)
			}
		}
		sort.Strings(paths)

		for _, path := range paths {
			entry := resp.Secrets[path]
			if audit.IsWeakPassword(entry.Value) {
				weakCount++
				fmt.Printf("%-36s \033[33mWEAK ENTROPY [⚠️]\033[0m\n", path)
			} else {
				passCount++
				fmt.Printf("%-36s \033[32mPASS [✓]\033[0m\n", path)
			}
		}

		fmt.Printf("\nSummary: %d key(s) PASS, %d key(s) WEAK ENTROPY.\n", passCount, weakCount)
		return
	}

	if templateFile != "" {
		// #nosec G304 G703
		data, err := os.ReadFile(templateFile)
		if err != nil {
			fail("FILE_READ_ERROR", fmt.Errorf("failed to read template file %s: %v", templateFile, err), "Check file path.")
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			if key != "" {
				requiredKeys = append(requiredKeys, key)
			}
		}
	}

	if pingHost != "" {
		targetAddr := pingHost
		if !strings.Contains(targetAddr, ":") {
			targetAddr = targetAddr + ":22"
		}
		// #nosec G102 G704
		conn, err := net.DialTimeout("tcp", targetAddr, 100*time.Millisecond)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[⚠️] Network Reachability Guard: Target host %s is UNREACHABLE (%v)\n", targetAddr, err)
			if jsonErrors {
				data, _ := json.Marshal(map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    "HOST_UNREACHABLE",
						"message": fmt.Sprintf("Target host %s is unreachable: %v", targetAddr, err),
					},
				})
				fmt.Println(string(data))
			}
			os.Exit(1)
		}
		_ = conn.Close()
		fmt.Fprintf(os.Stderr, "[✓] Network Reachability Guard: Target host %s is reachable\n", targetAddr)
		if len(requiredKeys) == 0 {
			return
		}
	}

	if len(requiredKeys) == 0 {
		fail("INVALID_ARGUMENT", fmt.Errorf("no required keys specified"), "Pass --template <file>, --required KEY1,KEY2, or --ping-host <host:port>")
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	available := make(map[string]string)
	for path, entry := range resp.Secrets {
		envKey := pathToEnvKeyWithEntry(path, entry)
		available[envKey] = path
		available[path] = path
	}

	fmt.Println("=== sec-agent Vault Schema Linter ===")
	missingCount := 0
	for _, req := range requiredKeys {
		if matchedPath, ok := available[req]; ok {
			fmt.Printf(" [✓] %-30s -> Found (path/alias: %s)\n", req, matchedPath)
		} else {
			fmt.Printf(" [✗] %-30s -> MISSING!\n", req)
			missingCount++
		}
	}

	if missingCount > 0 {
		fmt.Printf("\n\033[31mError: Missing %d required secret(s).\033[0m\n", missingCount)
		os.Exit(1)
	}
	fmt.Printf("\n\033[32mSuccess: All %d required keys/aliases present in session.\033[0m\n", len(requiredKeys))
	checkExpirationWarnings(resp.Secrets)
}

func handleCheckLeaks(profile string) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil || !resp.Success {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running or locked for profile %q", profile), "Run 'eval $(sec open)' to unlock.")
	}

	historyFiles := store.DiscoverShellHistoryFiles()
	fmt.Println("=== 🛡️ Workstation Shell History & Secret Leak Audit ===")
	if len(historyFiles) == 0 {
		fmt.Println("No shell history files (.zsh_history, .bash_history, fish_history) discovered in home directory.")
		return
	}

	fmt.Print("Auditing discovered history files: ")
	var filePaths []string
	for _, h := range historyFiles {
		filePaths = append(filePaths, h.Path)
	}
	fmt.Println(strings.Join(filePaths, ", "))

	matches := audit.AuditShellHistory(historyFiles, resp.Secrets)

	if len(matches) == 0 {
		fmt.Println("\n\033[32m[PASS] Zero secret leaks detected across shell history files.\033[0m")
		return
	}

	fmt.Printf("\n\033[1;31m⚠️  [FOUND] %d Potential Secret Leak(s) Detected!\033[0m\n\n", len(matches))
	for i, m := range matches {
		fmt.Printf("%d. [%s] File: %s (Line %d)\n", i+1, m.MatchType, m.Path, m.LineNumber)
		if m.SecretPath != "" {
			fmt.Printf("   Matched Vault Key: %s\n", m.SecretPath)
		}
		if m.PatternName != "" {
			fmt.Printf("   Matched Pattern:   %s\n", m.PatternName)
		}
		fmt.Printf("   Snippet:           %s\n\n", strings.TrimSpace(m.LineSnippet))
	}
}

func handleCheckScripts(targetPath string) {
	fmt.Println("=== 🛡️ sec-agent Script Argument & Plaintext Password Audit ===")
	allFindings, scannedFiles, err := audit.ScanScriptsDirectory(targetPath)
	if err != nil {
		fail("FILE_NOT_FOUND", fmt.Errorf("target path %q not found or inaccessible: %v", targetPath, err), "Provide a valid script or workspace directory.")
	}

	if len(allFindings) == 0 {
		fmt.Printf("\n\033[32m[PASS] Scanned %d script(s) across %s: Zero insecure password arguments detected.\033[0m\n", len(scannedFiles), targetPath)
		return
	}

	fmt.Printf("\n\033[1;31m⚠️  [FOUND] %d Insecure Plaintext Password Flag(s) Detected across %d script(s)!\033[0m\n\n", len(allFindings), len(scannedFiles))
	for i, f := range allFindings {
		fmt.Printf("%d. File: %s (Line %d)\n", i+1, f.FilePath, f.LineNumber)
		fmt.Printf("   Issue:       %s\n", f.Reason)
		fmt.Printf("   Snippet:     %s\n", f.LineSnippet)
		fmt.Printf("   Remediation: %s\n\n", f.Suggestion)
	}

	if jsonErrors {
		data, _ := json.Marshal(map[string]interface{}{
			"success":  false,
			"findings": allFindings,
			"count":    len(allFindings),
		})
		fmt.Println(string(data))
	}
	os.Exit(1)
}

func handleCheckRemote(profile, remoteHost string, uciChecks, envChecks []string) {
	fmt.Printf("=== 🔍 sec-agent Remote Configuration Drift Verification (%s) ===\n", remoteHost)

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil || !resp.Success {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("daemon not running or profile %q is locked", profile), "Run 'eval $(sec open)' to unlock.")
	}

	driftCount := 0
	checkCount := 0

	// 1. Process UCI checks
	for _, check := range uciChecks {
		parts := strings.SplitN(check, "=", 2)
		if len(parts) != 2 {
			continue
		}
		uciKey := strings.TrimSpace(parts[0])
		vaultKey := strings.TrimSpace(parts[1])
		checkCount++

		vaultEntry, ok := resp.Secrets[vaultKey]
		if !ok {
			fmt.Printf("[✗] Vault secret %q not found in profile %q\n", vaultKey, profile)
			driftCount++
			continue
		}

		// Execute SSH uci get command
		// #nosec G204 G702
		sshCmd := exec.Command("ssh", remoteHost, fmt.Sprintf("uci get %s", uciKey))
		out, err := sshCmd.Output()
		if err != nil {
			fmt.Printf("[✗] Remote query failed for UCI key %q on %s: %v\n", uciKey, remoteHost, err)
			driftCount++
			continue
		}

		remoteVal := strings.TrimSpace(string(out))
		vaultVal := strings.TrimSpace(vaultEntry.Value)

		if remoteVal == vaultVal {
			fmt.Printf(" [✓] %-32s == vault:%-24s (In Sync)\n", uciKey, vaultKey)
		} else {
			fmt.Printf(" [!] DRIFT DETECTED: %-26s != vault:%-24s\n", uciKey, vaultKey)
			driftCount++
		}
	}

	// 2. Process Remote Env checks
	for _, check := range envChecks {
		parts := strings.SplitN(check, "=", 2)
		if len(parts) != 2 {
			continue
		}
		envVar := strings.TrimSpace(parts[0])
		vaultKey := strings.TrimSpace(parts[1])
		checkCount++

		vaultEntry, ok := resp.Secrets[vaultKey]
		if !ok {
			fmt.Printf("[✗] Vault secret %q not found in profile %q\n", vaultKey, profile)
			driftCount++
			continue
		}

		// #nosec G204 G702
		sshCmd := exec.Command("ssh", remoteHost, fmt.Sprintf("printenv %s", envVar))
		out, err := sshCmd.Output()
		if err != nil {
			fmt.Printf("[✗] Remote query failed for env %q on %s: %v\n", envVar, remoteHost, err)
			driftCount++
			continue
		}

		remoteVal := strings.TrimSpace(string(out))
		vaultVal := strings.TrimSpace(vaultEntry.Value)

		if remoteVal == vaultVal {
			fmt.Printf(" [✓] %-32s == vault:%-24s (In Sync)\n", envVar, vaultKey)
		} else {
			fmt.Printf(" [!] DRIFT DETECTED: %-26s != vault:%-24s\n", envVar, vaultKey)
			driftCount++
		}
	}

	if driftCount > 0 {
		fmt.Printf("\n\033[31m[FAIL] %d drift(s) or mismatch(es) detected across %d checked configuration(s).\033[0m\n", driftCount, checkCount)
		os.Exit(1)
	}

	fmt.Printf("\n\033[32m[PASS] All %d remote configuration check(s) in sync with vault.\033[0m\n", checkCount)
}

