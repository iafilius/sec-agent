package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

func getProfileEnvTier(profile store.ProfileName) config.EnvironmentTier {
	resp, err := queryDaemonRaw(profile.String(), daemon.IPCRequest{
		Action: daemon.IPCActionGet,
		Path:   "__profile_env__",
	})
	if err == nil && resp.Success && resp.Value != "" {
		return config.ParseEnvironmentTier(resp.Value)
	}
	return config.TierUnset
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
	if tier.IsProduction() {
		hasConfirm := false
		for _, arg := range args {
			if arg == "--confirm-prod" {
				hasConfirm = true
				break
			}
		}
		if !hasConfirm {
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
		}
	}
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
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running or locked for profile %q.", p1), "Run 'eval $(sec open)' to unlock.")
	}

	resp2, err2 := queryDaemon(p2, daemon.IPCRequest{Action: "backup"})
	if err2 != nil || !resp2.Success {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running or locked for profile %q.", p2), "Run 'eval $(sec open --profile "+p2+")' to unlock.")
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

	if args[0] == "set-env" {
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
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
		}
		if !resp.Success {
			code, rem := mapDaemonError(resp.Error)
			fail(code, fmt.Errorf("%s", resp.Error), rem)
		}
		fmt.Printf("Profile %q successfully bound to environment tier %q.\n", profile, strings.ToUpper(tier))
		printEnvBadge(store.ProfileName(profile))
		return
	}

	fmt.Fprintln(os.Stderr, "Usage: sec profile [set-env dev|dta|staging|prod]")
	os.Exit(1)
}

func handleEnv(profile string, args []string) {
	prefix := ""
	if len(args) > 0 {
		prefix = args[0]
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
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
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
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
	target  io.Writer
	secrets []string
}

func (w *redactWriter) Write(p []byte) (n int, err error) {
	out := string(p)
	for _, sec := range w.secrets {
		if len(sec) > 3 {
			out = strings.ReplaceAll(out, sec, "[REDACTED_BY_SEC]")
		}
	}
	_, err = w.target.Write([]byte(out))
	return len(p), err
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

func handleRun(profile string, args []string) {
	groupPrefix := ""
	var allowedKeys []string
	dryRun := false
	noRedact := false
	sshKeyPath := ""
	sshPassphraseVaultKey := ""

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
		} else if args[i] == "--allow-keys" && i+1 < len(args) {
			allowedKeys = strings.Split(args[i+1], ",")
			i++
		} else if strings.HasPrefix(args[i], "--allow-keys=") {
			allowedKeys = strings.Split(strings.TrimPrefix(args[i], "--allow-keys="), ",")
		} else if args[i] == "--dry-run" {
			dryRun = true
		} else if args[i] == "--no-redact" {
			noRedact = true
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
		}
	}

	if cmdIndex == -1 || cmdIndex >= len(args) {
		fail("INVALID_ARGUMENTS", fmt.Errorf("no target command specified. Separate subagent flags and target command using '--'"), "Usage: sec run [--group <prefix>] [--ssh-key <path>] -- <cmd> [args...]")
	}

	targetCmd := args[cmdIndex]
	targetArgs := args[cmdIndex+1:]

	checkProductionGuard(store.ProfileName(profile), args)

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "get_group",
		Path:   groupPrefix,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
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
	if sshKeyPath != "" {
		sock, cleanup, err := setupEphemeralSSHAgent(profile, sshKeyPath, sshPassphraseVaultKey)
		if err != nil {
			fail("SSH_AGENT_FAILED", fmt.Errorf("failed to spin up ephemeral SSH agent: %v", err), "")
		}
		agentSocket = sock
		agentCleanup = cleanup
		defer agentCleanup()
		envMap["SSH_AUTH_SOCK"] = agentSocket
	}

	if dryRun {
		fmt.Println("=== Dry-Run: Subprocess Secret Injection Plan ===")
		fmt.Printf("Target Command:     %s %s\n", targetCmd, strings.Join(targetArgs, " "))
		tier := getProfileEnvTier(store.ProfileName(profile))
		if tier == config.TierUnset {
			tier = config.TierDev
		}
		fmt.Printf("Vault Profile:      %s (Tier: %s)\n", profile, strings.ToUpper(tier.String()))
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

	if noRedact {
		subProcess.Stdout = os.Stdout
		subProcess.Stderr = os.Stderr
	} else {
		subProcess.Stdout = &redactWriter{target: os.Stdout, secrets: secretValues}
		subProcess.Stderr = &redactWriter{target: os.Stderr, secrets: secretValues}
	}
	subProcess.Stdin = os.Stdin

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigChan {
			if subProcess.Process != nil {
				_ = subProcess.Process.Signal(sig)
			}
		}
	}()

	if err := subProcess.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fail("SUBPROCESS_EXEC_FAILED", fmt.Errorf("failed executing command %q: %v", targetCmd, err), "")
	}
}

func handleStream(profile string, args []string) {
	templateStr := ""
	for i := 0; i < len(args); i++ {
		if (args[i] == "--template" || args[i] == "-t") && i+1 < len(args) {
			templateStr = args[i+1]
			i++
		}
	}

	if templateStr == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fail("STDIN_READ_ERROR", fmt.Errorf("failed reading stream input: %v", err), "")
		}
		templateStr = string(data)
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil || !resp.Success {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock session."), "Run 'eval $(sec open)' to unlock.")
	}

	re := regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_\-\./]+)\s*\}\}`)
	rendered := re.ReplaceAllStringFunc(templateStr, func(match string) string {
		keyPath := strings.TrimSpace(match[2 : len(match)-2])
		if entry, ok := resp.Secrets[keyPath]; ok {
			return entry.Value
		}
		return match
	})

	fmt.Print(rendered)
}

func handlePrompt(profile string, args []string) {
	format := "plain"
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) {
			format = strings.ToLower(args[i+1])
			i++
		}
	}

	activeProfile := profile
	if activeProfile == "" {
		activeProfile = "default"
	}

	// High-speed non-blocking probe to daemon socket
	sockPath, err := config.GetSocketPath(activeProfile)
	if err != nil {
		printPromptFormat(format, activeProfile, "unknown", false)
		return
	}

	conn, err := net.DialTimeout("unix", sockPath, 10*time.Millisecond)
	if err != nil {
		printPromptFormat(format, activeProfile, "locked", false)
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
		printPromptFormat(format, activeProfile, "locked", false)
		return
	}

	var resp daemon.IPCResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil || !resp.Success {
		printPromptFormat(format, activeProfile, "locked", false)
		return
	}

	printPromptFormat(format, activeProfile, "unlocked", true)
}

func printPromptFormat(format, profile, status string, unlocked bool) {
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
