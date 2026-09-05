package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"secure_secrets/internal/biometrics"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "embed"

	"golang.org/x/term"
)

//go:embed SKILL.md
var embeddedSkillBytes []byte

var jsonErrors bool
var (
	Version   = "v2.8.0"
	BuildDate = "unknown"
)

type JSONErrorResponse struct {
	Success bool      `json:"success"`
	Error   JSONError `json:"error"`
}

type JSONError struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

func mapDaemonError(errStr string) (code string, remediation string) {
	if strings.Contains(errStr, "Invalid session token") || strings.Contains(errStr, "invalid session token") || strings.Contains(errStr, "Invalid or missing session token") {
		return "INVALID_TOKEN", "Run 'eval $(sec-agent open)' to authorize your shell session."
	}
	if strings.Contains(errStr, "locked or expired") || strings.Contains(errStr, "locked") {
		return "SESSION_LOCKED", "Run 'eval $(sec-agent open)' to unlock and authorize your shell session."
	}
	if strings.Contains(errStr, "expired") {
		return "SECRET_EXPIRED", "Pass the '--show-expired' flag to retrieve this secret."
	}
	if strings.Contains(errStr, "not found") {
		return "SECRET_NOT_FOUND", "Verify the path or run 'sec-agent set' to store the key."
	}
	if strings.Contains(errStr, "hijacking") || strings.Contains(errStr, "ScreenSharing") {
		return "ACCESS_DENIED_HIJACK", "Remote connections or active screen sharing are blocked."
	}
	return "OPERATION_FAILED", ""
}

func fail(code string, err error, remediation string) {
	if jsonErrors {
		resp := JSONErrorResponse{
			Success: false,
			Error: JSONError{
				Code:        code,
				Message:     err.Error(),
				Remediation: remediation,
			},
		}
		jsonBytes, _ := json.Marshal(resp)
		fmt.Fprintln(os.Stderr, string(jsonBytes))
	} else {
		if remediation != "" {
			fmt.Fprintf(os.Stderr, "Error: %v\nRemediation: %s\n", err, remediation)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	}
	os.Exit(1)
}

type SSHTarget struct {
	Host          string `json:"host"`
	User          string `json:"user,omitempty"`
	Port          int    `json:"port,omitempty"`
	IdentityFile  string `json:"identity_file,omitempty"`
	PassphraseKey string `json:"passphrase_key,omitempty"`
}

type WorkspaceConfig struct {
	Profile     store.ProfileName    `json:"profile,omitempty"`
	Prefix      string               `json:"prefix,omitempty"`
	AutoOpen    bool                 `json:"auto_open,omitempty"`
	Extends     string               `json:"extends,omitempty"`
	FlagAliases map[string]string    `json:"flag_aliases,omitempty"`
	SSHTargets  map[string]SSHTarget `json:"ssh_targets,omitempty"`
}

func findWorkspaceConfigFile() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		for _, name := range []string{".secenv", ".secrc", ".sec.json"} {
			path := filepath.Join(dir, name)
			// #nosec G304 G703
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func loadWorkspaceConfig() *WorkspaceConfig {
	cfg, _, _ := loadWorkspaceConfigVerbose()
	return cfg
}

func loadWorkspaceConfigVerbose() (*WorkspaceConfig, string, string) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, "", ""
	}
	for {
		for _, name := range []string{".secenv", ".secrc", ".sec.json"} {
			path := filepath.Join(dir, name)
			// #nosec G304 G703
			data, err := os.ReadFile(path)
			if err == nil {
				var cfg WorkspaceConfig
				if err := json.Unmarshal(data, &cfg); err == nil {
					return &cfg, filepath.Base(path), dir
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil, "", ""
}

func isInteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func extractGlobalFlags() (string, []string) {
	wsCfg := loadWorkspaceConfig()
	profile := os.Getenv("SEC_PROFILE")
	if profile == "" {
		if wsCfg != nil && wsCfg.Profile != "" {
			profile = wsCfg.Profile.String()
		} else {
			profile = "default"
		}
	}
	if wsCfg != nil && wsCfg.AutoOpen {
		_ = os.Setenv("SEC_AUTO_OPEN", "1")
	}

	args := os.Args
	var cleanArgs []string
	cleanArgs = append(cleanArgs, args[0])

	for i := 1; i < len(args); i++ {
		if args[i] == "--profile" || args[i] == "-P" {
			if i+1 < len(args) {
				profile = args[i+1]
				i++ // skip next arg
			}
			continue
		}
		if args[i] == "--auto-open" || args[i] == "--gui" {
			_ = os.Setenv("SEC_AUTO_OPEN", "1")
			continue
		}
		if args[i] == "--json-errors" || args[i] == "--json" {
			jsonErrors = true
			if args[i] == "--json-errors" {
				continue
			}
		}
		cleanArgs = append(cleanArgs, args[i])
	}
	return profile, cleanArgs
}

func queryDaemon(profile string, req daemon.IPCRequest) (*daemon.IPCResponse, error) {
	resp, err := queryDaemonRaw(profile, req)
	if (err != nil || (resp != nil && !resp.Success && strings.Contains(resp.Error, "locked"))) && req.Action != "open" && req.Action != "ping" {
		if os.Getenv("SEC_AUTO_OPEN") == "1" && os.Getenv("SEC_NO_AUTO_OPEN") != "1" && os.Getenv("SEC_DISABLE_AUTO_OPEN") != "1" {
			if isInteractiveTerminal() {
				handleOpen(profile, nil)
				req.Token = os.Getenv("SEC_SESSION_TOKEN")
				return queryDaemonRaw(profile, req)
			} else {
				// Non-TTY Subprocess GUI Touch ID Auto-Open Path
				if handleOpenGUI(profile) {
					req.Token = os.Getenv("SEC_SESSION_TOKEN")
					return queryDaemonRaw(profile, req)
				}
			}
		}
	}
	return resp, err
}

func handleOpenGUI(profile string) bool {
	if os.Getenv("SEC_TEST_MODE") != "1" {
		if !biometrics.Authenticate(fmt.Sprintf("Authorize sec-agent session (%s)", profile)) {
			return false
		}
	}

	wsCfg := loadWorkspaceConfig()
	openProfiles := []string{profile}
	if profile == "default" && wsCfg != nil && wsCfg.Profile != "" && wsCfg.Profile != "default" {
		openProfiles = append(openProfiles, wsCfg.Profile.String())
	}

	for _, p := range openProfiles {
		if err := ensureDaemonRunning(p); err != nil {
			return false
		}
		getter, setter := keychain.GetKeychainAccessPair(p)
		masterKey, err := store.InitializeMasterKey(p, getter, setter)
		if err != nil {
			return false
		}

		resp, err := queryDaemonRaw(p, daemon.IPCRequest{
			Action: "open",
			Key:    masterKey,
		})
		if err != nil || resp == nil || !resp.Success {
			return false
		}

		_ = os.Setenv("SEC_SESSION_TOKEN", resp.Token)
	}
	return true
}

func queryDaemonRaw(profile string, req daemon.IPCRequest) (*daemon.IPCResponse, error) {
	if req.Action != "open" && req.Action != "ping" {
		if req.Token == "" {
			req.Token = os.Getenv("SEC_SESSION_TOKEN")
		}
		if req.ExtendsProfile == "" {
			wsCfg := loadWorkspaceConfig()
			if wsCfg != nil && wsCfg.Extends != "" {
				req.ExtendsProfile = wsCfg.Extends
			}
		}
	}

	socketPath, err := config.GetSocketPath(profile)
	if err != nil {
		return nil, err
	}

	// #nosec G704
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err // Daemon likely not running
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}

	var resp daemon.IPCResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

func evictStaleDaemon(profile string) {
	_, _ = queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionClear})
	socketPath, _ := config.GetSocketPath(profile)
	pidPath, _ := config.GetPIDFilePath(profile)
	if pidPath != "" {
		// #nosec G304 G703
		if data, err := os.ReadFile(pidPath); err == nil {
			var info daemon.PIDLockInfo
			if json.Unmarshal(data, &info) == nil && info.PID > 0 && info.PID != os.Getpid() && info.PID != os.Getppid() {
				if os.Getenv("SEC_TEST_MODE") != "1" {
					proc, err := os.FindProcess(info.PID)
					if err == nil && proc != nil {
						_ = proc.Kill()
					}
				}
			}
		}
		// #nosec G703
		_ = os.Remove(pidPath)
	}
	if socketPath != "" {
		// #nosec G703
		_ = os.Remove(socketPath)
	}
}

func ensureDaemonRunning(profile string) error {
	currentExec, _ := os.Executable()
	resp, err := queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionPing})
	if err == nil && resp != nil {
		versionMismatch := resp.Version != "" && resp.Version != Version
		execMismatch := false
		pidPath, _ := config.GetPIDFilePath(profile)
		if pidPath != "" {
			// #nosec G304 G703
			if data, err := os.ReadFile(pidPath); err == nil {
				var info daemon.PIDLockInfo
				if json.Unmarshal(data, &info) == nil {
					if info.Executable != "" && currentExec != "" && info.Executable != currentExec {
						execMismatch = true
					}
				}
			}
		}

		if versionMismatch || execMismatch {
			fmt.Printf("DEBUG ensureDaemonRunning versionMismatch=%v (resp.Version=%q, Version=%q), execMismatch=%v\n", versionMismatch, resp.Version, Version, execMismatch)
			fmt.Fprintln(os.Stderr, "[NOTICE] Mismatched background daemon detected. Evicting and restarting fresh daemon...")
			evictStaleDaemon(profile)
		} else {
			return nil // Running and parity verified
		}
	}

	bin, err := os.Executable()
	if err != nil {
		return err
	}

	// #nosec G204
	cmd := exec.Command(bin, "daemon")
	cmd.Env = append(os.Environ(), fmt.Sprintf("SEC_PROFILE=%s", profile))
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start daemon process: %w", err)
	}

	socketPath, err := config.GetSocketPath(profile)
	if err != nil {
		return err
	}
	for i := 0; i < 20; i++ {
		// #nosec G703
		if _, err := os.Stat(socketPath); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("daemon socket failed to initialize within time limit")
}

func handleOpen(profile string, args []string) {
	ttlStr := ""
	graceStr := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "--ttl" || args[i] == "-t" {
			if i+1 < len(args) {
				ttlStr = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "Error: --ttl requires a duration value (e.g. 8h, 30m)")
				os.Exit(1)
			}
		} else if args[i] == "--grace" || args[i] == "-g" {
			if i+1 < len(args) {
				graceStr = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "Error: --grace requires a duration value (e.g. 30m, 1h)")
				os.Exit(1)
			}
		}
	}

	if ttlStr != "" {
		if _, err := time.ParseDuration(ttlStr); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid TTL duration format %q: %v\n", ttlStr, err)
			os.Exit(1)
		}
	}
	if graceStr != "" {
		if _, err := time.ParseDuration(graceStr); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid Grace duration format %q: %v\n", graceStr, err)
			os.Exit(1)
		}
	}

	wsCfg, wsCfgFile, _ := loadWorkspaceConfigVerbose()
	openProfiles := []string{profile}
	if profile == "default" && wsCfg != nil && wsCfg.Profile != "" && wsCfg.Profile != "default" {
		openProfiles = append(openProfiles, wsCfg.Profile.String())
	}

	if wsCfg != nil && wsCfg.Profile != "" {
		fmt.Fprintf(os.Stderr, "⚙️  Detected workspace config file (%s): profile = %q\n", wsCfgFile, wsCfg.Profile)
	} else if len(openProfiles) == 1 {
		fmt.Fprintln(os.Stderr, "💡 Tip: Create a '.secrc' file (e.g. `{\"profile\": \"<name>\"}`) in this repository to auto-unlock its profile in 1 Touch ID prompt.")
	}

	for _, p := range openProfiles {
		if err := ensureDaemonRunning(p); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting daemon for profile %q: %v\n", p, err)
			os.Exit(1)
		}
	}

	fmt.Fprintln(os.Stderr, "Authorizing session via Touch ID...")

	if os.Getenv("SEC_TEST_MODE") != "1" {
		if !biometrics.Authenticate("Authorize sec session") {
			fmt.Fprintln(os.Stderr, "Authentication failed: Biometric verification failed.")
			os.Exit(1)
		}
	}

	lastToken := ""
	for _, p := range openProfiles {
		getter, setter := keychain.GetKeychainAccessPair(p)

		masterKey, err := store.InitializeMasterKey(p, getter, setter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Authentication failed for profile %q: %v\n", p, err)
			continue
		}

		resp, err := queryDaemon(p, daemon.IPCRequest{
			Action: "open",
			Key:    masterKey,
			TTL:    ttlStr,
			Grace:  graceStr,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Daemon IPC error for profile %q: %v\n", p, err)
			continue
		}

		if !resp.Success {
			if strings.Contains(resp.Error, "cipher: message authentication failed") {
				fmt.Fprintf(os.Stderr, "\n❌ Unlock failed for profile %q: cipher: message authentication failed\n\n", p)
				fmt.Fprintln(os.Stderr, "💡 Remediation Hints:")
				fmt.Fprintf(os.Stderr, "  • Biometric Set Changed? Run 'sec session recover --profile %s' to un-brick with your 24-word paper seed.\n", p)
				fmt.Fprintf(os.Stderr, "  • Stale / Test Store? Run 'rm ~/.config/sec-agent/secrets_%s.enc' and 'sec init --profile %s' to reset.\n\n", p, p)
			} else {
				fmt.Fprintf(os.Stderr, "Unlock failed for profile %q: %s\n", p, resp.Error)
			}
			continue
		}

		if lastToken == "" {
			lastToken = resp.Token
		}
	}

	if len(openProfiles) > 1 {
		fmt.Fprintf(os.Stderr, "✨ Unlocked profile %q and workspace profile %q in 1 Touch ID prompt.\n", openProfiles[0], openProfiles[1])
	}

	msg := "Session unlocked successfully. Cache active."
	if ttlStr != "" {
		msg += fmt.Sprintf(" TTL: %s.", ttlStr)
	} else {
		msg += " TTL: 8h."
	}
	if graceStr != "" {
		msg += fmt.Sprintf(" Inactivity Grace: %s.", graceStr)
	} else {
		msg += " Inactivity Grace: 30m."
	}
	fmt.Fprintln(os.Stderr, msg)
	fmt.Fprintf(os.Stdout, "export SEC_SESSION_TOKEN=%q\n", lastToken)
	fmt.Fprintln(os.Stderr, "Tip: Run 'eval $(sec open)' to automatically authorize this shell session.")
}

func handleGen(profile string, path string, args []string) {
	length := 32
	useSymbols := true
	comment := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "--length" || args[i] == "-l" {
			if i+1 < len(args) {
				if l, err := strconv.Atoi(args[i+1]); err == nil && l > 0 {
					length = l
					i++
				}
			}
		} else if args[i] == "--no-symbols" {
			useSymbols = false
		} else if args[i] == "--comment" || args[i] == "-c" {
			if i+1 < len(args) {
				comment = args[i+1]
				i++
			}
		}
	}

	const charsetAlphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const charsetSymbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	charset := charsetAlphaNum
	if useSymbols {
		charset += charsetSymbols
	}

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		fail("CRYPTO_RAND_ERROR", err, "")
	}

	var secretBuilder strings.Builder
	for _, b := range buf {
		secretBuilder.WriteByte(charset[int(b)%len(charset)])
	}
	genValue := secretBuilder.String()

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:  "set",
		Path:    path,
		Value:   genValue,
		Comment: comment,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	if jsonErrors {
		data, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"path":    path,
			"value":   genValue,
			"comment": comment,
		})
		fmt.Println(string(data))
	} else {
		fmt.Printf("Generated secure password for %q (%d chars) -> %s\n", path, length, genValue)
	}
}

func handleRestart(profile string, args []string) {
	hotReload := false
	for _, arg := range args {
		if arg == "--hot-reload" || arg == "-H" || arg == "--force" {
			hotReload = true
		}
	}

	if hotReload {
		resp, err := queryDaemon(profile, daemon.IPCRequest{Action: daemon.IPCActionReexec})
		if err == nil && resp != nil && resp.Success {
			fmt.Printf("[✓] sec-agent daemon (%s) hot-reloaded in memory via kernel pipe handoff (Zero Touch ID required).\n", profile)
			return
		}
		errMsg := "Daemon not running or locked"
		if resp != nil && resp.Error != "" {
			errMsg = resp.Error
		} else if err != nil {
			errMsg = err.Error()
		}
		fmt.Fprintf(os.Stderr, "[NOTICE] In-memory hot-reload unavailable (%s). Performing standard Touch ID restart...\n", errMsg)
	}

	_, _ = queryDaemon(profile, daemon.IPCRequest{Action: daemon.IPCActionClear})
	socketPath, err := config.GetSocketPath(profile)
	if err == nil {
		_ = os.Remove(socketPath)
	}
	fmt.Printf("Restarting sec-agent daemon for profile %q...\n", profile)
	handleOpen(profile, nil)
}

func handleVersion(profile string) {
	fmt.Printf("sec-agent CLI:      %s\n", Version)

	daemonVer := "Not running"
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: daemon.IPCActionPing})
	if err == nil {
		if resp.Version != "" {
			daemonVer = fmt.Sprintf("%s (Running, profile: %s)", resp.Version, profile)
		} else {
			daemonVer = fmt.Sprintf("Active (Running, profile: %s)", profile)
		}
	}
	fmt.Printf("sec-agent Daemon:   %s\n", daemonVer)

	commit := "unknown"
	goVersion := runtime.Version()
	var deps []string

	if info, ok := debug.ReadBuildInfo(); ok {
		if goVersion == "" {
			goVersion = info.GoVersion
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				commit = setting.Value
			}
		}
		for _, dep := range info.Deps {
			deps = append(deps, fmt.Sprintf("  %s  %s", dep.Path, dep.Version))
		}
	}

	fmt.Printf("  Build Date:       %s\n", BuildDate)
	fmt.Printf("  Commit:           %s\n", commit)
	fmt.Printf("  Go Version:       %s\n", goVersion)
	fmt.Printf("  Platform:         %s/%s\n", runtime.GOOS, runtime.GOARCH)

	if len(deps) > 0 {
		fmt.Println("\nDependencies:")
		for _, d := range deps {
			fmt.Println(d)
		}
	}

	if err == nil && resp.Version != "" && resp.Version != Version {
		fmt.Printf("\n⚠️  WARNING: CLI version (%s) does not match running daemon version (%s).\n", Version, resp.Version)
		fmt.Println("To hot-reload the daemon in memory (Zero Touch ID required), run:")
		fmt.Println("  sec restart --hot-reload")
		fmt.Println("Or perform a full re-authentication restart:")
		fmt.Println("  sec restart")
	}
}

func runDaemon(profile string) {
	d, err := daemon.NewDaemon(profile, 8*time.Hour, Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating daemon: %v\n", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		d.Stop()
		os.Exit(0)
	}()

	if err := d.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Daemon runtime error: %v\n", err)
		os.Exit(1)
	}
}

func readInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return text
}

func parseExpiration(expStr string) (time.Time, error) {
	expStr = strings.TrimSpace(expStr)
	if expStr == "" {
		return time.Time{}, nil
	}

	if strings.HasSuffix(expStr, "d") {
		numStr := strings.TrimSuffix(expStr, "d")
		days, err := strconv.Atoi(numStr)
		if err == nil {
			return time.Now().AddDate(0, 0, days), nil
		}
	}
	if strings.HasSuffix(expStr, "y") {
		numStr := strings.TrimSuffix(expStr, "y")
		years, err := strconv.Atoi(numStr)
		if err == nil {
			return time.Now().AddDate(years, 0, 0), nil
		}
	}
	if strings.HasSuffix(expStr, "mo") {
		numStr := strings.TrimSuffix(expStr, "mo")
		months, err := strconv.Atoi(numStr)
		if err == nil {
			return time.Now().AddDate(0, months, 0), nil
		}
	}

	if d, err := time.ParseDuration(expStr); err == nil {
		return time.Now().Add(d), nil
	}

	if t, err := time.Parse(time.RFC3339, expStr); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", expStr); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("unknown expiration format %q (use e.g. '30d', '12h', or 'YYYY-MM-DD')", expStr)
}

func main() {
	profile, cleanArgs := extractGlobalFlags()
	os.Args = cleanArgs

	if len(os.Args) >= 2 {
		cmd := os.Args[1]
		if cmd == "help" || cmd == "--help" || cmd == "-h" {
			isJSONFormat := false
			for i := 0; i < len(os.Args); i++ {
				if os.Args[i] == "--format" && i+1 < len(os.Args) && os.Args[i+1] == "json" {
					isJSONFormat = true
				}
			}
			if isJSONFormat {
				printUsageJSON()
				os.Exit(0)
			}
			printUsage()
			os.Exit(0)
		}

		if cmd != "init" && cmd != "setup" && cmd != "version" && cmd != "completion" && cmd != "shell-completion" {
			if !config.IsConfigDirInitialized() {
				fail("VAULT_UNINITIALIZED", fmt.Errorf("sec-agent configuration directory (~/.config/sec-agent/) is missing or uninitialized"), "Please initialize your vault environment by running: sec-agent init")
			}
		}
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	syncInstalledSkillsIfOutdated()

	cmdName := os.Args[1]
	spec, ok := findCommandSpec(cmdName)
	if !ok || spec.Handler == nil {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmdName)
		printUsage()
		os.Exit(1)
	}

	spec.Handler(profile, os.Args[2:])
}
