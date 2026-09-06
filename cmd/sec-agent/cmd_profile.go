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
	"secure_secrets/internal/biometrics"
	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/keychain"
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

	subcmd := args[0]
	switch subcmd {
	case "new", "create", "init":
		handleProfileNew(args[1:])
		return
	case "ls", "list":
		handleProfileList()
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

	fmt.Fprintln(os.Stderr, "Usage: sec profile [new <name> [--seed <mnemonic>]] [ls] [set-env dev|dta|staging|prod]")
	os.Exit(1)
}

func handleProfileList() {
	vaults, err := store.ListVaultFiles()
	if err != nil {
		fail("LIST_PROFILES_ERROR", fmt.Errorf("failed to discover profiles: %w", err), "")
	}
	if len(vaults) == 0 {
		fmt.Println("No profiles discovered.")
		return
	}
	fmt.Println("Discovered Profiles:")
	for _, v := range vaults {
		status := "v1.0"
		if v.IsV2 {
			if v.HasSlot1 {
				status = "v2.0 Dual-Slot"
			} else {
				status = "v2.0 (Slot 1 missing)"
			}
		}
		fmt.Printf("  • %-20s [%s]\n", v.Profile, status)
	}
}

func handleProfileNew(args []string) {
	var name string
	seedInput := ""
	autoSecrc := false
	noSecrc := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" || a == "help" {
			fmt.Println("Usage: sec profile new <name> [--seed <mnemonic>] [--secrc|--no-secrc]")
			fmt.Println("\nCreate a new named profile with Dual-Slot Touch ID (Slot 0) and BIP39 recovery seed (Slot 1).")
			return
		}
		if a == "--seed" && i+1 < len(args) {
			seedInput = strings.Trim(args[i+1], `"'`)
			i++
		} else if strings.HasPrefix(a, "--seed=") {
			seedInput = strings.Trim(strings.TrimPrefix(a, "--seed="), `"'`)
		} else if a == "--secrc" {
			autoSecrc = true
		} else if a == "--no-secrc" {
			noSecrc = true
		} else if !strings.HasPrefix(a, "-") && name == "" {
			name = a
		}
	}

	if name == "" {
		fmt.Fprintln(os.Stderr, "Usage: sec profile new <name> [--seed <mnemonic>] [--secrc|--no-secrc]")
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

	if !isInteractiveTerminal() && seedInput == "" {
		printInteractiveBlocker("sec-agent profile new "+pName.String(), "Profile creation enrolls Touch ID and a 24-word recovery seed")
		os.Exit(78)
	}

	if os.Getenv("SEC_TEST_MODE") != "1" {
		if !biometrics.Authenticate("Authorize Creation of Profile " + pName.String()) {
			fmt.Fprintln(os.Stderr, "❌ Touch ID biometric authorization required for profile creation.")
			os.Exit(1)
		}
	}

	mnemonic := seedInput
	if mnemonic == "" {
		m, err := crypto.GenerateMnemonic()
		if err != nil {
			fail("CRYPTO_ERROR", fmt.Errorf("failed to generate recovery mnemonic: %w", err), "")
		}
		mnemonic = m
		words := strings.Fields(mnemonic)
		fmt.Printf("\n🔑 Your 24-word recovery mnemonic for profile %q (WRITE THIS DOWN NOW):\n", pName.String())
		for i, w := range words {
			fmt.Printf("  %2d. %-12s", i+1, w)
			if (i+1)%4 == 0 {
				fmt.Println()
			}
		}
		fmt.Println()

		fmt.Println("To confirm you have written down the mnemonic, please enter:")
		verificationWords := []int{4, 12, 20}
		for _, pos := range verificationWords {
			fmt.Printf("  Word #%d: ", pos)
			reader := bufio.NewReader(os.Stdin)
			entered, _ := reader.ReadString('\n')
			entered = strings.TrimSpace(strings.ToLower(entered))
			expected := strings.ToLower(words[pos-1])
			if entered != expected {
				fmt.Fprintf(os.Stderr, "\n❌ Word #%d mismatch (expected %q, got %q). Aborting.\n", pos, expected, entered)
				os.Exit(1)
			}
		}
	} else {
		if !crypto.MnemonicValid(mnemonic) {
			fmt.Fprintln(os.Stderr, "❌ Provided seed phrase is not a valid 24-word BIP39 mnemonic.")
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
		secrcData := fmt.Sprintf("{\n  \"profile\": %q\n}\n", pName.String())
		// #nosec G304 G703
		if err := os.WriteFile(filepath.Clean(".secrc"), []byte(secrcData), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Failed to write .secrc: %v\n", err)
		} else {
			fmt.Printf("✅ Created .secrc bound to profile %q\n", pName.String())
		}
	}
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
	buf     []byte
	maxLen  int
}

func newRedactWriter(target io.Writer, secrets []string) *redactWriter {
	max := 0
	var validSecrets []string
	for _, s := range secrets {
		trimmed := strings.TrimSpace(s)
		if len(trimmed) >= 4 {
			validSecrets = append(validSecrets, trimmed)
			if len(trimmed) > max {
				max = len(trimmed)
			}
		}
	}
	return &redactWriter{
		target:  target,
		secrets: validSecrets,
		maxLen:  max,
	}
}

func (w *redactWriter) Write(p []byte) (n int, err error) {
	if len(w.secrets) == 0 {
		return w.target.Write(p)
	}

	w.buf = append(w.buf, p...)
	out := string(w.buf)
	for _, sec := range w.secrets {
		out = strings.ReplaceAll(out, sec, "[REDACTED_BY_SEC]")
	}

	margin := w.maxLen - 1
	if margin < 0 {
		margin = 0
	}
	if len(out) <= margin {
		w.buf = []byte(out)
		return len(p), nil
	}

	safeLen := len(out) - margin
	toFlush := out[:safeLen]
	w.buf = []byte(out[safeLen:])
	_, err = w.target.Write([]byte(toFlush))
	return len(p), err
}

func (w *redactWriter) Flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	out := string(w.buf)
	for _, sec := range w.secrets {
		out = strings.ReplaceAll(out, sec, "[REDACTED_BY_SEC]")
	}
	w.buf = nil
	_, err := w.target.Write([]byte(out))
	return err
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
		} else if args[i] == "--redact" {
			noRedact = false
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

	runErr := subProcess.Run()
	if stdoutRedact != nil {
		_ = stdoutRedact.Flush()
	}
	if stderrRedact != nil {
		_ = stderrRedact.Flush()
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fail("SUBPROCESS_EXEC_FAILED", fmt.Errorf("failed executing command %q: %v", targetCmd, runErr), "")
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
