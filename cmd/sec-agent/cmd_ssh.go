package main

import (
	"bufio"
	"crypto/hmac"
	crand "crypto/rand"
	// #nosec G505 - required by OpenSSH known_hosts HMAC-SHA1 specification
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type hostKeyOptions struct {
	insecure        bool
	trustOnFirstUse bool
	updateHostKey   bool
	noTrace         bool
}

func handleSSH(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Usage: sec ssh [init <target>] [import-key <target> <file>] [sanitize [<target>]] [host-key show <target>] [reset-host-key <target>] | [<target> | user@host] [flags] [-- <cmd...>]")
		fmt.Println("\nExecutes remote SSH commands or interactive sessions under vault authentication with zero disk exposure.")
		fmt.Println("\nSubcommands:")
		fmt.Println("  init <target>                Configure remote SSH target into vault and workspace .secrc")
		fmt.Println("  import-key <target> <file>   Ingest SSH private key into vault, optionally shred, and sanitize")
		fmt.Println("  sanitize [<target>] [--all]  Scrub target hostnames and hashed entries from known_hosts")
		fmt.Println("  host-key show <target>       Show pinned SSH host key fingerprint from vault")
		fmt.Println("  reset-host-key <target>      Reset pinned SSH host key fingerprint in vault")
		fmt.Println("\nFlags & Arguments:")
		fmt.Println("  <target>                     Named target from .secrc or vault (ssh/<target>/...)")
		fmt.Println("  user@host                    Direct SSH user and host destination")
		fmt.Println("  --ssh-key-secret, --key-secret Vault secret path containing private key bytes")
		fmt.Println("  --ssh-key, -i <path>         Path to private key file")
		fmt.Println("  --ssh-passphrase-key         Vault key containing the private key passphrase")
		fmt.Println("  --openssh                    Delegate to host OpenSSH binary (/usr/bin/ssh)")
		fmt.Println("  --no-trace                   Suppress known_hosts writes during delegated OpenSSH")
		fmt.Println("  --tofu, --trust-first-use    Trust and pin remote host key into vault on first connection")
		fmt.Println("  --insecure, --no-verify      Disable host key verification")
		fmt.Println("  --update-host-key            Update pinned host key fingerprint in vault with new remote key")
		fmt.Println("  -p, --port <port>            Remote SSH port (default: 22)")
		fmt.Println("  -- <cmd...>                  Remote command to execute (omit for interactive shell)")
		return
	}

	if args[0] == "init" {
		handleSSHInit(profile, args[1:])
		return
	}
	if args[0] == "import-key" {
		handleSSHImportKey(profile, args[1:])
		return
	}
	if args[0] == "sanitize" {
		handleSSHSanitize(profile, args[1:])
		return
	}
	if args[0] == "host-key" || args[0] == "hostkey" {
		handleSSHHostKey(profile, args[1:])
		return
	}
	if args[0] == "reset-host-key" {
		handleSSHResetHostKey(profile, args[1:])
		return
	}

	targetName := ""
	sshKeyPath := ""
	sshKeySecret := ""
	sshPassphraseKey := ""
	sshPort := 0
	cmdIndex := -1
	useOpenSSH := false
	noTrace := false
	trustOnFirstUse := false
	insecureHostKey := false
	updateHostKey := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			cmdIndex = i + 1
			break
		}
		if (args[i] == "--ssh-key" || args[i] == "-i") && i+1 < len(args) {
			sshKeyPath = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--ssh-key=") {
			sshKeyPath = strings.TrimPrefix(args[i], "--ssh-key=")
		} else if (args[i] == "--ssh-key-secret" || args[i] == "--key-secret") && i+1 < len(args) {
			sshKeySecret = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--ssh-key-secret=") {
			sshKeySecret = strings.TrimPrefix(args[i], "--ssh-key-secret=")
		} else if strings.HasPrefix(args[i], "--key-secret=") {
			sshKeySecret = strings.TrimPrefix(args[i], "--key-secret=")
		} else if args[i] == "--ssh-passphrase-key" && i+1 < len(args) {
			sshPassphraseKey = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--ssh-passphrase-key=") {
			sshPassphraseKey = strings.TrimPrefix(args[i], "--ssh-passphrase-key=")
		} else if (args[i] == "--port" || args[i] == "-p") && i+1 < len(args) {
			if p, err := strconv.Atoi(args[i+1]); err == nil {
				sshPort = p
			}
			i++
		} else if args[i] == "--openssh" || args[i] == "--fallback-openssh" {
			useOpenSSH = true
		} else if args[i] == "--no-trace" || args[i] == "--ephemeral-known-hosts" {
			noTrace = true
		} else if args[i] == "--tofu" || args[i] == "--trust-first-use" {
			trustOnFirstUse = true
		} else if args[i] == "--insecure" || args[i] == "--no-verify" {
			insecureHostKey = true
		} else if args[i] == "--update-host-key" {
			updateHostKey = true
		} else if targetName == "" && !strings.HasPrefix(args[i], "-") {
			targetName = args[i]
		}
	}

	var resolvedHost, resolvedUser, resolvedPassword string
	resolvedPort := 22

	// 1. Check .secrc for target configuration
	wsCfg := loadWorkspaceConfig()
	if wsCfg != nil && wsCfg.SSHTargets != nil && targetName != "" {
		if tgt, ok := wsCfg.SSHTargets[targetName]; ok {
			resolvedHost = tgt.Host
			resolvedUser = tgt.User
			if tgt.Port > 0 {
				resolvedPort = tgt.Port
			}
			if tgt.IdentityFile != "" && sshKeyPath == "" {
				sshKeyPath = tgt.IdentityFile
			}
			if tgt.KeySecret != "" && sshKeySecret == "" {
				ks := strings.TrimSpace(tgt.KeySecret)
				if !strings.Contains(ks, "/") {
					ks = "ssh/shared/" + ks + "/private_key"
				}
				sshKeySecret = ks
			}
			if tgt.PassphraseKey != "" && sshPassphraseKey == "" {
				sshPassphraseKey = tgt.PassphraseKey
			}
			if tgt.PasswordKey != "" {
				if pResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: tgt.PasswordKey}); err == nil && pResp.Success {
					resolvedPassword = pResp.Value
				}
			}
		}
	}

	// 2. Check active profile vault for ssh/<targetName>/... or ssh/...
	prefixes := []string{"ssh/" + targetName + "/", "ssh/"}
	if targetName == "" {
		prefixes = []string{"ssh/"}
	}
	for _, pfx := range prefixes {
		if resolvedHost == "" {
			if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: pfx + "host"}); err == nil && resp.Success && resp.Value != "" {
				resolvedHost = resp.Value
			}
		}
		if resolvedUser == "" {
			if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: pfx + "user"}); err == nil && resp.Success && resp.Value != "" {
				resolvedUser = resp.Value
			}
		}
		if resolvedPort == 22 {
			if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: pfx + "port"}); err == nil && resp.Success && resp.Value != "" {
				if p, pErr := strconv.Atoi(resp.Value); pErr == nil && p > 0 {
					resolvedPort = p
				}
			}
		}
		if resolvedPassword == "" {
			if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: pfx + "password"}); err == nil && resp.Success && resp.Value != "" {
				resolvedPassword = resp.Value
			}
		}
		if sshKeySecret == "" && sshKeyPath == "" {
			if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: pfx + "private_key"}); err == nil && resp.Success && resp.Value != "" {
				sshKeySecret = pfx + "private_key"
			} else if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: pfx + "key_secret"}); err == nil && resp.Success && resp.Value != "" {
				resolvedPtr := strings.TrimSpace(resp.Value)
				if !strings.Contains(resolvedPtr, "/") {
					resolvedPtr = "ssh/shared/" + resolvedPtr + "/private_key"
				}
				sshKeySecret = resolvedPtr
			} else if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: pfx + "key"}); err == nil && resp.Success && resp.Value != "" {
				if strings.HasPrefix(strings.TrimSpace(resp.Value), "-----BEGIN") {
					sshKeySecret = pfx + "key"
				} else {
					sshKeyPath = resp.Value
				}
			}
		}
		if sshPassphraseKey == "" {
			if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: pfx + "passphrase"}); err == nil && resp.Success && resp.Value != "" {
				sshPassphraseKey = pfx + "passphrase"
			}
		}
	}

	// 3. Parse user@host or host if targetName is a direct address
	if resolvedHost == "" {
		if strings.Contains(targetName, "@") {
			parts := strings.SplitN(targetName, "@", 2)
			resolvedUser = parts[0]
			resolvedHost = parts[1]
		} else if targetName != "" && (strings.Contains(targetName, ".") || targetName == "localhost") {
			resolvedHost = targetName
		}
	}

	if resolvedHost == "" {
		fail("SSH_TARGET_NOT_FOUND", fmt.Errorf("unknown SSH target %q and not a valid user@host string", targetName), "Run 'sec ssh init <target>' to configure, define in .secrc, or specify user@host")
	}

	if sshPort > 0 {
		resolvedPort = sshPort
	}
	if resolvedUser == "" {
		if curUser, err := user.Current(); err == nil && curUser.Username != "" {
			resolvedUser = curUser.Username
		} else {
			resolvedUser = "root"
		}
	}

	// Expand home in sshKeyPath
	if strings.HasPrefix(sshKeyPath, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			sshKeyPath = filepath.Join(home, strings.TrimPrefix(sshKeyPath, "~/"))
		}
	}

	var remoteCmdArgs []string
	if cmdIndex != -1 && cmdIndex < len(args) {
		remoteCmdArgs = args[cmdIndex:]
	}

	// 4. Resolve key bytes & passphrase
	var keyBytes []byte
	if sshKeySecret != "" {
		if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: sshKeySecret}); err == nil && resp.Success && resp.Value != "" {
			keyBytes = []byte(resp.Value)
		} else {
			fail("SSH_KEY_SECRET_NOT_FOUND", fmt.Errorf("failed to retrieve SSH key secret %q from vault: %v", sshKeySecret, err), "")
		}
	} else if sshKeyPath != "" {
		// #nosec G304 G703
		if b, err := os.ReadFile(sshKeyPath); err == nil {
			keyBytes = b
		} else {
			// Vault path fallback
			if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: sshKeyPath}); err == nil && resp.Success && resp.Value != "" {
				keyBytes = []byte(resp.Value)
			} else {
				fail("SSH_KEY_FILE_NOT_FOUND", fmt.Errorf("failed to read SSH private key file %s: %w", sshKeyPath, err), "")
			}
		}
	}

	passphrase := ""
	if sshPassphraseKey != "" {
		if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: sshPassphraseKey}); err == nil && resp.Success {
			passphrase = resp.Value
		}
	}

	hostKeyOpts := hostKeyOptions{
		insecure:        insecureHostKey,
		trustOnFirstUse: trustOnFirstUse,
		updateHostKey:   updateHostKey,
		noTrace:         noTrace,
	}

	// 5. Native Go SSH Connection (default for both password and key auth)
	if !useOpenSSH {
		if resolvedPassword != "" || len(keyBytes) > 0 {
			err := runNativeSSH(profile, targetName, resolvedHost, resolvedPort, resolvedUser, resolvedPassword, keyBytes, passphrase, remoteCmdArgs, hostKeyOpts)
			if err != nil {
				if exitErr, ok := err.(*ssh.ExitError); ok {
					os.Exit(exitErr.ExitStatus())
				}
				fail("SSH_EXEC_FAILED", fmt.Errorf("SSH execution to %s@%s failed: %w", resolvedUser, resolvedHost, err), "")
			}
			return
		}
	}

	// 6. Delegated OpenSSH execution (fallback when --openssh is specified)
	var agentSocket string
	var agentCleanup func()
	if len(keyBytes) > 0 {
		sock, cleanup, err := setupEphemeralSSHAgentFromBytes(keyBytes, passphrase)
		if err != nil {
			fail("SSH_AGENT_FAILED", fmt.Errorf("failed to spin up ephemeral SSH agent: %v", err), "")
		}
		agentSocket = sock
		agentCleanup = cleanup
		defer agentCleanup()
	} else if sshKeyPath != "" {
		sock, cleanup, err := setupEphemeralSSHAgent(profile, sshKeyPath, sshPassphraseKey)
		if err != nil {
			fail("SSH_AGENT_FAILED", fmt.Errorf("failed to spin up ephemeral SSH agent for key %s: %v", sshKeyPath, err), "")
		}
		agentSocket = sock
		agentCleanup = cleanup
		defer agentCleanup()
	}

	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		fail("SSH_NOT_FOUND", fmt.Errorf("OpenSSH client 'ssh' not found on system PATH"), "Install OpenSSH")
	}

	userHost := fmt.Sprintf("%s@%s", resolvedUser, resolvedHost)
	execArgs := buildOpenSSHArgs(sshBin, resolvedPort, noTrace, userHost, remoteCmdArgs)

	// #nosec G204 G702
	cmd := exec.Command(execArgs[0], execArgs[1:]...)
	env := os.Environ()
	if agentSocket != "" {
		env = append(env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agentSocket))
	}
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fail("SSH_EXEC_FAILED", fmt.Errorf("SSH execution failed: %v", err), "")
	}
}

func buildOpenSSHArgs(sshBin string, port int, noTrace bool, userHost string, remoteCmdArgs []string) []string {
	execArgs := []string{sshBin, "-p", fmt.Sprintf("%d", port)}
	if noTrace {
		execArgs = append(execArgs,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "LogLevel=ERROR",
			"-o", "IdentitiesOnly=yes",
		)
	}
	execArgs = append(execArgs, userHost)
	if len(remoteCmdArgs) > 0 {
		execArgs = append(execArgs, remoteCmdArgs...)
	}
	return execArgs
}

func vaultHostKeyCallback(profile, target, host string, port int, opts hostKeyOptions) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if opts.insecure {
			return nil
		}

		fingerprint := ssh.FingerprintSHA256(key)
		vaultPath := "ssh/" + target + "/host_fingerprint"
		if target == "" {
			vaultPath = fmt.Sprintf("ssh/hosts/%s:%d/fingerprint", host, port)
		}

		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action:  "get",
			Path:    vaultPath,
			NoTrace: opts.noTrace,
		})

		hasPinned := (err == nil && resp.Success && resp.Value != "")

		if hasPinned && !opts.updateHostKey {
			if resp.Value == fingerprint {
				return nil
			}
			return fmt.Errorf("HOST_KEY_MISMATCH: remote host %s (%s) presented host key %s, but vault has pinned %s.\nIf the machine was reinstalled or reprovisioned, run:\n  sec ssh reset-host-key %s\n  or: sec ssh %s --update-host-key",
				hostname, remote.String(), fingerprint, resp.Value, target, target)
		}

		actionDesc := "Pin"
		if opts.updateHostKey && hasPinned {
			actionDesc = "Update pinned"
		}

		if opts.trustOnFirstUse || (opts.updateHostKey && !term.IsTerminal(int(os.Stdin.Fd()))) {
			setResp, sErr := queryDaemon(profile, daemon.IPCRequest{
				Action: "set",
				Path:   vaultPath,
				Value:  fingerprint,
				Description: fmt.Sprintf("Pinned SSH Host Fingerprint (%s)", key.Type()),
			})
			if sErr != nil || !setResp.Success {
				return fmt.Errorf("failed to pin host key to vault: %v", sErr)
			}
			fmt.Fprintf(os.Stderr, "[✓] %s host key for %s into vault: %s\n", actionDesc, hostname, fingerprint)
			return nil
		}

		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintf(os.Stderr, "\n⚠️  New SSH host key presented for %s (%s):\n", hostname, key.Type())
			fmt.Fprintf(os.Stderr, "   Fingerprint: %s\n", fingerprint)
			if hasPinned {
				fmt.Fprintf(os.Stderr, "   Existing pinned fingerprint in vault: %s\n", resp.Value)
			}
			fmt.Fprintf(os.Stderr, "%s this host fingerprint into sec-agent vault? [Y/n]: ", actionDesc)
			reader := bufio.NewReader(os.Stdin)
			ans, _ := reader.ReadString('\n')
			ans = strings.TrimSpace(strings.ToLower(ans))
			if ans == "" || ans == "y" || ans == "yes" {
				setResp, sErr := queryDaemon(profile, daemon.IPCRequest{
					Action: "set",
					Path:   vaultPath,
					Value:  fingerprint,
					Description: fmt.Sprintf("Pinned SSH Host Fingerprint (%s)", key.Type()),
				})
				if sErr != nil || !setResp.Success {
					return fmt.Errorf("failed to save host key to vault: %v", sErr)
				}
				fmt.Fprintf(os.Stderr, "[✓] Host key fingerprint pinned in vault under %s\n", vaultPath)
				return nil
			}
			return fmt.Errorf("host key rejected by operator")
		}

		return fmt.Errorf("untrusted host %s (fingerprint %s). Pass --tofu / --trust-first-use in non-interactive sessions, or run interactively to pin the host key", hostname, fingerprint)
	}
}

func handleSSHHostKey(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Usage: sec ssh host-key show <target>")
		fmt.Println("\nDisplays the currently pinned host key fingerprint for a target.")
		return
	}
	if args[0] == "show" && len(args) > 1 {
		target := args[1]
		vaultPath := "ssh/" + target + "/host_fingerprint"
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: "get",
			Path:   vaultPath,
		})
		if err != nil || !resp.Success || resp.Value == "" {
			fmt.Printf("No pinned host key fingerprint found for target %q in profile %q.\n", target, profile)
			return
		}
		fmt.Printf("Pinned SSH host key for target %q:\n", target)
		fmt.Printf("  Fingerprint: %s\n", resp.Value)
		return
	}
	fmt.Println("Usage: sec ssh host-key show <target>")
}

func handleSSHResetHostKey(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Usage: sec ssh reset-host-key <target>")
		fmt.Println("\nRemoves the pinned SSH host key fingerprint from the vault for a target.")
		return
	}
	target := args[0]
	vaultPath := "ssh/" + target + "/host_fingerprint"
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "delete",
		Path:   vaultPath,
	})
	if err != nil || !resp.Success {
		fail("SSH_RESET_FAILED", fmt.Errorf("failed to reset host key for target %q: %v", target, err), "")
	}
	fmt.Printf("[✓] Pinned SSH host key fingerprint for target %q was removed from vault.\n", target)
}

func runNativeSSH(profile, target, host string, port int, sshUser, password string, keyBytes []byte, passphrase string, remoteCmdArgs []string, opts hostKeyOptions) error {
	var authMethods []ssh.AuthMethod
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}
	if len(keyBytes) > 0 {
		var signer ssh.Signer
		var err error
		if passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return fmt.Errorf("failed to parse SSH private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	sshConfig := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            authMethods,
		HostKeyCallback: vaultHostKeyCallback(profile, target, host, port, opts),
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to dial SSH server at %s: %w", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if len(remoteCmdArgs) > 0 {
		// Non-interactive remote command execution
		fullCmd := strings.Join(remoteCmdArgs, " ")
		return session.Run(fullCmd)
	}

	// Interactive terminal session
	if term.IsTerminal(int(os.Stdin.Fd())) {
		width, height, err := term.GetSize(int(os.Stdin.Fd()))
		if err != nil {
			width, height = 80, 24
		}
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
			return fmt.Errorf("request for pseudo terminal failed: %w", err)
		}
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
		}
	}

	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell on remote host: %w", err)
	}
	return session.Wait()
}

func handleSSHInit(profile string, args []string) {
	var target, host, sshUser, password, keyPath, importKeyPath, keySecret string
	port := 22
	autoSecrc := false
	noSecrc := false
	shredKey := false
	keepPub := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" || a == "help" {
			fmt.Println("Usage: sec ssh init <target> [--host <host>] [--user <user>] [--port <port>] [--password <password> | --key <path> | --import-key <path> [--shred] [--keep-pub] | --key-secret <vault-key>] [--secrc|--no-secrc]")
			fmt.Println("\nConfigure remote SSH target credentials into vault and workspace .secrc without using sshpass.")
			return
		}
		if a == "--host" && i+1 < len(args) {
			host = args[i+1]
			i++
		} else if a == "--user" && i+1 < len(args) {
			sshUser = args[i+1]
			i++
		} else if a == "--port" && i+1 < len(args) {
			if p, err := strconv.Atoi(args[i+1]); err == nil && p > 0 {
				port = p
			}
			i++
		} else if a == "--password" && i+1 < len(args) {
			password = args[i+1]
			i++
		} else if a == "--key" && i+1 < len(args) {
			keyPath = args[i+1]
			i++
		} else if a == "--import-key" && i+1 < len(args) {
			importKeyPath = args[i+1]
			i++
		} else if (a == "--key-secret" || a == "--ssh-key-secret") && i+1 < len(args) {
			keySecret = args[i+1]
			i++
		} else if strings.HasPrefix(a, "--key-secret=") {
			keySecret = strings.TrimPrefix(a, "--key-secret=")
		} else if strings.HasPrefix(a, "--ssh-key-secret=") {
			keySecret = strings.TrimPrefix(a, "--ssh-key-secret=")
		} else if a == "--shred" {
			shredKey = true
		} else if a == "--keep-pub" {
			keepPub = true
		} else if a == "--secrc" {
			autoSecrc = true
		} else if a == "--no-secrc" {
			noSecrc = true
		} else if !strings.HasPrefix(a, "-") && target == "" {
			target = a
		}
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Usage: sec ssh init <target> [--host <host>] [--user <user>] [--port <port>] [--password <password> | --key <path> | --import-key <path> [--shred] [--keep-pub] | --key-secret <vault-key>] [--secrc|--no-secrc]")
		os.Exit(1)
	}

	if err := validateSSHTargetName(target); err != nil {
		fail("INVALID_TARGET_NAME", fmt.Errorf("invalid SSH target name %q: %w", target, err), "Target name must contain only alphanumeric characters, dashes, and underscores.")
	}

	reader := bufio.NewReader(os.Stdin)
	if isInteractiveTerminal() && host == "" {
		fmt.Printf("Configure SSH target %q:\n", target)
		fmt.Print("  Remote Host / IP: ")
		h, _ := reader.ReadString('\n')
		host = strings.TrimSpace(h)

		fmt.Print("  Remote Username [root]: ")
		u, _ := reader.ReadString('\n')
		u = strings.TrimSpace(u)
		if u != "" {
			sshUser = u
		} else {
			sshUser = "root"
		}

		fmt.Print("  Remote Port [22]: ")
		pStr, _ := reader.ReadString('\n')
		pStr = strings.TrimSpace(pStr)
		if pStr != "" {
			if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
				port = p
			}
		}

		if password == "" && keyPath == "" && importKeyPath == "" {
			fmt.Print("  Authentication [1: Password, 2: Key file, 3: Ingest Key into Vault] (default: 1): ")
			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(choice)
			if choice == "3" {
				fmt.Print("  Private Key Path to Ingest: ")
				kp, _ := reader.ReadString('\n')
				importKeyPath = strings.TrimSpace(kp)
			} else if choice == "2" {
				fmt.Print("  Private Key Path: ")
				kp, _ := reader.ReadString('\n')
				keyPath = strings.TrimSpace(kp)
			} else {
				fmt.Printf("  Enter password for %s@%s: ", sshUser, host)
				bytePass, _ := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				password = string(bytePass)
			}
		}
	}

	if host == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("remote host is required for SSH target %q", target), "Pass --host <hostname>")
	}
	if sshUser == "" {
		sshUser = "root"
	}

	// Validate and read imported key upfront before modifying vault
	var importKeyBytes []byte
	var importKeyType, importKeyFingerprint string
	if importKeyPath != "" {
		cleanImportPath := importKeyPath
		if strings.HasPrefix(cleanImportPath, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				cleanImportPath = filepath.Join(home, strings.TrimPrefix(cleanImportPath, "~/"))
			}
		}
		cleanImportPath = filepath.Clean(cleanImportPath)
		// #nosec G304 G703
		b, err := os.ReadFile(cleanImportPath)
		if err != nil {
			fail("SSH_KEY_FILE_NOT_FOUND", fmt.Errorf("failed to read SSH private key file %s: %w", importKeyPath, err), "Verify that the file path exists and is readable.")
		}
		var signer ssh.Signer
		if password != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(password))
		} else {
			signer, err = ssh.ParsePrivateKey(b)
		}
		if err != nil {
			if strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "encrypted") {
				fail("SSH_KEY_PASSPHRASE_REQUIRED", fmt.Errorf("private key in %s is encrypted with a passphrase: %w", importKeyPath, err), "Pass --password <passphrase> or import with 'sec ssh import-key --passphrase-key'")
			}
			fail("INVALID_SSH_KEY", fmt.Errorf("invalid SSH private key in %s: %w", importKeyPath, err), "Ensure the file contains a valid OpenSSH, RSA, ECDSA, or ED25519 private key.")
		}
		pubKey := signer.PublicKey()
		importKeyType = pubKey.Type()
		importKeyFingerprint = ssh.FingerprintSHA256(pubKey)
		importKeyBytes = b
	}

	// Store secrets in profile vault
	basePrefix := "ssh/" + target + "/"
	saveSecret := func(relKey, val, comment string, meta map[string]string) {
		req := daemon.IPCRequest{
			Action:   "set",
			Path:     basePrefix + relKey,
			Value:    val,
			Comment:  comment,
			Metadata: meta,
		}
		resp, err := queryDaemon(profile, req)
		if err != nil {
			failDaemonNotRunning(profile)
		}
		if !resp.Success {
			code, rem := mapDaemonError(resp.Error)
			fail(code, fmt.Errorf("%s", resp.Error), rem)
		}
	}

	saveSecret("host", host, fmt.Sprintf("SSH Host for %s", target), nil)
	saveSecret("user", sshUser, fmt.Sprintf("SSH User for %s", target), nil)
	saveSecret("port", strconv.Itoa(port), fmt.Sprintf("SSH Port for %s", target), nil)

	passwordKey := ""
	if password != "" && importKeyPath == "" {
		passwordKey = basePrefix + "password"
		saveSecret("password", password, fmt.Sprintf("SSH Password for %s", target), map[string]string{"alias": "SSH_PASSWORD"})
	}

	if len(importKeyBytes) > 0 {
		meta := map[string]string{
			"algorithm":     importKeyType,
			"fingerprint":   importKeyFingerprint,
			"imported_at":   time.Now().UTC().Format(time.RFC3339),
			"imported_from": filepath.Base(importKeyPath),
		}
		saveSecret("private_key", string(importKeyBytes), fmt.Sprintf("SSH Private Key for %s (%s)", target, importKeyType), meta)

		if shredKey {
			cleanImportPath := importKeyPath
			if strings.HasPrefix(cleanImportPath, "~/") {
				if home, err := os.UserHomeDir(); err == nil {
					cleanImportPath = filepath.Join(home, strings.TrimPrefix(cleanImportPath, "~/"))
				}
			}
			cleanImportPath = filepath.Clean(cleanImportPath)
			if sErr := shredFile(cleanImportPath); sErr != nil {
				fail("SHRED_FAILED", fmt.Errorf("failed to shred source key file %s: %w", importKeyPath, sErr), "")
			}
			fmt.Printf("[✓] Securely shredded source key file: %s\n", importKeyPath)

			if !keepPub {
				if pErr := shredCompanionPublicKeys(cleanImportPath); pErr != nil {
					fail("SHRED_FAILED", pErr, "")
				}
			}
		}

		khPath := getKnownHostsPath()
		if khPath != "" {
			var cands []string
			cands = append(cands, target, host)
			if port != 22 {
				cands = append(cands, fmt.Sprintf("[%s]:%d", host, port), fmt.Sprintf("[%s]:%d", target, port))
			}
			removed, _ := sanitizeKnownHosts(khPath, cands)
			if removed > 0 {
				fmt.Printf("[✓] Sanitized %d matching known_hosts entries for target %q\n", removed, target)
			}
		}
	} else if keySecret != "" {
		if !strings.Contains(keySecret, "/") {
			keySecret = "ssh/shared/" + keySecret + "/private_key"
		}
		saveSecret("key_secret", keySecret, fmt.Sprintf("SSH Shared Key Secret for %s", target), nil)
	} else if keyPath != "" {
		saveSecret("key", keyPath, fmt.Sprintf("SSH Key Path for %s", target), nil)
	}

	fmt.Printf("✅ Stored SSH credentials for target %q in profile %q\n", target, profile)

	// Workspace .secrc configuration
	if !noSecrc {
		doWriteSecrc := autoSecrc
		if !doWriteSecrc && isInteractiveTerminal() {
			fmt.Printf("\nAdd target %q to workspace .secrc 'ssh_targets'? [Y/n]: ", target)
			ans, _ := reader.ReadString('\n')
			ans = strings.ToLower(strings.TrimSpace(ans))
			if ans == "" || ans == "y" || ans == "yes" {
				doWriteSecrc = true
			}
		}

		if doWriteSecrc {
			cfgFile := findWorkspaceConfigFile()
			if cfgFile == "" {
				cfgFile = ".secrc"
			}
			var cfg WorkspaceConfig
			// #nosec G304 G703
			if data, err := os.ReadFile(cfgFile); err == nil {
				_ = json.Unmarshal(data, &cfg)
			}
			if cfg.SSHTargets == nil {
				cfg.SSHTargets = make(map[string]SSHTarget)
			}
			cfg.SSHTargets[target] = SSHTarget{
				Host:         host,
				User:         sshUser,
				Port:         port,
				PasswordKey:  passwordKey,
				IdentityFile: keyPath,
				KeySecret:    keySecret,
			}
			if data, err := json.MarshalIndent(cfg, "", "  "); err == nil {
				data = append(data, '\n')
				// #nosec G304 G703
				_ = os.WriteFile(filepath.Clean(cfgFile), data, 0600)
				fmt.Printf("✅ Updated %s with target %q\n", cfgFile, target)
			}
		}
	}

	fmt.Printf("\nConnect anytime using:\n  sec ssh %s\n  sec ssh %s -- <command...>\n", target, target)
}

func validateSSHTargetName(target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("target name cannot be empty")
	}
	if strings.Contains(target, "/") || strings.Contains(target, "\\") || strings.Contains(target, " ") || strings.Contains(target, "..") {
		return fmt.Errorf("target name cannot contain spaces, slashes, or relative path components")
	}
	for _, r := range target {
		if unicode.IsControl(r) {
			return fmt.Errorf("target name cannot contain control characters")
		}
	}
	return store.SecretKey("ssh/" + target).Validate()
}

func shredFile(path string) error {
	cleanPath := filepath.Clean(path)
	// #nosec G703
	info, err := os.Stat(cleanPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("cannot shred directory: %s", cleanPath)
	}
	size := info.Size()

	// #nosec G304 G703
	f, err := os.OpenFile(cleanPath, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if size > 0 {
		// Pass 1: Cryptographically secure random bytes
		randomBuf := make([]byte, 4096)
		remaining := size
		for remaining > 0 {
			toWrite := int64(len(randomBuf))
			if remaining < toWrite {
				toWrite = remaining
			}
			if _, err := io.ReadFull(crand.Reader, randomBuf[:toWrite]); err != nil {
				return fmt.Errorf("failed generating random bytes: %w", err)
			}
			if _, err := f.Write(randomBuf[:toWrite]); err != nil {
				return fmt.Errorf("failed writing random pass: %w", err)
			}
			remaining -= toWrite
		}
		if err := f.Sync(); err != nil {
			return fmt.Errorf("failed to sync random pass: %w", err)
		}

		// Pass 2: Overwrite with all zeros (0x00)
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed seeking start: %w", err)
		}
		zeroBuf := make([]byte, 4096)
		remaining = size
		for remaining > 0 {
			toWrite := int64(len(zeroBuf))
			if remaining < toWrite {
				toWrite = remaining
			}
			if _, err := f.Write(zeroBuf[:toWrite]); err != nil {
				return fmt.Errorf("failed writing zero pass: %w", err)
			}
			remaining -= toWrite
		}
		if err := f.Sync(); err != nil {
			return fmt.Errorf("failed to sync zero pass: %w", err)
		}
	}

	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("failed to truncate file: %w", err)
	}
	_ = f.Close()

	// #nosec G703
	return os.Remove(cleanPath)
}

func shredCompanionPublicKeys(privateKeyPath string) error {
	cleanPath := filepath.Clean(privateKeyPath)
	companionFiles := []string{cleanPath + ".pub", cleanPath + "-cert.pub"}
	for _, pubPath := range companionFiles {
		// #nosec G703
		if fi, err := os.Stat(pubPath); err == nil && !fi.IsDir() {
			if sErr := shredFile(pubPath); sErr != nil {
				return fmt.Errorf("failed to shred companion public key %s: %w", pubPath, sErr)
			}
			fmt.Printf("[✓] Securely shredded companion public key: %s\n", pubPath)
		}
	}
	return nil
}

func getKnownHostsPath() string {
	if custom := os.Getenv("SEC_KNOWN_HOSTS_PATH"); custom != "" {
		return custom
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

func sanitizeKnownHosts(knownHostsPath string, targets []string) (int, error) {
	if len(targets) == 0 {
		return 0, nil
	}
	cleanPath := filepath.Clean(knownHostsPath)
	// #nosec G304 G703
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	candidateMap := make(map[string]bool)
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t != "" {
			candidateMap[t] = true
			candidateMap[strings.ToLower(t)] = true
		}
	}
	if len(candidateMap) == 0 {
		return 0, nil
	}

	lines := strings.Split(string(data), "\n")
	var keptLines []string
	removedCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			keptLines = append(keptLines, line)
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			keptLines = append(keptLines, line)
			continue
		}

		hostField := fields[0]
		if (hostField == "@cert-authority" || hostField == "@revoked") && len(fields) >= 3 {
			hostField = fields[1]
		}

		matched := false

		if strings.HasPrefix(hostField, "|1|") {
			parts := strings.Split(hostField, "|")
			if len(parts) >= 4 && parts[1] == "1" {
				saltB64 := parts[2]
				expectedHash := parts[3]
				saltBytes, sErr := base64.StdEncoding.DecodeString(saltB64)
				if sErr == nil {
					for cand := range candidateMap {
						// #nosec G505 - required by OpenSSH known_hosts HMAC-SHA1 specification
						mac := hmac.New(sha1.New, saltBytes)
						mac.Write([]byte(cand))
						sumB64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))
						if sumB64 == expectedHash {
							matched = true
							break
						}
					}
				}
			}
		} else {
			subHosts := strings.Split(hostField, ",")
			for _, sh := range subHosts {
				sh = strings.TrimSpace(sh)
				if candidateMap[sh] || candidateMap[strings.ToLower(sh)] {
					matched = true
					break
				}
			}
		}

		if matched {
			removedCount++
		} else {
			keptLines = append(keptLines, line)
		}
	}

	if removedCount > 0 {
		newContent := strings.Join(keptLines, "\n")
		dir := filepath.Dir(cleanPath)
		tmpFile, err := os.CreateTemp(dir, "known_hosts_sanitize_*")
		if err != nil {
			return 0, fmt.Errorf("failed creating temp known_hosts: %w", err)
		}
		tmpName := tmpFile.Name()
		defer func() { _ = os.Remove(tmpName) }()

		if _, err := tmpFile.WriteString(newContent); err != nil {
			_ = tmpFile.Close()
			return 0, fmt.Errorf("failed writing sanitized known_hosts: %w", err)
		}
		if err := tmpFile.Sync(); err != nil {
			_ = tmpFile.Close()
			return 0, fmt.Errorf("failed syncing sanitized known_hosts: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return 0, fmt.Errorf("failed closing temp known_hosts: %w", err)
		}

		// #nosec G302 G703
		if err := os.Chmod(tmpName, 0600); err != nil {
			return 0, fmt.Errorf("failed chmod temp known_hosts: %w", err)
		}

		if err := os.Rename(tmpName, cleanPath); err != nil {
			return 0, fmt.Errorf("failed replacing known_hosts: %w", err)
		}
	}

	oldPath := cleanPath + ".old"
	if _, err := os.Stat(oldPath); err == nil {
		_ = os.Remove(oldPath)
	}

	return removedCount, nil
}

func handleSSHImportKey(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Usage: sec ssh import-key [<target> | --shared <name>] <file_path> [--shred] [--keep-pub] [--sanitize | --no-sanitize] [--passphrase-key <key>]")
		fmt.Println("\nIngest an OpenSSH private key directly into vault memory, record metadata, optionally shred source and companion public key files from disk, and sanitize known_hosts.")
		return
	}

	var target, filePath, passphraseKey, sharedName string
	shred := false
	keepPub := false
	doSanitize := true

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--shred" {
			shred = true
		} else if a == "--keep-pub" {
			keepPub = true
		} else if a == "--no-sanitize" {
			doSanitize = false
		} else if a == "--sanitize" {
			doSanitize = true
		} else if a == "--shared" && i+1 < len(args) {
			sharedName = args[i+1]
			i++
		} else if strings.HasPrefix(a, "--shared=") {
			sharedName = strings.TrimPrefix(a, "--shared=")
		} else if a == "--passphrase-key" && i+1 < len(args) {
			passphraseKey = args[i+1]
			i++
		} else if strings.HasPrefix(a, "--passphrase-key=") {
			passphraseKey = strings.TrimPrefix(a, "--passphrase-key=")
		} else if !strings.HasPrefix(a, "-") {
			if target == "" && sharedName == "" {
				target = a
			} else if filePath == "" {
				filePath = a
			}
		}
	}

	if sharedName != "" {
		if err := validateSSHTargetName(sharedName); err != nil {
			fail("INVALID_TARGET_NAME", fmt.Errorf("invalid shared key name %q: %w", sharedName, err), "Shared key name must contain only alphanumeric characters, dashes, and underscores.")
		}
		target = "shared/" + sharedName
		doSanitize = false
	} else {
		if target == "" || filePath == "" {
			fail("MISSING_ARGUMENT", fmt.Errorf("both target (or --shared <name>) and <file_path> are required"), "Usage: sec ssh import-key [<target> | --shared <name>] <file_path> [--shred] [--keep-pub] [--sanitize | --no-sanitize] [--passphrase-key <key>]")
		}
		if err := validateSSHTargetName(target); err != nil {
			fail("INVALID_TARGET_NAME", fmt.Errorf("invalid SSH target name %q: %w", target, err), "Target name must contain only alphanumeric characters, dashes, and underscores.")
		}
	}

	if filePath == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("file path is required"), "Usage: sec ssh import-key [<target> | --shared <name>] <file_path> [--shred] [--keep-pub] [--sanitize | --no-sanitize] [--passphrase-key <key>]")
	}

	cleanPath := filePath
	if strings.HasPrefix(cleanPath, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			cleanPath = filepath.Join(home, strings.TrimPrefix(cleanPath, "~/"))
		}
	}
	cleanPath = filepath.Clean(cleanPath)

	// #nosec G304 G703
	keyBytes, err := os.ReadFile(cleanPath)
	if err != nil {
		fail("SSH_KEY_FILE_NOT_FOUND", fmt.Errorf("failed to read SSH private key file %s: %w", filePath, err), "Verify that the file path exists and is readable.")
	}

	passphrase := ""
	if passphraseKey != "" {
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: "get",
			Path:   passphraseKey,
		})
		if err != nil {
			failDaemonNotRunning(profile)
		}
		if !resp.Success {
			code, rem := mapDaemonError(resp.Error)
			fail(code, fmt.Errorf("failed to read passphrase key %q from vault: %s", passphraseKey, resp.Error), rem)
		}
		passphrase = resp.Value
	}

	var signer ssh.Signer
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyBytes)
	}

	if err != nil {
		if strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "encrypted") {
			fail("SSH_KEY_PASSPHRASE_REQUIRED", fmt.Errorf("private key in %s is encrypted with a passphrase: %w", filePath, err), "Pass --passphrase-key <vault-key-containing-passphrase>")
		}
		fail("INVALID_SSH_KEY", fmt.Errorf("invalid SSH private key in %s: %w", filePath, err), "Ensure the file contains a valid OpenSSH, RSA, ECDSA, or ED25519 private key.")
	}

	pubKey := signer.PublicKey()
	keyType := pubKey.Type()
	fingerprint := ssh.FingerprintSHA256(pubKey)

	metadata := map[string]string{
		"algorithm":     keyType,
		"fingerprint":   fingerprint,
		"imported_at":   time.Now().UTC().Format(time.RFC3339),
		"imported_from": filepath.Base(filePath),
	}

	vaultPath := "ssh/" + target + "/private_key"
	req := daemon.IPCRequest{
		Action:   "set",
		Path:     vaultPath,
		Value:    string(keyBytes),
		Comment:  fmt.Sprintf("SSH Private Key for %s (%s)", target, keyType),
		Metadata: metadata,
	}

	resp, err := queryDaemon(profile, req)
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("failed to store private key into vault: %s", resp.Error), rem)
	}

	fmt.Printf("✅ Imported SSH private key for %q into vault (%s, %s)\n", target, keyType, fingerprint)

	// Post-commit Phase 2: Shredding (guaranteed only after successful vault commit)
	if shred {
		if sErr := shredFile(cleanPath); sErr != nil {
			fail("SHRED_FAILED", fmt.Errorf("failed to shred source key file %s: %w", filePath, sErr), "Ensure the file is writable and not locked.")
		}
		fmt.Printf("[✓] Securely shredded source key file: %s\n", filePath)

		if !keepPub {
			if pErr := shredCompanionPublicKeys(cleanPath); pErr != nil {
				fail("SHRED_FAILED", pErr, "Ensure the companion public key file is writable and not locked.")
			}
		}
	}

	// Host sanitization
	if doSanitize {
		var candidates []string
		candidates = append(candidates, target)

		if hResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/" + target + "/host"}); err == nil && hResp.Success && hResp.Value != "" {
			host := strings.TrimSpace(hResp.Value)
			candidates = append(candidates, host)
			port := 22
			if pResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/" + target + "/port"}); err == nil && pResp.Success && pResp.Value != "" {
				if p, pErr := strconv.Atoi(strings.TrimSpace(pResp.Value)); pErr == nil && p > 0 {
					port = p
				}
			}
			if port != 22 {
				candidates = append(candidates, fmt.Sprintf("[%s]:%d", host, port))
				candidates = append(candidates, fmt.Sprintf("[%s]:%d", target, port))
			}
		} else {
			cfgFile := findWorkspaceConfigFile()
			if cfgFile != "" {
				var cfg WorkspaceConfig
				// #nosec G304 G703
				if data, err := os.ReadFile(cfgFile); err == nil {
					_ = json.Unmarshal(data, &cfg)
					if tCfg, ok := cfg.SSHTargets[target]; ok && tCfg.Host != "" {
						candidates = append(candidates, tCfg.Host)
						if tCfg.Port > 0 && tCfg.Port != 22 {
							candidates = append(candidates, fmt.Sprintf("[%s]:%d", tCfg.Host, tCfg.Port))
							candidates = append(candidates, fmt.Sprintf("[%s]:%d", target, tCfg.Port))
						}
					}
				}
			}
		}

		khPath := getKnownHostsPath()
		if khPath != "" {
			removed, sErr := sanitizeKnownHosts(khPath, candidates)
			if sErr == nil && removed > 0 {
				fmt.Printf("[✓] Sanitized %d matching known_hosts entries for target %q\n", removed, target)
			}
		}
	}
}

func handleSSHSanitize(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Usage: sec ssh sanitize [<target>] [--all]")
		fmt.Println("\nScrub target hostnames, IPs, and HMAC-SHA1 hashed entries from ~/.ssh/known_hosts.")
		return
	}

	var target string
	allTargets := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--all" {
			allTargets = true
		} else if !strings.HasPrefix(a, "-") && target == "" {
			target = a
		}
	}

	if target == "" && !allTargets {
		fail("MISSING_ARGUMENT", fmt.Errorf("specify a <target> or pass --all"), "Usage: sec ssh sanitize [<target>] [--all]")
	}

	var candidates []string
	candidateSet := make(map[string]bool)

	addCandidate := func(c string) {
		c = strings.TrimSpace(c)
		if c != "" && !candidateSet[c] {
			candidateSet[c] = true
			candidates = append(candidates, c)
		}
	}

	if allTargets {
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: "list",
		})
		targetNames := make(map[string]bool)
		if err == nil && resp.Success {
			var keys []string
			if err := json.Unmarshal([]byte(resp.Value), &keys); err == nil {
				for _, k := range keys {
					if strings.HasPrefix(k, "ssh/") {
						parts := strings.Split(strings.TrimPrefix(k, "ssh/"), "/")
						if len(parts) >= 2 && parts[0] != "hosts" && parts[0] != "shared" {
							targetNames[parts[0]] = true
						}
					}
				}
			}
		}

		cfgFile := findWorkspaceConfigFile()
		if cfgFile != "" {
			var cfg WorkspaceConfig
			// #nosec G304 G703
			if data, err := os.ReadFile(cfgFile); err == nil {
				_ = json.Unmarshal(data, &cfg)
				for tName := range cfg.SSHTargets {
					targetNames[tName] = true
				}
			}
		}

		for tName := range targetNames {
			addCandidate(tName)
			host := ""
			port := 22
			if hResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/" + tName + "/host"}); err == nil && hResp.Success && hResp.Value != "" {
				host = strings.TrimSpace(hResp.Value)
			}
			if pResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/" + tName + "/port"}); err == nil && pResp.Success && pResp.Value != "" {
				if p, pErr := strconv.Atoi(strings.TrimSpace(pResp.Value)); pErr == nil && p > 0 {
					port = p
				}
			}
			if host != "" {
				addCandidate(host)
				if port != 22 {
					addCandidate(fmt.Sprintf("[%s]:%d", host, port))
					addCandidate(fmt.Sprintf("[%s]:%d", tName, port))
				}
			}
		}
	} else {
		addCandidate(target)
		host := ""
		port := 22
		if hResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/" + target + "/host"}); err == nil && hResp.Success && hResp.Value != "" {
			host = strings.TrimSpace(hResp.Value)
		}
		if pResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/" + target + "/port"}); err == nil && pResp.Success && pResp.Value != "" {
			if p, pErr := strconv.Atoi(strings.TrimSpace(pResp.Value)); pErr == nil && p > 0 {
				port = p
			}
		}
		if host == "" {
			cfgFile := findWorkspaceConfigFile()
			if cfgFile != "" {
				var cfg WorkspaceConfig
				// #nosec G304 G703
				if data, err := os.ReadFile(cfgFile); err == nil {
					_ = json.Unmarshal(data, &cfg)
					if tCfg, ok := cfg.SSHTargets[target]; ok {
						host = tCfg.Host
						if tCfg.Port > 0 {
							port = tCfg.Port
						}
					}
				}
			}
		}
		if host != "" {
			addCandidate(host)
			if port != 22 {
				addCandidate(fmt.Sprintf("[%s]:%d", host, port))
				addCandidate(fmt.Sprintf("[%s]:%d", target, port))
			}
		}
	}

	khPath := getKnownHostsPath()
	if khPath == "" {
		fail("SSH_KNOWN_HOSTS_NOT_FOUND", fmt.Errorf("could not determine user home directory for known_hosts"), "")
	}

	removed, err := sanitizeKnownHosts(khPath, candidates)
	if err != nil {
		fail("SANITIZE_FAILED", fmt.Errorf("failed to sanitize known_hosts: %w", err), "")
	}

	targetDesc := target
	if allTargets {
		targetDesc = "all targets"
	}
	fmt.Printf("[✓] Sanitized %d known_hosts entries for %s from %s\n", removed, targetDesc, khPath)
}
