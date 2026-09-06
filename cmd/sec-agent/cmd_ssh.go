package main

import (
	"bufio"
	"encoding/json"
	"fmt"
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

func handleSSH(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Usage: sec ssh [init <target>] | [<target> | user@host] [--ssh-key <path>] [--port <p>] [-- <cmd...>]")
		fmt.Println("\nExecutes remote SSH commands or interactive sessions under vault authentication without requiring sshpass.")
		fmt.Println("\nSubcommands:")
		fmt.Println("  init <target>          Configure remote SSH target into vault and workspace .secrc")
		fmt.Println("\nFlags & Arguments:")
		fmt.Println("  <target>               Named target from .secrc or vault (ssh/<target>/...)")
		fmt.Println("  user@host              Direct SSH user and host destination")
		fmt.Println("  --ssh-key, -i <path>   Path to encrypted private key file")
		fmt.Println("  --ssh-passphrase-key   Vault key containing the private key passphrase")
		fmt.Println("  -p, --port <port>      Remote SSH port (default: 22)")
		fmt.Println("  -- <cmd...>            Remote command to execute (omit for interactive shell)")
		return
	}

	if args[0] == "init" {
		handleSSHInit(profile, args[1:])
		return
	}

	targetName := ""
	sshKeyPath := ""
	sshPassphraseKey := ""
	sshPort := 0
	cmdIndex := -1

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
		if sshKeyPath == "" {
			if resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: pfx + "key"}); err == nil && resp.Success && resp.Value != "" {
				sshKeyPath = resp.Value
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

	// 4. Native Go SSH Connection (avoiding external sshpass)
	if resolvedPassword != "" {
		err := runNativeSSH(resolvedHost, resolvedPort, resolvedUser, resolvedPassword, nil, "", remoteCmdArgs)
		if err != nil {
			if exitErr, ok := err.(*ssh.ExitError); ok {
				os.Exit(exitErr.ExitStatus())
			}
			fail("SSH_EXEC_FAILED", fmt.Errorf("SSH execution to %s@%s failed: %w", resolvedUser, resolvedHost, err), "")
		}
		return
	}

	// 5. If Key authentication with passphrase or agent
	var agentSocket string
	var agentCleanup func()
	if sshKeyPath != "" {
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
	execArgs := []string{sshBin, "-p", fmt.Sprintf("%d", resolvedPort), userHost}
	if len(remoteCmdArgs) > 0 {
		execArgs = append(execArgs, remoteCmdArgs...)
	}

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

func runNativeSSH(host string, port int, sshUser, password string, keyBytes []byte, passphrase string, remoteCmdArgs []string) error {
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
		if err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}

	sshConfig := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106
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
	var target, host, sshUser, password, keyPath string
	port := 22
	autoSecrc := false
	noSecrc := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" || a == "help" {
			fmt.Println("Usage: sec ssh init <target> [--host <host>] [--user <user>] [--port <port>] [--password <password> | --key <path>] [--secrc|--no-secrc]")
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
		} else if a == "--secrc" {
			autoSecrc = true
		} else if a == "--no-secrc" {
			noSecrc = true
		} else if !strings.HasPrefix(a, "-") && target == "" {
			target = a
		}
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Usage: sec ssh init <target> [--host <host>] [--user <user>] [--port <port>] [--password <password> | --key <path>] [--secrc|--no-secrc]")
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

		if password == "" && keyPath == "" {
			fmt.Print("  Authentication [1: Password, 2: Key file] (default: 1): ")
			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(choice)
			if choice == "2" {
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
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("failed to save SSH secret: %v", err), "Run 'eval $(sec open)' to unlock session")
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
	if password != "" {
		passwordKey = basePrefix + "password"
		saveSecret("password", password, fmt.Sprintf("SSH Password for %s", target), map[string]string{"alias": "SSH_PASSWORD"})
	}
	if keyPath != "" {
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
