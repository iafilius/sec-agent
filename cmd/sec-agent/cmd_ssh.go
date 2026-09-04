package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func handleSSH(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Usage: sec ssh [target | user@host] [-- <cmd...>]")
		fmt.Println("\nExecutes remote SSH commands or interactive sessions under ephemeral in-memory SSH agent protection.")
		fmt.Println("\nFlags & Arguments:")
		fmt.Println("  <target>               Named target from .secrc 'ssh_targets' dictionary")
		fmt.Println("  user@host              Direct SSH user and host destination")
		fmt.Println("  --ssh-key, -i <path>   Path to encrypted private key file")
		fmt.Println("  --ssh-passphrase-key   Vault key containing the private key passphrase")
		fmt.Println("  -p, --port <port>      Remote SSH port (default: 22)")
		fmt.Println("  -- <cmd...>            Remote command to execute (omit for interactive shell)")
		return
	}

	targetName := ""
	sshKeyPath := ""
	sshPassphraseKey := ""
	sshPort := 22
	userHost := ""
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

	wsCfg := loadWorkspaceConfig()
	if wsCfg != nil && wsCfg.SSHTargets != nil && targetName != "" {
		if tgt, ok := wsCfg.SSHTargets[targetName]; ok {
			user := tgt.User
			if user == "" {
				user = "root"
			}
			userHost = fmt.Sprintf("%s@%s", user, tgt.Host)
			if tgt.Port > 0 {
				sshPort = tgt.Port
			}
			if tgt.IdentityFile != "" && sshKeyPath == "" {
				sshKeyPath = tgt.IdentityFile
			}
			if tgt.PassphraseKey != "" && sshPassphraseKey == "" {
				sshPassphraseKey = tgt.PassphraseKey
			}
		}
	}

	if userHost == "" {
		if strings.Contains(targetName, "@") || strings.Contains(targetName, ".") || targetName == "localhost" {
			userHost = targetName
		} else {
			fail("SSH_TARGET_NOT_FOUND", fmt.Errorf("unknown SSH target %q and not a valid user@host string", targetName), "Define target in .secrc 'ssh_targets' or specify user@host")
		}
	}

	// Expand home ~ in sshKeyPath
	if strings.HasPrefix(sshKeyPath, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			sshKeyPath = filepath.Join(home, strings.TrimPrefix(sshKeyPath, "~/"))
		}
	}

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

	var remoteCmdArgs []string
	if cmdIndex != -1 && cmdIndex < len(args) {
		remoteCmdArgs = args[cmdIndex:]
	}

	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		fail("SSH_NOT_FOUND", fmt.Errorf("OpenSSH client 'ssh' not found on system PATH"), "Install OpenSSH")
	}

	execArgs := []string{sshBin, "-p", fmt.Sprintf("%d", sshPort), userHost}
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
