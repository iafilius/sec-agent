package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"secure_secrets/internal/daemon"
)

func handleIDEProxy(profile string, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sec-agent ide-proxy [--profile <name>] -- <command> [args...]")
		os.Exit(1)
	}

	cmdArgs := args
	if args[0] == "--" {
		cmdArgs = args[1:]
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No target command specified for ide-proxy.")
		os.Exit(1)
	}

	// Ensure daemon is running and profile is unlocked
	req := daemon.IPCRequest{Action: "backup"}
	resp, err := queryDaemon(profile, req)
	if err != nil || resp == nil || !resp.Success {
		fmt.Fprintf(os.Stderr, "Error: Failed to query unlocked daemon for profile %q: %v\n", profile, err)
		os.Exit(1)
	}

	// Merge vault environment into child process execution
	envMap := make(map[string]string)
	for _, env := range os.Environ() {
		pair := splitEnvPair(env)
		if pair.Key != "" {
			envMap[pair.Key] = pair.Value
		}
	}
	if resp.Secrets != nil {
		for k, entry := range resp.Secrets {
			envKey := strings.ToUpper(strings.ReplaceAll(filepath.Base(k), "-", "_"))
			envMap[envKey] = entry.Value
		}
	}

	var mergedEnv []string
	for k, v := range envMap {
		mergedEnv = append(mergedEnv, fmt.Sprintf("%s=%s", k, v))
	}

	targetPath, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		targetPath = cmdArgs[0]
	}

	// #nosec G204 G702
	cmd := exec.Command(targetPath, cmdArgs[1:]...)
	cmd.Env = mergedEnv
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func handleInitIDE(profile string, args []string) {
	snippet := `{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug with sec-agent Enclave",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceFolder}",
      "args": [],
      "env": {
        "SEC_PROFILE": "` + profile + `"
      }
    }
  ]
}`
	fmt.Println(snippet)
}

type envPair struct {
	Key   string
	Value string
}

func splitEnvPair(env string) envPair {
	for i := 0; i < len(env); i++ {
		if env[i] == '=' {
			return envPair{Key: env[:i], Value: env[i+1:]}
		}
	}
	return envPair{Key: env, Value: ""}
}
