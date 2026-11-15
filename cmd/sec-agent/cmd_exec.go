package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
	"sort"
	"strings"

	"golang.org/x/term"
)

const (
	execVaultPrefix      = "exec/"
	secretTypeCmdScript  = "command_script"
	defaultExecShellBin  = "/bin/sh"
)

var execSecURIRegex = regexp.MustCompile(`sec://([a-zA-Z0-9_\-\./:]+)`)

// normalizeExecVaultKey normalizes a command name into a strongly-typed store.SecretKey.
// Names without a slash are stored under "exec/<name>"; paths containing a slash are preserved.
func normalizeExecVaultKey(name string) (store.SecretKey, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", store.ErrEmptySecretKey
	}
	if !strings.Contains(trimmed, "/") {
		trimmed = execVaultPrefix + trimmed
	}
	return store.NewSecretKey(trimmed)
}

// candidateExecVaultKeys returns the ordered vault keys to probe for a given command name.
func candidateExecVaultKeys(name string) []store.SecretKey {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return nil
	}
	var rawCandidates []string
	if !strings.Contains(trimmed, "/") {
		rawCandidates = []string{execVaultPrefix + trimmed, trimmed}
	} else if strings.HasPrefix(trimmed, execVaultPrefix) {
		rawCandidates = []string{trimmed, strings.TrimPrefix(trimmed, execVaultPrefix)}
	} else {
		rawCandidates = []string{trimmed, execVaultPrefix + trimmed}
	}

	var keys []store.SecretKey
	seen := make(map[store.SecretKey]bool)
	for _, c := range rawCandidates {
		if sk, err := store.NewSecretKey(c); err == nil && !seen[sk] {
			seen[sk] = true
			keys = append(keys, sk)
		}
	}
	return keys
}

// expandTildeDir expands a leading "~/" to the current user's home directory.
func expandTildeDir(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(trimmed, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, trimmed[2:])
		}
	}
	return trimmed
}

// saveExecScript stores a command script in the vault with secret_type="command_script".
func saveExecScript(profile string, name string, cmdStr string, desc string) (store.SecretKey, error) {
	vaultKey, err := normalizeExecVaultKey(name)
	if err != nil {
		return "", err
	}
	trimmedCmd := strings.TrimRight(cmdStr, "\r\n")
	if strings.TrimSpace(trimmedCmd) == "" {
		return "", fmt.Errorf("command script body cannot be empty")
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:      daemon.IPCActionSet,
		Path:        vaultKey.String(),
		Value:       trimmedCmd,
		Description: desc,
		Metadata: map[string]string{
			"secret_type": secretTypeCmdScript,
		},
	})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return "", fmt.Errorf("%s", resp.Error)
	}
	return vaultKey, nil
}

// resolveExecScript resolves a stored command script from the vault, probing exec/<name> and <name>.
func resolveExecScript(profile string, name string, noTrace bool) (string, store.SecretKey, error) {
	candidates := candidateExecVaultKeys(name)
	if len(candidates) == 0 {
		return "", "", store.ErrEmptySecretKey
	}

	var lastErr string
	for _, key := range candidates {
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action:  daemon.IPCActionGet,
			Path:    key.String(),
			NoTrace: noTrace,
		})
		if err != nil {
			return "", "", err
		}
		if resp.Success {
			return resp.Value, key, nil
		}
		lastErr = resp.Error
		if strings.Contains(resp.Error, "locked") || strings.Contains(resp.Error, "token") {
			return "", "", fmt.Errorf("%w: %s", store.ErrVaultLocked, resp.Error)
		}
	}

	if lastErr != "" && !strings.Contains(lastErr, "not found") {
		return "", "", fmt.Errorf("%s", lastErr)
	}
	return "", "", fmt.Errorf("%w: stealth command %q not found in profile %q", store.ErrSecretNotFound, name, profile)
}

// collectRedactionSecrets fetches secret values from the active profile with NoTrace so stdout/stderr can be redacted.
func collectRedactionSecrets(profile string, noTrace bool) []string {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:  daemon.IPCActionGetGroup,
		Path:    "",
		NoTrace: noTrace,
	})
	if err != nil || resp == nil || !resp.Success {
		return nil
	}
	var vals []string
	for k, entry := range resp.Secrets {
		if strings.HasPrefix(k, "__") {
			continue
		}
		if entry.Metadata != nil && entry.Metadata["secret_type"] == secretTypeCmdScript {
			continue
		}
		trimmed := strings.TrimSpace(entry.Value)
		if len(trimmed) >= 4 {
			vals = append(vals, trimmed)
		}
	}
	return vals
}

// expandInlineScriptSecrets expands any {{key}} or sec://key placeholders inside the script body in memory.
func expandInlineScriptSecrets(profile string, scriptBody string, noTrace bool) (string, []string, error) {
	var extraSecrets []string
	expanded := scriptBody

	if strings.Contains(expanded, "{{") && strings.Contains(expanded, "}}") {
		wsCfg := loadWorkspaceConfig()
		fetcher := func(p string) (map[string]string, error) {
			resp, err := queryDaemon(p, daemon.IPCRequest{
				Action:  daemon.IPCActionGetGroup,
				Path:    "",
				NoTrace: noTrace,
			})
			if err != nil {
				return nil, fmt.Errorf("daemon for profile %q is not running: %w", p, err)
			}
			if !resp.Success {
				return nil, fmt.Errorf("failed fetching secrets for profile %q: %s", p, resp.Error)
			}
			res := make(map[string]string, len(resp.Secrets))
			for k, v := range resp.Secrets {
				res[k] = v.Value
				if len(strings.TrimSpace(v.Value)) >= 4 {
					extraSecrets = append(extraSecrets, strings.TrimSpace(v.Value))
				}
			}
			return res, nil
		}
		rendered, err := renderStreamTemplate(profile, expanded, wsCfg, fetcher)
		if err != nil {
			return "", nil, err
		}
		expanded = rendered
	}

	if strings.Contains(expanded, "sec://") {
		expanded = execSecURIRegex.ReplaceAllStringFunc(expanded, func(match string) string {
			secretPath := strings.TrimPrefix(match, "sec://")
			targetProf := profile
			if strings.Contains(secretPath, ":") {
				parts := strings.SplitN(secretPath, ":", 2)
				targetProf = parts[0]
				secretPath = parts[1]
			}
			getResp, err := queryDaemon(targetProf, daemon.IPCRequest{
				Action:  daemon.IPCActionGet,
				Path:    secretPath,
				NoTrace: noTrace,
			})
			if err == nil && getResp != nil && getResp.Success {
				if len(strings.TrimSpace(getResp.Value)) >= 4 {
					extraSecrets = append(extraSecrets, strings.TrimSpace(getResp.Value))
				}
				return getResp.Value
			}
			return match
		})
	}

	return expanded, extraSecrets, nil
}

// executeScriptInMemory streams scriptBody over stdin into `<shellBin> -s [-- <scriptArgs...>]` without creating any temporary files on disk.
func executeScriptInMemory(scriptBody string, shellBin string, workDir string, scriptArgs []string, stdout, stderr io.Writer) error {
	if strings.TrimSpace(shellBin) == "" {
		shellBin = defaultExecShellBin
	}

	execArgs := []string{"-s"}
	if len(scriptArgs) > 0 {
		execArgs = append(execArgs, "--")
		execArgs = append(execArgs, scriptArgs...)
	}

	// #nosec G204 G702
	cmd := exec.Command(shellBin, execArgs...)
	if strings.TrimSpace(workDir) != "" {
		cmd.Dir = expandTildeDir(workDir)
	}

	if !strings.HasSuffix(scriptBody, "\n") {
		scriptBody += "\n"
	}
	cmd.Stdin = strings.NewReader(scriptBody)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return cmd.Run()
}

func handleExec(profile string, args []string) {
	if len(args) == 0 {
		fail("INVALID_ARGUMENTS", fmt.Errorf("missing command name or subcommand"), "Usage: sec exec <name> [-- <args...>] | sec exec save <name> [--stdin] | sec exec show <name> | sec exec list | sec exec rm <name>")
	}

	switch args[0] {
	case "save", "set", "add":
		handleExecSave(profile, args[1:])
		return
	case "show", "cat", "get":
		handleExecShow(profile, args[1:])
		return
	case "list", "ls":
		handleExecList(profile, args[1:])
		return
	case "rm", "delete", "del":
		handleExecRemove(profile, args[1:])
		return
	}

	noTrace := true
	shellBin := defaultExecShellBin
	workDir := ""
	redactOutput := true
	autoExtend := false
	var targetName string
	var scriptArgs []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			scriptArgs = append(scriptArgs, args[i+1:]...)
			break
		}
		switch {
		case a == "--no-trace":
			noTrace = true
		case a == "--trace":
			noTrace = false
		case a == "--redact":
			redactOutput = true
		case a == "--no-redact":
			redactOutput = false
		case a == "--auto-extend":
			autoExtend = true
		case (a == "--shell" || a == "-s") && i+1 < len(args):
			shellBin = args[i+1]
			i++
		case strings.HasPrefix(a, "--shell="):
			shellBin = strings.TrimPrefix(a, "--shell=")
		case (a == "--dir" || a == "-C" || a == "--cwd") && i+1 < len(args):
			workDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--dir="):
			workDir = strings.TrimPrefix(a, "--dir=")
		case strings.HasPrefix(a, "-"):
			fail("INVALID_ARGUMENTS", fmt.Errorf("unknown flag %q for sec exec", a), "Usage: sec exec <name> [--no-trace] [--trace] [--shell <bin>] [--dir <path>] [--redact|--no-redact] [-- <args...>]")
		default:
			if targetName == "" {
				targetName = a
			} else {
				scriptArgs = append(scriptArgs, a)
			}
		}
	}

	if targetName == "" {
		fail("INVALID_ARGUMENTS", fmt.Errorf("missing command name to execute"), "Usage: sec exec <name> [-- <args...>]")
	}

	checkProductionGuard(store.ProfileName(profile), args)
	checkAndAutoExtendSession(profile, autoExtend)

	scriptBody, _, err := resolveExecScript(profile, targetName, noTrace)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			fail("SECRET_NOT_FOUND", err, fmt.Sprintf("Store a command script first with: sec exec save %s --stdin", targetName))
		}
		if errors.Is(err, store.ErrVaultLocked) {
			code, rem := mapDaemonError(err.Error())
			fail(code, err, rem)
		}
		failDaemonNotRunning(profile)
	}

	expandedScript, inlineSecrets, err := expandInlineScriptSecrets(profile, scriptBody, noTrace)
	if err != nil {
		fail("EXEC_TEMPLATE_EXPANSION_FAILED", err, "Ensure referenced secrets and profiles exist and are unlocked.")
	}

	var outWriter io.Writer = os.Stdout
	var errWriter io.Writer = os.Stderr
	var stdoutRedact, stderrRedact *redactWriter

	if redactOutput {
		secretVals := collectRedactionSecrets(profile, noTrace)
		secretVals = append(secretVals, inlineSecrets...)
		if len(secretVals) > 0 {
			stdoutRedact = newRedactWriter(os.Stdout, secretVals)
			stderrRedact = newRedactWriter(os.Stderr, secretVals)
			outWriter = stdoutRedact
			errWriter = stderrRedact
		}
	}

	runErr := executeScriptInMemory(expandedScript, shellBin, workDir, scriptArgs, outWriter, errWriter)

	if stdoutRedact != nil {
		_ = stdoutRedact.Flush()
	}
	if stderrRedact != nil {
		_ = stderrRedact.Flush()
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fail("EXEC_FAILED", fmt.Errorf("failed executing stealth command %q: %w", targetName, runErr), "")
	}
}

func handleExecSave(profile string, args []string) {
	confirm := confirmProdFlag
	for _, a := range args {
		if a == "--confirm-prod" {
			confirm = true
		}
	}
	if err := validateProdMutationSafety(profile, true, confirm); err != nil {
		fail("PROD_MUTATION_CANCELLED", err, "")
	}

	var name string
	var cmdStr string
	var desc string
	useStdin := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--stdin":
			useStdin = true
		case (a == "--command" || a == "-c") && i+1 < len(args):
			cmdStr = args[i+1]
			i++
		case strings.HasPrefix(a, "--command="):
			cmdStr = strings.TrimPrefix(a, "--command=")
		case (a == "--description" || a == "--desc" || a == "-d") && i+1 < len(args):
			desc = args[i+1]
			i++
		case strings.HasPrefix(a, "--description="):
			desc = strings.TrimPrefix(a, "--description=")
		case strings.HasPrefix(a, "--desc="):
			desc = strings.TrimPrefix(a, "--desc=")
		case a == "--confirm-prod":
			// handled above
		case !strings.HasPrefix(a, "-") && name == "":
			name = a
		}
	}

	if name == "" {
		fail("INVALID_ARGUMENTS", fmt.Errorf("missing command name for 'sec exec save'"), "Usage: sec exec save <name> [--stdin] [--command <cmd>] [--description <desc>]")
	}

	if cmdStr == "" && (useStdin || !term.IsTerminal(int(os.Stdin.Fd()))) {
		data, err := readStdinSecretValue(name)
		if err != nil {
			fail("STDIN_READ_ERROR", fmt.Errorf("failed to read command script from stdin: %w", err), "")
		}
		cmdStr = strings.TrimRight(string(data), "\r\n")
	} else if cmdStr == "" {
		data, err := readStdinSecretValue(name)
		if err != nil {
			fail("STDIN_READ_ERROR", fmt.Errorf("failed to read command script from stdin: %w", err), "")
		}
		cmdStr = strings.TrimRight(string(data), "\r\n")
	}

	vaultKey, err := saveExecScript(profile, name, cmdStr, desc)
	if err != nil {
		if strings.Contains(err.Error(), "empty") {
			fail("INVALID_ARGUMENTS", err, "Provide a non-empty command via --stdin or --command.")
		}
		code, rem := mapDaemonError(err.Error())
		if code != "OPERATION_FAILED" {
			fail(code, err, rem)
		}
		failDaemonNotRunning(profile)
	}

	fmt.Printf("[✓] Stored stealth command script at %s\n", vaultKey)
}

func handleExecShow(profile string, args []string) {
	noTrace := true
	var name string
	for _, a := range args {
		if a == "--no-trace" {
			noTrace = true
		} else if a == "--trace" {
			noTrace = false
		} else if !strings.HasPrefix(a, "-") && name == "" {
			name = a
		}
	}

	if name == "" {
		fail("INVALID_ARGUMENTS", fmt.Errorf("missing command name for 'sec exec show'"), "Usage: sec exec show <name> [--no-trace]")
	}

	val, _, err := resolveExecScript(profile, name, noTrace)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			fail("SECRET_NOT_FOUND", err, "Run 'sec exec list' to see stored command scripts.")
		}
		if errors.Is(err, store.ErrVaultLocked) {
			code, rem := mapDaemonError(err.Error())
			fail(code, err, rem)
		}
		failDaemonNotRunning(profile)
	}

	if strings.HasSuffix(val, "\n") {
		fmt.Print(val)
	} else {
		fmt.Println(val)
	}
}

func handleExecList(profile string, args []string) {
	showJSON := false
	for _, a := range args {
		if a == "--json" {
			showJSON = true
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: daemon.IPCActionList,
		Path:   "",
	})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	type execListItem struct {
		Name        string `json:"name"`
		VaultKey    string `json:"vault_key"`
		Description string `json:"description,omitempty"`
	}

	var items []execListItem
	for k, entry := range resp.Secrets {
		isCmd := strings.HasPrefix(k, execVaultPrefix) || (entry.Metadata != nil && entry.Metadata["secret_type"] == secretTypeCmdScript)
		if !isCmd {
			continue
		}
		shortName := strings.TrimPrefix(k, execVaultPrefix)
		desc := entry.Description
		if desc == "" {
			desc = entry.Comment
		}
		items = append(items, execListItem{
			Name:        shortName,
			VaultKey:    k,
			Description: desc,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].VaultKey < items[j].VaultKey
	})

	if showJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(items)
		return
	}

	if len(items) == 0 {
		fmt.Println("No stealth command scripts found in vault.")
		return
	}

	fmt.Printf("%-24s %-32s %s\n", "NAME", "VAULT KEY", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 76))
	for _, item := range items {
		desc := item.Description
		if desc == "" {
			desc = "-"
		}
		fmt.Printf("%-24s %-32s %s\n", item.Name, item.VaultKey, desc)
	}
}

func handleExecRemove(profile string, args []string) {
	confirm := confirmProdFlag
	permanent := false
	var name string
	for _, a := range args {
		if a == "--confirm-prod" {
			confirm = true
		} else if a == "--permanent" {
			permanent = true
		} else if !strings.HasPrefix(a, "-") && name == "" {
			name = a
		}
	}
	if err := validateProdMutationSafety(profile, true, confirm); err != nil {
		fail("PROD_MUTATION_CANCELLED", err, "")
	}
	if name == "" {
		fail("INVALID_ARGUMENTS", fmt.Errorf("missing command name for 'sec exec rm'"), "Usage: sec exec rm <name> [--permanent]")
	}

	candidates := candidateExecVaultKeys(name)
	for _, key := range candidates {
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action:    daemon.IPCActionDelete,
			Path:      key.String(),
			Permanent: permanent,
		})
		if err != nil {
			failDaemonNotRunning(profile)
		}
		if resp.Success {
			fmt.Printf("[✓] Deleted stealth command script %s\n", key)
			return
		}
	}

	fail("SECRET_NOT_FOUND", fmt.Errorf("%w: stealth command %q not found", store.ErrSecretNotFound, name), "")
}
