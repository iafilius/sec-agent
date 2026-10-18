package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"secure_secrets/internal/daemon"
)

// isHexChar checks if byte is a valid hexadecimal character.
func isHexChar(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// isPureHex reports whether a string consists entirely of hexadecimal characters.
func isPureHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexChar(s[i]) {
			return false
		}
	}
	return true
}

// isHexCollisionAt checks if an occurrence of a hex secret at idx is part of a longer hex string (e.g. Git commit SHA or SHA-256).
func isHexCollisionAt(s string, idx int, subLen int) bool {
	if idx > 0 && isHexChar(s[idx-1]) {
		return true
	}
	end := idx + subLen
	if end < len(s) && isHexChar(s[end]) {
		return true
	}
	return false
}

// containsSecretValue checks if line contains secret, suppressing false-positive collisions with longer hex hashes.
func containsSecretValue(line, secret string) bool {
	if !strings.Contains(line, secret) {
		return false
	}
	if !isPureHex(secret) {
		return true
	}
	pos := 0
	for {
		idx := strings.Index(line[pos:], secret)
		if idx == -1 {
			break
		}
		actualIdx := pos + idx
		if !isHexCollisionAt(line, actualIdx, len(secret)) {
			return true
		}
		pos = actualIdx + 1
	}
	return false
}

// replaceSecretMatches replaces occurrences of secret in line, suppressing false-positive collisions with longer hex hashes.
func replaceSecretMatches(line, secret, replacement string) string {
	if !strings.Contains(line, secret) {
		return line
	}
	if !isPureHex(secret) {
		return strings.ReplaceAll(line, secret, replacement)
	}

	var sb strings.Builder
	pos := 0
	for {
		idx := strings.Index(line[pos:], secret)
		if idx == -1 {
			sb.WriteString(line[pos:])
			break
		}
		actualIdx := pos + idx
		if isHexCollisionAt(line, actualIdx, len(secret)) {
			// Substring of a longer hex digest - retain unchanged
			sb.WriteString(line[pos : actualIdx+len(secret)])
			pos = actualIdx + len(secret)
		} else {
			// Standalone secret match - redact
			sb.WriteString(line[pos:actualIdx])
			sb.WriteString(replacement)
			pos = actualIdx + len(secret)
		}
	}
	return sb.String()
}

// expandDerivedSecrets expands raw secrets into exact, Base64-encoded, and URL-encoded forms.
func expandDerivedSecrets(rawSecrets map[string]string) map[string]string {
	expanded := make(map[string]string)
	for name, val := range rawSecrets {
		trimmed := strings.TrimSpace(val)
		if len(trimmed) < 4 {
			continue
		}
		expanded[trimmed] = name

		// Standard Base64
		b64 := base64.StdEncoding.EncodeToString([]byte(trimmed))
		if len(b64) >= 6 && b64 != trimmed {
			expanded[b64] = name + " (base64)"
		}

		// URL Query Escaped
		qEsc := url.QueryEscape(trimmed)
		if len(qEsc) >= 6 && qEsc != trimmed {
			expanded[qEsc] = name + " (url-encoded)"
		}

		// URL Path Escaped
		pEsc := url.PathEscape(trimmed)
		if len(pEsc) >= 6 && pEsc != trimmed && pEsc != qEsc {
			expanded[pEsc] = name + " (url-encoded)"
		}
	}
	return expanded
}

// expandDerivedSecretList expands secret strings into exact, Base64-encoded, and URL-encoded forms for stream writers.
func expandDerivedSecretList(secrets []string) []string {
	var expanded []string
	seen := make(map[string]bool)
	add := func(s string) {
		trimmed := strings.TrimSpace(s)
		if len(trimmed) >= 4 && !seen[trimmed] {
			seen[trimmed] = true
			expanded = append(expanded, trimmed)
		}
	}

	for _, s := range secrets {
		trimmed := strings.TrimSpace(s)
		if len(trimmed) < 4 {
			continue
		}
		add(trimmed)

		b64 := base64.StdEncoding.EncodeToString([]byte(trimmed))
		if len(b64) >= 6 {
			add(b64)
		}

		qEsc := url.QueryEscape(trimmed)
		if len(qEsc) >= 6 {
			add(qEsc)
		}

		pEsc := url.PathEscape(trimmed)
		if len(pEsc) >= 6 {
			add(pEsc)
		}
	}
	return expanded
}

func handleRedact(profile string, args []string) {
	// Fetch active profile secrets for redaction scanning
	rawMap := make(map[string]string)
	req := daemon.IPCRequest{Action: "backup"}
	if resp, err := queryDaemon(profile, req); err == nil && resp != nil && resp.Success && resp.Secrets != nil {
		for k, entry := range resp.Secrets {
			val := strings.TrimSpace(entry.Value)
			if len(val) >= 4 {
				rawMap[k] = val
			}
		}
	}

	secretMap := expandDerivedSecrets(rawMap)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		for val, name := range secretMap {
			line = replaceSecretMatches(line, val, fmt.Sprintf("[REDACTED_SEC_SECRET:%s]", name))
		}
		fmt.Println(line)
	}
}

func handleEnvFile(profile string, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sec-agent env-file [--profile <name>] -- <command> [args...]")
		os.Exit(1)
	}

	cmdArgs := args
	if args[0] == "--" {
		cmdArgs = args[1:]
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No target command specified for env-file.")
		os.Exit(1)
	}

	// Fetch secrets from daemon
	req := daemon.IPCRequest{Action: "backup"}
	resp, err := queryDaemon(profile, req)
	if err != nil || resp == nil || !resp.Success {
		fmt.Fprintf(os.Stderr, "Error: Failed to fetch secrets for profile %q: %v\n", profile, err)
		os.Exit(1)
	}

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	randSuffix := hex.EncodeToString(b)
	tempEnvPath := filepath.Join(os.TempDir(), fmt.Sprintf(".env.tmp.%s", randSuffix))

	var envLines []string
	if resp.Secrets != nil {
		for k, entry := range resp.Secrets {
			envKey := strings.ToUpper(strings.ReplaceAll(filepath.Base(k), "-", "_"))
			envLines = append(envLines, fmt.Sprintf("%s=%s", envKey, entry.Value))
		}
	}

	envContent := strings.Join(envLines, "\n") + "\n"
	// #nosec G306
	if err := os.WriteFile(tempEnvPath, []byte(envContent), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing temporary env file: %v\n", err)
		os.Exit(1)
	}

	// Shred and remove temp file on exit or signal
	shredTempFile := func() {
		// #nosec G304
		if data, err := os.ReadFile(tempEnvPath); err == nil {
			zeroes := make([]byte, len(data))
			_ = os.WriteFile(tempEnvPath, zeroes, 0600)
		}
		_ = os.Remove(tempEnvPath)
	}
	defer shredTempFile()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigChan
		shredTempFile()
		os.Exit(1)
	}()

	envMap := make(map[string]string)
	for _, env := range os.Environ() {
		pair := splitEnvPair(env)
		if pair.Key != "" {
			envMap[pair.Key] = pair.Value
		}
	}
	envMap["ENV_FILE"] = tempEnvPath
	envMap["DOTENV_PATH"] = tempEnvPath

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

func handleClipboardWipe(args []string) {
	ttl := 15 * time.Second
	for i := 0; i < len(args); i++ {
		if (args[i] == "--ttl" || args[i] == "-t") && i+1 < len(args) {
			if d, err := time.ParseDuration(args[i+1]); err == nil {
				ttl = d
			}
		}
	}

	time.Sleep(ttl)

	// Wipe clipboard
	clearAppleScript := `
use framework "Foundation"
use framework "AppKit"
set pb to current application's NSPasteboard's generalPasteboard()
pb's clearContents()
`
	// #nosec G204
	_ = exec.Command("osascript", "-e", clearAppleScript).Run()
}

func copyConcealedToClipboard(val string) error {
	script := fmt.Sprintf(`
use framework "Foundation"
use framework "AppKit"
set pb to current application's NSPasteboard's generalPasteboard()
pb's clearContents()
pb's setString:%q forType:(current application's NSPasteboardTypeString)
pb's setString:"" forType:"org.nspasteboard.ConcealedType"
pb's setString:"" forType:"org.nspasteboard.AutoGeneratedType"
`, val)

	// #nosec G204
	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		// Fallback to pbcopy
		pbCmd := exec.Command("pbcopy")
		pbCmd.Stdin = strings.NewReader(val)
		_ = pbCmd.Run()
	}

	// Spawn background 15s clipboard wipe timer
	binPath, err := os.Executable()
	if err != nil {
		binPath = "sec-agent"
	}
	// #nosec G204
	wipeCmd := exec.Command(binPath, "clipboard-wipe", "--ttl", "15s")
	wipeCmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	_ = wipeCmd.Start()

	return nil
}
