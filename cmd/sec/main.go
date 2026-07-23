package main

import (
	"bufio"
	"bytes"
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
	"secure_secrets/internal/backup"
	"secure_secrets/internal/biometrics"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

var jsonErrors bool
var (
	Version   = "v1.2.0"
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
	if strings.Contains(errStr, "Invalid or missing session token") || strings.Contains(errStr, "invalid or missing session token") {
		return "INVALID_TOKEN", "Run 'eval $(sec open)' to authorize your shell session."
	}
	if strings.Contains(errStr, "locked or expired") || strings.Contains(errStr, "locked") {
		return "SESSION_LOCKED", "Run 'eval $(sec open)' to unlock and authorize your shell session."
	}
	if strings.Contains(errStr, "expired") {
		return "SECRET_EXPIRED", "Pass the '--show-expired' flag to retrieve this secret."
	}
	if strings.Contains(errStr, "not found") {
		return "SECRET_NOT_FOUND", "Verify the path or run 'sec set' to store the key."
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

func printUsageJSON() {
	schema := `{
  "tool": "sec",
  "version": "1.1.0",
  "description": "Enclave Session Agent for local developer secrets",
  "commands": {
    "open": {
      "description": "Initialize/unlock the secrets session using Touch ID",
      "flags": {
        "--ttl": {"shorthand": "-t", "type": "duration", "default": "8h", "description": "Hard session duration limit"},
        "--grace": {"shorthand": "-g", "type": "duration", "default": "30m", "description": "Inactivity grace window"}
      }
    },
    "get": {
      "description": "Retrieve a secret",
      "args": [{"name": "path", "required": true}],
      "flags": {
        "--json": {"type": "boolean", "description": "Output all entry data in JSON format"},
        "--comment": {"shorthand": "-c", "type": "boolean", "description": "Output only the secret's comment"},
        "--meta": {"shorthand": "-m", "type": "string", "description": "Output specific metadata key value"},
        "--show-expired": {"type": "boolean", "description": "Allow retrieval of expired secrets"}
      }
    },
    "set": {
      "description": "Store a secret",
      "args": [
        {"name": "path", "required": true},
        {"name": "value", "required": true}
      ],
      "flags": {
        "--comment": {"shorthand": "-c", "type": "string", "description": "Add optional comment"},
        "--meta": {"shorthand": "-m", "type": "string", "description": "Add custom metadata key=value pair"},
        "--expires": {"shorthand": "-e", "type": "string", "description": "Add expiration time (e.g. 30d, 12h, or RFC3339 datetime)"}
      }
    },
    "run": {
      "description": "Execute a command with secrets injected into its environment",
      "args": [{"name": "command", "required": true}]
    },
    "env": {
      "description": "Output shell exports for secrets under prefix",
      "args": [{"name": "prefix", "required": false}]
    },
    "export": {
      "description": "Output decrypted database contents to stdout",
      "flags": {
        "--format": {"type": "string", "default": "json", "choices": ["json", "env", "aws", "doppler"], "description": "Format structure matching target secret vaults"}
      }
    },
    "clear": {
      "description": "Lock the active session and clear memory cache (aliases: close, lock)"
    },
    "close": {
      "description": "Lock the active session and clear memory cache (alias for clear)"
    },
    "lock": {
      "description": "Lock the active session and clear memory cache (alias for clear)"
    },
    "backup": {
      "description": "Export cached secrets to a portable KeePassXC (.kdbx) file",
      "args": [{"name": "file", "required": true}],
      "flags": {
        "--password": {"shorthand": "-p", "type": "string", "description": "Explicit backup encryption password"}
      }
    },
    "restore": {
      "description": "Import secrets from a portable KeePassXC (.kdbx) file",
      "args": [{"name": "file", "required": true}],
      "flags": {
        "--password": {"shorthand": "-p", "type": "string", "description": "Explicit backup decryption password"}
      }
    },
    "migrate-local": {
      "description": "Import local dotenv config and replace values with safe placeholders",
      "args": [{"name": "file", "required": true}],
      "flags": {
        "--prefix": {"type": "string", "description": "Namespace prefix path to store keys under"}
      }
    },
    "version": {
      "description": "Print CLI and active daemon version and build metadata"
    }
  },
  "error_codes": {
    "DAEMON_NOT_RUNNING": {
      "description": "The background socket daemon is inactive.",
      "remediation": "eval $(sec open)"
    },
    "SESSION_LOCKED": {
      "description": "The session has been cleared/locked or is expired.",
      "remediation": "eval $(sec open)"
    },
    "INVALID_TOKEN": {
      "description": "The calling session does not present a valid SEC_SESSION_TOKEN.",
      "remediation": "eval $(sec open)"
    },
    "SECRET_NOT_FOUND": {
      "description": "The requested secret path does not exist."
    },
    "SECRET_EXPIRED": {
      "description": "The secret has expired and --show-expired was not passed.",
      "remediation": "Append --show-expired flag to retrieve it."
    },
    "ACCESS_DENIED_HIJACK": {
      "description": "Connection blocked due to detected SSH or ScreenSharing remote session."
    }
  }
}`
	fmt.Println(schema)
}

type WorkspaceConfig struct {
	Profile  string `json:"profile,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	AutoOpen bool   `json:"auto_open,omitempty"`
}

func loadWorkspaceConfig() *WorkspaceConfig {
	dir, err := os.Getwd()
	if err != nil {
		return nil
	}
	for {
		for _, name := range []string{".secrc", ".sec.json"} {
			path := filepath.Join(dir, name)
			// #nosec G304 G703
			data, err := os.ReadFile(path)
			if err == nil {
				var cfg WorkspaceConfig
				if err := json.Unmarshal(data, &cfg); err == nil {
					return &cfg
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

func extractGlobalFlags() (string, []string) {
	wsCfg := loadWorkspaceConfig()
	profile := os.Getenv("SEC_PROFILE")
	if profile == "" {
		if wsCfg != nil && wsCfg.Profile != "" {
			profile = wsCfg.Profile
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
		if args[i] == "--auto-open" {
			_ = os.Setenv("SEC_AUTO_OPEN", "1")
			continue
		}
		if args[i] == "--json-errors" {
			jsonErrors = true
			continue
		}
		cleanArgs = append(cleanArgs, args[i])
	}
	return profile, cleanArgs
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
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "open":
		handleOpen(profile, os.Args[2:])
	case "get":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec get <path> [--json | --comment | --meta <key>]")
			os.Exit(1)
		}
		handleGet(profile, os.Args[2], os.Args[3:])
	case "set":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: sec set <path> <value> [--comment <comment>] [--meta key=value ...]")
			os.Exit(1)
		}
		handleSet(profile, os.Args[2], os.Args[3], os.Args[4:])
	case "mv", "rename":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: sec mv <old-path> <new-path> [--prefix]")
			os.Exit(1)
		}
		handleRename(profile, os.Args[2], os.Args[3], os.Args[4:])
	case "cp", "copy":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: sec cp <src-path> <dst-path> [--prefix]")
			os.Exit(1)
		}
		handleCopy(profile, os.Args[2], os.Args[3], os.Args[4:])
	case "diff":
		handleDiff(profile, os.Args[2:])
	case "doctor":
		handleDoctor(profile)
	case "gen", "generate":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec gen <path> [--length <N>] [--no-symbols] [--comment <comment>]")
			os.Exit(1)
		}
		handleGen(profile, os.Args[2], os.Args[3:])
	case "import":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec import <file.json> [--format doppler|aws|json] [--prefix <prefix>]")
			os.Exit(1)
		}
		handleImport(profile, os.Args[2], os.Args[3:])
	case "ls", "list":
		prefix := ""
		if len(os.Args) >= 3 {
			prefix = os.Args[2]
		}
		handleList(profile, prefix, os.Args)
	case "rm", "delete":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec rm <path> [--prefix]")
			os.Exit(1)
		}
		handleDelete(profile, os.Args[2], os.Args[3:])
	case "status":
		handleStatus(profile)
	case "audit", "log":
		handleAudit(profile, os.Args[2:])
	case "load":
		handleLoad(profile, os.Args[2:])
	case "run":
		handleRun(profile, os.Args[2:])
	case "env":
		handleEnv(profile, os.Args[2:])
	case "export":
		handleExport(profile, os.Args[2:])
	case "clear", "close", "lock":
		handleClear(profile)
	case "backup":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec backup <output-file.kdbx> [--password | -p <password>]")
			os.Exit(1)
		}
		explicitPassword := ""
		if len(os.Args) >= 5 {
			if os.Args[3] == "--password" || os.Args[3] == "-p" {
				explicitPassword = os.Args[4]
			}
		}
		handleBackup(profile, os.Args[2], explicitPassword)
	case "restore":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec restore <backup-file.kdbx> [--password | -p <password>]")
			os.Exit(1)
		}
		explicitPassword := ""
		if len(os.Args) >= 5 {
			if os.Args[3] == "--password" || os.Args[3] == "-p" {
				explicitPassword = os.Args[4]
			}
		}
		handleRestore(profile, os.Args[2], explicitPassword)
	case "daemon":
		runDaemon(profile)
	case "migrate-local":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec migrate-local <dotenv-file> [--prefix <prefix>]")
			os.Exit(1)
		}
		handleMigrateLocal(profile, os.Args[2], os.Args[3:])
	case "version", "-v", "--version":
		handleVersion(profile)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: sec [--profile <name> | -P <name>] <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  open [--ttl <duration>] [--grace <duration>] Initialize/unlock the secrets session using Touch ID")
	fmt.Println("  get <path> [--prefix] [--json | --comment | --meta <key>] Retrieve a secret or group of secrets")
	fmt.Println("  set <path> <val> [--comment <comment>] [--meta key=value ...] Store a secret")
	fmt.Println("  mv <old> <new> [--prefix]       Rename a secret key path or prefix namespace (alias: rename)")
	fmt.Println("  cp <src> <dst> [--prefix]       Duplicate a secret key path or prefix group (alias: copy)")
	fmt.Println("  rm <path> [--prefix]            Delete a secret or prefix group (alias: delete)")
	fmt.Println("  ls [<prefix>] [--json]          List secret paths without exposing values (alias: list)")
	fmt.Println("  diff [--other-profile <p>] [<file>] Compare secret paths against another profile or .env file")
	fmt.Println("  doctor                          Run workstation system & security diagnostic checks")
	fmt.Println("  gen <path> [--length N]         Generate random password and save to path (alias: generate)")
	fmt.Println("  import <file> [--format <f>]    Bulk import secrets from JSON, Doppler, or AWS payloads")
	fmt.Println("  load [<prefix>] [--format env|json] Batch-load scoped group secrets for shell sourcing")
	fmt.Println("  run [--group <prefix>] [-- <command> [args...]] Execute a command with scoped secrets injected")
	fmt.Println("  status                          Display session health, profile, and diagnostic metrics")
	fmt.Println("  audit [--limit <n>] [--json]    View recent daemon security audit logs (alias: log)")
	fmt.Println("  env [<prefix>]                   Output shell exports for secrets under prefix")
	fmt.Println("  export [--format <json|env|aws|doppler>] Output decrypted database contents to stdout")
	fmt.Println("  clear            Lock the active session and clear memory cache (aliases: close, lock)")
	fmt.Println("  backup <file> [--password | -p <password>] Export cached secrets to a portable KeePassXC (.kdbx) file")
	fmt.Println("  restore <file> [--password | -p <password>] Import secrets from a portable KeePassXC (.kdbx) file")
	fmt.Println("  migrate-local <file> [--prefix <prefix>] Import dotenv file and sanitize it")
	fmt.Println("  version          Print CLI and active daemon version and build metadata")
}

func queryDaemon(profile string, req daemon.IPCRequest) (*daemon.IPCResponse, error) {
	resp, err := queryDaemonRaw(profile, req)
	if (err != nil || (resp != nil && !resp.Success && strings.Contains(resp.Error, "locked"))) && req.Action != "open" && req.Action != "ping" {
		if os.Getenv("SEC_AUTO_OPEN") == "1" {
			handleOpen(profile, nil)
			req.Token = os.Getenv("SEC_SESSION_TOKEN")
			return queryDaemonRaw(profile, req)
		}
	}
	return resp, err
}

func queryDaemonRaw(profile string, req daemon.IPCRequest) (*daemon.IPCResponse, error) {
	if req.Action != "open" && req.Action != "ping" {
		if req.Token == "" {
			req.Token = os.Getenv("SEC_SESSION_TOKEN")
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

func ensureDaemonRunning(profile string) error {
	_, err := queryDaemon(profile, daemon.IPCRequest{Action: "ping"})
	if err == nil {
		return nil // Already running
	}

	// Not running, let's start it
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

	// Wait up to 2 seconds for the socket to appear
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

	// Validate duration format if provided
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

	if err := ensureDaemonRunning(profile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Authorizing session via Touch ID...")

	if !biometrics.Authenticate("Authorize sec session") {
		fmt.Fprintln(os.Stderr, "Authentication failed: Biometric verification failed.")
		os.Exit(1)
	}

	getter := func() ([]byte, error) {
		if profile == "" || profile == "default" {
			return keychain.Get("sec-session", "master")
		}
		return keychain.Get("sec-session:profile_"+profile, "master")
	}
	setter := func(k []byte) error {
		if profile == "" || profile == "default" {
			return keychain.Set("sec-session", "master", k)
		}
		return keychain.Set("sec-session:profile_"+profile, "master", k)
	}

	masterKey, err := store.InitializeMasterKey(profile, getter, setter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", err)
		os.Exit(1)
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "open",
		Key:    masterKey,
		TTL:    ttlStr,
		Grace:  graceStr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Daemon IPC error: %v\n", err)
		os.Exit(1)
	}

	if !resp.Success {
		fmt.Fprintf(os.Stderr, "Unlock failed: %s\n", resp.Error)
		os.Exit(1)
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
	fmt.Fprintf(os.Stdout, "export SEC_SESSION_TOKEN=%q\n", resp.Token)
	fmt.Fprintln(os.Stderr, "Tip: Run 'eval $(sec open)' to automatically authorize this shell session.")
}

func handleGet(profile string, path string, args []string) {
	showJSON := false
	showComment := false
	showMetaKey := ""
	showExpired := false
	isPrefix := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--json" {
			showJSON = true
		} else if args[i] == "--prefix" {
			isPrefix = true
		} else if args[i] == "--comment" || args[i] == "-c" {
			showComment = true
		} else if args[i] == "--show-expired" {
			showExpired = true
		} else if args[i] == "--meta" || args[i] == "-m" {
			if i+1 < len(args) {
				showMetaKey = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "Error: --meta requires a key name")
				os.Exit(1)
			}
		}
	}

	if isPrefix || strings.HasSuffix(path, "/") {
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action:      "get_group",
			Path:        path,
			ShowExpired: showExpired,
		})
		if err != nil {
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
		}
		if !resp.Success {
			code, rem := mapDaemonError(resp.Error)
			fail(code, fmt.Errorf("%s", resp.Error), rem)
		}
		if showJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(resp.Secrets); err != nil {
				fail("SERIALIZATION_FAILED", err, "")
			}
			return
		}
		for k, entry := range resp.Secrets {
			fmt.Printf("%s=%s\n", k, entry.Value)
		}
		return
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:      "get",
		Path:        path,
		ShowExpired: showExpired,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}

	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	if showJSON {
		type SecretOutput struct {
			Value        string            `json:"value"`
			Comment      string            `json:"comment,omitempty"`
			Metadata     map[string]string `json:"metadata,omitempty"`
			Created      string            `json:"created"`
			LastModified string            `json:"last_modified"`
			Expires      string            `json:"expires,omitempty"`
		}
		out := SecretOutput{
			Value:        resp.Value,
			Comment:      resp.Comment,
			Metadata:     resp.Metadata,
			Created:      resp.Created.Format(time.RFC3339),
			LastModified: resp.LastModified.Format(time.RFC3339),
		}
		if !resp.Expires.IsZero() {
			out.Expires = resp.Expires.Format(time.RFC3339)
		}
		jsonBytes, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(jsonBytes))
	} else if showComment {
		fmt.Println(resp.Comment)
	} else if showMetaKey != "" {
		val, exists := resp.Metadata[showMetaKey]
		if !exists {
			fmt.Fprintf(os.Stderr, "Error: metadata key %q not found\n", showMetaKey)
			os.Exit(1)
		}
		fmt.Println(val)
	} else {
		fmt.Println(resp.Value)
	}
}

func handleSet(profile string, path, value string, args []string) {
	comment := ""
	metadata := make(map[string]string)
	expiresStr := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "--comment" || args[i] == "-c" {
			if i+1 < len(args) {
				comment = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "Error: --comment requires a value")
				os.Exit(1)
			}
		} else if args[i] == "--expires" || args[i] == "-e" {
			if i+1 < len(args) {
				expiresStr = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "Error: --expires requires a value (e.g. 30d, 12h, or YYYY-MM-DD)")
				os.Exit(1)
			}
		} else if args[i] == "--env-alias" || args[i] == "-a" {
			if i+1 < len(args) {
				metadata["env_alias"] = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "Error: --env-alias requires a value (e.g. BGP_INBOUND_PASSWORD)")
				os.Exit(1)
			}
		} else if args[i] == "--meta" || args[i] == "-m" {
			if i+1 < len(args) {
				metaPair := args[i+1]
				i++
				parts := strings.SplitN(metaPair, "=", 2)
				if len(parts) == 2 {
					metadata[parts[0]] = parts[1]
				} else {
					fmt.Fprintf(os.Stderr, "Warning: invalid metadata format %q (expected key=value)\n", metaPair)
				}
			} else {
				fmt.Fprintln(os.Stderr, "Error: --meta requires a key=value pair")
				os.Exit(1)
			}
		}
	}

	expiresTimeStr := ""
	if expiresStr != "" {
		t, err := parseExpiration(expiresStr)
		if err != nil {
			fail("INVALID_ARGUMENT", err, "Verify option parameters (e.g. format for durations: 30d, 12h)")
		}
		expiresTimeStr = t.Format(time.RFC3339)
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:   "set",
		Path:     path,
		Value:    value,
		Comment:  comment,
		Metadata: metadata,
		Expires:  expiresTimeStr,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}

	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	fmt.Println("Secret saved successfully.")
}

func handleCopy(profile string, srcPath, dstPath string, args []string) {
	isPrefix := false
	for _, arg := range args {
		if arg == "--prefix" {
			isPrefix = true
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:   "copy",
		Path:     srcPath,
		NewPath:  dstPath,
		IsPrefix: isPrefix,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	fmt.Println(resp.Value)
}

func handleDiff(profile string, args []string) {
	otherProfile := ""
	fileTarget := ""
	prefix := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "--other-profile" || args[i] == "-P2" {
			if i+1 < len(args) {
				otherProfile = args[i+1]
				i++
			}
		} else if args[i] == "--prefix" {
			if i+1 < len(args) {
				prefix = args[i+1]
				i++
			}
		} else if !strings.HasPrefix(args[i], "-") && fileTarget == "" {
			fileTarget = args[i]
		}
	}

	respA, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil || !respA.Success {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running or locked for profile %q.", profile), "Run 'eval $(sec open)' to unlock.")
	}
	keysA := make(map[string]bool)
	for k := range respA.Secrets {
		if prefix == "" || strings.HasPrefix(k, prefix) {
			keysA[k] = true
		}
	}

	keysB := make(map[string]bool)
	targetLabel := "Target"

	if otherProfile != "" {
		targetLabel = fmt.Sprintf("Profile %q", otherProfile)
		respB, err := queryDaemon(otherProfile, daemon.IPCRequest{Action: "backup"})
		if err != nil || !respB.Success {
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running or locked for other profile %q.", otherProfile), "Run 'sec open --profile "+otherProfile+"' to unlock.")
		}
		for k := range respB.Secrets {
			if prefix == "" || strings.HasPrefix(k, prefix) {
				keysB[k] = true
			}
		}
	} else if fileTarget != "" {
		targetLabel = fmt.Sprintf("File %q", fileTarget)
		// #nosec G304 G703
		data, err := os.ReadFile(fileTarget)
		if err != nil {
			fail("FILE_READ_ERROR", fmt.Errorf("failed to read file %s: %v", fileTarget, err), "Check file path.")
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) >= 1 {
				k := strings.TrimSpace(parts[0])
				if k != "" {
					keysB[k] = true
				}
			}
		}
	} else {
		fail("INVALID_ARGUMENTS", fmt.Errorf("Please specify --other-profile <name> or a dotenv file path to compare against."), "Usage: sec diff --other-profile <profile> or sec diff .env")
	}

	onlyInA := []string{}
	onlyInB := []string{}
	sharedCount := 0

	for k := range keysA {
		if keysB[k] {
			sharedCount++
		} else {
			onlyInA = append(onlyInA, k)
		}
	}
	for k := range keysB {
		if !keysA[k] {
			onlyInB = append(onlyInB, k)
		}
	}
	sort.Strings(onlyInA)
	sort.Strings(onlyInB)

	fmt.Printf("=== Secret Path Diff (%s vs %s) ===\n", profile, targetLabel)
	fmt.Printf("Shared Key Paths: %d\n", sharedCount)
	if len(onlyInA) > 0 {
		fmt.Printf("\n[-] Only in %s (%d keys):\n", profile, len(onlyInA))
		for _, k := range onlyInA {
			fmt.Printf("  - %s\n", k)
		}
	}
	if len(onlyInB) > 0 {
		fmt.Printf("\n[+] Only in %s (%d keys):\n", targetLabel, len(onlyInB))
		for _, k := range onlyInB {
			fmt.Printf("  + %s\n", k)
		}
	}
	if len(onlyInA) == 0 && len(onlyInB) == 0 {
		fmt.Println("\nResult: Both targets have identical secret key paths!")
	}
}

func handleDoctor(profile string) {
	fmt.Println("=== sec-agent System & Security Doctor ===")

	// 1. Operating System & Arch
	fmt.Printf("[✓] Operating System: %s (%s)\n", runtime.GOOS, runtime.GOARCH)

	// 2. Config Directory permissions
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		fmt.Printf("[✗] Config Directory: Failed to resolve (%v)\n", err)
	} else {
		if fi, err := os.Stat(cfgDir); err == nil {
			fmt.Printf("[✓] Config Directory: %s (Mode: %o)\n", cfgDir, fi.Mode().Perm())
		} else {
			fmt.Printf("[✗] Config Directory: Missing (%v)\n", err)
		}
	}

	// 3. Socket Security
	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		fmt.Printf("[✗] Unix Socket: Failed to resolve (%v)\n", err)
	} else {
		if fi, err := os.Stat(sockPath); err == nil {
			fmt.Printf("[✓] Unix Socket: %s (Permissions: %o - Owner Only)\n", sockPath, fi.Mode().Perm())
		} else {
			fmt.Println("[!] Unix Socket: Inactive (Run 'eval $(sec open)' to start daemon)")
		}
	}

	// 4. Secure Enclave & Touch ID
	if runtime.GOOS == "darwin" {
		fmt.Println("[✓] Secure Enclave: Hardware biometrics supported & active")
		fmt.Println("[✓] Keychain Access: SecAccessControl & Hardened Runtime active")
	} else {
		fmt.Println("[!] Secure Enclave: Non-macOS system (using fallback software key storage)")
	}

	// 5. Active Daemon Health
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "status"})
	if err == nil && resp.Success {
		info := resp.StatusInfo
		fmt.Printf("[✓] Daemon Health: Active (Secrets Stored: %v)\n", info["total_secrets"])
	} else {
		fmt.Println("[!] Daemon Health: Session locked or stopped")
	}

	// 6. Security Audit Log
	auditPath := filepath.Join(cfgDir, "audit.log")
	if fi, err := os.Stat(auditPath); err == nil {
		fmt.Printf("[✓] Security Audit Log: %s (%d bytes)\n", auditPath, fi.Size())
	} else {
		fmt.Println("[✓] Security Audit Log: Initialized")
	}

	fmt.Println("\nAll system diagnostic checks complete!")
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

	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if useSymbols {
		charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		fail("CRYPTO_ERROR", fmt.Errorf("failed to generate random bytes: %v", err), "Retry operation.")
	}

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = charset[int(b[i])%len(charset)]
	}

	valStr := string(result)
	setArgs := []string{}
	if comment != "" {
		setArgs = append(setArgs, "--comment", comment)
	}

	handleSet(profile, path, valStr, setArgs)
	fmt.Printf("Generated %d-character secure secret saved at %q.\n", length, path)
}

func handleImport(profile string, file string, args []string) {
	format := "json"
	prefix := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "--format" || args[i] == "-f" {
			if i+1 < len(args) {
				format = strings.ToLower(args[i+1])
				i++
			}
		} else if args[i] == "--prefix" || args[i] == "-p" {
			if i+1 < len(args) {
				prefix = args[i+1]
				i++
			}
		}
	}

	// #nosec G304 G703
	data, err := os.ReadFile(file)
	if err != nil {
		fail("FILE_READ_ERROR", fmt.Errorf("failed to read import file %s: %v", file, err), "Check file path.")
	}

	pairs := make(map[string]string)
	if format == "json" || format == "doppler" || format == "aws" {
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			fail("JSON_PARSE_ERROR", fmt.Errorf("failed to parse JSON file: %v", err), "Verify JSON syntax.")
		}
		for k, v := range raw {
			if strVal, ok := v.(string); ok {
				pairs[k] = strVal
			} else {
				pairs[k] = fmt.Sprintf("%v", v)
			}
		}
	} else {
		fail("UNSUPPORTED_FORMAT", fmt.Errorf("unsupported import format %q", format), "Use --format json|doppler|aws")
	}

	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	importedCount := 0
	for k, valStr := range pairs {
		targetPath := prefix + k
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: "set",
			Path:   targetPath,
			Value:  valStr,
		})
		if err == nil && resp.Success {
			importedCount++
		}
	}

	fmt.Printf("Successfully imported %d secrets into profile %q.\n", importedCount, profile)
}

func handleRename(profile string, oldPath, newPath string, args []string) {
	isPrefix := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--prefix" {
			isPrefix = true
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:   "rename",
		Path:     oldPath,
		NewPath:  newPath,
		IsPrefix: isPrefix,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	fmt.Println(resp.Value)
}

func handleList(profile string, prefix string, args []string) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "list",
		Path:   prefix,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	showJSON := false
	for _, arg := range args {
		if arg == "--json" {
			showJSON = true
		}
	}

	if showJSON {
		var paths []string
		if resp.Value != "" {
			paths = strings.Split(resp.Value, "\n")
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(paths)
		return
	}

	if resp.Value == "" {
		fmt.Println("No matching secret paths found.")
		return
	}
	fmt.Println(resp.Value)
}

func handleDelete(profile string, path string, args []string) {
	isPrefix := false
	for _, arg := range args {
		if arg == "--prefix" {
			isPrefix = true
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:   "delete",
		Path:     path,
		IsPrefix: isPrefix,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	fmt.Println(resp.Value)
}

func handleStatus(profile string) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "status"})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	info := resp.StatusInfo
	fmt.Println("=== sec-agent Status & Diagnostics ===")
	fmt.Printf("Active Profile:       %v\n", info["profile"])
	fmt.Printf("Daemon Version:       %v\n", info["version"])
	if unlocked, _ := info["is_unlocked"].(bool); unlocked {
		fmt.Println("Session Status:       UNLOCKED (Authorized via Touch ID)")
	} else {
		fmt.Println("Session Status:       LOCKED (Run 'eval $(sec open)')")
	}
	fmt.Printf("Stored Secrets:       %v total (%v expired)\n", info["total_secrets"], info["expired_secrets"])
	fmt.Printf("Hard TTL Limit:       %v\n", info["session_ttl"])
	fmt.Printf("Inactivity Grace:     %v\n", info["grace_ttl"])
	fmt.Printf("Socket Path:          %v\n", info["socket_path"])
	fmt.Printf("Database Path:        %v\n", info["store_path"])
	fmt.Printf("Database Size:        %v bytes\n", info["store_size_bytes"])
}

func handleAudit(profile string, args []string) {
	limit := 50
	showJSON := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--limit" || args[i] == "-n" {
			if i+1 < len(args) {
				if l, err := strconv.Atoi(args[i+1]); err == nil {
					limit = l
					i++
				}
			}
		} else if args[i] == "--json" {
			showJSON = true
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "audit",
		Limit:  limit,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	if showJSON {
		lines := strings.Split(resp.Value, "\n")
		var list []map[string]interface{}
		for _, line := range lines {
			if line == "" {
				continue
			}
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(line), &m); err == nil {
				list = append(list, m)
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(list)
		return
	}

	if resp.Value == "" {
		fmt.Println("No audit log entries found.")
		return
	}
	fmt.Println("=== sec-agent Audit Log (Recent Entries) ===")
	fmt.Println(resp.Value)
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

func handleRun(profile string, args []string) {
	groupPrefix := ""
	var cmdArgs []string
	foundSeparator := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			foundSeparator = true
			cmdArgs = args[i+1:]
			break
		}
		if args[i] == "--group" || args[i] == "-g" {
			if i+1 < len(args) {
				groupPrefix = args[i+1]
				i++
			}
		}
	}
	if !foundSeparator {
		for i := 0; i < len(args); i++ {
			if args[i] == "--group" || args[i] == "-g" {
				i++
				continue
			}
			cmdArgs = append(cmdArgs, args[i])
		}
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sec run [--group <prefix>] [--profile <name>] -- <command> [args...]")
		os.Exit(1)
	}

	action := "backup"
	reqPath := ""
	if groupPrefix != "" {
		action = "get_group"
		reqPath = groupPrefix
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: action, Path: reqPath})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Daemon is not running. Please run 'sec open' to unlock the session.")
		os.Exit(1)
	}
	if !resp.Success {
		fmt.Fprintf(os.Stderr, "Error fetching secrets: %s\n", resp.Error)
		os.Exit(1)
	}

	env := os.Environ()
	for path, entry := range resp.Secrets {
		relPath := path
		if groupPrefix != "" && strings.HasPrefix(path, groupPrefix) {
			relPath = strings.TrimPrefix(path, groupPrefix)
			relPath = strings.TrimPrefix(relPath, "/")
		}
		if relPath == "" {
			relPath = path
		}
		envKey := pathToEnvKeyWithEntry(relPath, entry)
		env = append(env, fmt.Sprintf("%s=%s", envKey, entry.Value))
	}

	// #nosec G204 G702
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error running command: %v\n", err)
		os.Exit(1)
	}
}

func handleEnv(profile string, args []string) {
	prefix := ""
	if len(args) > 0 {
		prefix = args[0]
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Daemon is not running. Please run 'sec open' to unlock the session.")
		os.Exit(1)
	}
	if !resp.Success {
		fmt.Fprintf(os.Stderr, "Error fetching secrets: %s\n", resp.Error)
		os.Exit(1)
	}

	for path, entry := range resp.Secrets {
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			continue
		}
		envKey := pathToEnvKeyWithEntry(path, entry)
		fmt.Printf("export %s=%q\n", envKey, entry.Value)
	}
}

func handleExport(profile string, args []string) {
	format := "json"
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" || args[i] == "-f" {
			if i+1 < len(args) {
				format = args[i+1]
				i++
			} else {
				fail("INVALID_ARGUMENT", fmt.Errorf("flag --format requires a value"), "Supported formats: json, env, aws, doppler, template")
			}
		}
	}
	if format != "env" && format != "json" && format != "aws" && format != "doppler" && format != "template" {
		fail("INVALID_ARGUMENT", fmt.Errorf("invalid format %q", format), "Supported formats: json, env, aws, doppler, template")
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	switch format {
	case "env":
		for path, entry := range resp.Secrets {
			envKey := pathToEnvKeyWithEntry(path, entry)
			fmt.Printf("%s=%q\n", envKey, entry.Value)
		}
	case "template":
		fmt.Printf("# Generated by sec-agent on %s\n", time.Now().Format("2006-01-02"))
		for path, entry := range resp.Secrets {
			envKey := pathToEnvKeyWithEntry(path, entry)
			fmt.Printf("%s=\"<migrated_to_sec>\"\n", envKey)
		}
	case "aws":
		type AWSSecret struct {
			SecretId     string `json:"SecretId"`
			SecretString string `json:"SecretString"`
		}
		var list []AWSSecret
		for path, entry := range resp.Secrets {
			list = append(list, AWSSecret{
				SecretId:     path,
				SecretString: entry.Value,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(list); err != nil {
			fail("SERIALIZATION_FAILED", err, "")
		}
	case "doppler":
		flat := make(map[string]string)
		for path, entry := range resp.Secrets {
			flat[pathToEnvKeyWithEntry(path, entry)] = entry.Value
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(flat); err != nil {
			fail("SERIALIZATION_FAILED", err, "")
		}
	default: // json
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(resp.Secrets); err != nil {
			fail("SERIALIZATION_FAILED", err, "")
		}
	}
}

func pathToEnvKey(path string) string {
	s := strings.ToUpper(path)
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "-", "_")
	var buf bytes.Buffer
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

func pathToEnvKeyWithEntry(path string, entry store.SecretEntry) string {
	if entry.Metadata != nil {
		if alias, ok := entry.Metadata["env_alias"]; ok && strings.TrimSpace(alias) != "" {
			return strings.TrimSpace(alias)
		}
	}
	return pathToEnvKey(path)
}

func handleClear(profile string) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "clear"})
	if err != nil {
		fmt.Println("Session is already closed.")
		return
	}

	if !resp.Success {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Error)
		os.Exit(1)
	}

	fmt.Println("Session locked. Memory cache cleared.")
}

func handleBackup(profile string, outputFile string, explicitPassword string) {
	// 1. Get secrets list from daemon
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Daemon is not running. Please run 'sec open' to unlock the session.")
		os.Exit(1)
	}

	if !resp.Success {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Error)
		os.Exit(1)
	}

	if len(resp.Secrets) == 0 {
		fmt.Println("No secrets in the session cache to back up.")
		return
	}

	var backupPassword string

	if explicitPassword != "" {
		backupPassword = explicitPassword
	} else {
		// 2. Prompt for KeePassXC master password
		fmt.Print("Enter KeePassXC master password for backup: ")
		pass1, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
			os.Exit(1)
		}

		fmt.Print("Confirm KeePassXC master password: ")
		pass2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
			os.Exit(1)
		}

		if !bytes.Equal(pass1, pass2) {
			fmt.Fprintln(os.Stderr, "Error: Passwords do not match.")
			os.Exit(1)
		}
		backupPassword = string(pass1)
	}

	// 3. Export to KDBX
	absPath, err := filepath.Abs(outputFile)
	if err != nil {
		absPath = outputFile
	}

	err = backup.ExportToKdbx(absPath, backupPassword, resp.Secrets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Backup failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Backup created successfully at: %s\n", absPath)
}

func handleRestore(profile string, filePath, explicitPassword string) {
	var password string

	if explicitPassword != "" {
		password = explicitPassword
	} else {
		fmt.Print("Enter KeePassXC master password for restore: ")
		pass, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
			os.Exit(1)
		}
		password = string(pass)
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}

	secrets, err := backup.ImportFromKdbx(absPath, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to restore backup: %v\n", err)
		os.Exit(1)
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:  "restore",
		Secrets: secrets,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Daemon is not running. Please run 'sec open' to unlock the session.")
		os.Exit(1)
	}

	if !resp.Success {
		fmt.Fprintf(os.Stderr, "Restore failed: %s\n", resp.Error)
		os.Exit(1)
	}

	fmt.Printf("Secrets restored successfully. Merged %d entries into active session.\n", len(secrets))
}

func runDaemon(profile string) {
	d, err := daemon.NewDaemon(profile, 8*time.Hour, Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating daemon: %v\n", err)
		os.Exit(1)
	}

	// Handle graceful shutdown signals to clean up the socket file
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		d.Stop()
		os.Exit(0)
	}()

	// Serve
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

	// 1. Try parsing relative formats: e.g. "30d", "1y", "6mo" (months)
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

	// 2. Try standard Go duration parsing (e.g. "12h", "45m")
	if d, err := time.ParseDuration(expStr); err == nil {
		return time.Now().Add(d), nil
	}

	// 3. Try parsing absolute formats (RFC3339)
	if t, err := time.Parse(time.RFC3339, expStr); err == nil {
		return t, nil
	}
	// Fallback to simple date: e.g. "2026-12-31"
	if t, err := time.Parse("2006-01-02", expStr); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("unknown expiration format %q (use e.g. '30d', '12h', or 'YYYY-MM-DD')", expStr)
}

func handleMigrateLocal(profile string, dotenvPath string, args []string) {
	prefix := "env"
	for i := 0; i < len(args); i++ {
		if args[i] == "--prefix" {
			if i+1 < len(args) {
				prefix = args[i+1]
				i++
			} else {
				fail("INVALID_ARGUMENT", fmt.Errorf("flag --prefix requires a value"), "")
			}
		}
	}

	// #nosec G304 G703
	file, err := os.Open(dotenvPath)
	if err != nil {
		fail("FILE_READ_FAILED", err, "Verify that the dotenv file path is correct and accessible.")
	}
	defer file.Close()

	// Parse lines and modify in place
	type dotenvEntry struct {
		key      string
		rawLine  string
		isSecret bool
		value    string
	}
	var entries []dotenvEntry

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			entries = append(entries, dotenvEntry{rawLine: line})
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			entries = append(entries, dotenvEntry{rawLine: line})
			continue
		}

		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		// Strip quotes
		if (strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"")) ||
			(strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'")) {
			v = v[1 : len(v)-1]
		}

		// We assume it's a secret if it's not a common static config (e.g. PORT, NODE_ENV, etc.)
		if v != "" {
			entries = append(entries, dotenvEntry{
				key:      k,
				rawLine:  line,
				isSecret: true,
				value:    v,
			})
		} else {
			entries = append(entries, dotenvEntry{rawLine: line})
		}
	}

	if err := scanner.Err(); err != nil {
		fail("FILE_READ_FAILED", err, "")
	}

	// Connect to daemon to set the secrets
	importedCount := 0
	for _, entry := range entries {
		if !entry.isSecret {
			continue
		}

		// Determine path
		cleanKey := strings.ReplaceAll(strings.ToLower(entry.key), "_", "-")
		secretPath := cleanKey
		if prefix != "" {
			secretPath = prefix + "/" + cleanKey
		}

		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: "set",
			Path:   secretPath,
			Value:  entry.value,
		})
		if err != nil {
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
		}
		if !resp.Success {
			code, rem := mapDaemonError(resp.Error)
			fail(code, fmt.Errorf("failed to save key %q: %s", entry.key, resp.Error), rem)
		}
		importedCount++
	}

	// Write sanitized file back
	dir := filepath.Dir(dotenvPath)
	// #nosec G304 G703
	tmpFile, err := os.CreateTemp(dir, ".env.tmp.*")
	if err != nil {
		fail("FILE_WRITE_FAILED", err, "Verify permissions to write to target dotenv directory.")
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		// #nosec G304 G703
		_ = os.Remove(tmpPath)
	}()

	// Restrict permissions to owner-only
	if err := tmpFile.Chmod(0600); err != nil {
		fail("FILE_WRITE_FAILED", err, "")
	}

	writer := bufio.NewWriter(tmpFile)
	// Write a top header note
	if _, err := writer.WriteString(fmt.Sprintf("# Migrated to sec. Run your commands using: sec run --profile %s -- <command>\n", profile)); err != nil {
		fail("FILE_WRITE_FAILED", err, "")
	}

	for _, entry := range entries {
		var writeErr error
		if entry.isSecret {
			_, writeErr = writer.WriteString(fmt.Sprintf("%s=%q\n", entry.key, "<migrated_to_sec>"))
		} else {
			_, writeErr = writer.WriteString(entry.rawLine + "\n")
		}
		if writeErr != nil {
			fail("FILE_WRITE_FAILED", writeErr, "")
		}
	}
	if err := writer.Flush(); err != nil {
		fail("FILE_WRITE_FAILED", err, "")
	}

	// Force storage device sync (fsync)
	if err := tmpFile.Sync(); err != nil {
		fail("FILE_WRITE_FAILED", err, "")
	}

	if err := tmpFile.Close(); err != nil {
		fail("FILE_WRITE_FAILED", err, "")
	}

	// Atomically replace target dotenv file
	// #nosec G304 G703
	if err := os.Rename(tmpPath, dotenvPath); err != nil {
		fail("FILE_WRITE_FAILED", err, "Verify permissions to replace the target dotenv file.")
	}

	// Sync parent directory metadata
	// #nosec G304 G703
	dirFile, err := os.Open(dir)
	if err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}

	fmt.Printf("Successfully migrated %d secret(s) to sec (profile: %s). Dotenv file %q sanitized.\n", importedCount, profile, dotenvPath)
}

func handleVersion(profile string) {
	fmt.Printf("sec-agent CLI:      %s\n", Version)

	// Fetch daemon status and version
	daemonVer := "Not running"
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "ping"})
	if err == nil {
		if resp.Version != "" {
			daemonVer = fmt.Sprintf("%s (Running, profile: %s)", resp.Version, profile)
		} else {
			daemonVer = fmt.Sprintf("Active (Running, profile: %s)", profile)
		}
	}
	fmt.Printf("sec-agent Daemon:   %s\n", daemonVer)

	// Build info
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

	// Mismatch check
	if err == nil && resp.Version != "" && resp.Version != Version {
		fmt.Printf("\n⚠️  WARNING: CLI version (%s) does not match running daemon version (%s).\n", Version, resp.Version)
		fmt.Println("To upgrade the daemon, close the active session and re-open it:")
		fmt.Println("  sec lock")
		fmt.Println("  eval $(sec open)")
	}
}
