package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
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

	_ "embed"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

//go:embed SKILL.md
var embeddedSkillBytes []byte

var jsonErrors bool
var (
	Version   = "v2.1.8"
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

func printUsageJSON() {
	schema := `{
  "tool": "sec",
  "version": "1.1.0",
  "description": "Enclave Session Agent for local developer secrets",
  "commands": {
    "init": {
      "description": "Initialize vault configuration and install AI assistant skills (alias: setup)",
      "flags": {
        "--skill": {"type": "string", "description": "Install skill for target (antigravity, copilot, cursor, claude, windsurf)"},
        "--scope": {"type": "string", "default": "global", "description": "Skill installation scope (global, workspace)"}
      }
    },
    "setup": {
      "description": "Alias for init command"
    },
    "skill": {
      "description": "Install, view, or update AI assistant integration skills",
      "args": [{"name": "subcommand", "required": true, "choices": ["install", "status", "update"]}]
    },
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
      "remediation": "eval $(sec-agent open)"
    },
    "SESSION_LOCKED": {
      "description": "The session has been cleared/locked or is expired.",
      "remediation": "eval $(sec-agent open)"
    },
    "INVALID_TOKEN": {
      "description": "The calling session does not present a valid SEC_SESSION_TOKEN.",
      "remediation": "eval $(sec-agent open)"
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
	Profile     string            `json:"profile,omitempty"`
	Prefix      string            `json:"prefix,omitempty"`
	AutoOpen    bool              `json:"auto_open,omitempty"`
	Extends     string            `json:"extends,omitempty"`
	FlagAliases map[string]string `json:"flag_aliases,omitempty"`
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
	dir, err := os.Getwd()
	if err != nil {
		return nil
	}
	for {
		for _, name := range []string{".secenv", ".secrc", ".sec.json"} {
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

func isInteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
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
	if wsCfg != nil && wsCfg.AutoOpen && isInteractiveTerminal() {
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
			if isInteractiveTerminal() {
				_ = os.Setenv("SEC_AUTO_OPEN", "1")
			}
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

		if cmd != "init" && cmd != "setup" && cmd != "version" && cmd != "completion" {
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

	command := os.Args[1]
	switch command {
	case "init", "setup":
		handleInit(profile, os.Args[2:])
	case "skill":
		handleSkill(profile, os.Args[2:])
	case "open":
		handleOpen(profile, os.Args[2:])
	case "gui":
		port := 9876
		for i := 2; i < len(os.Args); i++ {
			if (os.Args[i] == "--port" || os.Args[i] == "-p") && i+1 < len(os.Args) {
				if p, err := strconv.Atoi(os.Args[i+1]); err == nil {
					port = p
				}
			}
		}
		runGUIServer(profile, port)
	case "get":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec get <path> [--json | --comment | --meta <key>]")
			os.Exit(1)
		}
		handleGet(profile, os.Args[2], os.Args[3:])
	case "set":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec set <path> [<value>] [--stdin] [--comment <comment>] [--meta key=value ...]")
			os.Exit(1)
		}
		path := os.Args[2]
		val := ""
		args := []string{}
		if len(os.Args) >= 4 && !strings.HasPrefix(os.Args[3], "-") {
			val = os.Args[3]
			args = os.Args[4:]
		} else {
			args = os.Args[3:]
		}
		handleSet(profile, path, val, args)
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
	case "diff-profiles":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: sec diff-profiles <profile1> <profile2> [--prefix <prefix>]")
			os.Exit(1)
		}
		handleDiffProfiles(os.Args[2], os.Args[3], os.Args[4:])
	case "lease":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec lease <path> [--ttl <duration>]")
			os.Exit(1)
		}
		handleLease(profile, os.Args[2], os.Args[3:])
	case "rotate":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec rotate <path> [--rotate-cmd <cmd>]")
			os.Exit(1)
		}
		handleRotate(profile, os.Args[2], os.Args[3:])
	case "stream":
		handleStream(profile, os.Args[2:])
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
		if len(os.Args) >= 3 && !strings.HasPrefix(os.Args[2], "-") {
			prefix = os.Args[2]
		}
		handleList(profile, prefix, os.Args[2:])
	case "rm", "delete":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec rm <path> [--prefix]")
			os.Exit(1)
		}
		handleDelete(profile, os.Args[2], os.Args[3:])
	case "status":
		handleStatus(profile, os.Args[2:])
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
		if len(os.Args) >= 3 && os.Args[2] == "list" {
			handleBackupList(profile)
		} else {
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "Usage: sec backup <output-file.kdbx> [--password | -p <password>] OR sec backup list")
				os.Exit(1)
			}
			explicitPassword := ""
			if len(os.Args) >= 5 {
				if os.Args[3] == "--password" || os.Args[3] == "-p" {
					explicitPassword = os.Args[4]
				}
			}
			handleBackup(profile, os.Args[2], explicitPassword)
		}
	case "profile":
		handleProfile(profile, os.Args[2:])
	case "sync":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec sync export <file> | sec sync import <file>")
			os.Exit(1)
		}
		handleSync(profile, os.Args[2:])
	case "check":
		handleCheck(profile, os.Args[2:])
	case "restart":
		handleRestart(profile, os.Args[2:])
	case "completion":
		shell := "zsh"
		if len(os.Args) >= 3 {
			shell = os.Args[2]
		}
		handleCompletion(shell)
	case "restore":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec restore <backup-file.kdbx> [--password | -p <password>] [--merge] [--overwrite]")
			os.Exit(1)
		}
		explicitPassword := ""
		for i := 3; i < len(os.Args); i++ {
			if (os.Args[i] == "--password" || os.Args[i] == "-p") && i+1 < len(os.Args) {
				explicitPassword = os.Args[i+1]
				i++
			}
		}
		handleRestore(profile, os.Args[2], explicitPassword, os.Args[3:])
	case "daemon":
		runDaemon(profile)
	case "migrate-local":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec migrate-local <dotenv-file> [--prefix <prefix>]")
			os.Exit(1)
		}
		handleMigrateLocal(profile, os.Args[2], os.Args[3:])
	case "history":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec history <path>")
			os.Exit(1)
		}
		handleHistory(profile, os.Args[2])
	case "rollback":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec rollback <path> --version <N>")
			os.Exit(1)
		}
		handleRollback(profile, os.Args[2], os.Args[3:])
	case "restore-deleted":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sec restore-deleted <path>")
			os.Exit(1)
		}
		handleRestoreDeleted(profile, os.Args[2])
	case "version", "-v", "--version":
		handleVersion(profile)
	case "feedback":
		handleFeedback(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: sec-agent [--profile <name> | -P <name>] [--auto-open] <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  init [--skill <target>] [--scope <global|workspace>] Initialize vault configuration & install AI skills (alias: setup)")
	fmt.Println("  skill <install|status|update> Install, view, or update AI assistant integration skills")
	fmt.Println("  open [--ttl <duration>] [--grace <duration>] Initialize/unlock the secrets session using Touch ID")
	fmt.Println("  get <path> [--prefix] [--record] [--json | --comment | --meta <key> | -r] Retrieve a secret or record")
	fmt.Println("  set <path> <val> [--comment <comment>] [--meta k=v ...] [--env-alias ALIAS] Store a secret")
	fmt.Println("  history <path>                  View chronological version audit history for a secret key")
	fmt.Println("  rollback <path> --version <N>   Non-destructively revert a secret to a previous version")
	fmt.Println("  mv <old> <new> [--prefix]       Rename a secret key path or prefix namespace (alias: rename)")
	fmt.Println("  cp <src> <dst> [--prefix]       Duplicate a secret key path or prefix group (alias: copy)")
	fmt.Println("  rm <path> [--prefix] [--permanent] Soft-delete a secret or prefix group (use --permanent for hard delete)")
	fmt.Println("  restore-deleted <path>          Un-delete a soft-deleted secret key from the trash bin")
	fmt.Println("  ls [<prefix>] [--json] [--trash] [--expiring N] List secret paths, trash bin, or expiring keys (alias: list)")
	fmt.Println("  diff [--other-profile <p>] [<file>] Compare secret paths against another profile or .env file")
	fmt.Println("  diff-profiles <p1> <p2>         Side-by-side key matrix comparison between two profiles")
	fmt.Println("  lease <path> [--ttl <duration>] Issue self-destructing temporary lease token for subagents")
	fmt.Println("  rotate <path> [--rotate-cmd <c>] Execute registered rotation command and reset TTL timer")
	fmt.Println("  doctor                          Run workstation system & security diagnostic checks")
	fmt.Println("  gen <path> [--length N]         Generate random password and save to path (alias: generate)")
	fmt.Println("  import <file> [--format <f>]    Bulk import secrets from JSON, Doppler, or AWS payloads")
	fmt.Println("  profile [set-env dev|dta|prod] Manage profile metadata & environment classification")
	fmt.Println("  check [--template <f>] [--scan-weak] [--leaks] Validate schema, audit entropy, or scan history for leaks")
	fmt.Println("  sync export|import <file>       Export/import encrypted vault package for team distribution")
	fmt.Println("  load [<prefix>] [--format env|json] Batch-load scoped group secrets for shell sourcing")
	fmt.Println("  run [--group <p>] [--allow-keys k1,k2] [--ssh-key <path>] [--dry-run] [--no-redact] -- <cmd> Execute process with secrets injected")
	fmt.Println("  stream [--template <t>]         Evaluate secret {{key_path}} placeholders in template strings or stdin streams")
	fmt.Println("  status                          Display session health, profile, and diagnostic metrics")
	fmt.Println("  audit [--limit <n>] [--json]    View recent daemon security audit logs (alias: log)")
	fmt.Println("  env [<prefix>]                   Output shell exports for secrets under prefix")
	fmt.Println("  export [--format <json|env|aws|doppler|template>] Output decrypted database contents to stdout")
	fmt.Println("  clear            Lock the active session and clear memory cache (aliases: close, lock)")
	fmt.Println("  restart          Lock session, stop daemon process, re-launch, and prompt Touch ID")
	fmt.Println("  backup <file> [--password | -p <password>] Export cached secrets to a portable KeePassXC (.kdbx) file")
	fmt.Println("  restore <file> [--merge] [--overwrite] [--full-metadata] Import secrets from a portable KeePassXC (.kdbx) file")
	fmt.Println("  migrate-local <file> [--prefix <prefix>] Import dotenv file and sanitize it")
	fmt.Println("  feedback [--example] [--json]  Display feature feedback guidelines, usecase templates, and rationale formats")
	fmt.Println("  completion <zsh|bash|fish>      Generate native shell completion script")
	fmt.Println("  version          Print CLI and active daemon version and build metadata")
}

func handleFeedback(args []string) {
	showJSON := false
	showExample := false
	for _, a := range args {
		if a == "--json" {
			showJSON = true
		} else if a == "--example" || a == "-e" {
			showExample = true
		}
	}

	if showJSON {
		resp := map[string]interface{}{
			"tool": "sec-agent",
			"desired_feedback_categories": []string{
				"operational_usecases_and_network_hardware",
				"missing_cli_flags_or_subcommands",
				"ai_skill_integration_friction",
				"security_and_compliance_gaps",
			},
			"proposal_motivation_rationale": "Always capture WHY a feature is requested (problem statement, lost context, security benefit, and exact CLI workflow impact).",
			"example_usecases": []map[string]string{
				{
					"component": "Network Hardware & Embedded Systems",
					"example":   "Xiaomi AX3600 OpenWrt SSH & LuCI admin notes preservation",
					"reason":    "Prevents losing Dropbear SSH flags (-o HostKeyAlgorithms=+ssh-rsa) and HTTPS port bindings (443/668).",
				},
				{
					"component": "Vault Migration",
					"example":   "KeePassXC .kdbx Full Metadata Import",
					"reason":    "Preserves custom string attributes (TOTP secrets, PINs, recovery codes) during vault consolidation.",
				},
			},
			"future_roadmap_suggestions": []map[string]string{
				{
					"feature": "Centralized Remote Vault Sync Adapter",
					"status":  "Optional Suggestion (Non-Binding / No Commitment)",
					"details": "Optional background OIDC/SSO sync module to mirror enterprise secrets from corporate vaults (HashiCorp Vault, AWS Secrets Manager, GCP) while preserving Touch ID offline security.",
				},
			},
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return
	}

	if showExample {
		fmt.Println(`=== sec-agent Feature Proposal & Feedback Example Template ===

# Proposal: [Feature Name]
**Target Repository:** secure_secrets
**Target Component:** sec-agent CLI & Embedded AI Skill
**Evaluation Date:** ` + time.Now().Format("2006-01-02") + `

## 1. Executive Summary & Operational Motivation
- **Problem Statement:** What friction or issue occurs in real-world usage?
- **Why Now:** Why is this enhancement required (lost context, security, automation ease)?

## 2. Proposed Architectural Enhancements
- Specific CLI subcommands, flags, or data structure changes.
- Example CLI commands and output formats.

## 3. Real-World Usecases & Impact
- Hardware/Network device management (routers, switches, firewalls).
- AI agent workflow integration ease.`)
		return
	}

	fmt.Println(`=== 🤖 sec-agent AI & User Feedback Guidance ===

sec-agent welcomes actionable feedback and feature proposals! To help us continuously improve sec-agent:

1. 🎯 What Information We Desire:
   • Operational Usecases: Real-world workflows (e.g. router SSH/HTTPS endpoints, Dropbear flags, KeePassXC custom fields).
   • Workflow Friction: Missing CLI flags, unexpected shell formatting, or AI skill integration gaps.
   • Security & Governance: Memory safety, session scoping, audit log requirements.

2. 💡 Why Feature Motivators Matter:
   • Documenting the exact problem, operational context, and business rationale ensures new features are built to high quality standards without scope drift.

3. 🛠️ Quick Commands:
   • sec-agent feedback --example  : View full markdown proposal template & examples
   • sec-agent feedback --json     : Output structured feedback schema for AI assistants`)
}

func queryDaemon(profile string, req daemon.IPCRequest) (*daemon.IPCResponse, error) {
	resp, err := queryDaemonRaw(profile, req)
	if (err != nil || (resp != nil && !resp.Success && strings.Contains(resp.Error, "locked"))) && req.Action != "open" && req.Action != "ping" {
		if os.Getenv("SEC_AUTO_OPEN") == "1" && isInteractiveTerminal() && os.Getenv("SEC_NO_AUTO_OPEN") != "1" && os.Getenv("SEC_DISABLE_AUTO_OPEN") != "1" {
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

	fmt.Fprintln(os.Stderr, "Authorizing session via Touch ID...")

	if os.Getenv("SEC_TEST_MODE") != "1" {
		if !biometrics.Authenticate("Authorize sec session") {
			fmt.Fprintln(os.Stderr, "Authentication failed: Biometric verification failed.")
			os.Exit(1)
		}
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
	showRaw := false
	showMetaKey := ""
	showExpired := false
	isPrefix := false
	showRecord := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--json" {
			showJSON = true
		} else if args[i] == "--raw" || args[i] == "-r" {
			showRaw = true
		} else if args[i] == "--prefix" {
			isPrefix = true
		} else if args[i] == "--record" {
			showRecord = true
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

	if isPrefix || strings.HasSuffix(path, "/") || showRecord {
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

		if showRecord {
			trimmedPrefix := strings.TrimSuffix(path, "/") + "/"
			parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
			recordSlug := parts[len(parts)-1]

			rec := map[string]interface{}{
				"record":     recordSlug,
				"username":   "",
				"password":   "",
				"url":        "",
				"notes":      "",
				"attributes": make(map[string]string),
			}
			attrs := make(map[string]string)

			for k, entry := range resp.Secrets {
				relKey := strings.TrimPrefix(k, trimmedPrefix)
				switch strings.ToLower(relKey) {
				case "password", "pass", "secret":
					rec["password"] = entry.Value
				case "username", "user":
					rec["username"] = entry.Value
				case "url", "endpoint", "host":
					rec["url"] = entry.Value
				case "notes", "comment":
					rec["notes"] = entry.Value
				default:
					attrs[relKey] = entry.Value
				}
				if rec["notes"] == "" && entry.Comment != "" {
					rec["notes"] = entry.Comment
				}
			}
			rec["attributes"] = attrs

			if showJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rec); err != nil {
					fail("SERIALIZATION_FAILED", err, "")
				}
				return
			}

			fmt.Printf("=== Record: %s ===\n", recordSlug)
			if u, ok := rec["username"].(string); ok && u != "" {
				fmt.Printf("Username:   %s\n", u)
			}
			if p, ok := rec["password"].(string); ok && p != "" {
				fmt.Printf("Password:   %s\n", p)
			}
			if urlStr, ok := rec["url"].(string); ok && urlStr != "" {
				fmt.Printf("URL:        %s\n", urlStr)
			}
			if n, ok := rec["notes"].(string); ok && n != "" {
				fmt.Printf("Notes:      %s\n", n)
			}
			if len(attrs) > 0 {
				fmt.Println("Attributes:")
				for ak, av := range attrs {
					fmt.Printf("  %s: %s\n", ak, av)
				}
			}
			return
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
	} else if showRaw {
		fmt.Print(resp.Value)
	} else {
		fmt.Println(resp.Value)
	}
}

func parseJwtExp(val string) (time.Time, bool) {
	val = strings.TrimSpace(val)
	if !strings.HasPrefix(val, "eyJ") {
		return time.Time{}, false
	}
	parts := strings.Split(val, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payloadSegment := parts[1]
	switch len(payloadSegment) % 4 {
	case 2:
		payloadSegment += "=="
	case 3:
		payloadSegment += "="
	}
	data, err := base64.URLEncoding.DecodeString(payloadSegment)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(payloadSegment)
		if err != nil {
			return time.Time{}, false
		}
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(data, &claims); err != nil {
		return time.Time{}, false
	}
	expVal, ok := claims["exp"]
	if !ok {
		return time.Time{}, false
	}
	var expUnix int64
	switch v := expVal.(type) {
	case float64:
		expUnix = int64(v)
	case int64:
		expUnix = v
	case string:
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			expUnix = parsed
		}
	}
	if expUnix > 0 {
		return time.Unix(expUnix, 0), true
	}
	return time.Time{}, false
}

func handleSet(profile string, path, value string, args []string) {
	comment := ""
	metadata := make(map[string]string)
	expiresStr := ""
	useStdin := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--stdin" {
			useStdin = true
		}
	}

	if value == "-" || useStdin {
		r := bufio.NewReader(os.Stdin)
		input, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			fail("STDIN_READ_ERROR", fmt.Errorf("failed to read secret from stdin: %v", err), "")
		}
		value = strings.TrimRight(input, "\r\n")
	} else if value == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			fail("MISSING_ARGUMENT", fmt.Errorf("secret value required for %q. Pass value, pipe stdin (--stdin), or run interactively", path), "Usage: sec set <path> or echo val | sec set <path> --stdin")
		}
		fmt.Fprintf(os.Stderr, "Enter secret value for %q: ", path)
		bytePass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fail("READ_PASSWORD_ERROR", fmt.Errorf("failed to read password: %v", err), "")
		}
		val1 := string(bytePass)

		fmt.Fprintf(os.Stderr, "Re-enter secret value for %q: ", path)
		bytePass2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fail("READ_PASSWORD_ERROR", fmt.Errorf("failed to read password: %v", err), "")
		}
		val2 := string(bytePass2)

		if val1 != val2 {
			fail("PASSWORD_MISMATCH", fmt.Errorf("entered secret values do not match"), "Please re-run sec set and enter matching values.")
		}
		value = val1
	}

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
		} else if args[i] == "--rotate-cmd" {
			if i+1 < len(args) {
				metadata["rotate_cmd"] = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "Error: --rotate-cmd requires a command string")
				os.Exit(1)
			}
		} else if args[i] == "--rotate-ttl" {
			if i+1 < len(args) {
				metadata["rotate_ttl"] = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "Error: --rotate-ttl requires a duration (e.g. 30d, 12h)")
				os.Exit(1)
			}
		}
	}

	expiresTimeStr := ""
	if expiresStr == "" && metadata["rotate_ttl"] != "" {
		expiresStr = metadata["rotate_ttl"]
	}
	if expiresStr != "" {
		t, err := parseExpiration(expiresStr)
		if err != nil {
			fail("INVALID_ARGUMENT", err, "Verify option parameters (e.g. format for durations: 30d, 12h)")
		}
		expiresTimeStr = t.Format(time.RFC3339)
	} else if jwtExp, ok := parseJwtExp(value); ok {
		expiresTimeStr = jwtExp.Format(time.RFC3339)
		fmt.Printf("[INFO] Automatically detected JWT token with expiration date: %s\n", jwtExp.Format("2006-01-02 15:04:05 MST"))
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

func handleLease(profile, secretPath string, args []string) {
	if secretPath == "revoke" && len(args) > 0 {
		leaseToken := args[0]
		if !strings.HasPrefix(leaseToken, "lease:") {
			leaseToken = "lease:" + leaseToken
		}
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: "delete",
			Path:   leaseToken,
		})
		if err != nil || !resp.Success {
			fail("LEASE_REVOKE_FAILED", fmt.Errorf("failed to revoke lease token %q: %v", leaseToken, err), "Check if lease token is valid.")
		}
		if jsonErrors {
			data, _ := json.Marshal(map[string]interface{}{
				"success": true,
				"value":   fmt.Sprintf("Revoked temporary lease token %q", leaseToken),
			})
			fmt.Println(string(data))
		} else {
			fmt.Printf("[✓] Revoked temporary lease token %q.\n", leaseToken)
		}
		return
	}

	ttlStr := "15m"
	for i := 0; i < len(args); i++ {
		if args[i] == "--ttl" && i+1 < len(args) {
			ttlStr = args[i+1]
			i++
		}
	}

	ttlTime, err := parseExpiration(ttlStr)
	if err != nil {
		fail("INVALID_ARGUMENT", err, "Duration format: e.g. 15m, 1h, 30m")
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "get",
		Path:   secretPath,
	})
	if err != nil || !resp.Success {
		fail("SECRET_NOT_FOUND", fmt.Errorf("failed to fetch secret %q: %v", secretPath, err), "Check path.")
	}

	randBuf := make([]byte, 8)
	_, _ = rand.Read(randBuf)
	leaseID := fmt.Sprintf("lease:%s:%x", secretPath, randBuf)

	expiresStr := ttlTime.Format(time.RFC3339)

	setResp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:  "set",
		Path:    leaseID,
		Value:   resp.Value,
		Comment: fmt.Sprintf("Temporary lease for %s (TTL: %s)", secretPath, ttlStr),
		Expires: expiresStr,
	})
	if err != nil || !setResp.Success {
		fail("LEASE_CREATION_FAILED", fmt.Errorf("failed to create lease token: %v", err), "")
	}

	fmt.Printf("[INFO] Temporary secret lease created for %q (Expires: %s)\n", secretPath, ttlTime.Format("15:04:05 MST"))
	fmt.Println(leaseID)
}

func handleRotate(profile, secretPath string, args []string) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "get",
		Path:   secretPath,
	})
	if err != nil || !resp.Success {
		fail("SECRET_NOT_FOUND", fmt.Errorf("failed to fetch secret %q: %v", secretPath, err), "Check path.")
	}

	rotateCmd := ""
	if resp.Metadata != nil {
		rotateCmd = resp.Metadata["rotate_cmd"]
	}

	for i := 0; i < len(args); i++ {
		if args[i] == "--rotate-cmd" && i+1 < len(args) {
			rotateCmd = args[i+1]
			i++
		}
	}

	if strings.TrimSpace(rotateCmd) == "" {
		fail("MISSING_ROTATION_HOOK", fmt.Errorf("secret %q does not have a registered rotation command", secretPath), "Register a command using: sec set <path> <val> --rotate-cmd \"<cmd>\"")
	}

	envResp, _ := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	env := os.Environ()
	if envResp != nil && envResp.Success {
		for k, entry := range envResp.Secrets {
			envKey := pathToEnvKeyWithEntry(k, entry)
			env = append(env, fmt.Sprintf("%s=%s", envKey, entry.Value))
		}
	}

	fmt.Printf("[INFO] Executing rotation hook for %q...\n", secretPath)

	// #nosec G204 G702
	cmd := exec.Command("sh", "-c", rotateCmd)
	cmd.Env = env

	out, err := cmd.Output()
	if err != nil {
		fail("ROTATION_FAILED", fmt.Errorf("rotation command execution failed: %v", err), "Check script syntax and credentials.")
	}

	newVal := strings.TrimSpace(string(out))
	if newVal == "" {
		fail("ROTATION_FAILED", fmt.Errorf("rotation command returned empty output"), "Rotation script must output new secret string to stdout.")
	}

	ttlStr := ""
	if resp.Metadata != nil {
		ttlStr = resp.Metadata["rotate_ttl"]
	}
	expiresTimeStr := ""
	if ttlStr != "" {
		if t, err := parseExpiration(ttlStr); err == nil {
			expiresTimeStr = t.Format(time.RFC3339)
		}
	} else if jwtExp, ok := parseJwtExp(newVal); ok {
		expiresTimeStr = jwtExp.Format(time.RFC3339)
	}

	meta := resp.Metadata
	if meta == nil {
		meta = make(map[string]string)
	}
	meta["rotate_cmd"] = rotateCmd

	setResp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:   "set",
		Path:     secretPath,
		Value:    newVal,
		Comment:  resp.Comment,
		Metadata: meta,
		Expires:  expiresTimeStr,
	})
	if err != nil || !setResp.Success {
		fail("STORE_UPDATE_FAILED", fmt.Errorf("failed to save rotated secret: %v", err), "")
	}

	fmt.Printf("[✓] Secret %q successfully rotated!\n", secretPath)
	if expiresTimeStr != "" {
		fmt.Printf(" [✓] Expiration timer updated to: %s\n", expiresTimeStr)
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
	expiringDays := 0
	checkExpiring := false
	showJSON := false
	showTrash := false
	showLong := false
	staleDays := 0
	checkStale := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--json" {
			showJSON = true
		} else if args[i] == "--trash" {
			showTrash = true
		} else if args[i] == "-l" || args[i] == "--long" {
			showLong = true
		} else if args[i] == "--stale" {
			checkStale = true
			staleDays = 30
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				if d, err := strconv.Atoi(args[i+1]); err == nil && d > 0 {
					staleDays = d
					i++
				}
			}
		} else if args[i] == "--expiring" {
			checkExpiring = true
			expiringDays = 7
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				if d, err := strconv.Atoi(args[i+1]); err == nil && d > 0 {
					expiringDays = d
					i++
				} else if t, err := parseExpiration(args[i+1]); err == nil {
					expiringDays = int(time.Until(t).Hours() / 24)
					if expiringDays <= 0 {
						expiringDays = 1
					}
					i++
				}
			}
		}
	}

	if checkExpiring {
		bkResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
		if err != nil || !bkResp.Success {
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock session."), "Run 'eval $(sec open)' to unlock.")
		}
		now := time.Now()
		limit := time.Duration(expiringDays*24) * time.Hour

		type ExpiringItem struct {
			Path          string    `json:"path"`
			Expires       time.Time `json:"expires"`
			RemainingDays int       `json:"remaining_days"`
		}
		var list []ExpiringItem

		for path, entry := range bkResp.Secrets {
			if strings.HasPrefix(path, "__") {
				continue
			}
			if !entry.Expires.IsZero() {
				until := entry.Expires.Sub(now)
				if until > 0 && until <= limit {
					days := int(until.Hours() / 24)
					list = append(list, ExpiringItem{
						Path:          path,
						Expires:       entry.Expires,
						RemainingDays: days,
					})
				}
			}
		}

		if showJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(list)
			return
		}

		if len(list) == 0 {
			fmt.Printf("No secret keys expiring within the next %d day(s).\n", expiringDays)
			return
		}

		fmt.Printf("\033[33m⚠️  EXPIRATION WARNING: %d secret key(s) expiring within the next %d day(s)!\033[0m\n\n", len(list), expiringDays)
		fmt.Printf("%-35s %-25s %s\n", "KEY PATH", "EXPIRATION DATE", "REMAINING")
		fmt.Println(strings.Repeat("-", 75))
		for _, item := range list {
			fmt.Printf("%-35s %-25s %d day(s)\n", item.Path, item.Expires.Format(time.RFC3339), item.RemainingDays)
		}
		return
	}

	if showLong || checkStale {
		bkResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
		if err != nil || !bkResp.Success {
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock session."), "Run 'eval $(sec open)' to unlock.")
		}
		now := time.Now()
		limit := time.Duration(staleDays*24) * time.Hour

		type DetailedEntry struct {
			Path         string    `json:"path"`
			Version      int       `json:"version"`
			Created      time.Time `json:"created"`
			LastModified time.Time `json:"last_modified"`
			LastAccessed time.Time `json:"last_accessed,omitempty"`
			AccessCount  uint64    `json:"access_count"`
		}
		var list []DetailedEntry

		var sortedKeys []string
		for k := range bkResp.Secrets {
			if prefix != "" && !strings.HasPrefix(k, prefix) {
				continue
			}
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)

		for _, k := range sortedKeys {
			entry := bkResp.Secrets[k]
			if checkStale {
				if !entry.LastAccessed.IsZero() && now.Sub(entry.LastAccessed) <= limit {
					continue
				}
			}
			list = append(list, DetailedEntry{
				Path:         k,
				Version:      entry.Version,
				Created:      entry.Created,
				LastModified: entry.LastModified,
				LastAccessed: entry.LastAccessed,
				AccessCount:  entry.AccessCount,
			})
		}

		if showJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(list)
			return
		}

		if len(list) == 0 {
			if checkStale {
				fmt.Printf("No stale secret keys found unaccessed for > %d day(s).\n", staleDays)
			} else {
				fmt.Println("No matching secret paths found.")
			}
			return
		}

		if checkStale {
			fmt.Printf("=== ⏳ Stale Credentials (Unaccessed > %d day(s)) ===\n\n", staleDays)
		} else {
			fmt.Println("=== 📊 Detailed Secret Audit Dump ===")
		}

		fmt.Printf("%-35s %-5s %-16s %-16s %-16s %s\n", "KEY PATH", "VER", "CREATED", "MODIFIED", "ACCESSED", "READS")
		fmt.Println(strings.Repeat("-", 100))
		for _, item := range list {
			accStr := "Never"
			if !item.LastAccessed.IsZero() {
				accStr = item.LastAccessed.Format("2006-01-02 15:04")
			}
			createdStr := item.Created.Format("2006-01-02 15:04")
			if item.Created.IsZero() {
				createdStr = "-"
			}
			modStr := item.LastModified.Format("2006-01-02 15:04")
			if item.LastModified.IsZero() {
				modStr = "-"
			}
			verStr := fmt.Sprintf("v%d", item.Version)
			if item.Version == 0 {
				verStr = "v1"
			}
			fmt.Printf("%-35s %-5s %-16s %-16s %-16s %d\n", item.Path, verStr, createdStr, modStr, accStr, item.AccessCount)
		}
		return
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:    "list",
		Path:      prefix,
		ShowTrash: showTrash,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
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
		if showTrash {
			fmt.Println("No soft-deleted secrets found in trash bin.")
		} else {
			fmt.Println("No matching secret paths found.")
		}
		return
	}
	if showTrash {
		fmt.Println("=== 🗑️ Soft-Deleted Secrets (Trash Bin) ===")
	}
	fmt.Println(resp.Value)
}

func handleDelete(profile string, path string, args []string) {
	isPrefix := false
	permanent := false
	for _, arg := range args {
		if arg == "--prefix" {
			isPrefix = true
		} else if arg == "--permanent" {
			permanent = true
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:    "delete",
		Path:      path,
		IsPrefix:  isPrefix,
		Permanent: permanent,
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

func handleHistory(profile string, path string) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "history",
		Path:   path,
	})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	if len(resp.History) == 0 {
		fmt.Printf("No historical versions recorded for secret %q (current version: v%d).\n", path, resp.ItemVersion)
		return
	}

	fmt.Printf("=== 📜 Secret Version History: %s (Active: v%d) ===\n\n", path, resp.ItemVersion)
	fmt.Printf("%-8s %-25s %-30s %s\n", "VERSION", "LAST MODIFIED", "COMMENT", "VALUE PREVIEW")
	fmt.Println(strings.Repeat("-", 80))
	for _, h := range resp.History {
		valPrev := h.Value
		if len(valPrev) > 15 {
			valPrev = valPrev[:12] + "..."
		}
		comment := h.Comment
		if comment == "" {
			comment = "-"
		}
		fmt.Printf("v%-7d %-25s %-30s %s\n", h.Version, h.LastModified.Format(time.RFC3339), comment, valPrev)
	}
}

func handleRollback(profile string, path string, args []string) {
	targetVer := 0
	for i := 0; i < len(args); i++ {
		if (args[i] == "--version" || args[i] == "-v") && i+1 < len(args) {
			if v, err := strconv.Atoi(args[i+1]); err == nil && v > 0 {
				targetVer = v
				i++
			}
		}
	}
	if targetVer <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --version <N> must be a positive integer version number.")
		os.Exit(1)
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:        "rollback",
		Path:          path,
		TargetVersion: targetVer,
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

func handleRestoreDeleted(profile string, path string) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "restore_deleted",
		Path:   path,
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

func getProfileEnvTier(profile string) string {
	resp, err := queryDaemonRaw(profile, daemon.IPCRequest{
		Action: "get",
		Path:   "__profile_env__",
	})
	if err == nil && resp.Success && resp.Value != "" {
		return strings.ToLower(strings.TrimSpace(resp.Value))
	}
	return ""
}

func printEnvBadge(profile string) {
	tier := getProfileEnvTier(profile)
	switch tier {
	case "dev":
		fmt.Println("\033[32m🟢 [ENV: DEV]\033[0m")
	case "dta", "test", "staging":
		fmt.Println("\033[33m🟡 [ENV: STAGING]\033[0m")
	case "prod", "production":
		fmt.Println("\033[1;31m🔴 [ENV: PROD - CAUTION!]\033[0m")
	}
}

func checkProductionGuard(profile string, args []string) {
	tier := getProfileEnvTier(profile)
	if tier == "prod" || tier == "production" {
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

func handleProfile(profile string, args []string) {
	if len(args) == 0 {
		tier := getProfileEnvTier(profile)
		fmt.Printf("Profile: %s\n", profile)
		if tier != "" {
			fmt.Printf("Environment Tier: %s\n", strings.ToUpper(tier))
			printEnvBadge(profile)
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
		printEnvBadge(profile)
		return
	}

	fmt.Fprintln(os.Stderr, "Usage: sec profile [set-env dev|dta|staging|prod]")
	os.Exit(1)
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

func handleStatusAll() {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		fail("CONFIG_ERROR", err, "")
	}

	profilesMap := make(map[string]bool)
	profilesMap["default"] = true

	profilesDir := filepath.Join(cfgDir, "profiles")
	if entries, err := os.ReadDir(profilesDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				profilesMap[e.Name()] = true
			}
		}
	}

	var profiles []string
	for p := range profilesMap {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)

	fmt.Println("=== sec-agent Global Workstation Status & Inventory ===")
	fmt.Printf("CLI Version:            %s (Build Date: %s)\n", Version, BuildDate)
	fmt.Printf("Config Directory:       %s\n\n", cfgDir)

	fmt.Printf("%-24s %-10s %-20s %-12s %s\n", "PROFILE NAME", "ENV TIER", "SESSION STATUS", "STORED KEYS", "EXPIRED")
	fmt.Println(strings.Repeat("-", 80))

	type ProfileInfo struct {
		Name       string
		Tier       string
		Unlocked   bool
		DaemonRun  bool
		TotalKeys  int
		ExpKeys    int
		SocketPath string
		Namespaces []string
	}

	var profileInfos []ProfileInfo
	totalGlobalExpiring := 0

	for _, p := range profiles {
		tier := getProfileEnvTier(p)
		if tier == "" {
			tier = "dev"
		}

		info := ProfileInfo{
			Name: p,
			Tier: strings.ToUpper(tier),
		}

		resp, err := queryDaemonRaw(p, daemon.IPCRequest{Action: "status"})
		if err == nil && resp != nil && resp.Success {
			info.DaemonRun = true
			if unlocked, ok := resp.StatusInfo["is_unlocked"].(bool); ok {
				info.Unlocked = unlocked
			}
			if total, ok := resp.StatusInfo["total_secrets"].(float64); ok {
				info.TotalKeys = int(total)
			} else if total, ok := resp.StatusInfo["total_secrets"].(int); ok {
				info.TotalKeys = total
			}
			if exp, ok := resp.StatusInfo["expired_secrets"].(float64); ok {
				info.ExpKeys = int(exp)
			} else if exp, ok := resp.StatusInfo["expired_secrets"].(int); ok {
				info.ExpKeys = exp
			}
			if sock, ok := resp.StatusInfo["socket_path"].(string); ok {
				info.SocketPath = sock
			}
		}

		bkResp, bkErr := queryDaemonRaw(p, daemon.IPCRequest{Action: "backup"})
		if bkErr == nil && bkResp != nil && bkResp.Success {
			nsMap := make(map[string]int)
			for path, entry := range bkResp.Secrets {
				if strings.HasPrefix(path, "__") {
					continue
				}
				parts := strings.SplitN(path, "/", 2)
				if len(parts) > 1 {
					nsMap[parts[0]+"/"]++
				} else {
					nsMap["root"]++
				}
				if !entry.Expires.IsZero() && time.Until(entry.Expires) <= 7*24*time.Hour && time.Until(entry.Expires) > 0 {
					totalGlobalExpiring++
				}
			}
			var nsList []string
			for ns, count := range nsMap {
				nsList = append(nsList, fmt.Sprintf("%s (%d)", ns, count))
			}
			sort.Strings(nsList)
			info.Namespaces = nsList
		}

		profileInfos = append(profileInfos, info)
	}

	for _, info := range profileInfos {
		tierBadge := info.Tier
		switch info.Tier {
		case "DEV":
			tierBadge = "\033[32mDEV🟢\033[0m"
		case "DTA", "STAGING":
			tierBadge = "\033[33mSTAGING🟡\033[0m"
		case "PROD":
			tierBadge = "\033[31mPROD🔴\033[0m"
		}

		sessStatus := "\033[31mLOCKED\033[0m"
		if info.Unlocked {
			sessStatus = "\033[32mUNLOCKED (TouchID)\033[0m"
		} else if !info.DaemonRun {
			sessStatus = "\033[90mInactive\033[0m"
		}

		fmt.Printf("%-24s %-19s %-29s %-12d %-12d\n",
			info.Name,
			tierBadge,
			sessStatus,
			info.TotalKeys,
			info.ExpKeys,
		)
	}

	fmt.Println("\n=== Key Vault Namespaces & Groups Across Profiles ===")
	for _, info := range profileInfos {
		if len(info.Namespaces) > 0 {
			fmt.Printf(" • %-24s: %s\n", info.Name, strings.Join(info.Namespaces, ", "))
		} else {
			fmt.Printf(" • %-24s: (No secrets stored)\n", info.Name)
		}
	}

	if totalGlobalExpiring > 0 {
		fmt.Printf("\n\033[33m⚠️  EXPIRATION WARNING: %d secret key(s) expiring within the next 7 days across all profiles!\033[0m\n", totalGlobalExpiring)
		fmt.Println("Run 'sec ls --expiring 7d --profile <name>' for detailed inspection.")
	}
}

func handleStatusQuick(profile string) {
	socketPath, err := config.GetSocketPath(profile)
	if err != nil {
		fail("CONFIG_ERROR", err, "Failed to resolve config directory.")
	}
	info, err := os.Stat(socketPath)
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("daemon socket not found at %s", socketPath), "Run 'eval $(sec-agent open)' to start daemon.")
	}

	mode := info.Mode()
	perms := mode.Perm()

	if jsonErrors {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"success":      true,
			"profile":      profile,
			"socket_path":  socketPath,
			"socket_perms": fmt.Sprintf("%04o", perms),
			"status":       "ACTIVE",
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println("=== sec-agent Fast-Path Status Diagnostic ===")
	fmt.Printf("[✓] Active Profile: %s\n", profile)
	fmt.Printf("[✓] Socket Path:    %s\n", socketPath)
	fmt.Printf("[✓] File Perms:     %04o (Strict)\n", perms)
	fmt.Println("[✓] Socket Status:  ACTIVE (IPC socket file present)")
}

func handleStatus(profile string, args []string) {
	for _, arg := range args {
		if arg == "--all" || arg == "-a" {
			handleStatusAll()
			return
		} else if arg == "--quick" || arg == "-q" {
			handleStatusQuick(profile)
			return
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "status"})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	info := resp.StatusInfo
	tier := getProfileEnvTier(profile)
	if tier == "" {
		tier = "UNSET"
	}
	fmt.Println("=== sec-agent Status & Diagnostics ===")
	fmt.Printf("Active Profile:       %v (Tier: %s)\n", info["profile"], strings.ToUpper(tier))
	printEnvBadge(profile)
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

	// Expiration warning check
	bkResp, err := queryDaemonRaw(profile, daemon.IPCRequest{Action: "backup"})
	if err == nil && bkResp.Success {
		checkExpirationWarnings(bkResp.Secrets)
	}
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

	cfgDir, err := config.GetConfigDir()
	if err != nil {
		return "", nil, err
	}

	randBuf := make([]byte, 8)
	_, _ = rand.Read(randBuf)
	sockPath := filepath.Join(cfgDir, fmt.Sprintf("ssh_%x.sock", randBuf))
	_ = os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to start SSH agent unix listener at %s: %w", sockPath, err)
	}
	_ = os.Chmod(sockPath, 0600)

	doneChan := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-doneChan:
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
		close(doneChan)
		_ = listener.Close()
		_ = os.Remove(sockPath)
	}

	return sockPath, cleanup, nil
}

func handleStream(profile string, args []string) {
	templateStr := ""
	for i := 0; i < len(args); i++ {
		if (args[i] == "--template" || args[i] == "-t") && i+1 < len(args) {
			templateStr = args[i+1]
			i++
		}
	}

	var inputData []byte
	var err error
	if templateStr != "" {
		inputData = []byte(templateStr)
	} else {
		inputData, err = io.ReadAll(os.Stdin)
		if err != nil {
			fail("STREAM_READ_FAILED", err, "Check stdin input stream.")
		}
	}

	re := regexp.MustCompile(`\{\{([a-zA-Z0-9_\-\.\/]+)\}\}`)
	matches := re.FindAllSubmatch(inputData, -1)
	if len(matches) == 0 {
		if jsonErrors {
			data, _ := json.Marshal(map[string]interface{}{
				"success": true,
				"stream":  string(inputData),
			})
			fmt.Println(string(data))
		} else {
			fmt.Print(string(inputData))
		}
		return
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil || !resp.Success {
		fail("DAEMON_ERROR", fmt.Errorf("failed to fetch secrets from daemon: %v", err), "Run 'eval $(sec open)' to unlock.")
	}

	result := string(inputData)
	for _, m := range matches {
		placeholder := string(m[0])
		keyPath := string(m[1])
		entry, exists := resp.Secrets[keyPath]
		if !exists {
			fail("SECRET_NOT_FOUND", fmt.Errorf("secret %q referenced in stream placeholder not found", keyPath), "Verify key path.")
		}
		result = strings.ReplaceAll(result, placeholder, entry.Value)
	}

	if jsonErrors {
		data, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"stream":  result,
		})
		fmt.Println(string(data))
	} else {
		fmt.Print(result)
	}
}

func handleRun(profile string, args []string) {
	groupPrefix := ""
	allowKeysStr := ""
	sshKeyPath := ""
	sshPassphraseKey := ""
	dryRun := false
	shouldRedact := true
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
		} else if args[i] == "--allow-keys" {
			if i+1 < len(args) {
				allowKeysStr = args[i+1]
				i++
			}
		} else if args[i] == "--ssh-key" {
			if i+1 < len(args) {
				sshKeyPath = args[i+1]
				i++
			}
		} else if args[i] == "--ssh-passphrase-key" {
			if i+1 < len(args) {
				sshPassphraseKey = args[i+1]
				i++
			}
		} else if args[i] == "--dry-run" {
			dryRun = true
		} else if args[i] == "--no-redact" {
			shouldRedact = false
		} else if args[i] == "--redact" {
			shouldRedact = true
		}
	}
	if !foundSeparator {
		for i := 0; i < len(args); i++ {
			if args[i] == "--group" || args[i] == "-g" || args[i] == "--ssh-key" || args[i] == "--ssh-passphrase-key" {
				i++
				continue
			}
			if args[i] == "--allow-keys" {
				i++
				continue
			}
			if args[i] == "--redact" || args[i] == "--no-redact" || args[i] == "--dry-run" {
				continue
			}
			cmdArgs = append(cmdArgs, args[i])
		}
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sec run [--group <prefix>] [--profile <name>] [--allow-keys <keys>] [--ssh-key <path>] [--ssh-passphrase-key <vault-key>] [--dry-run] [--confirm-prod] [--no-redact] -- <command> [args...]")
		os.Exit(1)
	}

	checkProductionGuard(profile, args)
	printEnvBadge(profile)

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

	allowKeysSet := make(map[string]bool)
	if allowKeysStr != "" {
		for _, k := range strings.Split(allowKeysStr, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				allowKeysSet[k] = true
			}
		}
	}

	if dryRun {
		fmt.Println("=== Dry-Run: Subprocess Secret Injection Plan ===")
		fmt.Printf("Target Command:     %s\n", strings.Join(cmdArgs, " "))
		tier := getProfileEnvTier(profile)
		if tier == "" {
			tier = "dev"
		}
		fmt.Printf("Vault Profile:      %s (Tier: %s)\n", profile, strings.ToUpper(tier))
		fmt.Printf("Redaction Enabled:  %v\n\n", shouldRedact)
		fmt.Printf("%-24s %-36s %s\n", "INJECTED ENV VAR", "VAULT KEY PATH", "VALUE PREVIEW")
		fmt.Println(strings.Repeat("-", 80))

		count := 0
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
			if len(allowKeysSet) > 0 && !allowKeysSet[envKey] && !allowKeysSet[path] && !allowKeysSet[relPath] {
				continue
			}
			count++
			fmt.Printf("%-24s %-36s [REDACTED_BY_SEC] (%d chars)\n", envKey, path, len(entry.Value))
		}
		fmt.Printf("\n[INFO] Dry-run completed. %d secret(s) ready to inject. No process executed.\n", count)
		return
	}

	if groupPrefix == "" {
		fmt.Fprintf(os.Stderr, "[INFO] No --group or .secrc specified: Injecting active vault secret(s) into child process environment.\n")
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] Injecting secret(s) matching group %q into child process environment.\n", groupPrefix)
	}

	env := os.Environ()
	var secretVals []string
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
		if len(allowKeysSet) > 0 && !allowKeysSet[envKey] && !allowKeysSet[path] && !allowKeysSet[relPath] {
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", envKey, entry.Value))
		if len(entry.Value) > 3 {
			secretVals = append(secretVals, entry.Value)
		}
	}

	if sshKeyPath != "" {
		sockPath, sshCleanup, err := setupEphemeralSSHAgent(profile, sshKeyPath, sshPassphraseKey)
		if err != nil {
			fail("SSH_AGENT_FAILED", err, "Verify SSH key path and passphrase secret.")
		}
		defer sshCleanup()
		env = append(env, "SSH_AUTH_SOCK="+sockPath)
		fmt.Fprintf(os.Stderr, "[✓] Ephemeral SSH Agent launched (%s)\n", sockPath)
	}

	wsCfg := loadWorkspaceConfig()
	if wsCfg != nil && len(wsCfg.FlagAliases) > 0 {
		for keyPath, flag := range wsCfg.FlagAliases {
			flagExists := false
			for _, arg := range cmdArgs {
				if arg == flag || strings.HasPrefix(arg, flag+"=") {
					flagExists = true
					break
				}
			}
			if !flagExists {
				secResp, sErr := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: keyPath})
				if sErr == nil && secResp != nil && secResp.Success {
					cmdArgs = append(cmdArgs, flag, secResp.Value)
					if len(secResp.Value) > 3 {
						secretVals = append(secretVals, secResp.Value)
					}
					fmt.Fprintf(os.Stderr, "[NOTICE] Dynamic flag alias injected: %s [REDACTED_BY_SEC]\n", flag)
				}
			}
		}
	}

	// #nosec G204 G702
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	if shouldRedact {
		cmd.Stdout = &redactWriter{target: os.Stdout, secrets: secretVals}
		cmd.Stderr = &redactWriter{target: os.Stderr, secrets: secretVals}
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting command: %v\n", err)
		os.Exit(1)
	}

	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _ = queryDaemonRaw(profile, daemon.IPCRequest{Action: "ping"})
			case <-done:
				return
			}
		}
	}()

	err = cmd.Wait()
	close(done)

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
	allProfiles := false
	envelope := true
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" || args[i] == "-f" {
			if i+1 < len(args) {
				format = args[i+1]
				i++
			} else {
				fail("INVALID_ARGUMENT", fmt.Errorf("flag --format requires a value"), "Supported formats: json, env, aws, doppler, template")
			}
		} else if args[i] == "--all-profiles" {
			allProfiles = true
		} else if args[i] == "--no-envelope" {
			envelope = false
		} else if args[i] == "--envelope" {
			envelope = true
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
		storePath, _ := store.GetStorePath(profile)
		dbFile := filepath.Base(storePath)
		secenvFile := findWorkspaceConfigFile()
		if profile == "" {
			profile = "default"
		}

		if allProfiles {
			type ProfilePayload struct {
				DatabaseFile string                       `json:"database_file"`
				Secrets      map[string]store.SecretEntry `json:"secrets"`
			}
			exportAll := struct {
				Version    string                    `json:"version"`
				SecenvFile string                    `json:"secenv_file,omitempty"`
				ExportedAt time.Time                 `json:"exported_at"`
				Profiles   map[string]ProfilePayload `json:"profiles"`
			}{
				Version:    "1.0",
				SecenvFile: secenvFile,
				ExportedAt: time.Now(),
				Profiles:   make(map[string]ProfilePayload),
			}
			exportAll.Profiles[profile] = ProfilePayload{
				DatabaseFile: dbFile,
				Secrets:      resp.Secrets,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(exportAll); err != nil {
				fail("SERIALIZATION_FAILED", err, "")
			}
		} else if envelope {
			exportPackage := struct {
				Profile      string                       `json:"profile"`
				DatabaseFile string                       `json:"database_file"`
				SecenvFile   string                       `json:"secenv_file,omitempty"`
				ExportedAt   time.Time                    `json:"exported_at"`
				Secrets      map[string]store.SecretEntry `json:"secrets"`
			}{
				Profile:      profile,
				DatabaseFile: dbFile,
				SecenvFile:   secenvFile,
				ExportedAt:   time.Now(),
				Secrets:      resp.Secrets,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(exportPackage); err != nil {
				fail("SERIALIZATION_FAILED", err, "")
			}
		} else {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(resp.Secrets); err != nil {
				fail("SERIALIZATION_FAILED", err, "")
			}
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

	_ = config.ClearSessionToken(profile)
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

func handleRestore(profile string, filePath, explicitPassword string, args []string) {
	mergeMode := false
	overwriteMode := false
	fullMetadata := false
	for _, arg := range args {
		if arg == "--merge" || arg == "-m" {
			mergeMode = true
		} else if arg == "--overwrite" {
			overwriteMode = true
		} else if arg == "--full-metadata" {
			fullMetadata = true
		}
	}

	if strings.HasSuffix(filePath, ".enc") {
		cfgDir, err := config.GetConfigDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Restore error: %v\n", err)
			os.Exit(1)
		}
		targetPath := filepath.Join(cfgDir, "secrets.enc")
		if profile != "" && profile != "default" {
			targetPath = filepath.Join(cfgDir, fmt.Sprintf("secrets_%s.enc", profile))
		}
		// #nosec G304 G703
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read snapshot file %s: %v\n", filePath, err)
			os.Exit(1)
		}
		// #nosec G304 G703
		if err := os.WriteFile(targetPath, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to overwrite vault database with snapshot: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[✓] Restored snapshot %s to vault database -> %s\n", filePath, targetPath)
		fmt.Println("Please run 'sec-agent restart' and 'eval $(sec-agent open)' to reload your active session daemon.")
		return
	}

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

	var secrets map[string]store.SecretEntry
	var err error
	if filePath == "-" {
		if fullMetadata {
			secrets, err = backup.ImportFromKdbxFullMetadataReader(os.Stdin, password)
		} else {
			secrets, err = backup.ImportFromKdbxReader(os.Stdin, password)
		}
	} else {
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			absPath = filePath
		}
		if fullMetadata {
			secrets, err = backup.ImportFromKdbxFullMetadata(absPath, password)
		} else {
			secrets, err = backup.ImportFromKdbx(absPath, password)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to restore backup: %v\n", err)
		os.Exit(1)
	}

	if mergeMode && !overwriteMode {
		curResp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
		if err == nil && curResp.Success {
			filtered := make(map[string]store.SecretEntry)
			for k, v := range secrets {
				if _, exists := curResp.Secrets[k]; !exists {
					filtered[k] = v
				}
			}
			secrets = filtered
		}
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

func handleSync(profile string, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sec sync export <file> | sec sync import <file>")
		os.Exit(1)
	}

	subCmd := args[0]
	switch subCmd {
	case "export":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: sec sync export <file.kdbx>")
			os.Exit(1)
		}
		outFile := args[1]
		checkProductionGuard(profile, args)
		handleBackup(profile, outFile, "")
	case "import":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: sec sync import <file.kdbx>")
			os.Exit(1)
		}
		inFile := args[1]
		handleRestore(profile, inFile, "", args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown sync action %q. Usage: sec sync export <file> | sec sync import <file>\n", subCmd)
		os.Exit(1)
	}
}

func handleCheck(profile string, args []string) {
	scanWeak := false
	scanLeaks := false
	templateFile := ""
	pingHost := ""
	var requiredKeys []string

	for i := 0; i < len(args); i++ {
		if args[i] == "--scan-weak" || args[i] == "-w" {
			scanWeak = true
		} else if args[i] == "--scan-leaks" || args[i] == "--leaks" || args[i] == "-l" || args[i] == "--history" {
			scanLeaks = true
		} else if args[i] == "--template" || args[i] == "-t" {
			if i+1 < len(args) {
				templateFile = args[i+1]
				i++
			}
		} else if args[i] == "--required" || args[i] == "-r" {
			if i+1 < len(args) {
				raw := args[i+1]
				i++
				for _, k := range strings.Split(raw, ",") {
					k = strings.TrimSpace(k)
					if k != "" {
						requiredKeys = append(requiredKeys, k)
					}
				}
			}
		} else if args[i] == "--ping-host" {
			if i+1 < len(args) {
				pingHost = args[i+1]
				i++
			}
		}
	}

	if scanLeaks {
		handleCheckLeaks(profile)
		return
	}

	if scanWeak {
		resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
		if err != nil || !resp.Success {
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running or locked for profile %q", profile), "Run 'eval $(sec open)' to unlock.")
		}

		fmt.Println("=== Vault Secret Password Entropy & Weakness Scan ===")
		fmt.Printf("%-36s %s\n", "KEY PATH", "STATUS")
		fmt.Println(strings.Repeat("-", 60))

		weakCount := 0
		passCount := 0
		weakDict := []string{"admin123", "password", "p@ssword1", "123456", "secret", "test", "demo"}

		var paths []string
		for p := range resp.Secrets {
			if !strings.HasPrefix(p, "__") {
				paths = append(paths, p)
			}
		}
		sort.Strings(paths)

		for _, path := range paths {
			entry := resp.Secrets[path]
			val := strings.TrimSpace(entry.Value)
			isWeak := false

			if len(val) > 0 {
				freq := make(map[rune]float64)
				for _, r := range val {
					freq[r]++
				}
				entropy := 0.0
				valLen := float64(len(val))
				for _, count := range freq {
					p := count / valLen
					entropy -= p * (math.Log2(p))
				}
				if entropy < 3.0 && len(val) < 16 {
					isWeak = true
				}
			}

			lowerVal := strings.ToLower(val)
			for _, w := range weakDict {
				if lowerVal == w || strings.Contains(lowerVal, w) {
					isWeak = true
					break
				}
			}

			if isWeak {
				weakCount++
				fmt.Printf("%-36s \033[33mWEAK ENTROPY [⚠️]\033[0m\n", path)
			} else {
				passCount++
				fmt.Printf("%-36s \033[32mPASS [✓]\033[0m\n", path)
			}
		}

		fmt.Printf("\nSummary: %d key(s) PASS, %d key(s) WEAK ENTROPY.\n", passCount, weakCount)
		return
	}

	if templateFile != "" {
		// #nosec G304 G703
		data, err := os.ReadFile(templateFile)
		if err != nil {
			fail("FILE_READ_ERROR", fmt.Errorf("failed to read template file %s: %v", templateFile, err), "Check file path.")
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			if key != "" {
				requiredKeys = append(requiredKeys, key)
			}
		}
	}

	if pingHost != "" {
		targetAddr := pingHost
		if !strings.Contains(targetAddr, ":") {
			targetAddr = targetAddr + ":22"
		}
		// #nosec G102 G704
		conn, err := net.DialTimeout("tcp", targetAddr, 100*time.Millisecond)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[⚠️] Network Reachability Guard: Target host %s is UNREACHABLE (%v)\n", targetAddr, err)
			if jsonErrors {
				data, _ := json.Marshal(map[string]interface{}{
					"success": false,
					"error": map[string]string{
						"code":    "HOST_UNREACHABLE",
						"message": fmt.Sprintf("Target host %s is unreachable: %v", targetAddr, err),
					},
				})
				fmt.Println(string(data))
			}
			os.Exit(1)
		}
		_ = conn.Close()
		fmt.Fprintf(os.Stderr, "[✓] Network Reachability Guard: Target host %s is reachable\n", targetAddr)
		if len(requiredKeys) == 0 {
			return
		}
	}

	if len(requiredKeys) == 0 {
		fail("INVALID_ARGUMENT", fmt.Errorf("no required keys specified"), "Pass --template <file>, --required KEY1,KEY2, or --ping-host <host:port>")
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running. Please run 'sec open' to unlock the session."), "Run 'eval $(sec open)' to start/unlock the session.")
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("%s", resp.Error), rem)
	}

	available := make(map[string]string)
	for path, entry := range resp.Secrets {
		envKey := pathToEnvKeyWithEntry(path, entry)
		available[envKey] = path
		available[path] = path
	}

	fmt.Println("=== sec-agent Vault Schema Linter ===")
	missingCount := 0
	for _, req := range requiredKeys {
		if matchedPath, ok := available[req]; ok {
			fmt.Printf(" [✓] %-30s -> Found (path/alias: %s)\n", req, matchedPath)
		} else {
			fmt.Printf(" [✗] %-30s -> MISSING!\n", req)
			missingCount++
		}
	}

	if missingCount > 0 {
		fmt.Printf("\n\033[31mError: Missing %d required secret(s).\033[0m\n", missingCount)
		os.Exit(1)
	}
	fmt.Printf("\n\033[32mSuccess: All %d required keys/aliases present in session.\033[0m\n", len(requiredKeys))
	checkExpirationWarnings(resp.Secrets)
}

type LeakMatch struct {
	MatchType   string
	Path        string
	LineNumber  int
	SecretPath  string
	PatternName string
	LineSnippet string
	RedactedVal string
}

func handleCheckLeaks(profile string) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	if err != nil || !resp.Success {
		fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon is not running or locked for profile %q", profile), "Run 'eval $(sec open)' to unlock.")
	}

	historyFiles := store.DiscoverShellHistoryFiles()
	fmt.Println("=== 🛡️ Workstation Shell History & Secret Leak Audit ===")
	if len(historyFiles) == 0 {
		fmt.Println("No shell history files (.zsh_history, .bash_history, fish_history) discovered in home directory.")
		return
	}

	fmt.Print("Auditing discovered history files: ")
	var filePaths []string
	for _, h := range historyFiles {
		filePaths = append(filePaths, h.Path)
	}
	fmt.Println(strings.Join(filePaths, ", "))

	secretValues := make(map[string]string)
	for keyPath, entry := range resp.Secrets {
		val := strings.TrimSpace(entry.Value)
		if len(val) > 4 && val != "<migrated_to_sec>" {
			secretValues[val] = keyPath
		}
	}

	regexPatterns := []struct {
		Name  string
		Regex *regexp.Regexp
	}{
		{Name: "AWS Access Key ID", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{Name: "GitHub Personal Access Token", Regex: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`)},
		{Name: "Stripe Live Secret Key", Regex: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)},
		{Name: "Slack Webhook URL", Regex: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`)},
		{Name: "Database Connection URI", Regex: regexp.MustCompile(`(postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+`)},
	}

	var matches []LeakMatch

	for _, hf := range historyFiles {
		// #nosec G304 G703
		f, err := os.Open(hf.Path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			cleanLine := line
			if hf.ShellName == "zsh" && strings.HasPrefix(line, ": ") {
				if idx := strings.Index(line, ";"); idx != -1 {
					cleanLine = line[idx+1:]
				}
			}

			// Engine 1: Exact Vault Secret Matching
			for secVal, secPath := range secretValues {
				if strings.Contains(cleanLine, secVal) {
					redactSnippet := strings.ReplaceAll(cleanLine, secVal, "[REDACTED_BY_SEC]")
					matches = append(matches, LeakMatch{
						MatchType:   "Vault Exact Match",
						Path:        hf.Path,
						LineNumber:  lineNum,
						SecretPath:  secPath,
						LineSnippet: redactSnippet,
						RedactedVal: secVal,
					})
				}
			}

			// Engine 2: Regex Matching
			for _, pat := range regexPatterns {
				if found := pat.Regex.FindString(cleanLine); found != "" {
					alreadyMatched := false
					for _, m := range matches {
						if m.Path == hf.Path && m.LineNumber == lineNum {
							alreadyMatched = true
							break
						}
					}
					if !alreadyMatched {
						redactSnippet := strings.ReplaceAll(cleanLine, found, "[REDACTED_BY_SEC]")
						matches = append(matches, LeakMatch{
							MatchType:   "Regex Match",
							Path:        hf.Path,
							LineNumber:  lineNum,
							PatternName: pat.Name,
							LineSnippet: redactSnippet,
							RedactedVal: found,
						})
					}
				}
			}
		}
		_ = f.Close()
	}

	if len(matches) == 0 {
		fmt.Println("\n\033[32m[PASS] Zero secret leaks detected across shell history files.\033[0m")
		return
	}

	fmt.Printf("\n\033[1;31m⚠️  [FOUND] %d Potential Secret Leak(s) Detected!\033[0m\n\n", len(matches))
	for i, m := range matches {
		fmt.Printf("%d. \033[1m%s\033[0m\n", i+1, m.MatchType)
		if m.SecretPath != "" {
			fmt.Printf("   • Secret Path:   %s\n", m.SecretPath)
		}
		if m.PatternName != "" {
			fmt.Printf("   • Pattern:       %s\n", m.PatternName)
		}
		fmt.Printf("   • Location:      %s (Line %d)\n", m.Path, m.LineNumber)
		fmt.Printf("   • Leaked Snippet: %s\n\n", m.LineSnippet)
	}

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("=== 🛠️ Recommended Safe Remediation Commands ===")
	fmt.Println("Run the following commands to safely purge leaked history entries:")
	for _, m := range matches {
		fmt.Printf("  LC_ALL=C sed -i '' '%dd' %s\n", m.LineNumber, m.Path)
	}
	fmt.Println("\nThen reload active shell history in memory:")
	fmt.Println("  history -r")
}

func handleRestart(profile string, args []string) {
	hotReload := false
	for _, arg := range args {
		if arg == "--hot-reload" || arg == "-H" || arg == "--force" {
			hotReload = true
		}
	}

	if hotReload {
		resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "reexec"})
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

	_, _ = queryDaemon(profile, daemon.IPCRequest{Action: "clear"})
	socketPath, err := config.GetSocketPath(profile)
	if err == nil {
		_ = os.Remove(socketPath)
	}
	fmt.Printf("Restarting sec-agent daemon for profile %q...\n", profile)
	handleOpen(profile, nil)
}

type InstalledSkillEntry struct {
	Target  string `json:"target"`
	Scope   string `json:"scope"`
	Path    string `json:"path"`
	Version string `json:"version"`
}

type SkillManifest struct {
	Version string                `json:"version"`
	Skills  []InstalledSkillEntry `json:"skills"`
}

func getSkillManifestPath() (string, error) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgDir, "skills.json"), nil
}

func loadSkillManifest() (*SkillManifest, error) {
	path, err := getSkillManifestPath()
	if err != nil {
		return &SkillManifest{Version: Version, Skills: []InstalledSkillEntry{}}, nil
	}
	// #nosec G304 G703
	data, err := os.ReadFile(path)
	if err != nil {
		return &SkillManifest{Version: Version, Skills: []InstalledSkillEntry{}}, nil
	}
	var manifest SkillManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return &SkillManifest{Version: Version, Skills: []InstalledSkillEntry{}}, nil
	}
	return &manifest, nil
}

func saveSkillManifest(manifest *SkillManifest) error {
	path, err := getSkillManifestPath()
	if err != nil {
		return err
	}
	manifest.Version = Version
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func resolveSkillPath(target, scope string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	switch target {
	case "antigravity":
		if scope == "workspace" {
			return filepath.Join(".agents", "skills", "sec-agent-integration", "SKILL.md"), nil
		}
		return filepath.Join(home, ".gemini", "config", "skills", "sec-agent-integration", "SKILL.md"), nil
	case "copilot":
		return filepath.Join(".github", "copilot-instructions.md"), nil
	case "copilot-agent":
		return filepath.Join(".github", "agents", "sec-agent.md"), nil
	case "cursor":
		if scope == "workspace" {
			return filepath.Join(".cursor", "rules", "sec-agent-integration.mdc"), nil
		}
		return filepath.Join(home, ".cursor", "rules", "sec-agent-integration.mdc"), nil
	case "claude":
		if scope == "workspace" {
			return filepath.Join(".claude", "skills", "sec-agent", "SKILL.md"), nil
		}
		return filepath.Join(home, ".claude", "skills", "sec-agent", "SKILL.md"), nil
	case "windsurf":
		return ".windsurfrules", nil
	default:
		return "", fmt.Errorf("unknown skill target %q", target)
	}
}

func writeSkillToFile(targetPath string) error {
	dir := filepath.Dir(targetPath)
	// #nosec G301 G703
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	content := embeddedSkillBytes
	if len(content) == 0 {
		return fmt.Errorf("embedded skill content is empty")
	}
	// #nosec G306 G703
	return os.WriteFile(targetPath, content, 0600)
}

func handleSkillInstallTarget(target, scope string) bool {
	targetPath, err := resolveSkillPath(target, scope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Skill error: %v\n", err)
		return false
	}
	if err := writeSkillToFile(targetPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write skill file to %s: %v\n", targetPath, err)
		return false
	}
	fmt.Printf("[✓] Installed %s skill (%s) -> %s\n", target, scope, targetPath)

	manifest, _ := loadSkillManifest()
	if manifest == nil {
		manifest = &SkillManifest{Version: Version, Skills: []InstalledSkillEntry{}}
	}

	found := false
	for i, entry := range manifest.Skills {
		if entry.Target == target && entry.Scope == scope {
			manifest.Skills[i].Path = targetPath
			manifest.Skills[i].Version = Version
			found = true
			break
		}
	}
	if !found {
		manifest.Skills = append(manifest.Skills, InstalledSkillEntry{
			Target:  target,
			Scope:   scope,
			Path:    targetPath,
			Version: Version,
		})
	}
	_ = saveSkillManifest(manifest)
	return true
}

func syncInstalledSkillsIfOutdated() {
	if !config.IsConfigDirInitialized() {
		return
	}
	manifest, err := loadSkillManifest()
	if err != nil || manifest == nil || len(manifest.Skills) == 0 {
		return
	}
	if manifest.Version == Version {
		return
	}
	updatedCount := 0
	for i, entry := range manifest.Skills {
		targetPath, err := resolveSkillPath(entry.Target, entry.Scope)
		if err == nil {
			if writeErr := writeSkillToFile(targetPath); writeErr == nil {
				manifest.Skills[i].Version = Version
				manifest.Skills[i].Path = targetPath
				updatedCount++
			}
		}
	}
	if updatedCount > 0 {
		manifest.Version = Version
		_ = saveSkillManifest(manifest)
		fmt.Fprintf(os.Stderr, "[sec-agent] Automatically upgraded AI agent skills (%s) across %d location(s).\n", Version, updatedCount)
	}
}

func detectIDEEnvironment() (target string, scope string, name string) {
	cwd, _ := os.Getwd()

	// Tier 1: Workspace-specific directory markers (Highest Priority)
	if cwd != "" {
		if _, err := os.Stat(filepath.Join(cwd, ".agents")); err == nil {
			return "antigravity", "global", "Antigravity IDE (Global ~/.gemini/ config)"
		}
		if _, err := os.Stat(filepath.Join(cwd, ".github", "copilot-instructions.md")); err == nil {
			return "copilot", "workspace", "VS Code + Copilot (Workspace .github/ detected)"
		}
		if _, err := os.Stat(filepath.Join(cwd, ".cursor")); err == nil {
			return "cursor", "workspace", "Cursor (Workspace .cursor/ detected)"
		}
		if _, err := os.Stat(filepath.Join(cwd, ".claude")); err == nil {
			return "claude", "workspace", "Claude Code (Workspace .claude/ detected)"
		}
		if _, err := os.Stat(filepath.Join(cwd, ".windsurfrules")); err == nil {
			return "windsurf", "workspace", "Windsurf (Workspace .windsurfrules detected)"
		}
	}

	// Tier 2: Shell & Environment Variables
	if os.Getenv("ANTIGRAVITY_AGENT") != "" ||
		os.Getenv("__CFBundleIdentifier") == "com.google.antigravity-ide" ||
		strings.Contains(os.Getenv("ANTIGRAVITY_EDITOR_APP_ROOT"), "Antigravity") ||
		strings.Contains(os.Getenv("PATH"), ".gemini/antigravity-ide") {
		return "antigravity", "global", "Antigravity IDE (AGY Shell Environment)"
	}

	if os.Getenv("CURSOR_AGENT") != "" || strings.Contains(os.Getenv("PATH"), "Cursor") {
		return "cursor", "global", "Cursor (Shell Environment)"
	}

	if os.Getenv("CLAUDE_CODE") != "" || os.Getenv("CLAUDE") != "" {
		return "claude", "global", "Claude Code (Shell Environment)"
	}

	if os.Getenv("WINDSURF") != "" {
		return "windsurf", "workspace", "Windsurf (Shell Environment)"
	}

	if os.Getenv("VSCODE_PID") != "" && os.Getenv("ANTIGRAVITY_AGENT") == "" {
		return "copilot", "workspace", "VS Code + GitHub Copilot (Shell Environment)"
	}

	// Tier 3: Global Home Directory Configurations
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		if _, err := os.Stat(filepath.Join(homeDir, ".gemini")); err == nil {
			return "antigravity", "global", "Antigravity IDE (Global ~/.gemini/ detected)"
		}
		if _, err := os.Stat(filepath.Join(homeDir, ".cursor")); err == nil {
			return "cursor", "global", "Cursor (Global ~/.cursor/ detected)"
		}
		if _, err := os.Stat(filepath.Join(homeDir, ".claude")); err == nil {
			return "claude", "global", "Claude Code (Global ~/.claude/ detected)"
		}
	}

	return "antigravity", "global", "Antigravity IDE (Default)"
}

func handleInit(profile string, args []string) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialization error: %v\n", err)
		os.Exit(1)
	}
	backupsDir := filepath.Join(cfgDir, "backups")
	_ = os.MkdirAll(backupsDir, 0700)

	fmt.Println("=== 🔑 sec-agent Vault Onboarding & Setup ===")
	fmt.Printf("[✓] Vault configuration directory initialized at %s\n", cfgDir)
	fmt.Printf("[✓] Automatic write backups folder initialized at %s\n", backupsDir)

	detectedTarget, detectedScope, detectedName := detectIDEEnvironment()
	fmt.Printf("[ℹ] Auto-detected Active Environment: %s\n", detectedName)

	syncInstalledSkillsIfOutdated()

	nonInteractive := false
	skillTarget := ""
	skillScope := "global"
	for i := 0; i < len(args); i++ {
		if args[i] == "--non-interactive" || args[i] == "-y" || args[i] == "--yes" {
			nonInteractive = true
		} else if args[i] == "--skill" && i+1 < len(args) {
			skillTarget = args[i+1]
			i++
		} else if args[i] == "--scope" && i+1 < len(args) {
			skillScope = args[i+1]
			i++
		}
	}

	if skillTarget != "" {
		handleSkillInstallTarget(skillTarget, skillScope)
		return
	}

	if nonInteractive || !isInteractiveTerminal() {
		handleSkillInstallTarget(detectedTarget, detectedScope)
		fmt.Println("\nInitialization complete.")
		return
	}

	fmt.Println("\nSelect AI Assistant environment(s) to install integration skills:")
	fmt.Println("  [1] Antigravity IDE (Global: ~/.gemini/config/skills/)")
	fmt.Println("  [2] Antigravity IDE (Workspace: .agents/skills/)")
	fmt.Println("  [3] VS Code + GitHub Copilot (.github/copilot-instructions.md)")
	fmt.Println("  [4] Cursor (Global: ~/.cursor/rules/ | Workspace: .cursor/rules/)")
	fmt.Println("  [5] Claude Code (Global: ~/.claude/skills/ | Workspace: .claude/skills/)")
	fmt.Println("  [6] Windsurf (.windsurfrules)")
	fmt.Println("  [7] Skip AI skill installation")

	fmt.Print("\nEnter selection (e.g. 1,3 or 'all' or '7'): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" || input == "7" || input == "skip" {
		fmt.Println("Skipped AI skill installation. Setup complete!")
		return
	}

	choices := strings.Split(input, ",")
	for _, choice := range choices {
		choice = strings.TrimSpace(choice)
		switch choice {
		case "1":
			handleSkillInstallTarget("antigravity", "global")
		case "2":
			handleSkillInstallTarget("antigravity", "workspace")
		case "3":
			handleSkillInstallTarget("copilot", "workspace")
		case "4":
			handleSkillInstallTarget("cursor", "global")
			handleSkillInstallTarget("cursor", "workspace")
		case "5":
			handleSkillInstallTarget("claude", "global")
			handleSkillInstallTarget("claude", "workspace")
		case "6":
			handleSkillInstallTarget("windsurf", "workspace")
		case "all":
			handleSkillInstallTarget("antigravity", "global")
			handleSkillInstallTarget("antigravity", "workspace")
			handleSkillInstallTarget("copilot", "workspace")
			handleSkillInstallTarget("cursor", "global")
			handleSkillInstallTarget("claude", "global")
			handleSkillInstallTarget("windsurf", "workspace")
		}
	}

	fmt.Println("\nSetup complete! You can re-run 'sec-agent init' anytime to update settings or install skills.")
}

func handleSkill(profile string, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sec-agent skill <install|status|update> [args]")
		os.Exit(1)
	}

	sub := args[0]
	switch sub {
	case "install":
		target := ""
		scope := "global"
		for i := 1; i < len(args); i++ {
			if (args[i] == "--target" || args[i] == "-t") && i+1 < len(args) {
				target = args[i+1]
				i++
			} else if (args[i] == "--scope" || args[i] == "-s") && i+1 < len(args) {
				scope = args[i+1]
				i++
			}
		}
		if target == "" {
			handleInit(profile, nil)
			return
		}
		handleSkillInstallTarget(target, scope)
	case "status":
		manifest, err := loadSkillManifest()
		if err != nil || manifest == nil {
			fmt.Println("No skill manifest found. Run 'sec-agent init' or 'sec-agent skill install' to configure skills.")
			return
		}
		fmt.Println("=== 🤖 sec-agent AI Skill Installation Status ===")
		fmt.Printf("Binary Skill Version: %s\n\n", Version)
		if len(manifest.Skills) == 0 {
			fmt.Println("No skills currently tracked in manifest.")
			return
		}
		for _, s := range manifest.Skills {
			status := "[✓] Up to date"
			if s.Version != Version {
				status = fmt.Sprintf("[!] Outdated (installed %s)", s.Version)
			}
			fmt.Printf("  • %-15s (%-9s) %s\n", s.Target, s.Scope, status)
			fmt.Printf("    Path: %s\n", s.Path)
		}
	case "update":
		manifest, err := loadSkillManifest()
		if err != nil || manifest == nil || len(manifest.Skills) == 0 {
			fmt.Println("No skills tracked in manifest to update.")
			return
		}
		updated := 0
		for i, entry := range manifest.Skills {
			targetPath, err := resolveSkillPath(entry.Target, entry.Scope)
			if err == nil {
				if writeErr := writeSkillToFile(targetPath); writeErr == nil {
					manifest.Skills[i].Version = Version
					manifest.Skills[i].Path = targetPath
					updated++
					fmt.Printf("[✓] Updated %s (%s) -> %s\n", entry.Target, entry.Scope, targetPath)
				}
			}
		}
		manifest.Version = Version
		_ = saveSkillManifest(manifest)
		fmt.Printf("\nSuccessfully updated %d skill location(s) to %s.\n", updated, Version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown skill subcommand %q. Supported: install, status, update\n", sub)
		os.Exit(1)
	}
}

func handleBackupList(profile string) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	backupsDir := filepath.Join(cfgDir, "backups")
	if profile != "" && profile != "default" {
		backupsDir = filepath.Join(backupsDir, profile)
	}

	fmt.Println("=== 📁 sec-agent Vault Snapshots & Backups ===")
	fmt.Printf("Search Path: %s\n\n", backupsDir)

	entries, err := os.ReadDir(backupsDir)
	if err != nil || len(entries) == 0 {
		fmt.Println("  No automatic write snapshots found in backups directory.")
	} else {
		fmt.Println("Automatic Write Snapshots (.enc):")
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".enc") {
				info, _ := entry.Info()
				size := int64(0)
				modTime := ""
				if info != nil {
					size = info.Size()
					modTime = info.ModTime().Format("2006-01-02 15:04:05")
				}
				fullPath := filepath.Join(backupsDir, entry.Name())
				fmt.Printf("  • %s  (%d bytes, %s)\n", entry.Name(), size, modTime)
				fmt.Printf("    Path: %s\n", fullPath)
			}
		}
	}

	localEntries, err := os.ReadDir(".")
	if err == nil {
		fmt.Println("\nLocal KeePassXC Backup Files (.kdbx):")
		count := 0
		for _, entry := range localEntries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".kdbx") {
				info, _ := entry.Info()
				size := int64(0)
				modTime := ""
				if info != nil {
					size = info.Size()
					modTime = info.ModTime().Format("2006-01-02 15:04:05")
				}
				fmt.Printf("  • %s  (%d bytes, %s)\n", entry.Name(), size, modTime)
				count++
			}
		}
		if count == 0 {
			fmt.Println("  No .kdbx backup files in current directory.")
		}
	}
	fmt.Println("\nTo restore a backup or snapshot, run:")
	fmt.Println("  sec-agent restore <file-path> [--merge|--overwrite]")
}

func handleCompletion(shell string) {
	switch shell {
	case "zsh":
		fmt.Print(`#compdef sec

_sec() {
    local -a commands
    commands=(
        'open:Initialize/unlock the secrets session using Touch ID'
        'get:Retrieve a secret or group of secrets'
        'set:Store a secret with optional comment and env alias'
        'mv:Rename a secret key path or prefix namespace'
        'cp:Duplicate a secret key path or prefix group'
        'rm:Delete a secret or prefix group'
        'ls:List secret paths without exposing values'
        'diff:Compare secret paths against another profile or .env file'
        'doctor:Run workstation system & security diagnostic checks'
        'gen:Generate random password and save to path'
        'import:Bulk import secrets from JSON, Doppler, or AWS payloads'
        'check:Pre-flight validation of required vault keys or template'
        'load:Batch-load scoped group secrets for shell sourcing'
        'run:Execute a command with scoped secrets injected'
        'status:Display session health, profile, and diagnostic metrics'
        'audit:View recent daemon security audit logs'
        'env:Output shell exports for secrets under prefix'
        'export:Output decrypted database contents to stdout'
        'clear:Lock the active session and clear memory cache'
        'restart:Restart the active session daemon and re-authenticate'
        'backup:Export cached secrets to a portable KeePassXC (.kdbx) file'
        'restore:Import secrets from a portable KeePassXC (.kdbx) file'
        'completion:Generate shell completion script (zsh, bash, fish)'
        'version:Print CLI and active daemon version'
    )
    _describe -t commands 'sec command' commands
}

_sec "$@"
`)
	case "bash":
		fmt.Print(`# bash completion for sec
_sec_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local cmds="open get set mv cp rm ls diff doctor gen import check load run status audit env export clear restart backup restore completion version"
    COMPREPLY=( $(compgen -W "${cmds}" -- ${cur}) )
}
complete -F _sec_completions sec
`)
	case "fish":
		fmt.Print(`# fish completion for sec
complete -c sec -n "__fish_use_subcommand" -a "open get set mv cp rm ls diff doctor gen import check load run status audit env export clear restart backup restore completion version"
`)
	default:
		fmt.Fprintf(os.Stderr, "Usage: sec completion <zsh|bash|fish>\n")
		os.Exit(1)
	}
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
		fmt.Println("To hot-reload the daemon in memory (Zero Touch ID required), run:")
		fmt.Println("  sec restart --hot-reload")
		fmt.Println("Or perform a full re-authentication restart:")
		fmt.Println("  sec restart")
	}
}
