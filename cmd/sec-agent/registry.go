package main

import (
	"fmt"
	"os"
	"strconv"
)

type CommandHandler func(profile string, args []string)

type SubcommandSpec struct {
	Name        string
	Aliases     []string
	Description string
	Flags       []string
}

type CommandSpec struct {
	Name        string
	Aliases     []string
	Category    string // "Session & Setup", "Core Secrets", "Profiles & Scope", "Security & Maintenance", "Backup & Migration", "System"
	Description string
	Usage       string
	Subcommands []SubcommandSpec
	Flags       []string
	ExpectsKeys bool
	Handler     CommandHandler
}

var CommandRegistry []CommandSpec

func initRegistry() {
	CommandRegistry = []CommandSpec{
		{
			Name:        "open",
			Category:    "Session & Setup",
			Description: "Initialize/unlock the secrets session using Touch ID",
			Usage:       "sec open [--ttl <duration>] [--grace <duration>]",
			Handler:     handleOpen,
		},
		{
			Name:        "init",
			Aliases:     []string{"setup"},
			Category:    "Session & Setup",
			Description: "Initialize vault configuration & install AI skills",
			Usage:       "sec init [--vault] [--skill <target>] [--scope <global|workspace>]",
			Flags:       []string{"--vault", "--skill", "--scope", "--non-interactive"},
			Handler:     handleInit,
		},
		{
			Name:        "prompt",
			Category:    "Session & Setup",
			Description: "Output formatted shell prompt status indicator (<5ms probe)",
			Usage:       "sec prompt [--format plain|starship|p10k] [--profile <name>]",
			Flags:       []string{"--format"},
			Handler:     handlePrompt,
		},
		{
			Name:        "init-direnv",
			Category:    "Session & Setup",
			Description: "Install native 'use sec-agent' helper into ~/.config/direnv/direnvrc",
			Usage:       "sec init-direnv",
			Handler: func(profile string, args []string) {
				handleInitDirenv()
			},
		},
		{
			Name:        "get",
			Category:    "Core Secrets",
			Description: "Retrieve a secret or group of secrets",
			Usage:       "sec get <path> [--prefix] [--record] [--json | --comment | --meta <key>]",
			ExpectsKeys: true,
			Flags:       []string{"--copy", "--json", "--show", "--comment", "--meta"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec get <path> [--json | --comment | --meta <key>]")
					os.Exit(1)
				}
				handleGet(profile, args[0], args[1:])
			},
		},
		{
			Name:        "set",
			Category:    "Core Secrets",
			Description: "Store a secret with optional comment and env alias",
			Usage:       "sec set <path> [<value>] [--stdin] [--comment <comment>] [--meta key=value ...]",
			Flags:       []string{"--comment", "--meta", "--stdin", "--env-alias"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec set <path> [<value>] [--stdin] [--comment <comment>] [--meta key=value ...]")
					os.Exit(1)
				}
				path := args[0]
				val := ""
				remArgs := []string{}
				if len(args) >= 2 && !hasPrefix(args[1], "-") {
					val = args[1]
					remArgs = args[2:]
				} else {
					remArgs = args[1:]
				}
				handleSet(profile, path, val, remArgs)
			},
		},
		{
			Name:        "mv",
			Aliases:     []string{"rename"},
			Category:    "Core Secrets",
			Description: "Rename a secret key path or prefix namespace",
			Usage:       "sec mv <old-path> <new-path> [--prefix]",
			ExpectsKeys: true,
			Flags:       []string{"--prefix"},
			Handler: func(profile string, args []string) {
				if len(args) < 2 {
					fmt.Fprintln(os.Stderr, "Usage: sec mv <old-path> <new-path> [--prefix]")
					os.Exit(1)
				}
				handleRename(profile, args[0], args[1], args[2:])
			},
		},
		{
			Name:        "relabel",
			Aliases:     []string{"edit-meta"},
			Category:    "Core Secrets",
			Description: "Update comment, environment alias, or tags on an existing secret",
			Usage:       "sec relabel <path> [--comment <text>] [--env-alias <alias>] [--expires <ttl>] [--meta <k=v>] [--clear-alias]",
			ExpectsKeys: true,
			Flags:       []string{"--comment", "-c", "--env-alias", "-a", "--expires", "-e", "--meta", "-m", "--clear-alias"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec relabel <path> [flags]")
					os.Exit(1)
				}
				handleRelabel(profile, args[0], args[1:])
			},
		},
		{
			Name:        "cp",
			Aliases:     []string{"copy"},
			Category:    "Core Secrets",
			Description: "Duplicate a secret key path or prefix group",
			Usage:       "sec cp <src-path> <dst-path> [--prefix]",
			ExpectsKeys: true,
			Flags:       []string{"--prefix", "--from-profile", "--to-profile"},
			Handler: func(profile string, args []string) {
				if len(args) < 2 {
					fmt.Fprintln(os.Stderr, "Usage: sec cp <src-path> <dst-path> [--prefix]")
					os.Exit(1)
				}
				handleCopy(profile, args[0], args[1], args[2:])
			},
		},
		{
			Name:        "rm",
			Aliases:     []string{"delete"},
			Category:    "Core Secrets",
			Description: "Delete a secret or prefix group (soft-delete by default)",
			Usage:       "sec rm <path> [--prefix] [--permanent]",
			ExpectsKeys: true,
			Flags:       []string{"--prefix", "--permanent"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec rm <path> [--prefix] [--permanent]")
					os.Exit(1)
				}
				handleDelete(profile, args[0], args[1:])
			},
		},
		{
			Name:        "restore-deleted",
			Category:    "Core Secrets",
			Description: "Un-delete a soft-deleted secret key from the trash bin",
			Usage:       "sec restore-deleted <path>",
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec restore-deleted <path>")
					os.Exit(1)
				}
				handleRestoreDeleted(profile, args[0])
			},
		},
		{
			Name:        "ls",
			Aliases:     []string{"list"},
			Category:    "Core Secrets",
			Description: "List secret paths, trash bin, or expiring keys",
			Usage:       "sec ls [<prefix>] [--json] [--trash] [--expiring N]",
			Flags:       []string{"--json", "--trash", "--expiring"},
			Handler:     handleList,
		},
		{
			Name:        "history",
			Category:    "Core Secrets",
			Description: "View chronological version audit history for a secret key",
			Usage:       "sec history <path>",
			ExpectsKeys: true,
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec history <path>")
					os.Exit(1)
				}
				handleHistory(profile, args[0])
			},
		},
		{
			Name:        "rollback",
			Category:    "Core Secrets",
			Description: "Non-destructively revert a secret to a previous version",
			Usage:       "sec rollback <path> --version <N>",
			ExpectsKeys: true,
			Flags:       []string{"--version"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec rollback <path> --version <N>")
					os.Exit(1)
				}
				handleRollback(profile, args[0], args[1:])
			},
		},
		{
			Name:        "diff",
			Category:    "Core Secrets",
			Description: "Compare secret paths against another profile or .env file",
			Usage:       "sec diff [--other-profile <p>] [<file>]",
			ExpectsKeys: true,
			Flags:       []string{"--other-profile"},
			Handler:     handleDiff,
		},
		{
			Name:        "diff-profiles",
			Category:    "Profiles & Scope",
			Description: "Side-by-side key matrix comparison between two profiles",
			Usage:       "sec diff-profiles <profile1> <profile2> [--prefix <prefix>]",
			Flags:       []string{"--prefix"},
			Handler: func(profile string, args []string) {
				if len(args) < 2 {
					fmt.Fprintln(os.Stderr, "Usage: sec diff-profiles <profile1> <profile2> [--prefix <prefix>]")
					os.Exit(1)
				}
				handleDiffProfiles(args[0], args[1], args[2:])
			},
		},
		{
			Name:        "profile",
			Category:    "Profiles & Scope",
			Description: "Inspect or configure secret profiles & environment tier",
			Usage:       "sec profile [set-env dev|dta|staging|prod]",
			Subcommands: []SubcommandSpec{
				{
					Name:        "set-env",
					Description: "Set profile environment tier (dev, dta, staging, prod)",
					Flags:       []string{"dev", "dta", "staging", "prod"},
				},
			},
			Handler: handleProfile,
		},
		{
			Name:        "env",
			Category:    "Profiles & Scope",
			Description: "Output shell exports for secrets under prefix",
			Usage:       "sec env [<prefix>]",
			Handler:     handleEnv,
		},
		{
			Name:        "load",
			Category:    "Profiles & Scope",
			Description: "Batch-load scoped group secrets for shell sourcing",
			Usage:       "sec load [<prefix>] [--format env|json]",
			Flags:       []string{"--format"},
			Handler:     handleLoad,
		},
		{
			Name:        "run",
			Category:    "Profiles & Scope",
			Description: "Execute process with scoped secrets injected",
			Usage:       "sec run [--group <p>] [--allow-keys k1,k2] [--ssh-key <path>] -- <cmd>",
			Flags:       []string{"--group", "--allow-keys", "--ssh-key", "--ssh-passphrase-key", "--dry-run", "--no-redact"},
			Handler:     handleRun,
		},
		{
			Name:        "ssh",
			Category:    "Profiles & Scope",
			Description: "Execute remote SSH commands or interactive sessions under ephemeral agent protection",
			Usage:       "sec ssh [target | user@host] [--ssh-key <path>] [--port <p>] [-- <cmd...>]",
			Flags:       []string{"--ssh-key", "--ssh-passphrase-key", "--port"},
			Handler:     handleSSH,
		},
		{
			Name:        "stream",
			Category:    "Profiles & Scope",
			Description: "Evaluate secret {{key_path}} placeholders in template strings",
			Usage:       "sec stream [--template <t>]",
			Flags:       []string{"--template"},
			Handler:     handleStream,
		},
		{
			Name:        "lease",
			Category:    "Security & Maintenance",
			Description: "Issue self-destructing temporary lease token for subagents",
			Usage:       "sec lease <path> [--ttl <duration>]",
			ExpectsKeys: true,
			Flags:       []string{"--ttl"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec lease <path> [--ttl <duration>]")
					os.Exit(1)
				}
				handleLease(profile, args[0], args[1:])
			},
		},
		{
			Name:        "rotate",
			Category:    "Security & Maintenance",
			Description: "Execute registered rotation command and reset TTL timer",
			Usage:       "sec rotate <path> [--rotate-cmd <c>]",
			Flags:       []string{"--rotate-cmd"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec rotate <path> [--rotate-cmd <cmd>]")
					os.Exit(1)
				}
				handleRotate(profile, args[0], args[1:])
			},
		},
		{
			Name:        "check",
			Category:    "Security & Maintenance",
			Description: "Validate schema, audit entropy, scan history, audit scripts, or verify remote drift",
			Usage:       "sec check [--template <f>] [--scan-weak] [--leaks] [--scripts [<path>]] [--remote <host> --uci <k>=<v>]",
			Flags:       []string{"--template", "--scan-weak", "--leaks", "--scripts", "--remote", "--uci", "--env"},
			Handler:     handleCheck,
		},
		{
			Name:        "doctor",
			Category:    "Security & Maintenance",
			Description: "Run workstation system & security diagnostic checks",
			Usage:       "sec doctor",
			Handler: func(profile string, args []string) {
				handleDoctor(profile)
			},
		},
		{
			Name:        "githook",
			Category:    "Security & Maintenance",
			Description: "Install or execute git pre-commit privacy guard scanner",
			Usage:       "sec githook <install|check> [--global]",
			Subcommands: []SubcommandSpec{
				{Name: "install", Description: "Install pre-commit hook in local or global git config", Flags: []string{"--global"}},
				{Name: "check", Description: "Scan staged git files against privacy rules & active vault values"},
			},
			Handler: func(profile string, args []string) {
				if len(args) > 0 && args[0] == "install" {
					handleGitHookInstall(profile, args[1:])
				} else {
					handleGitHookCheck(profile, args)
				}
			},
		},
		{
			Name:        "ide-proxy",
			Category:    "Profiles & Scope",
			Description: "Execute target process under IDE debug session with enclave secrets",
			Usage:       "sec ide-proxy [--profile <name>] -- <cmd> [args...]",
			Handler:     handleIDEProxy,
		},
		{
			Name:        "init-ide",
			Category:    "Session & Setup",
			Description: "Generate VS Code / Antigravity IDE launch.json debug snippet",
			Usage:       "sec init-ide",
			Handler:     handleInitIDE,
		},
		{
			Name:        "status",
			Category:    "Security & Maintenance",
			Description: "Display session health, profile, and diagnostic metrics",
			Usage:       "sec status [--quick] [--all] [--json]",
			Flags:       []string{"--quick", "--all", "--json"},
			Handler: func(profile string, args []string) {
				handleStatus(profile, args)
			},
		},
		{
			Name:        "audit",
			Aliases:     []string{"log"},
			Category:    "Security & Maintenance",
			Description: "View recent daemon security audit logs",
			Usage:       "sec audit [--limit <n>] [--verbose] [--json]",
			Flags:       []string{"--limit", "--verbose", "--json"},
			Handler:     handleAudit,
		},
		{
			Name:        "gen",
			Aliases:     []string{"generate"},
			Category:    "Core Secrets",
			Description: "Generate random password and save to path",
			Usage:       "sec gen <path> [--length N] [--no-symbols] [--comment <comment>]",
			Flags:       []string{"--length", "--no-symbols", "--comment"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec gen <path> [--length <N>] [--no-symbols] [--comment <comment>]")
					os.Exit(1)
				}
				handleGen(profile, args[0], args[1:])
			},
		},
		{
			Name:        "import",
			Category:    "Backup & Migration",
			Description: "Bulk import secrets from JSON, Doppler, or AWS payloads",
			Usage:       "sec import <file> [--format <f>]",
			Flags:       []string{"--format", "--prefix"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec import <file.json> [--format doppler|aws|json] [--prefix <prefix>]")
					os.Exit(1)
				}
				handleImport(profile, args[0], args[1:])
			},
		},
		{
			Name:        "export",
			Category:    "Backup & Migration",
			Description: "Output decrypted database contents to stdout",
			Usage:       "sec export [--format <json|env|aws|doppler|template>]",
			Flags:       []string{"--format"},
			Handler:     handleExport,
		},
		{
			Name:        "sync",
			Category:    "Backup & Migration",
			Description: "Export/import encrypted vault package for team distribution",
			Usage:       "sec sync export <file> | sec sync import <file>",
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec sync export <file> | sec sync import <file>")
					os.Exit(1)
				}
				handleSync(profile, args)
			},
		},
		{
			Name:        "backup",
			Category:    "Backup & Migration",
			Description: "Export secrets to KeePassXC (.kdbx) file",
			Usage:       "sec backup <file> [--custom-password | -p <password>]",
			Flags:       []string{"--custom-password", "-p"},
			Handler: func(profile string, args []string) {
				if len(args) >= 1 && args[0] == "list" {
					handleBackupList(profile)
					return
				}
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec backup <file.kdbx> [--custom-password]")
					os.Exit(1)
				}
				explicitPassword := ""
				for i := 1; i < len(args); i++ {
					if (args[i] == "-p" || args[i] == "--password" || args[i] == "--custom-password") && i+1 < len(args) {
						explicitPassword = args[i+1]
						break
					}
				}
				handleBackup(profile, args[0], explicitPassword)
			},
		},
		{
			Name:        "snapshot",
			Aliases:     []string{"snapshots"},
			Category:    "Backup & Migration",
			Description: "Manage point-in-time vault snapshots (list, create, restore)",
			Usage:       "sec snapshot <list|create|restore>",
			Flags:       []string{"--json", "--comment", "--force", "--all-profiles", "--verbose"},
			Handler:     handleSnapshot,
		},
		{
			Name:        "migrate-v2",
			Category:    "Backup & Migration",
			Description: "Upgrade vault(s) to v2.0 Dual-Slot with BIP39 recovery key",
			Usage:       "sec migrate-v2 [--dry-run]",
			Flags:       []string{"--dry-run"},
			Handler:     handleMigrateV2,
		},
		{
			Name:        "migrate-local",
			Category:    "Backup & Migration",
			Description: "Import dotenv file and sanitize it",
			Usage:       "sec migrate-local <file> [--prefix <prefix>]",
			Flags:       []string{"--prefix"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec migrate-local <dotenv-file> [--prefix <prefix>]")
					os.Exit(1)
				}
				handleMigrateLocal(profile, args[0], args[1:])
			},
		},
		{
			Name:        "session",
			Category:    "Session & Setup",
			Description: "Recover session from 24-word BIP39 recovery mnemonic",
			Usage:       "sec session recover",
			Handler:     handleSession,
		},
		{
			Name:        "skill",
			Category:    "Session & Setup",
			Description: "Install, view, or update AI assistant integration skills",
			Usage:       "sec skill <install|status|update>",
			Subcommands: []SubcommandSpec{
				{ Name: "install", Description: "Install sec-agent integration skill across IDEs" },
				{ Name: "status", Aliases: []string{"list", "ls"}, Description: "Display installed AI agent skill status" },
				{ Name: "update", Description: "Sync AI skills across all installed IDE targets" },
			},
			Handler: handleSkill,
		},
		{
			Name:        "init-shell",
			Category:    "Session & Setup",
			Description: "Install alias and autocompletions into shell startup",
			Usage:       "sec init-shell <zsh|bash>",
			Subcommands: []SubcommandSpec{
				{ Name: "zsh", Description: "Install alias sec=sec-agent and Zsh completions" },
				{ Name: "bash", Description: "Install alias sec=sec-agent and Bash completions" },
			},
			Handler: func(profile string, args []string) {
				handleInitShell(args)
			},
		},
		{
			Name:        "completion",
			Aliases:     []string{"shell-completion"},
			Category:    "Session & Setup",
			Description: "Generate native shell completion script",
			Usage:       "sec completion <zsh|bash|fish>",
			Subcommands: []SubcommandSpec{
				{ Name: "zsh", Description: "Generate Zsh autocompletion script" },
				{ Name: "bash", Description: "Generate Bash autocompletion script" },
				{ Name: "fish", Description: "Generate Fish autocompletion script" },
			},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintf(os.Stderr, "Usage: sec completion <zsh|bash|fish>\n")
					os.Exit(1)
				}
				handleCompletion(args[0])
			},
		},
		{
			Name:        "clear",
			Aliases:     []string{"close", "lock"},
			Category:    "Session & Setup",
			Description: "Lock active session and clear memory cache",
			Usage:       "sec clear",
			Handler: func(profile string, args []string) {
				handleClear(profile)
			},
		},
		{
			Name:        "restart",
			Category:    "Session & Setup",
			Description: "Lock session, stop daemon process, re-launch, and prompt Touch ID",
			Usage:       "sec restart [--hot-reload]",
			Flags:       []string{"--hot-reload"},
			Handler:     handleRestart,
		},
		{
			Name:        "gui",
			Category:    "Session & Setup",
			Description: "Launch web GUI dashboard server",
			Usage:       "sec gui [--port <port>]",
			Flags:       []string{"--port"},
			Handler: func(profile string, args []string) {
				port := 9876
				for i := 0; i < len(args); i++ {
					if (args[i] == "--port" || args[i] == "-p") && i+1 < len(args) {
						if p, err := strconv.Atoi(args[i+1]); err == nil {
							port = p
						}
					}
				}
				runGUIServer(profile, port)
			},
		},
		{
			Name:        "cleanup",
			Category:    "Security & Maintenance",
			Description: "Clean legacy backup snapshots, test artifacts, and orphaned sockets",
			Usage:       "sec cleanup [--dry-run]",
			Flags:       []string{"--dry-run"},
			Handler: func(profile string, args []string) {
				dryRun := false
				for _, arg := range args {
					if arg == "--dry-run" || arg == "--dryrun" {
						dryRun = true
					}
				}
				handleCleanup(profile, dryRun)
			},
		},
		{
			Name:        "dedupe",
			Category:    "Security & Maintenance",
			Description: "Deduplicate and consolidate secret keys between profiles",
			Usage:       "sec dedupe [--from <src>] --to <dst> [--prefix <prefix>] [--dry-run]",
			Flags:       []string{"--from", "--to", "--prefix", "--dry-run"},
			Handler: func(profile string, args []string) {
				handleUniversalDedupe(profile, args)
			},
		},
		{
			Name:        "feedback",
			Category:    "System",
			Description: "Display feature feedback guidelines and templates",
			Usage:       "sec feedback [--example] [--json]",
			Flags:       []string{"--example", "--json"},
			Handler: func(profile string, args []string) {
				handleFeedback(args)
			},
		},
		{
			Name:        "version",
			Aliases:     []string{"-v", "--version"},
			Category:    "System",
			Description: "Print CLI and active daemon version and build metadata",
			Usage:       "sec version",
			Handler: func(profile string, args []string) {
				handleVersion(profile)
			},
		},
		{
			Name:        "redact",
			Category:    "Security & Maintenance",
			Description: "Filter stdin stream, replacing active profile secrets with [REDACTED_SEC_SECRET:<path>]",
			Usage:       "sec redact",
			Handler: func(profile string, args []string) {
				handleRedact(profile, args)
			},
		},
		{
			Name:        "env-file",
			Category:    "Profiles & Scope",
			Description: "Run command with temporary .env file and auto-shred it on exit",
			Usage:       "sec env-file [--profile <name>] -- <command> [args...]",
			Handler: func(profile string, args []string) {
				handleEnvFile(profile, args)
			},
		},
		{
			Name:        "clipboard-wipe",
			Category:    "Internal",
			Description: "Wipe system clipboard after specified TTL duration",
			Usage:       "sec clipboard-wipe [--ttl 15s]",
			Flags:       []string{"--ttl"},
			Handler: func(profile string, args []string) {
				handleClipboardWipe(args)
			},
		},
		{
			Name:        "daemon",
			Category:    "Internal",
			Description: "Start the background socket daemon process",
			Usage:       "sec daemon",
			Handler: func(profile string, args []string) {
				runDaemon(profile)
			},
		},
	}
}

func findCommandSpec(cmd string) (CommandSpec, bool) {
	if len(CommandRegistry) == 0 {
		initRegistry()
	}
	for _, spec := range CommandRegistry {
		if spec.Name == cmd {
			return spec, true
		}
		for _, alias := range spec.Aliases {
			if alias == cmd {
				return spec, true
			}
		}
	}
	return CommandSpec{}, false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
