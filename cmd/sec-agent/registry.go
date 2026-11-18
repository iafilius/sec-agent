package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
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
			Usage:       "sec open [--ttl <duration>] [--grace <duration>] [--timeout <duration>]",
			Flags:       []string{"--ttl", "--grace", "--timeout"},
			Handler:     handleOpen,
		},
		{
			Name:        "extend",
			Category:    "Session & Setup",
			Description: "Extend the lifetime of the active secrets session without Touch ID",
			Usage:       "sec extend [--ttl <duration>] [--grace <duration>] [--token <token>]",
			Flags:       []string{"--ttl", "-t", "--grace", "-g", "--token"},
			Handler:     handleExtend,
		},
		{
			Name:        "init",
			Aliases:     []string{"setup"},
			Category:    "Session & Setup",
			Description: "Initialize vault configuration & install AI skills",
			Usage:       "sec init [--vault] [--skill <target>] [--scope <global|workspace>] [--non-interactive]",
			Flags:       []string{"--vault", "--skill", "--scope", "--non-interactive"},
			Handler:     handleInit,
		},
		{
			Name:        "prompt",
			Category:    "Session & Setup",
			Description: "Output formatted shell prompt status indicator (<5ms probe)",
			Usage:       "sec prompt [--format plain|starship|p10k] [--profile <name>]",
			Flags:       []string{"--format", "--profile"},
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
			Usage:       "sec get <path> [--prefix] [--record] [--copy] [--raw] [--show-expired] [--auto-extend] [--json | --comment | --meta <key>]",
			ExpectsKeys: true,
			Flags:       []string{"--copy", "-C", "--raw", "-r", "--show", "--prefix", "--record", "--show-expired", "--auto-extend", "--json", "--comment", "-c", "--meta", "-m"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec get <path> [--prefix] [--record] [--copy] [--raw] [--show-expired] [--auto-extend] [--json | --comment | --meta <key>]")
					os.Exit(1)
				}
				handleGet(profile, args[0], args[1:])
			},
		},
		{
			Name:        "pipe",
			Category:    "Core Secrets",
			Description: "Stream raw secret bytes directly to standard output for shell piping",
			Usage:       "sec pipe <path>",
			ExpectsKeys: true,
			Handler:     handlePipe,
		},
		{
			Name:        "describe",
			Category:    "Core Secrets",
			Description: "Display full metadata, timestamps, description, and notes for a secret",
			Usage:       "sec describe <path> [--json]",
			ExpectsKeys: true,
			Flags:       []string{"--json"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec describe <path> [--json]")
					os.Exit(1)
				}
				handleDescribe(profile, args[0], args[1:])
			},
		},
		{
			Name:        "edit-notes",
			Category:    "Core Secrets",
			Description: "Edit multiline secret notes in $EDITOR using a secure temporary file",
			Usage:       "sec edit-notes <path>",
			ExpectsKeys: true,
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec edit-notes <path>")
					os.Exit(1)
				}
				handleEditNotes(profile, args[0], args[1:])
			},
		},
		{
			Name:        "set",
			Category:    "Core Secrets",
			Description: "Store a secret with optional description, notes, comment, and env alias",
			Usage:       "sec set <path> [<value>] [--stdin] [--no-trim] [--allow-command-string] [--quick] [--desc <desc>] [--notes <notes>] [--comment <comment>] [--env-alias <alias>] [--expires <ttl>] [--rotate-cmd <cmd>] [--rotate-ttl <ttl>] [--meta key=value ...]",
			Flags:       []string{"--desc", "--description", "--notes", "--comment", "-c", "--meta", "-m", "--stdin", "--no-trim", "--allow-command-string", "--force", "--quick", "-q", "--env-alias", "-a", "--expires", "-e", "--rotate-cmd", "--rotate-ttl"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec set <path> [<value>] [--stdin] [--no-trim] [--allow-command-string] [--quick] [--desc <desc>] [--notes <notes>] [--comment <comment>] [--env-alias <alias>] [--expires <ttl>] [--rotate-cmd <cmd>] [--rotate-ttl <ttl>] [--meta key=value ...]")
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
			Description: "Update comment, environment alias, description, notes, or tags on an existing secret",
			Usage:       "sec relabel <path> [--comment <text>] [--env-alias <alias>] [--desc <text>] [--notes <text>] [--expires <ttl>] [--meta <k=v>] [--clear-alias] [--clear-desc] [--clear-notes]",
			ExpectsKeys: true,
			Flags:       []string{"--comment", "-c", "--env-alias", "-a", "--desc", "--description", "--notes", "--clear-desc", "--clear-notes", "--expires", "-e", "--meta", "-m", "--clear-alias"},
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
			Usage:       "sec cp <src-path> <dst-path> [--prefix] [--from-profile <p>] [--to-profile <p>]",
			ExpectsKeys: true,
			Flags:       []string{"--prefix", "--from-profile", "--to-profile"},
			Handler: func(profile string, args []string) {
				if len(args) < 2 {
					fmt.Fprintln(os.Stderr, "Usage: sec cp <src-path> <dst-path> [--prefix] [--from-profile <p>] [--to-profile <p>]")
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
			Description: "List secret paths, hygiene audit, trash bin, or expiring keys",
			Usage:       "sec ls [<prefix>] [--long] [--stale [N]] [--expiring [N]] [--incomplete] [--hygiene] [--trash] [--json]",
			Flags:       []string{"--long", "-l", "--stale", "--expiring", "--incomplete", "--hygiene", "--audit-hygiene", "--trash", "--json"},
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
			Usage:       "sec profile [new <name> [--summary <text>] [--comment <c>] [--description <d>] [--seed <mnemonic>] [--reuse-seed | --existing-seed] [--secrc | --no-secrc] [--no-single-line]] [ls [--long] [-l] [--json]] [describe <name> [--summary <text>] [--comment <c>] [--description <d>] [--clear-summary] [--json]] [enroll-recovery [--seed <mnemonic>] [--force] [--dry-run] [--no-single-line]] [which [<path>]] [set-env dev|dta|staging|prod]",
			Flags:       []string{"--summary", "--comment", "--description", "--seed", "--reuse-seed", "--existing-seed", "--secrc", "--no-secrc", "--no-single-line", "--clear-summary", "--long", "-l", "--json", "--force", "--dry-run"},
			Subcommands: []SubcommandSpec{
				{
					Name:        "new",
					Description: "Create a new named profile with Dual-Slot Touch ID and BIP39 recovery seed",
					Flags:       []string{"--summary", "--comment", "--description", "--seed", "--reuse-seed", "--existing-seed", "--secrc", "--no-secrc", "--no-single-line"},
				},
				{
					Name:        "ls",
					Aliases:     []string{"list"},
					Description: "List all discovered profiles on disk",
					Flags:       []string{"--long", "-l", "--json"},
				},
				{
					Name:        "describe",
					Aliases:     []string{"info"},
					Description: "Inspect or update unencrypted profile metadata and summary without Touch ID",
					Flags:       []string{"--summary", "--comment", "--description", "--clear-summary", "--json"},
				},
				{
					Name:        "enroll-recovery",
					Description: "Enroll or re-wrap Slot 1 (BIP39) recovery seed on profile vault",
					Flags:       []string{"--seed", "--force", "--dry-run", "--no-single-line"},
				},
				{
					Name:        "which",
					Description: "Statelessly inspect and resolve workspace configuration for a directory",
					Flags:       []string{"--json"},
				},
				{
					Name:        "set-env",
					Description: "Set profile environment tier (dev, dta, staging, prod)",
					Flags:       []string{"dev", "dta", "staging", "prod"},
				},
			},
			Handler: handleProfile,
		},
		{
			Name:        "which",
			Category:    "Profiles & Scope",
			Description: "Statelessly inspect and resolve workspace configuration for a directory",
			Usage:       "sec which [<path>] [--json]",
			Flags:       []string{"--json"},
			Handler:     handleWhich,
		},
		{
			Name:        "use",
			Category:    "Profiles & Scope",
			Description: "Switch active workspace environment context in current shell (zero disk writes)",
			Usage:       "sec use [<alias>] [--clear] [--export]",
			Flags:       []string{"--clear", "-c", "--export"},
			Handler:     handleUse,
		},
		{
			Name:        "env",
			Category:    "Profiles & Scope",
			Description: "Introspect and list workspace environments or export secrets under prefix",
			Usage:       "sec env [ls] [<prefix>] [--json]",
			Flags:       []string{"--json"},
			Subcommands: []SubcommandSpec{
				{Name: "ls", Description: "List all workspace environments"},
				{Name: "list", Description: "List all workspace environments"},
			},
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
			Usage:       "sec run [--redact] [--no-redact] [--dry-run] [--confirm-prod] [--auto-extend] [--timeout <d>] [--group <p>] [--allow-keys k1,k2] [--temp-file <ENV>=<target>] [--stdin-key <k>] [--stdin-raw] [--ssh-key <path>] [--ssh-key-secret <key>] [--ssh-passphrase-key <key>] -- <cmd>",
			Flags:       []string{"--redact", "--group", "--allow-keys", "--temp-file", "--stdin-key", "--stdin-raw", "--stdin-no-newline", "--ssh-key", "--ssh-key-secret", "--key-secret", "--ssh-passphrase-key", "--dry-run", "--no-redact", "--confirm-prod", "--auto-extend", "--timeout"},
			Handler:     handleRun,
		},
		{
			Name:        "exec",
			Category:    "Profiles & Scope",
			Description: "Execute vault-stored command or script in memory via stdin with zero host traces",
			Usage:       "sec exec [save <name> [--stdin] [--command <cmd>] [--description <desc>] | show <name> [--no-trace] | list [--json] | rm <name> [--permanent]] | <name> [--no-trace] [--trace] [--shell <bin>] [--dir <path>] [--redact] [--no-redact] [-- <args...>]",
			Flags:       []string{"--stdin", "--command", "-c", "--description", "-d", "--no-trace", "--trace", "--shell", "--dir", "--redact", "--no-redact", "--json", "--permanent"},
			Subcommands: []SubcommandSpec{
				{Name: "save", Description: "Store executable command or script in vault (exec/<name>)", Flags: []string{"--stdin", "--command", "-c", "--description", "-d"}},
				{Name: "show", Description: "Print stored command script from vault", Flags: []string{"--no-trace", "--trace"}},
				{Name: "list", Aliases: []string{"ls"}, Description: "List stored command scripts in vault", Flags: []string{"--json"}},
				{Name: "rm", Aliases: []string{"delete", "del"}, Description: "Delete stored command script from vault", Flags: []string{"--permanent"}},
			},
			Handler: handleExec,
		},
		{
			Name:        "ssh",
			Category:    "Profiles & Scope",
			Description: "Execute remote SSH commands or interactive sessions under vault authentication with zero disk exposure",
			Usage:       "sec ssh [init <target> [--host <h>] [--user <u>] [--port <p>] [--password <p>] [--key <path>] [--import-key <path>] [--shred] [--keep-pub] [--key-secret <k>] [--secrc | --no-secrc]] [import-key [<target> | --shared <name>] <file> [--shred] [--keep-pub] [--sanitize | --no-sanitize] [--passphrase-key <k>]] [sanitize [<target>] [--all]] [host-key show <target>] [reset-host-key <target>] | [<target> | user@host] [--ssh-key <path>] [--ssh-key-secret <key>] [--ssh-passphrase-key <key>] [--port <p>] [--openssh] [--no-trace] [--tofu] [--insecure] [--update-host-key] [-- <cmd...>]",
			Flags:       []string{"--ssh-key", "-i", "--ssh-key-secret", "--key-secret", "--ssh-passphrase-key", "--port", "-p", "--openssh", "--no-trace", "--tofu", "--trust-first-use", "--insecure", "--no-verify", "--update-host-key", "--host", "--user", "--password", "--key", "--import-key", "--shred", "--keep-pub", "--shared", "--sanitize", "--no-sanitize", "--passphrase-key", "--all", "--secrc", "--no-secrc"},
			Subcommands: []SubcommandSpec{
				{
					Name:        "init",
					Description: "Configure remote SSH credentials for target node into vault and .secrc",
					Flags:       []string{"--host", "--user", "--port", "--password", "--key", "--import-key", "--shred", "--keep-pub", "--key-secret", "--ssh-key-secret", "--secrc", "--no-secrc"},
				},
				{
					Name:        "import-key",
					Description: "Ingest SSH private key into vault, optionally shred, and sanitize known_hosts",
					Flags:       []string{"--shred", "--keep-pub", "--shared", "--sanitize", "--no-sanitize", "--passphrase-key"},
				},
				{
					Name:        "sanitize",
					Description: "Scrub target hostnames, IPs, and HMAC-SHA1 hashed entries from known_hosts",
					Flags:       []string{"--all"},
				},
				{
					Name:        "host-key",
					Description: "Inspect or manage pinned SSH host key fingerprints in vault",
					Flags:       []string{"show"},
				},
				{
					Name:        "reset-host-key",
					Description: "Remove pinned SSH host key fingerprint from vault",
				},
			},
			Handler: handleSSH,
		},
		{
			Name:        "stream",
			Category:    "Profiles & Scope",
			Description: "Evaluate secret {{key_path}} placeholders in template strings or files",
			Usage:       "sec stream [<file>] [--file <f>] [--template <t>]",
			Flags:       []string{"--file", "-f", "--template", "-t"},
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
			Name:        "scan",
			Category:    "Security & Maintenance",
			Description: "Scan workspace, folder, or home directory for plaintext credentials and output a Security Improvement Action List",
			Usage:       "sec scan [<path>] [--json] [--output <file>] [--git-history] [--deep] [--verify-live] [--install-tools]",
			Flags:       []string{"--json", "--output", "-o", "--git-history", "--deep", "--verify-live", "--install-tools"},
			Handler:     handleScan,
		},
		{
			Name:        "check",
			Category:    "Security & Maintenance",
			Description: "Validate schema, audit entropy, scan history/workspaces, audit scripts, or verify remote drift",
			Usage:       "sec check [--scan [<path>]] [--required <keys>] [--template <f>] [--scan-weak] [--leaks] [--scripts [<path>]] [--ping-host <host>] [--remote <host> --uci <k>=<v>] [--env <k>=<v>]",
			Flags:       []string{"--scan", "--scan-workspace", "--required", "-r", "--template", "-t", "--scan-weak", "-w", "--leaks", "--scan-leaks", "-l", "--history", "--scripts", "--scan-scripts", "--ping-host", "--remote", "--uci", "--env"},
			Handler:     handleCheck,
		},
		{
			Name:        "doctor",
			Category:    "Security & Maintenance",
			Description: "Run workstation system & security diagnostic checks and repair nested vault envelopes",
			Usage:       "sec doctor [--skip-keychain] [--probe-keychain] [--repair]",
			Flags:       []string{"--skip-keychain", "--probe-keychain", "--repair"},
			Handler: func(profile string, args []string) {
				handleDoctor(profile, args)
			},
		},
		{
			Name:        "githook",
			Category:    "Security & Maintenance",
			Description: "Install or execute git pre-commit privacy guard scanner",
			Usage:       "sec githook <install|check> [--global]",
			Flags:       []string{"--global"},
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
			Flags:       []string{"--profile"},
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
			Usage:       "sec import <file> [--format <f>] [--prefix <prefix>]",
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
			Usage:       "sec export [--format <json|env|aws|doppler|template>] [--all-profiles] [--envelope | --no-envelope]",
			Flags:       []string{"--format", "-f", "--all-profiles", "--envelope", "--no-envelope"},
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
			Description: "Manage stealth multi-folder rsync backups or export/import KeePassXC (.kdbx) backups",
			Usage:       "sec backup <init|add-folder|remove-folder|show|jobs|run|batch|export|import|list> [<name>|<file.kdbx>] [--target <user@host>] [--local-base <path>] [--remote-base <path>] [--ssh-key-secret <key>] [--ssh-password-key <key>] [--port <p>] [--remote-rsync <bin>] [--modify-window <sec>] [--partial-dir <dir>] [--exclude <pat>] [--folder <src>] [--dest <dst>] [--history-prefix <pfx>] [--slug <s>] [--file <json>] [--stdin] [--max-attempts <n>] [--timeout <sec>] [--server-alive-interval <sec>] [--server-alive-count-max <count>] [--sparse] [--backup-dir <dir>] [--log-file <path>] [--dry-run] [--no-trace] [--trace] [--tofu] [--insecure] [--json] [--password <p> | --custom-password] [--merge | --overwrite] [--full-metadata]",
			Flags:       []string{"--target", "--local-base", "--remote-base", "--ssh-key-secret", "--key-secret", "--ssh-password-key", "--port", "-p", "--remote-rsync", "--modify-window", "--partial-dir", "--exclude", "--folder", "--dest", "--history-prefix", "--slug", "--file", "-f", "--stdin", "--max-attempts", "--timeout", "--server-alive-interval", "--server-alive-count-max", "--sparse", "--backup-dir", "--log-file", "--dry-run", "-n", "--no-trace", "--trace", "--tofu", "--trust-first-use", "--insecure", "--no-verify", "--update-host-key", "--json", "--password", "--custom-password", "--merge", "-m", "--overwrite", "--full-metadata"},
			Subcommands: []SubcommandSpec{
				{Name: "init", Description: "Initialize stealth multi-folder rsync backup job in vault", Flags: []string{"--target", "--local-base", "--remote-base", "--ssh-key-secret", "--key-secret", "--ssh-password-key", "--port", "-p", "--remote-rsync", "--modify-window", "--partial-dir", "--exclude", "--folder", "--file", "-f", "--stdin", "--max-attempts", "--timeout", "--server-alive-interval", "--server-alive-count-max", "--sparse"}},
				{Name: "add-folder", Description: "Add or update a folder in a stealth backup job", Flags: []string{"--dest", "--history-prefix", "--slug", "--sparse", "--timeout", "--server-alive-interval", "--server-alive-count-max", "--backup-dir", "--log-file", "--exclude"}},
				{Name: "remove-folder", Description: "Remove a folder from a stealth backup job"},
				{Name: "show", Description: "Inspect stealth backup job manifest and derived remote paths"},
				{Name: "jobs", Description: "List stealth rsync backup jobs in vault"},
				{Name: "run", Description: "Run stealth rsync backup job over in-memory SSH transport", Flags: []string{"--max-attempts", "--timeout", "--server-alive-interval", "--server-alive-count-max", "--dry-run", "-n", "--no-trace", "--trace", "--tofu", "--trust-first-use", "--insecure", "--no-verify", "--update-host-key"}},
				{Name: "batch", Description: "Define, list, or run a stealth multi-folder backup batch (with retry and keepalive)", Flags: []string{"--file", "-f", "--stdin", "--max-attempts", "--timeout", "--server-alive-interval", "--server-alive-count-max", "--dry-run", "-n", "--no-trace", "--trace", "--tofu", "--trust-first-use", "--insecure", "--no-verify"}},
				{Name: "export", Description: "Export secrets to KeePassXC (.kdbx) file", Flags: []string{"--password", "-p", "--custom-password"}},
				{Name: "import", Description: "Import secrets from KeePassXC (.kdbx) file", Flags: []string{"--password", "-p", "--merge", "-m", "--overwrite", "--full-metadata"}},
				{Name: "list", Description: "List automatic KeePassXC backups and stealth backup jobs in vault"},
			},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec backup <file.kdbx> [--custom-password] | sec backup <init|add-folder|remove-folder|show|jobs|run|batch|export|import|list> [<name>|<file.kdbx>]")
					os.Exit(1)
				}
				if isStealthBackupSubcommand(args[0]) {
					handleStealthBackup(profile, args)
					return
				}
				if args[0] == "list" {
					handleBackupList(profile)
					return
				}
				if args[0] == "import" {
					if len(args) < 2 {
						fmt.Fprintln(os.Stderr, "Usage: sec backup import <file.kdbx> [--password <p>] [--merge | --overwrite]")
						os.Exit(1)
					}
					handleRestore(profile, args[1], args[2:])
					return
				}
				if args[0] == "export" {
					if len(args) < 2 {
						fmt.Fprintln(os.Stderr, "Usage: sec backup export <file.kdbx> [--custom-password | -p <password>]")
						os.Exit(1)
					}
					explicitPassword := ""
					for i := 2; i < len(args); i++ {
						if (args[i] == "-p" || args[i] == "--password" || args[i] == "--custom-password") && i+1 < len(args) {
							explicitPassword = args[i+1]
							break
						}
					}
					handleBackup(profile, args[1], explicitPassword)
					return
				}
				for _, tok := range args {
					if !strings.HasPrefix(tok, "-") && isStealthBackupSubcommand(tok) {
						handleStealthBackup(profile, args)
						return
					}
				}
				if !strings.HasSuffix(strings.ToLower(args[0]), ".kdbx") {
					printStealthBackupUsage()
					os.Exit(2)
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
			Name:        "restore",
			Category:    "Backup & Migration",
			Description: "Import/restore secrets from a KeePassXC (.kdbx) backup file",
			Usage:       "sec restore <file.kdbx> [--password <p>] [--merge | --overwrite] [--full-metadata]",
			Flags:       []string{"--password", "-p", "--merge", "-m", "--overwrite", "--full-metadata"},
			Handler: func(profile string, args []string) {
				if len(args) < 1 {
					fmt.Fprintln(os.Stderr, "Usage: sec restore <file.kdbx> [--password <p>] [--merge | --overwrite] [--full-metadata]")
					os.Exit(1)
				}
				handleRestore(profile, args[0], args[1:])
			},
		},
		{
			Name:        "snapshot",
			Aliases:     []string{"snapshots"},
			Category:    "Backup & Migration",
			Description: "Manage point-in-time vault snapshots (list, create, restore)",
			Usage:       "sec snapshot <list|create|restore> [--all-profiles] [--comment <c>] [--force] [--verbose] [--json]",
			Flags:       []string{"--json", "--comment", "--force", "--all-profiles", "--verbose"},
			Handler:     handleSnapshot,
		},
		{
			Name:        "migrate-v2",
			Category:    "Backup & Migration",
			Description: "Upgrade vault(s) to v2.0 Dual-Slot with BIP39 recovery key",
			Usage:       "sec migrate-v2 [--dry-run] [--all-profiles] [--seed <mnemonic>] [--force] [--no-single-line]",
			Flags:       []string{"--dry-run", "--all-profiles", "--seed", "--force", "--no-single-line"},
			Handler:     handleMigrateV2,
		},
		{
			Name:        "enroll-recovery",
			Category:    "Backup & Migration",
			Description: "Enroll or re-wrap Slot 1 (BIP39) recovery seed on vault(s)",
			Usage:       "sec enroll-recovery [--profile <name>] [--seed <mnemonic>] [--force] [--all-profiles] [--dry-run] [--no-single-line]",
			Flags:       []string{"--profile", "--seed", "--force", "--all-profiles", "--dry-run", "--no-single-line"},
			Handler:     handleEnrollRecovery,
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
			Description: "Recover session or rotate 24-word BIP39 recovery mnemonic",
			Usage:       "sec session <recover|rotate-seed> [--profile <name>] [--seed <mnemonic>] [--no-single-line]",
			Flags:       []string{"--profile", "--seed", "--no-single-line"},
			Subcommands: []SubcommandSpec{
				{Name: "recover", Description: "Recover vault access from 24-word BIP39 mnemonic", Flags: []string{"--profile"}},
				{Name: "rotate-seed", Description: "Rotate 24-word BIP39 recovery seed across profile vaults", Flags: []string{"--profile", "--seed", "--no-single-line"}},
			},
			Handler: handleSession,
		},
		{
			Name:        "skill",
			Category:    "Session & Setup",
			Description: "Install, view, or update AI assistant integration skills",
			Usage:       "sec skill <install|install-rules|show|status|update> [--target <t>] [--scope <global|workspace>] [--global] [--workspace]",
			Flags:       []string{"--target", "--scope", "--global", "--workspace"},
			Subcommands: []SubcommandSpec{
				{Name: "install", Description: "Install sec-agent integration skill across IDEs", Flags: []string{"--target", "--scope"}},
				{Name: "install-rules", Aliases: []string{"rules"}, Description: "Install Turn-1 anti-stall rule files", Flags: []string{"--global", "--workspace"}},
				{Name: "show", Aliases: []string{"view"}, Description: "Display AI integration instructions or manual to stdout"},
				{Name: "status", Aliases: []string{"list", "ls"}, Description: "Display installed AI agent skill status"},
				{Name: "update", Description: "Sync AI skills across all installed IDE targets"},
			},
			Handler: handleSkill,
		},
		{
			Name:        "install-rules",
			Category:    "Session & Setup",
			Description: "Install Turn-1 anti-stall rule across IDE configurations",
			Usage:       "sec install-rules [--global] [--workspace]",
			Flags:       []string{"--global", "--workspace"},
			Handler: func(profile string, args []string) {
				handleInstallRules(args)
			},
		},
		{
			Name:        "init-shell",
			Category:    "Session & Setup",
			Description: "Install alias and autocompletions into shell startup",
			Usage:       "sec init-shell <zsh|bash>",
			Subcommands: []SubcommandSpec{
				{Name: "zsh", Description: "Install alias sec=sec-agent and Zsh completions"},
				{Name: "bash", Description: "Install alias sec=sec-agent and Bash completions"},
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
				{Name: "zsh", Description: "Generate Zsh autocompletion script"},
				{Name: "bash", Description: "Generate Bash autocompletion script"},
				{Name: "fish", Description: "Generate Fish autocompletion script"},
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
			Name:        "keychain",
			Category:    "Security & Maintenance",
			Description: "Manage macOS Keychain biometric binding and prune historical binary authorizations",
			Usage:       "sec keychain <prune|status> [--profile <name>] [--all] [--json]",
			Flags:       []string{"--profile", "-p", "--all", "-a", "--json"},
			Subcommands: []SubcommandSpec{
				{
					Name:        "prune",
					Description: "Re-seal Keychain items to active binary, purging stale historical authorizations",
					Flags:       []string{"--profile", "--all", "-p", "-a"},
				},
				{
					Name:        "status",
					Aliases:     []string{"info"},
					Description: "Inspect Keychain item binding, accessibility, and active binary registration",
					Flags:       []string{"--profile", "-p", "--json"},
				},
			},
			Handler: handleKeychain,
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
			Flags:       []string{"--profile"},
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
			Description: "Start the background socket daemon process or list active instances",
			Usage:       "sec daemon [list|ps] [--json]",
			Flags:       []string{"--json"},
			Subcommands: []SubcommandSpec{
				{Name: "list", Aliases: []string{"ps"}, Description: "List all active background daemon processes"},
			},
			Handler: func(profile string, args []string) {
				if len(args) > 0 && (args[0] == "list" || args[0] == "ps") {
					handleDaemonList(args[1:])
					return
				}
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
