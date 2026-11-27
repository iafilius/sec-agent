package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// isStealthBackupSubcommand returns true when sub is a subcommand of the stealth
// multi-folder rsync backup subsystem (`sec backup <subcommand>`).
func isStealthBackupSubcommand(sub string) bool {
	switch sub {
	case "init", "add-folder", "remove-folder", "show", "jobs", "run", "batch", "ssh-stdio":
		return true
	default:
		return false
	}
}

// shellQuotePOSIX wraps a string in POSIX single quotes, escaping any internal single quotes.
func shellQuotePOSIX(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func printStealthBackupUsage() {
	fmt.Println("Usage:")
	fmt.Println("  sec backup init <name> [--file <manifest.json> | --stdin] [--local | --pull] [--target <ssh-target-or-user@host>] (--remote-base <path> | --dest-base <path>) [--local-base <path> | --source-base <path>] [--max-attempts <n>] [--timeout <sec>] [--no-progress-timeout <dur>] [--sparse] [--ssh-key-secret <vault-key>] [--ssh-password-key <vault-key>] [--port <port>] [--remote-rsync <path>] [--modify-window <sec>] [--partial-dir <dir>] [--exclude <pattern>...] [--folder <folder>...]")
	fmt.Println("  sec backup add-folder <name> <folder> [--dest <remote-folder-name>] [--history-prefix <prefix>] [--slug <slug>] [--sparse] [--backup-dir <path>] [--log-file <path>] [--exclude <pattern>...]")
	fmt.Println("  sec backup remove-folder <name> <folder>")
	fmt.Println("  sec backup show <name>")
	fmt.Println("  sec backup jobs")
	fmt.Println("  sec backup run <name> [<folder-filter>] [--max-attempts <n>] [--timeout <sec>] [--no-progress-timeout <dur>] [--dry-run] [--verbose] [--suggest-excludes] [--log-file <path>] [--no-trace] [--trace] [--tofu] [--insecure]")
	fmt.Println("  sec backup batch <define|list|show|run> [<name>] [--file <manifest.json>]")
	fmt.Println("  sec backup <export|import|list> [<file.kdbx>]")
}

func handleStealthBackup(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printStealthBackupUsage()
		return
	}

	// If leading flags precede the subcommand (e.g. "sec backup --dry-run run home-nas"),
	// move the subcommand token to position 0 while preserving all flags for the subcommand parser.
	if !isStealthBackupSubcommand(args[0]) && args[0] != "list" {
		for i, tok := range args {
			if isStealthBackupSubcommand(tok) {
				reordered := make([]string, 0, len(args))
				reordered = append(reordered, tok)
				reordered = append(reordered, args[:i]...)
				reordered = append(reordered, args[i+1:]...)
				args = reordered
				break
			}
		}
	}

	switch args[0] {
	case "init":
		handleStealthBackupInit(profile, args[1:])
	case "add-folder":
		handleStealthBackupAddFolder(profile, args[1:])
	case "remove-folder":
		handleStealthBackupRemoveFolder(profile, args[1:])
	case "show":
		handleStealthBackupShow(profile, args[1:])
	case "jobs", "list":
		handleStealthBackupJobs(profile, args[1:])
	case "run":
		handleStealthBackupRun(profile, args[1:])
	case "batch":
		handleStealthBackupBatch(profile, args[1:])
	case "ssh-stdio":
		os.Exit(runInternalSSHStdio(args[1:]))
	default:
		printStealthBackupUsage()
		os.Exit(2)
	}
}

func expandLocalBasePath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		trimmed = "~"
	}
	if trimmed == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return trimmed
	}
	if strings.HasPrefix(trimmed, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, strings.TrimPrefix(trimmed, "~/"))
		}
	}
	return filepath.Clean(trimmed)
}

func handleStealthBackupBatch(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Println("Usage:")
		fmt.Println("  sec backup batch define <name> --file <manifest.json> [--stdin]")
		fmt.Println("  sec backup batch list")
		fmt.Println("  sec backup batch show <name>")
		fmt.Println("  sec backup batch run <name> [<folder-filter>] [--max-attempts <n>] [--dry-run] [--verbose] [--log-file <path>] [--tofu]")
		fmt.Println("  sec backup batch run <name> [<folder-filter>] [--max-attempts <n>] [--timeout <sec>] [--no-progress-timeout <dur>] [--dry-run] [--verbose] [--log-file <path>] [--tofu]")
		return
	}
	switch args[0] {
	case "define", "init":
		handleStealthBackupInit(profile, args[1:])
	case "list", "jobs":
		handleStealthBackupJobs(profile, args[1:])
	case "show":
		handleStealthBackupShow(profile, args[1:])
	case "run":
		handleStealthBackupRun(profile, args[1:])
	default:
		printStealthBackupUsage()
		os.Exit(2)
	}
}

func shellQuoteIfNeeded(s string) string {
	if strings.ContainsAny(s, " \t\"'\\") {
		return shellQuotePOSIX(s)
	}
	return s
}
