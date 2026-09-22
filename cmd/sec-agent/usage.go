package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
)

func printVerboseUsage(profile string) {
	if len(CommandRegistry) == 0 {
		initRegistry()
	}

	fmt.Printf("sec-agent %s — Enclave Session Agent for local developer secrets\n\n", Version)

	cfgDir, _ := config.GetConfigDir()
	sockPath, _ := config.GetSocketPath(profile)
	pidPath, _ := config.GetPIDFilePath(profile)
	activePID := 0
	if pidPath != "" {
		// #nosec G304 G703
		if data, err := os.ReadFile(pidPath); err == nil {
			var info daemon.PIDLockInfo
			if json.Unmarshal(data, &info) == nil {
				activePID = info.PID
			}
		}
	}

	fmt.Println("=== Runtime Configuration & Diagnostics ===")
	fmt.Printf("  Config Directory  : %s\n", cfgDir)
	fmt.Printf("  Active Profile    : %s\n", profile)
	fmt.Printf("  Socket Path       : %s\n", sockPath)
	if activePID > 0 {
		fmt.Printf("  Active Daemon PID : %d (running)\n", activePID)
	} else {
		fmt.Println("  Active Daemon PID : (not running)")
	}
	fmt.Println()

	fmt.Println("=== Global Flags ===")
	fmt.Println("  --profile, -P <name>     Target vault profile (default: 'default' or resolved from .secrc)")
	fmt.Println("  --auto-open, --gui       Enable background biometric unlock via GUI prompt")
	fmt.Println("  --json, --json-errors    Format errors and help output as JSON")
	fmt.Println("  --verbose, -V            Enable extended diagnostic messages on stderr")
	fmt.Println("  --help, -h               Display help documentation")
	fmt.Println()

	fmt.Println("=== Categorized Commands ===")
	categories := []string{
		"Session & Setup",
		"Core Secrets",
		"Profiles & Scope",
		"Security & Maintenance",
		"Backup & Migration",
		"System",
	}

	for _, cat := range categories {
		var catCmds []CommandSpec
		for _, spec := range CommandRegistry {
			if spec.Category == cat {
				catCmds = append(catCmds, spec)
			}
		}
		if len(catCmds) == 0 {
			continue
		}
		fmt.Printf("[%s]\n", cat)
		for _, spec := range catCmds {
			aliasStr := ""
			if len(spec.Aliases) > 0 {
				var validAliases []string
				for _, a := range spec.Aliases {
					if !strings.HasPrefix(a, "-") {
						validAliases = append(validAliases, a)
					}
				}
				if len(validAliases) > 0 {
					aliasStr = fmt.Sprintf(" (alias: %s)", strings.Join(validAliases, ", "))
				}
			}
			usageText := spec.Name
			if spec.Usage != "" {
				if strings.HasPrefix(spec.Usage, "sec ") {
					usageText = spec.Usage[4:]
				} else {
					usageText = spec.Usage
				}
			}
			fmt.Printf("  %-32s %s%s\n", usageText, spec.Description, aliasStr)
			if len(spec.Flags) > 0 {
				fmt.Printf("    Flags: %s\n", strings.Join(spec.Flags, ", "))
			}
			if len(spec.Subcommands) > 0 {
				for _, sub := range spec.Subcommands {
					fmt.Printf("    • %-18s %s\n", sub.Name, sub.Description)
				}
			}
		}
		fmt.Println()
	}
}

func printUsage() {
	if len(CommandRegistry) == 0 {
		initRegistry()
	}

	fmt.Println("Usage: sec-agent [--profile <name> | -P <name>] [--auto-open] <command> [args]")
	fmt.Println("Commands:")

	for _, spec := range CommandRegistry {
		aliasStr := ""
		if len(spec.Aliases) > 0 {
			var validAliases []string
			for _, a := range spec.Aliases {
				if !strings.HasPrefix(a, "-") {
					validAliases = append(validAliases, a)
				}
			}
			if len(validAliases) > 0 {
				aliasStr = fmt.Sprintf(" (alias: %s)", strings.Join(validAliases, ", "))
			}
		}

		usageText := spec.Name
		if spec.Usage != "" {
			if strings.HasPrefix(spec.Usage, "sec ") {
				usageText = spec.Usage[4:]
			} else {
				usageText = spec.Usage
			}
		}

		fmt.Printf("  %-32s %s%s\n", usageText, spec.Description, aliasStr)
	}
}

// HelpFlagDTO represents a CLI flag entry in JSON help output.
type HelpFlagDTO struct {
	Type string `json:"type"`
}

// HelpCommandDTO represents a command entry in JSON help output.
type HelpCommandDTO struct {
	Description string                 `json:"description"`
	Flags       map[string]HelpFlagDTO `json:"flags,omitempty"`
	Subcommands []string               `json:"subcommands,omitempty"`
}

// HelpSchemaDTO represents the full structured CLI usage schema.
type HelpSchemaDTO struct {
	Tool        string                    `json:"tool"`
	Version     string                    `json:"version"`
	Description string                    `json:"description"`
	Commands    map[string]HelpCommandDTO `json:"commands"`
}

func printUsageJSON() {
	if len(CommandRegistry) == 0 {
		initRegistry()
	}

	cmdMap := make(map[string]HelpCommandDTO)
	for _, spec := range CommandRegistry {
		flagsMap := make(map[string]HelpFlagDTO)
		for _, fl := range spec.Flags {
			flagsMap[fl] = HelpFlagDTO{Type: "flag"}
		}

		entry := HelpCommandDTO{
			Description: spec.Description,
		}
		if len(flagsMap) > 0 {
			entry.Flags = flagsMap
		}
		if len(spec.Subcommands) > 0 {
			var subs []string
			for _, sub := range spec.Subcommands {
				subs = append(subs, sub.Name)
			}
			entry.Subcommands = subs
		}
		cmdMap[spec.Name] = entry

		for _, alias := range spec.Aliases {
			if !strings.HasPrefix(alias, "-") {
				cmdMap[alias] = HelpCommandDTO{
					Description: fmt.Sprintf("Alias for %s command", spec.Name),
				}
			}
		}
	}

	schema := HelpSchemaDTO{
		Tool:        "sec",
		Version:     Version,
		Description: "Enclave Session Agent for local developer secrets",
		Commands:    cmdMap,
	}

	out, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating JSON usage schema: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
