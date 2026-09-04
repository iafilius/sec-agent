package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

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
