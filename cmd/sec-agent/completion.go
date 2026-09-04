package main

import (
	"fmt"
	"os"
	"strings"
)

func handleCompletion(shell string) {
	if len(CommandRegistry) == 0 {
		initRegistry()
	}

	switch shell {
	case "zsh":
		var zshBuf strings.Builder
		zshBuf.WriteString(`#compdef sec sec-agent

if ! type compdef &>/dev/null; then
    autoload -U compinit && compinit
fi

_sec_keys() {
    if command -v sec-agent >/dev/null 2>&1; then
        local -a keys
        keys=($(sec-agent ls --json 2>/dev/null | grep -o '"key":"[^"]*"' | cut -d'"' -f4))
        if [ ${#keys[@]} -gt 0 ]; then
            _values 'secret key' $keys
        fi
    fi
}

_sec() {
    local context state state_descr line
    typeset -A opt_args

    _arguments -C \
        '--profile[Target secret profile]:profile:' \
        '--json[Output results in JSON format]' \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            local -a commands
            commands=(
`)
		for _, cmd := range CommandRegistry {
			zshBuf.WriteString(fmt.Sprintf("                '%s:%s'\n", cmd.Name, cmd.Description))
		}
		zshBuf.WriteString(`            )
            _describe -t commands 'sec command' commands
            ;;
        args)
            case $words[1] in
`)
		var keyCmds []string
		for _, cmd := range CommandRegistry {
			if cmd.ExpectsKeys {
				keyCmds = append(keyCmds, cmd.Name)
				for _, alias := range cmd.Aliases {
					keyCmds = append(keyCmds, alias)
				}
			}
		}
		if len(keyCmds) > 0 {
			zshBuf.WriteString(fmt.Sprintf("                %s)\n                    _sec_keys\n                    ;;\n", strings.Join(keyCmds, "|")))
		}

		for _, cmd := range CommandRegistry {
			if len(cmd.Subcommands) > 0 {
				var names []string
				names = append(names, cmd.Name)
				names = append(names, cmd.Aliases...)
				zshBuf.WriteString(fmt.Sprintf("                %s)\n                    local -a subcmds\n                    subcmds=(\n", strings.Join(names, "|")))
				for _, sub := range cmd.Subcommands {
					zshBuf.WriteString(fmt.Sprintf("                        '%s:%s'\n", sub.Name, sub.Description))
					for _, alias := range sub.Aliases {
						zshBuf.WriteString(fmt.Sprintf("                        '%s:%s'\n", alias, sub.Description))
					}
				}
				zshBuf.WriteString("                    )\n                    _describe -t subcmds '" + cmd.Name + " subcommand' subcmds\n                    ;;\n")
			} else if len(cmd.Flags) > 0 && !cmd.ExpectsKeys {
				var names []string
				names = append(names, cmd.Name)
				names = append(names, cmd.Aliases...)
				zshBuf.WriteString(fmt.Sprintf("                %s)\n                    local -a flags\n                    flags=(\n", strings.Join(names, "|")))
				for _, flag := range cmd.Flags {
					zshBuf.WriteString(fmt.Sprintf("                        '%s'\n", flag))
				}
				zshBuf.WriteString("                    )\n                    _describe -t flags '" + cmd.Name + " flags' flags\n                    ;;\n")
			}
		}
		zshBuf.WriteString(`            esac
            ;;
    esac
}

compdef _sec sec sec-agent
`)
		fmt.Print(zshBuf.String())

	case "bash":
		var bashBuf strings.Builder
		bashBuf.WriteString(`# bash completion for sec
_sec_completions() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

`)
		var topCmds []string
		for _, cmd := range CommandRegistry {
			topCmds = append(topCmds, cmd.Name)
		}
		bashBuf.WriteString(fmt.Sprintf("    local cmds=\"%s\"\n\n", strings.Join(topCmds, " ")))
		bashBuf.WriteString(`    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "${cmds}" -- ${cur}) )
        return 0
    fi

    case "${COMP_WORDS[1]}" in
`)
		for _, cmd := range CommandRegistry {
			if len(cmd.Subcommands) > 0 {
				var subNames []string
				for _, sub := range cmd.Subcommands {
					subNames = append(subNames, sub.Name)
					subNames = append(subNames, sub.Aliases...)
				}
				var matchNames []string
				matchNames = append(matchNames, cmd.Name)
				matchNames = append(matchNames, cmd.Aliases...)
				bashBuf.WriteString(fmt.Sprintf("        %s)\n            COMPREPLY=( $(compgen -W \"%s\" -- ${cur}) )\n            ;;\n", strings.Join(matchNames, "|"), strings.Join(subNames, " ")))
			} else if len(cmd.Flags) > 0 && !cmd.ExpectsKeys {
				var matchNames []string
				matchNames = append(matchNames, cmd.Name)
				matchNames = append(matchNames, cmd.Aliases...)
				bashBuf.WriteString(fmt.Sprintf("        %s)\n            COMPREPLY=( $(compgen -W \"%s\" -- ${cur}) )\n            ;;\n", strings.Join(matchNames, "|"), strings.Join(cmd.Flags, " ")))
			}
		}

		var keyCmds []string
		for _, cmd := range CommandRegistry {
			if cmd.ExpectsKeys {
				keyCmds = append(keyCmds, cmd.Name)
				for _, alias := range cmd.Aliases {
					keyCmds = append(keyCmds, alias)
				}
			}
		}
		if len(keyCmds) > 0 {
			bashBuf.WriteString(fmt.Sprintf("        %s)\n            if command -v sec-agent >/dev/null 2>&1; then\n                local keys=$(sec-agent ls --json 2>/dev/null | grep -o '\"key\":\"[^\"]*\"' | cut -d'\"' -f4)\n                COMPREPLY=( $(compgen -W \"${keys}\" -- ${cur}) )\n            fi\n            ;;\n", strings.Join(keyCmds, "|")))
		}

		bashBuf.WriteString(`    esac
}
complete -F _sec_completions sec sec-agent
`)
		fmt.Print(bashBuf.String())

	case "fish":
		var fishBuf strings.Builder
		fishBuf.WriteString("# fish completion for sec\n")
		var topCmds []string
		for _, cmd := range CommandRegistry {
			topCmds = append(topCmds, cmd.Name)
		}
		fishBuf.WriteString(fmt.Sprintf("complete -c sec -n \"__fish_use_subcommand\" -a \"%s\"\n\n", strings.Join(topCmds, " ")))

		for _, cmd := range CommandRegistry {
			if len(cmd.Subcommands) > 0 {
				var subNames []string
				for _, sub := range cmd.Subcommands {
					subNames = append(subNames, sub.Name)
					for _, alias := range sub.Aliases {
						subNames = append(subNames, alias)
					}
				}
				fishBuf.WriteString(fmt.Sprintf("complete -c sec -n \"__fish_seen_subcommand_from %s\" -a \"%s\"\n", cmd.Name, strings.Join(subNames, " ")))
			}
		}
		fishBuf.WriteString("\ncomplete -c sec -l profile -d \"Target secret profile\"\n")
		fishBuf.WriteString("complete -c sec -l json -d \"Output results in JSON format\"\n")
		fmt.Print(fishBuf.String())

	default:
		fmt.Fprintf(os.Stderr, "Usage: sec completion <zsh|bash|fish>\n")
		os.Exit(1)
	}
}
