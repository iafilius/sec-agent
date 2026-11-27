package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// maxOpaqueCmdBytes caps the opaque command vector read from stdin or --cmd-fd
// to prevent unbounded memory allocation on accidental large pipe inputs.
const maxOpaqueCmdBytes = 64 * 1024

// resolveOpaqueArgs inspects argv for opaque command invocation modes:
//   - `sec -` (reads command vector from stdin)
//   - `sec --cmd-fd <n>` or `sec --cmd-fd=<n>` (reads command vector from inherited FD >= 3)
//
// When neither mode is requested, args is returned unchanged.
// When an opaque mode is requested, the command vector is read, parsed (JSON
// string array or POSIX shell-quoted line), validated against recursive opaque
// invocation, and returned as `append([]string{args[0]}, parsed...)`.
func resolveOpaqueArgs(args []string) ([]string, error) {
	if len(args) < 2 {
		return args, nil
	}

	first := args[1]
	switch {
	case first == "-":
		if len(args) > 2 {
			return nil, fmt.Errorf("opaque stdin invocation ('-') cannot be combined with extra CLI arguments")
		}
		parsed, err := readOpaqueCommandArgs(os.Stdin)
		if err != nil {
			return nil, err
		}
		return append([]string{args[0]}, parsed...), nil

	case first == "--cmd-fd" || strings.HasPrefix(first, "--cmd-fd="):
		var fdStr string
		if first == "--cmd-fd" {
			if len(args) != 3 {
				return nil, fmt.Errorf("--cmd-fd requires a single file descriptor number (>= 3) and no extra CLI arguments")
			}
			fdStr = args[2]
		} else {
			if len(args) != 2 {
				return nil, fmt.Errorf("--cmd-fd=<n> cannot be combined with extra CLI arguments")
			}
			fdStr = strings.TrimPrefix(first, "--cmd-fd=")
		}

		fd, err := strconv.Atoi(strings.TrimSpace(fdStr))
		if err != nil || fd < 3 {
			return nil, fmt.Errorf("invalid --cmd-fd value %q: must be an inherited file descriptor integer >= 3", fdStr)
		}

		f := os.NewFile(uintptr(fd), "cmd-fd")
		if f == nil {
			return nil, fmt.Errorf("failed to open inherited command file descriptor %d", fd)
		}
		defer func() { _ = f.Close() }()

		parsed, err := readOpaqueCommandArgs(f)
		if err != nil {
			return nil, err
		}
		return append([]string{args[0]}, parsed...), nil

	default:
		return args, nil
	}
}

// readOpaqueCommandArgs reads at most maxOpaqueCmdBytes from r, zeroes the raw
// buffer after parsing, and rejects empty, oversized, or recursive payloads.
func readOpaqueCommandArgs(r io.Reader) ([]string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxOpaqueCmdBytes+1))
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("failed reading opaque command payload: %w", err)
	}
	if len(raw) > maxOpaqueCmdBytes {
		return nil, fmt.Errorf("opaque command payload exceeds maximum size of %d bytes (64 KiB)", maxOpaqueCmdBytes)
	}

	parsed, err := parseOpaqueCommandPayload(raw)
	if err != nil {
		return nil, err
	}

	if len(parsed) > 0 && (parsed[0] == "-" || parsed[0] == "--cmd-fd" || strings.HasPrefix(parsed[0], "--cmd-fd=")) {
		return nil, fmt.Errorf("recursive opaque command invocation (%q) is not allowed", parsed[0])
	}
	return parsed, nil
}

// parseOpaqueCommandPayload parses either:
//  1. A JSON string array (e.g. `["--profile", "prod", "status", "--quick"]`) when
//     trimmed input starts with `[`, or
//  2. A POSIX-style shell-quoted command line fallback otherwise.
func parseOpaqueCommandPayload(raw []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("opaque command payload is empty")
	}

	if trimmed[0] == '[' {
		var parsed []string
		if err := json.Unmarshal(trimmed, &parsed); err != nil {
			return nil, fmt.Errorf("invalid opaque JSON command array: %w", err)
		}
		if len(parsed) == 0 {
			return nil, fmt.Errorf("opaque JSON command array must contain at least one argument")
		}
		return parsed, nil
	}

	return parseShellQuotedArgs(string(trimmed))
}

// parseShellQuotedArgs tokenizes a POSIX-style shell-quoted string supporting
// single quotes ('...'), double quotes ("..."), and backslash escapes.
func parseShellQuotedArgs(input string) ([]string, error) {
	var args []string
	var current strings.Builder
	inToken := false
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(input); i++ {
		ch := input[i]

		if escaped {
			if inDouble {
				// In POSIX double quotes, backslash escapes only ", \, $, `, and newline.
				switch ch {
				case '"', '\\', '$', '`':
					current.WriteByte(ch)
				case '\n':
					// Line continuation inside double quotes: drop both.
				default:
					current.WriteByte('\\')
					current.WriteByte(ch)
				}
			} else {
				if ch != '\n' {
					current.WriteByte(ch)
				}
			}
			inToken = true
			escaped = false
			continue
		}

		if inSingle {
			if ch == '\'' {
				inSingle = false
			} else {
				current.WriteByte(ch)
			}
			continue
		}

		if inDouble {
			switch ch {
			case '"':
				inDouble = false
			case '\\':
				escaped = true
			default:
				current.WriteByte(ch)
			}
			continue
		}

		switch ch {
		case ' ', '\t', '\r', '\n':
			if inToken {
				args = append(args, current.String())
				current.Reset()
				inToken = false
			}
		case '\'':
			inSingle = true
			inToken = true
		case '"':
			inDouble = true
			inToken = true
		case '\\':
			escaped = true
			inToken = true
		default:
			current.WriteByte(ch)
			inToken = true
		}
	}

	if escaped {
		return nil, fmt.Errorf("invalid opaque command line: trailing unescaped backslash")
	}
	if inSingle {
		return nil, fmt.Errorf("invalid opaque command line: unterminated single quote")
	}
	if inDouble {
		return nil, fmt.Errorf("invalid opaque command line: unterminated double quote")
	}
	if inToken {
		args = append(args, current.String())
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("opaque command payload is empty")
	}
	return args, nil
}
