package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// SecretRecordDTO represents structured record metadata.
type SecretRecordDTO struct {
	Record     string            `json:"record"`
	Username   string            `json:"username,omitempty"`
	Password   string            `json:"password,omitempty"`
	URL        string            `json:"url,omitempty"`
	Notes      string            `json:"notes,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func handleGet(profile string, path string, args []string) {
	showJSON := false
	showComment := false
	showRaw := false
	showCopy := false
	showMetaKey := ""
	showExpired := false
	isPrefix := false
	showRecord := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--json" {
			showJSON = true
		} else if args[i] == "--raw" || args[i] == "-r" {
			showRaw = true
		} else if args[i] == "--copy" || args[i] == "-C" {
			showCopy = true
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
			Action:      daemon.IPCActionGetGroup,
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

			rec := SecretRecordDTO{
				Record:     recordSlug,
				Attributes: make(map[string]string),
			}

			for k, entry := range resp.Secrets {
				relKey := strings.TrimPrefix(k, trimmedPrefix)
				switch strings.ToLower(relKey) {
				case "password", "pass", "secret":
					rec.Password = entry.Value
				case "username", "user":
					rec.Username = entry.Value
				case "url", "endpoint", "host":
					rec.URL = entry.Value
				case "notes", "comment":
					rec.Notes = entry.Value
				default:
					rec.Attributes[relKey] = entry.Value
				}
				if rec.Notes == "" && entry.Comment != "" {
					rec.Notes = entry.Comment
				}
			}

			if showJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				// #nosec G117
				if err := enc.Encode(rec); err != nil {
					fail("SERIALIZATION_FAILED", err, "")
				}
				return
			}

			fmt.Printf("=== Record: %s ===\n", recordSlug)
			if rec.Username != "" {
				fmt.Printf("Username:   %s\n", rec.Username)
			}
			if rec.Password != "" {
				fmt.Printf("Password:   %s\n", rec.Password)
			}
			if rec.URL != "" {
				fmt.Printf("URL:        %s\n", rec.URL)
			}
			if rec.Notes != "" {
				fmt.Printf("Notes:      %s\n", rec.Notes)
			}
			if len(rec.Attributes) > 0 {
				fmt.Println("Custom Attributes:")
				var attrKeys []string
				for ak := range rec.Attributes {
					attrKeys = append(attrKeys, ak)
				}
				sort.Strings(attrKeys)
				for _, ak := range attrKeys {
					fmt.Printf("  • %-16s: %s\n", ak, rec.Attributes[ak])
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
		Action:      daemon.IPCActionGet,
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

	if showCopy {
		if err := copyConcealedToClipboard(resp.Value); err != nil {
			fmt.Fprintf(os.Stderr, "Error copying secret to clipboard: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("📋 Secret copied to clipboard (ConcealedType metadata set, auto-wipe in 15s).")
	} else if showJSON {
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
		Action:   daemon.IPCActionSet,
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
	fromProfile := profile
	toProfile := profile
	hasExplicitFrom := false
	hasExplicitTo := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--prefix" {
			isPrefix = true
		} else if (a == "--from-profile" || a == "-f") && i+1 < len(args) {
			fromProfile = args[i+1]
			hasExplicitFrom = true
			i++
		} else if strings.HasPrefix(a, "--from-profile=") {
			fromProfile = strings.TrimPrefix(a, "--from-profile=")
			hasExplicitFrom = true
		} else if (a == "--to-profile" || a == "-t") && i+1 < len(args) {
			toProfile = args[i+1]
			hasExplicitTo = true
			i++
		} else if strings.HasPrefix(a, "--to-profile=") {
			toProfile = strings.TrimPrefix(a, "--to-profile=")
			hasExplicitTo = true
		}
	}

	wsCfg, wsFile, _ := loadWorkspaceConfigVerbose()
	if hasExplicitFrom && !hasExplicitTo {
		if wsCfg != nil && wsCfg.Profile != "" {
			toProfile = wsCfg.Profile.String()
		}
	}

	if fromProfile != toProfile {
		resp, err := queryDaemon(fromProfile, daemon.IPCRequest{
			Action: "get",
			Path:   srcPath,
		})
		if err != nil {
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon for source profile %q is not running. Run 'eval $(sec open --profile %s)' to unlock.", fromProfile, fromProfile), "")
		}
		if !resp.Success {
			fail("SECRET_NOT_FOUND", fmt.Errorf("Source secret %q not found in profile %q: %s", srcPath, fromProfile, resp.Error), "")
		}

		setResp, err := queryDaemon(toProfile, daemon.IPCRequest{
			Action:  "set",
			Path:    dstPath,
			Value:   resp.Value,
			Comment: resp.Comment,
		})
		if err != nil {
			fail("DAEMON_NOT_RUNNING", fmt.Errorf("Daemon for target profile %q is not running. Run 'eval $(sec open --profile %s)' to unlock.", toProfile, toProfile), "")
		}
		if !setResp.Success {
			fail("COPY_FAILED", fmt.Errorf("Failed writing secret to target profile %q: %s", toProfile, setResp.Error), "")
		}

		toMeta := toProfile
		if wsCfg != nil && wsCfg.Profile.String() == toProfile && !hasExplicitTo {
			toMeta = fmt.Sprintf("%s via %s", toProfile, wsFile)
		}
		fmt.Printf("✅ Successfully copied secret %q (profile %q) -> %q (profile %q)\n", srcPath, fromProfile, dstPath, toMeta)
		return
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

func handleRelabel(profile string, path string, args []string) {
	if path == "" {
		fmt.Fprintln(os.Stderr, "Usage: sec relabel <path> [flags]")
		os.Exit(1)
	}

	comment := ""
	metadata := make(map[string]string)
	expiresStr := ""
	clearAlias := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--comment", "-c":
			if i+1 < len(args) {
				comment = args[i+1]
				i++
			} else {
				fail("MISSING_ARGUMENT", fmt.Errorf("flag --comment requires a value"), fmt.Sprintf("Example: sec relabel %s -c \"Production DB\"", path))
			}
		case "--expires", "-e":
			if i+1 < len(args) {
				expiresStr = args[i+1]
				i++
			} else {
				fail("MISSING_ARGUMENT", fmt.Errorf("flag --expires requires a value (e.g. 30d, 12h, YYYY-MM-DD, or 'clear')"), "")
			}
		case "--env-alias", "-a":
			if i+1 < len(args) {
				metadata["env_alias"] = args[i+1]
				i++
			} else {
				fail("MISSING_ARGUMENT", fmt.Errorf("flag --env-alias requires a value (e.g. DB_PASSWORD)"), "")
			}
		case "--clear-alias":
			clearAlias = true
		case "--meta", "-m":
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
				fail("MISSING_ARGUMENT", fmt.Errorf("flag --meta requires a key=value pair"), "")
			}
		}
	}

	expiresTimeStr := ""
	if expiresStr != "" {
		if expiresStr == "clear" || expiresStr == "0" {
			expiresTimeStr = "clear"
		} else {
			t, err := parseExpiration(expiresStr)
			if err != nil {
				fail("INVALID_ARGUMENT", err, "Verify format for duration: 30d, 12h, or YYYY-MM-DD")
			}
			expiresTimeStr = t.Format(time.RFC3339)
		}
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:     daemon.IPCActionRelabel,
		Path:       path,
		Comment:    comment,
		Metadata:   metadata,
		Expires:    expiresTimeStr,
		ClearAlias: clearAlias,
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

func handleList(profile string, args []string) {
	prefix := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		prefix = args[0]
		args = args[1:]
	}

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

