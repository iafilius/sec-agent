package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"sort"
	"strings"
	"time"
)

var version = "v2.0.0-gui-dev"

func queryDaemon(profile string, req daemon.IPCRequest) (*daemon.IPCResponse, error) {
	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, err
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

func ensureUnlocked(profile string) (*daemon.IPCResponse, error) {
	tok := config.LoadSessionToken(profile)
	if tok == "" {
		tok = os.Getenv("SEC_SESSION_TOKEN")
	}
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "backup", Token: tok})
	if err == nil && resp != nil && resp.Success {
		return resp, nil
	}

	fmt.Println("Session is locked/offline. Triggering Touch ID unlock...")

	secBin := "./sec"
	if _, err := os.Stat(secBin); os.IsNotExist(err) {
		if p, err := exec.LookPath("sec-agent"); err == nil {
			secBin = p
		} else if p, err := exec.LookPath("sec"); err == nil {
			secBin = p
		}
	}

	var outBuf bytes.Buffer
	// #nosec G204
	cmd := exec.Command(secBin, "open", "--profile", profile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.MultiWriter(os.Stdout, &outBuf)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to unlock session: %w", err)
	}

	for _, line := range strings.Split(outBuf.String(), "\n") {
		if strings.Contains(line, "SEC_SESSION_TOKEN=") {
			parts := strings.Split(line, "SEC_SESSION_TOKEN=")
			if len(parts) == 2 {
				tokenVal := strings.Trim(parts[1], "\"' \r\n")
				if tokenVal != "" {
					tok = tokenVal
					_ = config.SaveSessionToken(profile, tokenVal)
					_ = os.Setenv("SEC_SESSION_TOKEN", tokenVal)
				}
			}
		}
	}

	if tok == "" {
		tok = config.LoadSessionToken(profile)
	}

	return queryDaemon(profile, daemon.IPCRequest{Action: "ping", Token: tok})
}

func main() {
	profile := flag.String("profile", "default", "Vault profile to inspect")
	showStale := flag.Bool("stale", false, "Show stale secrets unaccessed > 30 days")
	showTrash := flag.Bool("trash", false, "Show trash bin secrets")
	flag.Parse()

	fmt.Printf("🔒 sec-agent-gui %s (macOS Menu Bar Utility)\n", version)
	fmt.Printf("Active Profile: %s\n", *profile)
	fmt.Println(strings.Repeat("-", 60))

	resp, err := ensureUnlocked(*profile)
	if err != nil || resp == nil || !resp.Success {
		fmt.Printf("Status: 🔴 Unlock Failed (%v)\n", err)
		os.Exit(1)
	}
	fmt.Printf("Status: 🟢 Active Session (Daemon v%s)\n\n", resp.Version)

	tok := config.LoadSessionToken(*profile)
	bkResp, err := queryDaemon(*profile, daemon.IPCRequest{Action: "backup", Token: tok})
	if err != nil {
		fmt.Printf("Error querying vault: %v\n", err)
		os.Exit(1)
	}
	if bkResp != nil && !bkResp.Success {
		fmt.Printf("Error querying vault: %s\n", bkResp.Error)
		os.Exit(1)
	}

	now := time.Now()
	var keys []string
	for k := range bkResp.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if *showTrash {
		fmt.Println("=== 🗑️ Trash Bin Inspector ===")
	} else if *showStale {
		fmt.Println("=== ⏳ Stale Secrets Inspector (>30d Unread) ===")
	} else {
		fmt.Println("=== 📁 Secret Hierarchy Tree ===")
	}

	count := 0
	for _, k := range keys {
		entry := bkResp.Secrets[k]
		if *showStale {
			if !entry.LastAccessed.IsZero() && now.Sub(entry.LastAccessed) <= 30*24*time.Hour {
				continue
			}
		}
		count++
		accStr := "Never"
		if !entry.LastAccessed.IsZero() {
			accStr = entry.LastAccessed.Format("2006-01-02 15:04")
		}
		verStr := fmt.Sprintf("v%d", entry.Version)
		if entry.Version == 0 {
			verStr = "v1"
		}
		fmt.Printf("  • %-32s [%s]  Last Read: %-16s (Reads: %d)\n", k, verStr, accStr, entry.AccessCount)
	}

	if count == 0 {
		fmt.Println("  (No entries match current view filter)")
	}
	fmt.Println("\nGUI Inspector active. Press Ctrl+C to minimize to menu bar tray.")
}
