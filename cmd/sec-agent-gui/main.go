package main

import (
	"encoding/json"
	"flag"
	"fmt"
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
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "ping"})
	if err == nil && resp != nil && resp.Success {
		return resp, nil
	}

	fmt.Println("Session is locked/offline. Triggering Touch ID unlock...")

	secBin, err := exec.LookPath("sec-agent")
	if err != nil {
		secBin, err = exec.LookPath("sec")
		if err != nil {
			secBin = "./sec"
		}
	}

	// #nosec G204
	cmd := exec.Command(secBin, "open", "--profile", profile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to unlock session: %w", err)
	}

	return queryDaemon(profile, daemon.IPCRequest{Action: "ping"})
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

	bkResp, err := queryDaemon(*profile, daemon.IPCRequest{Action: "backup"})
	if err != nil || !bkResp.Success {
		fmt.Printf("Error querying vault: %v\n", err)
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
