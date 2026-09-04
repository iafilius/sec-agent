package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
)

func handleLease(profile, secretPath string, args []string) {
	if secretPath == "revoke" && len(args) > 0 {
		rawToken := args[0]
		if !strings.HasPrefix(rawToken, "lease:") {
			rawToken = "lease:" + rawToken
		}
		leaseToken := store.LeaseID(rawToken)
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action: daemon.IPCActionDelete,
			Path:   leaseToken.String(),
		})
		if err != nil || !resp.Success {
			fail("LEASE_REVOKE_FAILED", fmt.Errorf("failed to revoke lease token %q: %v", leaseToken, err), "Check if lease token is valid.")
		}
		if jsonErrors {
			data, _ := json.Marshal(map[string]interface{}{
				"success": true,
				"value":   fmt.Sprintf("Revoked temporary lease token %q", leaseToken),
			})
			fmt.Println(string(data))
		} else {
			fmt.Printf("[✓] Revoked temporary lease token %q.\n", leaseToken)
		}
		return
	}

	ttlStr := "15m"
	for i := 0; i < len(args); i++ {
		if args[i] == "--ttl" && i+1 < len(args) {
			ttlStr = args[i+1]
			i++
		}
	}

	ttlTime, err := parseExpiration(ttlStr)
	if err != nil {
		fail("INVALID_ARGUMENT", err, "Duration format: e.g. 15m, 1h, 30m")
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "get",
		Path:   secretPath,
	})
	if err != nil || !resp.Success {
		fail("SECRET_NOT_FOUND", fmt.Errorf("failed to fetch secret %q: %v", secretPath, err), "Check path.")
	}

	randBuf := make([]byte, 8)
	_, _ = rand.Read(randBuf)
	leaseID := fmt.Sprintf("lease:%s:%x", secretPath, randBuf)

	expiresStr := ttlTime.Format(time.RFC3339)

	setResp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:  "set",
		Path:    leaseID,
		Value:   resp.Value,
		Comment: fmt.Sprintf("Temporary lease for %s (TTL: %s)", secretPath, ttlStr),
		Expires: expiresStr,
	})
	if err != nil || !setResp.Success {
		fail("LEASE_CREATION_FAILED", fmt.Errorf("failed to create lease token: %v", err), "")
	}

	fmt.Printf("[INFO] Temporary secret lease created for %q (Expires: %s)\n", secretPath, ttlTime.Format("15:04:05 MST"))
	fmt.Println(leaseID)
}

func handleRotate(profile, secretPath string, args []string) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "get",
		Path:   secretPath,
	})
	if err != nil || !resp.Success {
		fail("SECRET_NOT_FOUND", fmt.Errorf("failed to fetch secret %q: %v", secretPath, err), "Check path.")
	}

	rotateCmd := ""
	if resp.Metadata != nil {
		rotateCmd = resp.Metadata["rotate_cmd"]
	}

	for i := 0; i < len(args); i++ {
		if args[i] == "--rotate-cmd" && i+1 < len(args) {
			rotateCmd = args[i+1]
			i++
		}
	}

	if strings.TrimSpace(rotateCmd) == "" {
		fail("MISSING_ROTATION_HOOK", fmt.Errorf("secret %q does not have a registered rotation command", secretPath), "Register a command using: sec set <path> <val> --rotate-cmd \"<cmd>\"")
	}

	envResp, _ := queryDaemon(profile, daemon.IPCRequest{Action: "backup"})
	env := os.Environ()
	if envResp != nil && envResp.Success {
		for k, entry := range envResp.Secrets {
			envKey := pathToEnvKeyWithEntry(k, entry)
			env = append(env, fmt.Sprintf("%s=%s", envKey, entry.Value))
		}
	}

	fmt.Printf("[INFO] Executing rotation hook for %q...\n", secretPath)

	// #nosec G204 G702
	cmd := exec.Command("sh", "-c", rotateCmd)
	cmd.Env = env

	out, err := cmd.Output()
	if err != nil {
		fail("ROTATION_FAILED", fmt.Errorf("rotation command execution failed: %v", err), "Check script syntax and credentials.")
	}

	newVal := strings.TrimSpace(string(out))
	if newVal == "" {
		fail("ROTATION_FAILED", fmt.Errorf("rotation command returned empty output"), "Rotation script must output new secret string to stdout.")
	}

	ttlStr := ""
	if resp.Metadata != nil {
		ttlStr = resp.Metadata["rotate_ttl"]
	}
	expiresTimeStr := ""
	if ttlStr != "" {
		if t, err := parseExpiration(ttlStr); err == nil {
			expiresTimeStr = t.Format(time.RFC3339)
		}
	} else if jwtExp, ok := parseJwtExp(newVal); ok {
		expiresTimeStr = jwtExp.Format(time.RFC3339)
	}

	meta := resp.Metadata
	if meta == nil {
		meta = make(map[string]string)
	}
	meta["rotate_cmd"] = rotateCmd

	setResp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:   "set",
		Path:     secretPath,
		Value:    newVal,
		Comment:  resp.Comment,
		Metadata: meta,
		Expires:  expiresTimeStr,
	})
	if err != nil || !setResp.Success {
		fail("STORE_UPDATE_FAILED", fmt.Errorf("failed to save rotated secret: %v", err), "")
	}

	fmt.Printf("[✓] Secret %q successfully rotated!\n", secretPath)
	if expiresTimeStr != "" {
		fmt.Printf(" [✓] Expiration timer updated to: %s\n", expiresTimeStr)
	}
}
