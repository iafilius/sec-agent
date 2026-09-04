package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"secure_secrets/internal/store"
	"time"
)

// handleLease processes temporary secret lease tokens.
func (d *Daemon) handleLease(req IPCRequest) (IPCResponse, error) {
	if d.masterKey == nil {
		return IPCResponse{Success: false, Error: "Session locked"}, nil
	}

	leaseDuration := 15 * time.Minute
	if req.TTL != "" {
		if dur, err := time.ParseDuration(req.TTL); err == nil {
			leaseDuration = dur
		}
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return IPCResponse{Success: false, Error: fmt.Sprintf("failed to generate lease token: %v", err)}, err
	}

	leaseID := store.LeaseID("lease_" + hex.EncodeToString(tokenBytes))
	exp := time.Now().Add(leaseDuration)

	entry, exists := d.resolveSecret(req.Path, req.ExtendsProfile)
	if !exists {
		return IPCResponse{Success: false, Error: fmt.Sprintf("secret %q not found", req.Path)}, nil
	}

	leaseEntry := store.SecretEntry{
		Value:        entry.Value,
		Comment:      fmt.Sprintf("Temporary lease token for %s", req.Path),
		Created:      time.Now(),
		LastModified: time.Now(),
		Expires:      exp,
		Metadata: map[string]string{
			"lease_target": req.Path,
			"lease_id":     leaseID.String(),
		},
	}

	if d.secretsStore != nil && d.secretsStore.Secrets != nil {
		d.secretsStore.Secrets[store.SecretKey(leaseID.String())] = leaseEntry
		_ = store.SaveStore(d.profile, d.secretsStore, d.masterKey)
	}

	return IPCResponse{
		Success: true,
		Value:   leaseID.String(),
		Expires: exp,
	}, nil
}
