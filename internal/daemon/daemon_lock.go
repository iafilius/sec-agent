package daemon

import (
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"secure_secrets/internal/config"
	"time"
)

type PIDLockInfo struct {
	PID        int    `json:"pid"`
	Executable string `json:"executable"`
	Version    string `json:"version"`
	Profile    string `json:"profile"`
}

func (d *Daemon) writePIDLockfile() {
	pidPath, err := config.GetPIDFilePath(d.profile)
	if err != nil {
		return
	}
	execPath, _ := os.Executable()
	info := PIDLockInfo{
		PID:        os.Getpid(),
		Executable: execPath,
		Version:    d.version,
		Profile:    d.profile,
	}
	data, err := json.Marshal(info)
	if err != nil {
		return
	}
	_ = os.WriteFile(pidPath, data, 0600)
}

func (d *Daemon) removePIDLockfile() {
	pidPath, err := config.GetPIDFilePath(d.profile)
	if err == nil {
		_ = os.Remove(pidPath)
	}
}

func (d *Daemon) wipeMemory() {
	if d.masterKey != nil {
		// Zero out master key bytes in memory
		for i := range d.masterKey {
			d.masterKey[i] = 0
		}
		d.masterKey = nil
	}
	d.secretsStore = nil
	d.sessionStart = time.Time{}
	d.lastUsed = time.Time{}
	d.sessionToken = ""
}

func (d *Daemon) expiryTicker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		d.mu.Lock()
		if d.isExpired() {
			d.wipeMemory()
		}
		d.mu.Unlock()
	}
}

func (d *Daemon) isExpired() bool {
	if d.sessionStart.IsZero() {
		return false // Not initialized
	}
	// Within hard TTL
	if time.Since(d.sessionStart) <= d.sessionTTL {
		return false
	}
	// Within inactivity grace period
	if !d.lastUsed.IsZero() && time.Since(d.lastUsed) <= d.graceTTL {
		return false
	}
	return true
}

func (d *Daemon) checkMemoryGuardrail() bool {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if ms.Alloc > 512*1024*1024 {
		runtime.GC()
		runtime.ReadMemStats(&ms)
		if ms.Alloc > 512*1024*1024 {
			return false
		}
	}
	return true
}

func initMemoryLimits() {
	// Set Go runtime soft memory limit to 256 MB to protect against OOM spikes
	debug.SetMemoryLimit(256 * 1024 * 1024)
}
