package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"secure_secrets/internal/config"
	"secure_secrets/internal/store"
)

// IPCRequest defines the format for messages sent to the daemon.
type IPCRequest struct {
	Action      string                         `json:"action"` // "open", "get", "set", "ping", "clear", "backup", "restore"
	Path        string                         `json:"path,omitempty"`
	Value       string                         `json:"value,omitempty"`
	Comment     string                         `json:"comment,omitempty"`
	Metadata    map[string]string              `json:"metadata,omitempty"`
	TTL         string                         `json:"ttl,omitempty"`
	Grace       string                         `json:"grace,omitempty"`
	Secrets     map[string]store.SecretEntry   `json:"secrets,omitempty"`
	Key         []byte                         `json:"key,omitempty"`
	NewPath     string                         `json:"new_path,omitempty"`
	IsPrefix    bool                           `json:"is_prefix,omitempty"`
	Limit       int                            `json:"limit,omitempty"`
	Expires     string                         `json:"expires,omitempty"`      // RFC3339 formatted expiration time
	ShowExpired    bool                           `json:"show_expired,omitempty"` // Override to show expired secrets
	Token          string                         `json:"token,omitempty"`        // Shell session token
	ExtendsProfile string                         `json:"extends_profile,omitempty"`
	TargetVersion  int                            `json:"target_version,omitempty"`
	ShowTrash      bool                           `json:"show_trash,omitempty"`
	Permanent      bool                           `json:"permanent,omitempty"`
}

// DaemonStatePayload defines the in-memory payload transferred across kernel pipe during hot-reload.
type DaemonStatePayload struct {
	MasterKey    []byte                       `json:"master_key"`
	Profile      string                       `json:"profile"`
	SessionStart time.Time                    `json:"session_start"`
	SessionTTL   time.Duration                `json:"session_ttl"`
	GraceTTL     time.Duration                `json:"grace_ttl"`
	LastUsed     time.Time                    `json:"last_used"`
	SessionToken string                       `json:"session_token"`
	Secrets      map[string]store.SecretEntry `json:"secrets,omitempty"`
}

// AuditLogEntry represents a single audit event record.
type AuditLogEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Path      string `json:"path,omitempty"`
	PeerPID   int    `json:"peer_pid"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// IPCResponse defines the format for replies from the daemon.
type IPCResponse struct {
	Success      bool                         `json:"success"`
	Value        string                       `json:"value,omitempty"`
	Comment      string                       `json:"comment,omitempty"`
	Metadata     map[string]string            `json:"metadata,omitempty"`
	Error        string                       `json:"error,omitempty"`
	Secrets      map[string]store.SecretEntry `json:"secrets,omitempty"`
	Created      time.Time                    `json:"created,omitempty"`
	LastModified time.Time                    `json:"last_modified,omitempty"`
	LastAccessed time.Time                    `json:"last_accessed,omitempty"`
	AccessCount  uint64                       `json:"access_count,omitempty"`
	Expires      time.Time                    `json:"expires,omitempty"`
	Token        string                       `json:"token,omitempty"` // Shell session token
	Version      string                       `json:"version,omitempty"`
	StatusInfo   map[string]interface{}       `json:"status_info,omitempty"`
	History      []store.SecretVersion        `json:"history,omitempty"`
	ItemVersion  int                          `json:"item_version,omitempty"`
}

// Daemon represents the background secrets agent.
type Daemon struct {
	mu           sync.Mutex
	masterKey    []byte
	secretsStore *store.EncryptedStore
	sessionStart time.Time
	sessionTTL   time.Duration
	lastUsed     time.Time
	graceTTL     time.Duration
	socketPath   string
	listener     net.Listener
	profile      string
	sessionToken string
	version      string
	IsTestInstance bool
}

// NewDaemon creates a new daemon instance.
func NewDaemon(profile string, ttl time.Duration, version string) (*Daemon, error) {
	// Set Go runtime soft memory limit to 256 MB to protect against OOM spikes
	debug.SetMemoryLimit(256 * 1024 * 1024)

	sock, err := config.GetSocketPath(profile)
	if err != nil {
		return nil, err
	}
	return &Daemon{
		sessionTTL: ttl,
		socketPath: sock,
		profile:    profile,
		version:    version,
	}, nil
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

func (d *Daemon) checkAndRestoreReexecState() error {
	fdStr := os.Getenv("SEC_REEXEC_FD")
	if fdStr == "" {
		return nil
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return nil
	}
	_ = os.Unsetenv("SEC_REEXEC_FD")

	// #nosec G115
	file := os.NewFile(uintptr(fd), "reexec_pipe")
	if file == nil {
		return fmt.Errorf("invalid reexec pipe file descriptor")
	}
	defer file.Close()

	var payload DaemonStatePayload
	if err := json.NewDecoder(file).Decode(&payload); err != nil {
		return fmt.Errorf("failed to decode reexec payload: %w", err)
	}

	if len(payload.MasterKey) > 0 {
		storeInstance, err := store.LoadStore(d.profile, payload.MasterKey)
		if err != nil || storeInstance == nil {
			storeInstance = &store.EncryptedStore{Secrets: make(map[string]store.SecretEntry)}
		}
		if len(payload.Secrets) > 0 {
			if storeInstance.Secrets == nil {
				storeInstance.Secrets = make(map[string]store.SecretEntry)
			}
			for k, v := range payload.Secrets {
				storeInstance.Secrets[k] = v
			}
		}
		d.mu.Lock()
		d.masterKey = payload.MasterKey
		d.secretsStore = storeInstance
		d.sessionStart = payload.SessionStart
		d.sessionTTL = payload.SessionTTL
		d.graceTTL = payload.GraceTTL
		d.lastUsed = payload.LastUsed
		d.sessionToken = payload.SessionToken
		d.mu.Unlock()
		d.logAudit("reexec", d.profile, 0, true, "")
	}
	return nil
}

// Start runs the IPC Unix socket server.
func (d *Daemon) Start() error {
	// Restore state if spawned from in-memory hot-reload pipe
	_ = d.checkAndRestoreReexecState()

	// Clean up existing socket file if it exists
	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove old socket: %w", err)
	}

	// Purge any lingering token files on disk
	config.PurgeAllSessionTokenFiles()

	l, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket %s: %w", d.socketPath, err)
	}
	d.listener = l

	// Set socket file permissions to 0600 (owner-only read/write)
	if err := os.Chmod(d.socketPath, 0600); err != nil {
		_ = l.Close()
		return fmt.Errorf("failed to secure socket permissions: %w", err)
	}

	d.writePIDLockfile()
	defer d.removePIDLockfile()

	// Periodically check for session expiration
	go d.expiryTicker()

	for {
		conn, err := l.Accept()
		if err != nil {
			// Listener was closed
			return nil
		}
		go d.handleConnection(conn)
	}
}

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

// Stop stops the server and wipes memory cache.
func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wipeMemory()
	if d.listener != nil {
		_ = d.listener.Close()
	}
	_ = os.Remove(d.socketPath)
	d.removePIDLockfile()
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

// getsockopt local peer PID
func getPeerPID(conn *net.UnixConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var peerPID int
	var sysErr error
	err = rawConn.Control(func(fd uintptr) {
		peerPID, sysErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil {
		return 0, err
	}
	if sysErr != nil {
		return 0, sysErr
	}
	return peerPID, nil
}

// isHijacked checks if the client connection is running via SSH or Screensharing is active
func (d *Daemon) isHijacked(peerPID int) bool {
	// 1. Check if macOS screensharing/VNC/remote pairing services are active
	sharingServices := []string{"screensharingd", "AppleVNCServer", "remotepairingd"}
	for _, svc := range sharingServices {
		// #nosec G204
		cmd := exec.Command("pgrep", svc)
		if err := cmd.Run(); err == nil {
			return true // Screen sharing or VNC server is running!
		}
	}

	// 2. Check peer environment variables for SSH tags using BSD ps
	// #nosec G204
	envOut, err := exec.Command("ps", "e", "-ww", "-p", strconv.Itoa(peerPID)).Output()
	if err == nil {
		envStr := string(envOut)
		if strings.Contains(envStr, "SSH_CLIENT=") ||
			strings.Contains(envStr, "SSH_TTY=") ||
			strings.Contains(envStr, "SSH_CONNECTION=") {
			return true // Remote SSH session detected in peer process environment!
		}
	}

	// 3. Walk up the process tree starting from peerPID to check for sshd (defense in depth)
	currentPID := peerPID
	for currentPID > 1 {
		// #nosec G204
		out, err := exec.Command("ps", "-o", "ppid=,comm=", "-p", strconv.Itoa(currentPID)).Output()
		if err != nil {
			break
		}

		parts := strings.Fields(string(out))
		if len(parts) < 2 {
			break
		}

		ppidVal, err := strconv.Atoi(parts[0])
		if err != nil {
			break
		}

		comm := parts[1]
		if strings.Contains(strings.ToLower(comm), "sshd") {
			return true // Found sshd in ancestor tree!
		}

		currentPID = ppidVal
	}

	return false
}

func (d *Daemon) handleConnection(c net.Conn) {
	defer c.Close()

	unixConn, ok := c.(*net.UnixConn)
	if !ok {
		return
	}

	peerPID, err := getPeerPID(unixConn)
	if err != nil {
		d.sendError(c, fmt.Sprintf("failed to resolve peer PID: %v", err))
		return
	}

	// Check if hijacked - if yes, immediately wipe cache and lock
	if d.isHijacked(peerPID) {
		d.mu.Lock()
		d.wipeMemory()
		d.mu.Unlock()
		d.sendError(c, "ACCESS DENIED: Remote session hijacking or screen sharing detected.")
		return
	}

	decoder := json.NewDecoder(c)
	var req IPCRequest
	if err := decoder.Decode(&req); err != nil {
		if err != io.EOF {
			d.sendError(c, "invalid request encoding")
		}
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Check expiration before servicing request
	if d.isExpired() {
		d.wipeMemory()
	}

	// Validate session token for protected actions
	if req.Action != "open" && req.Action != "ping" {
		if d.sessionToken == "" || d.masterKey == nil {
			d.sendResponse(c, IPCResponse{Success: false, Error: "Session locked or expired. Please run 'sec open' to authorize."})
			return
		}
		// Allow subshell execution when req.Token is empty: caller is verified via socket peer credentials (0600) and daemon RAM is UNLOCKED
		if req.Token != "" && req.Token != d.sessionToken {
			d.sendResponse(c, IPCResponse{Success: false, Error: "ACCESS DENIED: Invalid session token"})
			return
		}
	}

	switch req.Action {
	case "ping":
		if d.masterKey == nil {
			d.sendResponse(c, IPCResponse{Success: false, Error: "Session locked", Version: d.version})
		} else {
			d.sendResponse(c, IPCResponse{Success: true, Value: "Active", Version: d.version})
		}

	case "reexec":
		if d.masterKey == nil {
			d.sendResponse(c, IPCResponse{Success: false, Error: "Session locked. Cannot hot-reload a locked daemon.", Version: d.version})
			return
		}

		r, w, err := os.Pipe()
		if err != nil {
			d.sendError(c, fmt.Sprintf("failed to create hot-reload state pipe: %v", err))
			return
		}

		var activeSecrets map[string]store.SecretEntry
		if d.secretsStore != nil && d.secretsStore.Secrets != nil {
			activeSecrets = d.secretsStore.Secrets
		}

		if d.sessionToken == "" {
			d.sessionToken = "reexec-active-token"
		}

		payload := DaemonStatePayload{
			MasterKey:    d.masterKey,
			Profile:      d.profile,
			SessionStart: d.sessionStart,
			SessionTTL:   d.sessionTTL,
			GraceTTL:     d.graceTTL,
			LastUsed:     d.lastUsed,
			SessionToken: d.sessionToken,
			Secrets:      activeSecrets,
		}

		// #nosec G117
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			_ = r.Close()
			_ = w.Close()
			d.sendError(c, fmt.Sprintf("failed to encode hot-reload payload: %v", err))
			return
		}
		_ = w.Close()

		execPath, err := os.Executable()
		if err != nil {
			_ = r.Close()
			d.sendError(c, fmt.Sprintf("failed to resolve executable path: %v", err))
			return
		}

		// Acknowledge reexec to client before spawning new process
		d.sendResponse(c, IPCResponse{
			Success: true,
			Value:   "Daemon hot-reloading in memory via pipe handoff...",
			Version: d.version,
		})

		// Unbind listener so child process can bind unix socket immediately
		if d.listener != nil {
			_ = d.listener.Close()
		}

		// #nosec G204
		cmd := exec.Command(execPath, "--profile", d.profile, "daemon")
		cmd.Env = append(os.Environ(), "SEC_REEXEC_FD=3", fmt.Sprintf("SEC_PROFILE=%s", d.profile))
		cmd.ExtraFiles = []*os.File{r}
		cmd.Stdout = nil
		cmd.Stderr = nil

		if err := cmd.Start(); err != nil {
			_ = r.Close()
			d.logAudit("reexec", d.profile, peerPID, false, err.Error())
			return
		}
		_ = r.Close()
		d.logAudit("reexec", d.profile, peerPID, true, "")
		go func() {
			time.Sleep(50 * time.Millisecond)
			if !d.IsTestInstance && os.Getenv("SEC_TEST_MODE") != "1" {
				os.Exit(0)
			}
		}()
		return

	case "open":
		if len(req.Key) != 32 {
			d.sendError(c, "invalid master key length")
			return
		}
		s, err := store.LoadStore(d.profile, req.Key)
		if err != nil {
			d.sendError(c, fmt.Sprintf("failed to unlock store: %v", err))
			return
		}
		d.masterKey = make([]byte, 32)
		copy(d.masterKey, req.Key)
		d.secretsStore = s
		d.sessionStart = time.Now()
		d.lastUsed = time.Now()

		// Set custom TTL if provided
		if req.TTL != "" {
			if parsedTTL, err := time.ParseDuration(req.TTL); err == nil {
				d.sessionTTL = parsedTTL
			}
		}
		// Set custom grace TTL if provided
		if req.Grace != "" {
			if parsedGrace, err := time.ParseDuration(req.Grace); err == nil {
				d.graceTTL = parsedGrace
			} else {
				d.graceTTL = 30 * time.Minute
			}
		} else {
			d.graceTTL = 30 * time.Minute
		}

		if d.sessionToken == "" {
			tokenBytes := make([]byte, 16)
			if _, randErr := rand.Read(tokenBytes); randErr != nil {
				d.sendError(c, fmt.Sprintf("failed to generate session token: %v", randErr))
				return
			}
			d.sessionToken = hex.EncodeToString(tokenBytes)
		}

		d.sendResponse(c, IPCResponse{
			Success: true,
			Token:   d.sessionToken,
		})

	case "get":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		entry, exists := d.resolveSecret(req.Path, req.ExtendsProfile)
		if !exists {
			d.sendError(c, fmt.Sprintf("secret %q not found", req.Path))
			return
		}

		// Check expiration
		if !entry.Expires.IsZero() && time.Now().After(entry.Expires) {
			if !req.ShowExpired {
				d.sendError(c, "Secret has expired")
				return
			}
		}

		now := time.Now()
		entry.LastAccessed = now
		entry.AccessCount++

		// Update access metrics in active local store if entry belongs to local store
		if d.secretsStore != nil && d.secretsStore.Secrets != nil {
			if localEntry, ok := d.secretsStore.Secrets[req.Path]; ok {
				localEntry.LastAccessed = now
				localEntry.AccessCount++
				d.secretsStore.Secrets[req.Path] = localEntry
				_ = store.SaveStore(d.profile, d.secretsStore, d.masterKey)
			}
		}

		d.lastUsed = now
		d.sendResponse(c, IPCResponse{
			Success:      true,
			Value:        entry.Value,
			Comment:      entry.Comment,
			Metadata:     entry.Metadata,
			Created:      entry.Created,
			LastModified: entry.LastModified,
			LastAccessed: entry.LastAccessed,
			AccessCount:  entry.AccessCount,
			Expires:      entry.Expires,
		})

	case "get_group":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		if !d.checkMemoryGuardrail() {
			d.sendError(c, "RESOURCE_EXHAUSTED: Memory saturation threshold exceeded. Please use scoped prefix filtering.")
			return
		}
		allSecrets := d.resolveAllSecrets(req.ExtendsProfile)
		filteredGroup := make(map[string]store.SecretEntry, len(allSecrets))
		now := time.Now()
		storeUpdated := false
		for k, entry := range allSecrets {
			if req.Path != "" && !strings.HasPrefix(k, req.Path) {
				continue
			}
			if !entry.Expires.IsZero() && now.After(entry.Expires) && !req.ShowExpired {
				continue
			}
			entry.LastAccessed = now
			entry.AccessCount++
			filteredGroup[k] = entry

			if d.secretsStore != nil && d.secretsStore.Secrets != nil {
				if localEntry, ok := d.secretsStore.Secrets[k]; ok {
					localEntry.LastAccessed = now
					localEntry.AccessCount++
					d.secretsStore.Secrets[k] = localEntry
					storeUpdated = true
				}
			}
		}

		if storeUpdated {
			_ = store.SaveStore(d.profile, d.secretsStore, d.masterKey)
		}

		d.lastUsed = now
		d.sendResponse(c, IPCResponse{
			Success: true,
			Secrets: filteredGroup,
		})


	case "set":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}

		if d.secretsStore == nil {
			d.secretsStore = &store.EncryptedStore{Secrets: make(map[string]store.SecretEntry)}
		}
		if d.secretsStore.Secrets == nil {
			d.secretsStore.Secrets = make(map[string]store.SecretEntry)
		}

		entry, exists := d.secretsStore.Secrets[req.Path]
		if exists {
			// Push current active state to version history before mutating
			oldVer := entry.Version
			if oldVer <= 0 {
				oldVer = 1
			}
			verSnapshot := store.SecretVersion{
				Version:      oldVer,
				Value:        entry.Value,
				Comment:      entry.Comment,
				Metadata:     entry.Metadata,
				LastModified: entry.LastModified,
			}
			entry.History = append(entry.History, verSnapshot)
			if len(entry.History) > 10 {
				entry.History = entry.History[len(entry.History)-10:]
			}
			entry.Version = oldVer + 1
			entry.DeletedAt = nil

			// Update values selectively if this is a partial update
			if req.Value != "" {
				entry.Value = req.Value
			}
			if req.Comment != "" {
				entry.Comment = req.Comment
			}
			if len(req.Metadata) > 0 {
				if entry.Metadata == nil {
					entry.Metadata = make(map[string]string)
				}
				for mk, mv := range req.Metadata {
					entry.Metadata[mk] = mv
				}
			}
			entry.LastModified = time.Now()
		} else {
			entry = store.SecretEntry{
				Value:        req.Value,
				Comment:      req.Comment,
				Metadata:     req.Metadata,
				Created:      time.Now(),
				LastModified: time.Now(),
				Version:      1,
			}
		}

		// Parse expiration if provided
		if req.Expires != "" {
			if t, err := time.Parse(time.RFC3339, req.Expires); err == nil {
				entry.Expires = t
			} else {
				d.sendError(c, fmt.Sprintf("invalid expiration date format: %v", err))
				return
			}
		}

		d.secretsStore.Secrets[req.Path] = entry

		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{Success: true})

	case "rename":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		oldPath := req.Path
		newPath := req.NewPath
		if newPath == "" {
			newPath = req.Value
		}
		if req.IsPrefix {
			count, err := d.secretsStore.RenamePrefix(oldPath, newPath)
			if err != nil {
				d.sendError(c, fmt.Sprintf("failed to rename prefix: %v", err))
				return
			}
			if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
				d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
				return
			}
			d.lastUsed = time.Now()
			d.sendResponse(c, IPCResponse{
				Success: true,
				Value:   fmt.Sprintf("Renamed %d secrets under prefix %q to %q", count, oldPath, newPath),
			})
		} else {
			err := d.secretsStore.RenameSecret(oldPath, newPath)
			if err != nil {
				d.sendError(c, fmt.Sprintf("failed to rename secret: %v", err))
				return
			}
			if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
				d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
				return
			}
			d.lastUsed = time.Now()
			d.sendResponse(c, IPCResponse{
				Success: true,
				Value:   fmt.Sprintf("Renamed secret %q to %q", oldPath, newPath),
			})
		}

	case "copy":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		srcPath := req.Path
		dstPath := req.NewPath
		if req.IsPrefix {
			count, err := d.secretsStore.CopyPrefix(srcPath, dstPath)
			if err != nil {
				d.sendError(c, fmt.Sprintf("failed to copy prefix: %v", err))
				return
			}
			if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
				d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
				return
			}
			d.lastUsed = time.Now()
			d.sendResponse(c, IPCResponse{
				Success: true,
				Value:   fmt.Sprintf("Copied %d secrets under prefix %q to %q", count, srcPath, dstPath),
			})
		} else {
			err := d.secretsStore.CopySecret(srcPath, dstPath)
			if err != nil {
				d.sendError(c, fmt.Sprintf("failed to copy secret: %v", err))
				return
			}
			if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
				d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
				return
			}
			d.lastUsed = time.Now()
			d.sendResponse(c, IPCResponse{
				Success: true,
				Value:   fmt.Sprintf("Copied secret %q to %q", srcPath, dstPath),
			})
		}

	case "clear":
		d.wipeMemory()
		d.sendResponse(c, IPCResponse{Success: true})

	case "backup":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		if !d.checkMemoryGuardrail() {
			d.sendError(c, "RESOURCE_EXHAUSTED: Memory saturation threshold exceeded. Please use scoped prefix filtering.")
			return
		}
		// Return all secrets for the backup/export
		d.sendResponse(c, IPCResponse{Success: true, Secrets: d.resolveAllSecrets(req.ExtendsProfile)})

	case "restore":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		if req.Secrets == nil {
			d.sendError(c, "no secrets provided to restore")
			return
		}
		// Merge secrets
		for k, entryVal := range req.Secrets {
			d.secretsStore.Secrets[k] = entryVal
		}
		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{Success: true})

	case "list":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		var paths []string
		var group map[string]store.SecretEntry
		if req.ShowTrash {
			secCount := len(d.secretsStore.Secrets)
			paths = make([]string, 0, secCount)
			group = make(map[string]store.SecretEntry, secCount)
			for k, entry := range d.secretsStore.Secrets {
				if entry.DeletedAt != nil {
					if req.Path == "" || strings.HasPrefix(k, req.Path) {
						paths = append(paths, k)
						group[k] = entry
					}
				}
			}
		} else {
			allSecrets := d.resolveAllSecrets(req.ExtendsProfile)
			paths = make([]string, 0, len(allSecrets))
			group = make(map[string]store.SecretEntry, len(allSecrets))
			for k, entry := range allSecrets {
				if req.Path == "" || strings.HasPrefix(k, req.Path) {
					paths = append(paths, k)
					group[k] = entry
				}
			}
		}
		sort.Strings(paths)
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success: true,
			Value:   strings.Join(paths, "\n"),
			Secrets: group,
		})

	case "delete":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		if req.IsPrefix {
			var count int
			var err error
			if req.Permanent {
				count, err = d.secretsStore.HardDeletePrefix(req.Path)
			} else {
				count, err = d.secretsStore.SoftDeletePrefix(req.Path)
			}
			if err != nil {
				d.sendError(c, fmt.Sprintf("failed to delete prefix: %v", err))
				return
			}
			if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
				d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
				return
			}
			d.lastUsed = time.Now()
			msg := fmt.Sprintf("Soft-deleted %d secrets under prefix %q (use 'sec ls --trash' to view)", count, req.Path)
			if req.Permanent {
				msg = fmt.Sprintf("Permanently deleted %d secrets under prefix %q", count, req.Path)
			}
			d.sendResponse(c, IPCResponse{
				Success: true,
				Value:   msg,
			})
		} else {
			var err error
			if req.Permanent {
				err = d.secretsStore.HardDeleteSecret(req.Path)
			} else {
				err = d.secretsStore.SoftDeleteSecret(req.Path)
			}
			if err != nil {
				d.sendError(c, fmt.Sprintf("failed to delete secret: %v", err))
				return
			}
			if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
				d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
				return
			}
			d.lastUsed = time.Now()
			msg := fmt.Sprintf("Soft-deleted secret %q (use 'sec restore-deleted %s' to undo)", req.Path, req.Path)
			if req.Permanent {
				msg = fmt.Sprintf("Permanently deleted secret %q", req.Path)
			}
			d.sendResponse(c, IPCResponse{
				Success: true,
				Value:   msg,
			})
		}

	case "restore_deleted":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		if err := d.secretsStore.RestoreDeletedSecret(req.Path); err != nil {
			d.sendError(c, fmt.Sprintf("failed to restore deleted secret: %v", err))
			return
		}
		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success: true,
			Value:   fmt.Sprintf("Restored soft-deleted secret %q", req.Path),
		})

	case "history":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		entry, exists := d.secretsStore.Secrets[req.Path]
		if !exists {
			d.sendError(c, fmt.Sprintf("secret %q not found", req.Path))
			return
		}
		currVer := entry.Version
		if currVer <= 0 {
			currVer = 1
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success:     true,
			ItemVersion: currVer,
			History:     entry.History,
		})

	case "rollback":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		entry, exists := d.secretsStore.Secrets[req.Path]
		if !exists {
			d.sendError(c, fmt.Sprintf("secret %q not found", req.Path))
			return
		}
		targetVer := req.TargetVersion
		var found *store.SecretVersion
		for _, h := range entry.History {
			if h.Version == targetVer {
				found = &h
				break
			}
		}
		if found == nil {
			d.sendError(c, fmt.Sprintf("version %d not found in history for secret %q", targetVer, req.Path))
			return
		}

		// Push current state into history before rolling back
		oldVer := entry.Version
		if oldVer <= 0 {
			oldVer = 1
		}
		verSnapshot := store.SecretVersion{
			Version:      oldVer,
			Value:        entry.Value,
			Comment:      entry.Comment,
			Metadata:     entry.Metadata,
			LastModified: entry.LastModified,
		}
		entry.History = append(entry.History, verSnapshot)
		if len(entry.History) > 10 {
			entry.History = entry.History[len(entry.History)-10:]
		}

		entry.Version = oldVer + 1
		entry.Value = found.Value
		entry.Comment = found.Comment
		entry.Metadata = found.Metadata
		entry.LastModified = time.Now()
		entry.DeletedAt = nil

		d.secretsStore.Secrets[req.Path] = entry
		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success: true,
			Value:   fmt.Sprintf("Rolled back secret %q to version %d (new active version: v%d)", req.Path, targetVer, entry.Version),
		})

	case "status":
		d.lastUsed = time.Now()
		totalSecrets := 0
		expiredSecrets := 0
		if d.secretsStore != nil && d.secretsStore.Secrets != nil {
			totalSecrets = len(d.secretsStore.Secrets)
			now := time.Now()
			for _, entry := range d.secretsStore.Secrets {
				if !entry.Expires.IsZero() && now.After(entry.Expires) {
					expiredSecrets++
				}
			}
		}
		storePath, _ := store.GetStorePath(d.profile)
		var fileSize int64
		if fi, err := os.Stat(storePath); err == nil {
			fileSize = fi.Size()
		}

		info := map[string]interface{}{
			"profile":          d.profile,
			"version":          d.version,
			"socket_path":      d.socketPath,
			"store_path":       storePath,
			"store_size_bytes": fileSize,
			"is_unlocked":      d.masterKey != nil,
			"total_secrets":    totalSecrets,
			"expired_secrets":  expiredSecrets,
			"session_start":    d.sessionStart.Format(time.RFC3339),
			"last_used":        d.lastUsed.Format(time.RFC3339),
			"session_ttl":      d.sessionTTL.String(),
			"grace_ttl":        d.graceTTL.String(),
		}
		d.sendResponse(c, IPCResponse{
			Success:    true,
			StatusInfo: info,
		})

	case "audit":
		cfgDir, err := config.GetConfigDir()
		if err != nil {
			d.sendError(c, fmt.Sprintf("failed to resolve config dir: %v", err))
			return
		}
		logPath := filepath.Join(cfgDir, "audit.log")
		// #nosec G304
		data, err := os.ReadFile(logPath)
		if err != nil && !os.IsNotExist(err) {
			d.sendError(c, fmt.Sprintf("failed to read audit log: %v", err))
			return
		}
		rawStr := strings.TrimSpace(string(data))
		if rawStr == "" {
			d.sendResponse(c, IPCResponse{Success: true, Value: ""})
			return
		}
		lines := strings.Split(rawStr, "\n")
		limit := req.Limit
		if limit <= 0 || limit > len(lines) {
			limit = 50
		}
		if limit < len(lines) {
			lines = lines[len(lines)-limit:]
		}
		d.sendResponse(c, IPCResponse{
			Success: true,
			Value:   strings.Join(lines, "\n"),
		})

	default:
		d.sendError(c, "unknown action")
	}
}

func (d *Daemon) logAudit(action, path string, peerPID int, success bool, errStr string) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		return
	}
	logPath := filepath.Join(cfgDir, "audit.log")
	entry := AuditLogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    action,
		Path:      path,
		PeerPID:   peerPID,
		Success:   success,
		Error:     errStr,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	// #nosec G304 G703
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.Write(append(data, '\n'))
		_ = f.Close()
	}
}

func (d *Daemon) sendResponse(c net.Conn, resp IPCResponse) {
	_ = json.NewEncoder(c).Encode(resp)
}

func (d *Daemon) sendError(c net.Conn, msg string) {
	_ = json.NewEncoder(c).Encode(IPCResponse{
		Success: false,
		Error:   msg,
	})
}

func (d *Daemon) resolveSecret(path string, extendsProfile string) (store.SecretEntry, bool) {
	entry, exists := d.secretsStore.Secrets[path]
	if exists && entry.DeletedAt == nil {
		return entry, true
	}
	if extendsProfile != "" && extendsProfile != d.profile {
		parentStore, err := store.LoadStore(extendsProfile, d.masterKey)
		if err == nil && parentStore != nil {
			entry, exists := parentStore.Secrets[path]
			if exists && entry.DeletedAt == nil {
				return entry, true
			}
		}
	}
	return store.SecretEntry{}, false
}

func (d *Daemon) resolveAllSecrets(extendsProfile string) map[string]store.SecretEntry {
	allocCap := 0
	if d.secretsStore != nil && d.secretsStore.Secrets != nil {
		allocCap += len(d.secretsStore.Secrets)
	}
	res := make(map[string]store.SecretEntry, allocCap)
	if extendsProfile != "" && extendsProfile != d.profile {
		parentStore, err := store.LoadStore(extendsProfile, d.masterKey)
		if err == nil && parentStore != nil {
			for k, v := range parentStore.Secrets {
				if v.DeletedAt == nil {
					res[k] = v
				}
			}
		}
	}
	for k, v := range d.secretsStore.Secrets {
		if v.DeletedAt == nil {
			res[k] = v
		}
	}
	return res
}
