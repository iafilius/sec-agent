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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"secure_secrets/config"
	"secure_secrets/store"
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
	Expires     string                         `json:"expires,omitempty"`      // RFC3339 formatted expiration time
	ShowExpired bool                           `json:"show_expired,omitempty"` // Override to show expired secrets
	Token       string                         `json:"token,omitempty"`        // Shell session token
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
	Expires      time.Time                    `json:"expires,omitempty"`
	Token        string                       `json:"token,omitempty"` // Shell session token
	Version      string                       `json:"version,omitempty"`
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
}

// NewDaemon creates a new daemon instance.
func NewDaemon(profile string, ttl time.Duration, version string) (*Daemon, error) {
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

// Start runs the IPC Unix socket server.
func (d *Daemon) Start() error {
	// Clean up existing socket file if it exists
	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove old socket: %w", err)
	}

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

// Stop stops the server and wipes memory cache.
func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wipeMemory()
	if d.listener != nil {
		_ = d.listener.Close()
	}
	_ = os.Remove(d.socketPath)
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
		if req.Token != d.sessionToken {
			d.sendResponse(c, IPCResponse{Success: false, Error: "ACCESS DENIED: Invalid or missing session token"})
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
		entry, exists := d.secretsStore.Secrets[req.Path]
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

		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success:      true,
			Value:        entry.Value,
			Comment:      entry.Comment,
			Metadata:     entry.Metadata,
			Created:      entry.Created,
			LastModified: entry.LastModified,
			Expires:      entry.Expires,
		})

	case "set":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}

		entry, exists := d.secretsStore.Secrets[req.Path]
		if exists {
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

	case "clear":
		d.wipeMemory()
		d.sendResponse(c, IPCResponse{Success: true})

	case "backup":
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		// Return all secrets for the backup/export
		d.sendResponse(c, IPCResponse{Success: true, Secrets: d.secretsStore.Secrets})

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

	default:
		d.sendError(c, "unknown action")
	}
}

func (d *Daemon) sendResponse(c net.Conn, resp IPCResponse) {
	_ = json.NewEncoder(c).Encode(resp)
}

func (d *Daemon) sendError(c net.Conn, msg string) {
	d.sendResponse(c, IPCResponse{Success: false, Error: msg})
}
