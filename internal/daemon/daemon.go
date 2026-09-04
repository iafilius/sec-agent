package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/store"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IPCAction represents a strongly-typed IPC command action.
type IPCAction string

const (
	IPCActionOpen           IPCAction = "open"
	IPCActionPing           IPCAction = "ping"
	IPCActionGet            IPCAction = "get"
	IPCActionSet            IPCAction = "set"
	IPCActionDelete         IPCAction = "delete"
	IPCActionRestore        IPCAction = "restore"
	IPCActionBackup         IPCAction = "backup"
	IPCActionRestoreDeleted IPCAction = "restore_deleted"
	IPCActionAudit          IPCAction = "audit"
	IPCActionList           IPCAction = "list"
	IPCActionGetGroup       IPCAction = "get_group"
	IPCActionRename         IPCAction = "rename"
	IPCActionCopy           IPCAction = "copy"
	IPCActionClear          IPCAction = "clear"
	IPCActionStatus         IPCAction = "status"
	IPCActionHistory        IPCAction = "history"
	IPCActionRollback       IPCAction = "rollback"
	IPCActionReexec         IPCAction = "reexec"
	IPCActionLease          IPCAction = "lease"
)

// String returns the string representation of IPCAction.
func (a IPCAction) String() string {
	return string(a)
}

// IPCRequest defines the format for messages sent to the daemon.
type IPCRequest struct {
	Action         IPCAction                    `json:"action"`
	Path           string                       `json:"path,omitempty"`
	Value          string                       `json:"value,omitempty"`
	Comment        string                       `json:"comment,omitempty"`
	Metadata       map[string]string            `json:"metadata,omitempty"`
	TTL            string                       `json:"ttl,omitempty"`
	Grace          string                       `json:"grace,omitempty"`
	Secrets        map[string]store.SecretEntry `json:"secrets,omitempty"`
	Key            []byte                       `json:"key,omitempty"`
	NewPath        string                       `json:"new_path,omitempty"`
	IsPrefix       bool                         `json:"is_prefix,omitempty"`
	Limit          int                          `json:"limit,omitempty"`
	Expires        string                       `json:"expires,omitempty"`
	ShowExpired    bool                         `json:"show_expired,omitempty"`
	Token          string                       `json:"token,omitempty"`
	ExtendsProfile string                       `json:"extends_profile,omitempty"`
	TargetVersion  int                          `json:"target_version,omitempty"`
	ShowTrash      bool                         `json:"show_trash,omitempty"`
	Permanent      bool                         `json:"permanent,omitempty"`
}

// Validate checks whether the IPCRequest action is supported.
func (req *IPCRequest) Validate() error {
	switch req.Action {
	case IPCActionOpen, IPCActionPing, IPCActionGet, IPCActionSet, IPCActionDelete,
		IPCActionRestore, IPCActionBackup, IPCActionRestoreDeleted, IPCActionAudit,
		IPCActionList, IPCActionGetGroup, IPCActionRename, IPCActionCopy,
		IPCActionClear, IPCActionStatus, IPCActionHistory, IPCActionRollback, IPCActionReexec, IPCActionLease:
		return nil
	default:
		return fmt.Errorf("unknown or unsupported IPC action: %q", req.Action)
	}
}

// DaemonStatePayload defines the in-memory payload transferred across kernel pipe during hot-reload.
type DaemonStatePayload struct {
	MasterKey    []byte                                `json:"master_key"`
	Profile      string                                `json:"profile"`
	SessionStart time.Time                             `json:"session_start"`
	SessionTTL   time.Duration                         `json:"session_ttl"`
	GraceTTL     time.Duration                         `json:"grace_ttl"`
	LastUsed     time.Time                             `json:"last_used"`
	SessionToken string                                `json:"session_token"`
	Secrets      map[store.SecretKey]store.SecretEntry `json:"secrets,omitempty"`
}

// AuditEventAction represents a strongly-typed security audit event action.
type AuditEventAction string

const (
	AuditEventOpen   AuditEventAction = "OPEN"
	AuditEventGet    AuditEventAction = "GET"
	AuditEventSet    AuditEventAction = "SET"
	AuditEventDelete AuditEventAction = "DELETE"
	AuditEventClear  AuditEventAction = "CLEAR"
	AuditEventAudit  AuditEventAction = "AUDIT"
	AuditEventReexec AuditEventAction = "REEXEC"
)

// Validate checks whether the audit action is valid.
func (a AuditEventAction) Validate() error {
	switch a {
	case AuditEventOpen, AuditEventGet, AuditEventSet, AuditEventDelete, AuditEventClear, AuditEventAudit, AuditEventReexec:
		return nil
	default:
		return fmt.Errorf("unsupported audit event action: %q", a)
	}
}

// AuditLogEntry represents a single audit event record.
type AuditLogEntry struct {
	Timestamp       string           `json:"timestamp"`
	Action          AuditEventAction `json:"action"`
	Profile         string           `json:"profile,omitempty"`
	StoreFilePath   string           `json:"store_file_path,omitempty"`
	Path            string           `json:"path,omitempty"`
	MasterKeySHA256 string           `json:"master_key_sha256,omitempty"`
	PeerPID         int              `json:"peer_pid,omitempty"`
	ProcessName     string           `json:"process_name,omitempty"`
	Actor           string           `json:"actor,omitempty"`
	ClientMode      string           `json:"client_mode,omitempty"`
	ValueLength     int              `json:"value_length,omitempty"`
	SecretVersion   int              `json:"secret_version,omitempty"`
	Success         bool             `json:"success"`
	Error           string           `json:"error,omitempty"`
	Details         string           `json:"details,omitempty"`
}

// DaemonStatusInfo represents strongly-typed diagnostic status metadata.
type DaemonStatusInfo struct {
	Profile        string `json:"profile"`
	Version        string `json:"version"`
	SocketPath     string `json:"socket_path"`
	StorePath      string `json:"store_path"`
	StoreSizeBytes int64  `json:"store_size_bytes"`
	IsUnlocked     bool   `json:"is_unlocked"`
	TotalSecrets   int    `json:"total_secrets"`
	ExpiredSecrets int    `json:"expired_secrets"`
	SessionStart   string `json:"session_start"`
	LastUsed       string `json:"last_used"`
	SessionTTL     string `json:"session_ttl"`
	GraceTTL       string `json:"grace_ttl"`
}

// IPCResponse defines the format for replies from the daemon.
type IPCResponse struct {
	Success      bool                         `json:"success"`
	Value        string                       `json:"value,omitempty"`
	Comment      string                       `json:"comment,omitempty"`
	Metadata     map[string]string            `json:"metadata,omitempty"`
	Error        string                       `json:"error,omitempty"`
	ErrorCode    store.ErrorCode              `json:"error_code,omitempty"`
	Secrets      map[string]store.SecretEntry `json:"secrets,omitempty"`
	Created      time.Time                    `json:"created,omitempty"`
	LastModified time.Time                    `json:"last_modified,omitempty"`
	LastAccessed time.Time                    `json:"last_accessed,omitempty"`
	AccessCount  uint64                       `json:"access_count,omitempty"`
	Expires      time.Time                    `json:"expires,omitempty"`
	Token        string                       `json:"token,omitempty"`
	Version      string                       `json:"version,omitempty"`
	StatusInfo   *DaemonStatusInfo            `json:"status_info,omitempty"`
	History      []store.SecretVersion        `json:"history,omitempty"`
	ItemVersion  int                          `json:"item_version,omitempty"`
}

// Daemon represents the background secrets agent.
type Daemon struct {
	mu             sync.Mutex
	masterKey      []byte
	secretsStore   *store.EncryptedStore
	sessionStart   time.Time
	sessionTTL     time.Duration
	lastUsed       time.Time
	graceTTL       time.Duration
	socketPath     string
	listener       net.Listener
	profile        string
	sessionToken   string
	version        string
	IsTestInstance bool
}

// NewDaemon creates a new daemon instance.
func NewDaemon(profile string, ttl time.Duration, version string) (*Daemon, error) {
	initMemoryLimits()

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
			storeInstance = &store.EncryptedStore{Secrets: make(map[store.SecretKey]store.SecretEntry)}
		}
		if len(payload.Secrets) > 0 {
			if storeInstance.Secrets == nil {
				storeInstance.Secrets = make(map[store.SecretKey]store.SecretEntry)
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
		d.logAudit(AuditEventReexec, d.profile, 0, true, "")
	}
	return nil
}

// Start runs the IPC Unix socket server.
func (d *Daemon) Start() error {
	_ = d.checkAndRestoreReexecState()

	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove old socket: %w", err)
	}

	config.PurgeAllSessionTokenFiles()

	l, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket %s: %w", d.socketPath, err)
	}
	d.listener = l

	if err := os.Chmod(d.socketPath, 0600); err != nil {
		_ = l.Close()
		return fmt.Errorf("failed to secure socket permissions: %w", err)
	}

	d.writePIDLockfile()
	defer d.removePIDLockfile()

	go d.expiryTicker()

	for {
		conn, err := l.Accept()
		if err != nil {
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
	d.removePIDLockfile()
}

func (d *Daemon) processRequest(c net.Conn, req IPCRequest, peerPID int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := req.Validate(); err != nil {
		d.sendErrorCode(c, err.Error(), store.ErrCodeInternalError)
		return
	}

	if d.isExpired() {
		d.wipeMemory()
	}

	if req.Action != IPCActionOpen && req.Action != IPCActionPing {
		if d.sessionToken == "" || d.masterKey == nil {
			d.sendResponse(c, IPCResponse{Success: false, Error: "Session locked or expired. Please run 'sec open' to authorize."})
			return
		}
		if req.Token != "" && req.Token != d.sessionToken {
			d.sendResponse(c, IPCResponse{Success: false, Error: "ACCESS DENIED: Invalid session token"})
			return
		}
	}

	switch req.Action {
	case IPCActionPing:
		if d.masterKey == nil {
			d.sendResponse(c, IPCResponse{Success: false, Error: "Session locked", Version: d.version})
		} else {
			d.sendResponse(c, IPCResponse{Success: true, Value: "Active", Version: d.version})
		}

	case IPCActionReexec:
		if d.masterKey == nil {
			d.sendResponse(c, IPCResponse{Success: false, Error: "Session locked. Cannot hot-reload a locked daemon.", Version: d.version})
			return
		}

		r, w, err := os.Pipe()
		if err != nil {
			d.sendError(c, fmt.Sprintf("failed to create hot-reload state pipe: %v", err))
			return
		}

		var activeSecrets map[store.SecretKey]store.SecretEntry
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

		d.sendResponse(c, IPCResponse{
			Success: true,
			Value:   "Daemon hot-reloading in memory via pipe handoff...",
			Version: d.version,
		})

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
			d.logAudit(AuditEventReexec, d.profile, peerPID, false, err.Error())
			return
		}
		_ = r.Close()
		d.logAudit(AuditEventReexec, d.profile, peerPID, true, "")
		go func() {
			time.Sleep(50 * time.Millisecond)
			if !d.IsTestInstance && os.Getenv("SEC_TEST_MODE") != "1" {
				os.Exit(0)
			}
		}()
		return

	case IPCActionOpen:
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

		if req.TTL != "" {
			if parsedTTL, err := time.ParseDuration(req.TTL); err == nil {
				d.sessionTTL = parsedTTL
			}
		}
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

	case IPCActionGet:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		entry, exists := d.resolveSecret(req.Path, req.ExtendsProfile)
		if !exists {
			d.sendError(c, fmt.Sprintf("secret %q not found", req.Path))
			return
		}

		if !entry.Expires.IsZero() && time.Now().After(entry.Expires) {
			if !req.ShowExpired {
				d.sendError(c, "Secret has expired")
				return
			}
		}

		now := time.Now()
		entry.LastAccessed = now
		entry.AccessCount++

		if d.secretsStore != nil && d.secretsStore.Secrets != nil {
			if localEntry, ok := d.secretsStore.Secrets[store.SecretKey(req.Path)]; ok {
				localEntry.LastAccessed = now
				localEntry.AccessCount++
				d.secretsStore.Secrets[store.SecretKey(req.Path)] = localEntry
				_ = store.SaveStore(d.profile, d.secretsStore, d.masterKey)
			}
		}

		d.lastUsed = time.Now()
		d.logAudit(AuditEventGet, req.Path, peerPID, true, "")
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
			ItemVersion:  entry.Version,
		})

	case IPCActionSet:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		d.ensureStoreInitialized()

		var expTime time.Time
		if req.Expires != "" {
			parsedTime, err := time.Parse(time.RFC3339, req.Expires)
			if err != nil {
				d.sendError(c, fmt.Sprintf("invalid expiration format (expected RFC3339): %v", err))
				return
			}
			expTime = parsedTime
		}

		existing, ok := d.secretsStore.Secrets[store.SecretKey(req.Path)]
		newVersion := 1
		var history []store.SecretVersion

		if ok {
			newVersion = existing.Version + 1
			history = existing.History

			verSnapshot := store.SecretVersion{
				Version:      existing.Version,
				Value:        existing.Value,
				Comment:      existing.Comment,
				Metadata:     existing.Metadata,
				LastModified: existing.LastModified,
			}
			history = append(history, verSnapshot)
			if len(history) > 10 {
				history = history[len(history)-10:]
			}
		}

		entry := store.SecretEntry{
			Value:        req.Value,
			Comment:      req.Comment,
			Metadata:     req.Metadata,
			Created:      time.Now(),
			LastModified: time.Now(),
			Expires:      expTime,
			Version:      newVersion,
			History:      history,
		}
		if ok && !existing.Created.IsZero() {
			entry.Created = existing.Created
		}

		d.secretsStore.Secrets[store.SecretKey(req.Path)] = entry
		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.logAudit(AuditEventSet, req.Path, peerPID, true, "")
		d.sendResponse(c, IPCResponse{Success: true})

	case IPCActionDelete:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		d.ensureStoreInitialized()

		if req.IsPrefix {
			prefix := req.Path
			if prefix != "" && !strings.HasSuffix(prefix, "/") {
				prefix += "/"
			}
			now := time.Now()
			deletedCount := 0
			for k, entry := range d.secretsStore.Secrets {
				keyStr := string(k)
				if strings.HasPrefix(keyStr, prefix) || keyStr == req.Path {
					if req.Permanent {
						delete(d.secretsStore.Secrets, k)
					} else {
						entry.DeletedAt = &now
						d.secretsStore.Secrets[k] = entry
					}
					deletedCount++
				}
			}
			if deletedCount == 0 {
				d.sendError(c, fmt.Sprintf("no secrets found matching prefix %q", req.Path))
				return
			}
		} else {
			if req.Permanent {
				delete(d.secretsStore.Secrets, store.SecretKey(req.Path))
			} else {
				entry, ok := d.secretsStore.Secrets[store.SecretKey(req.Path)]
				if !ok {
					d.sendError(c, fmt.Sprintf("secret %q not found", req.Path))
					return
				}
				now := time.Now()
				entry.DeletedAt = &now
				d.secretsStore.Secrets[store.SecretKey(req.Path)] = entry
			}
		}
		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.logAudit(AuditEventDelete, req.Path, peerPID, true, "")
		d.sendResponse(c, IPCResponse{Success: true})

	case IPCActionRestoreDeleted:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		d.ensureStoreInitialized()
		entry, ok := d.secretsStore.Secrets[store.SecretKey(req.Path)]
		if !ok || entry.DeletedAt == nil {
			d.sendError(c, fmt.Sprintf("no soft-deleted secret found at path %q", req.Path))
			return
		}
		entry.DeletedAt = nil
		d.secretsStore.Secrets[store.SecretKey(req.Path)] = entry
		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{Success: true})

	case IPCActionBackup:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		all := d.resolveAllSecrets(req.ExtendsProfile, false)
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success: true,
			Secrets: all,
		})

	case IPCActionRestore:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		if d.secretsStore.Secrets == nil {
			d.secretsStore.Secrets = make(map[store.SecretKey]store.SecretEntry)
		}
		for k, v := range req.Secrets {
			d.secretsStore.Secrets[store.SecretKey(k)] = v
		}
		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{Success: true})

	case IPCActionList:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		all := d.resolveAllSecrets(req.ExtendsProfile, req.ShowTrash)
		var list []string
		now := time.Now()
		for k, entry := range all {
			if req.ShowTrash {
				if entry.DeletedAt != nil {
					list = append(list, k)
				}
				continue
			}
			if entry.DeletedAt != nil {
				continue
			}
			if !entry.Expires.IsZero() && now.After(entry.Expires) {
				if !req.ShowExpired {
					continue
				}
			}
			list = append(list, k)
		}
		sort.Strings(list)
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success: true,
			Value:   strings.Join(list, "\n"),
		})

	case IPCActionGetGroup:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		all := d.resolveAllSecrets(req.ExtendsProfile, false)
		res := make(map[string]store.SecretEntry)
		prefix := req.Path
		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		now := time.Now()
		for k, entry := range all {
			if strings.HasPrefix(k, prefix) {
				if !entry.Expires.IsZero() && now.After(entry.Expires) {
					if !req.ShowExpired {
						continue
					}
				}
				res[k] = entry
			}
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success: true,
			Secrets: res,
		})

	case IPCActionRename:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		d.ensureStoreInitialized()
		if req.NewPath == "" {
			d.sendError(c, "new_path is required for rename action")
			return
		}

		if req.IsPrefix {
			oldPrefix := req.Path
			if !strings.HasSuffix(oldPrefix, "/") {
				oldPrefix += "/"
			}
			newPrefix := req.NewPath
			if !strings.HasSuffix(newPrefix, "/") {
				newPrefix += "/"
			}

			count := 0
			for k, entry := range d.secretsStore.Secrets {
				keyStr := string(k)
				if strings.HasPrefix(keyStr, oldPrefix) {
					newKeyStr := newPrefix + strings.TrimPrefix(keyStr, oldPrefix)
					delete(d.secretsStore.Secrets, k)
					entry.LastModified = time.Now()
					d.secretsStore.Secrets[store.SecretKey(newKeyStr)] = entry
					count++
				}
			}
			if count == 0 {
				d.sendError(c, fmt.Sprintf("no secrets found under prefix %q", oldPrefix))
				return
			}
		} else {
			entry, ok := d.secretsStore.Secrets[store.SecretKey(req.Path)]
			if !ok {
				d.sendError(c, fmt.Sprintf("secret %q not found", req.Path))
				return
			}
			delete(d.secretsStore.Secrets, store.SecretKey(req.Path))
			entry.LastModified = time.Now()
			d.secretsStore.Secrets[store.SecretKey(req.NewPath)] = entry
		}

		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{Success: true})

	case IPCActionCopy:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		d.ensureStoreInitialized()
		if req.NewPath == "" {
			d.sendError(c, "new_path is required for copy action")
			return
		}

		if req.IsPrefix {
			oldPrefix := req.Path
			if !strings.HasSuffix(oldPrefix, "/") {
				oldPrefix += "/"
			}
			newPrefix := req.NewPath
			if !strings.HasSuffix(newPrefix, "/") {
				newPrefix += "/"
			}

			all := d.resolveAllSecrets(req.ExtendsProfile, false)
			count := 0
			for k, entry := range all {
				if strings.HasPrefix(k, oldPrefix) {
					newKeyStr := newPrefix + strings.TrimPrefix(k, oldPrefix)
					entry.Created = time.Now()
					entry.LastModified = time.Now()
					d.secretsStore.Secrets[store.SecretKey(newKeyStr)] = entry
					count++
				}
			}
			if count == 0 {
				d.sendError(c, fmt.Sprintf("no secrets found under prefix %q", oldPrefix))
				return
			}
		} else {
			entry, exists := d.resolveSecret(req.Path, req.ExtendsProfile)
			if !exists {
				d.sendError(c, fmt.Sprintf("secret %q not found", req.Path))
				return
			}
			entry.Created = time.Now()
			entry.LastModified = time.Now()
			d.secretsStore.Secrets[store.SecretKey(req.NewPath)] = entry
		}

		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{Success: true})

	case IPCActionClear:
		d.wipeMemory()
		d.logAudit(AuditEventClear, d.profile, peerPID, true, "")
		d.sendResponse(c, IPCResponse{Success: true})

	case IPCActionHistory:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		entry, exists := d.resolveSecret(req.Path, req.ExtendsProfile)
		if !exists {
			d.sendError(c, fmt.Sprintf("secret %q not found", req.Path))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success:     true,
			History:     entry.History,
			ItemVersion: entry.Version,
		})

	case IPCActionRollback:
		if d.masterKey == nil {
			d.sendError(c, "Session locked. Please unlock first.")
			return
		}
		d.ensureStoreInitialized()
		entry, exists := d.resolveSecret(req.Path, req.ExtendsProfile)
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

		d.secretsStore.Secrets[store.SecretKey(req.Path)] = entry
		if err := store.SaveStore(d.profile, d.secretsStore, d.masterKey); err != nil {
			d.sendError(c, fmt.Sprintf("failed to persist store: %v", err))
			return
		}
		d.lastUsed = time.Now()
		d.sendResponse(c, IPCResponse{
			Success: true,
			Value:   fmt.Sprintf("Rolled back secret %q to version %d (new active version: v%d)", req.Path, targetVer, entry.Version),
		})

	case IPCActionStatus:
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

		info := &DaemonStatusInfo{
			Profile:        d.profile,
			Version:        d.version,
			SocketPath:     d.socketPath,
			StorePath:      storePath,
			StoreSizeBytes: fileSize,
			IsUnlocked:     d.masterKey != nil,
			TotalSecrets:   totalSecrets,
			ExpiredSecrets: expiredSecrets,
			SessionStart:   d.sessionStart.Format(time.RFC3339),
			LastUsed:       d.lastUsed.Format(time.RFC3339),
			SessionTTL:     d.sessionTTL.String(),
			GraceTTL:       d.graceTTL.String(),
		}
		d.sendResponse(c, IPCResponse{
			Success:    true,
			StatusInfo: info,
		})

	case IPCActionAudit:
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

	case IPCActionLease:
		resp, err := d.handleLease(req)
		if err != nil {
			d.sendError(c, err.Error())
			return
		}
		d.sendResponse(c, resp)

	default:
		d.sendError(c, "unknown action")
	}
}

type OperationLogEntry struct {
	Timestamp       string `json:"timestamp"`
	Actor           string `json:"actor"`
	Action          string `json:"action"`
	Profile         string `json:"profile"`
	MasterKeySHA256 string `json:"master_key_sha256"`
	Details         string `json:"details"`
	Success         bool   `json:"success"`
	Error           string `json:"error,omitempty"`
}

func LogOperation(actor, action, profile, masterKeyFP, details string, success bool, errStr string) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		return
	}
	logPath := filepath.Join(cfgDir, "operations.log")
	if actor == "" {
		actor = "terminal"
	}
	if profile == "" {
		profile = "default"
	}

	entry := OperationLogEntry{
		Timestamp:       time.Now().Format(time.RFC3339),
		Actor:           actor,
		Action:          action,
		Profile:         profile,
		MasterKeySHA256: masterKeyFP,
		Details:         details,
		Success:         success,
		Error:           errStr,
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

func getProcessName(pid int) string {
	if pid <= 0 {
		return ""
	}
	// #nosec G204
	out, err := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "comm=").Output()
	if err != nil {
		return fmt.Sprintf("PID %d", pid)
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		return fmt.Sprintf("PID %d", pid)
	}
	return filepath.Base(name)
}

func (d *Daemon) logAudit(action AuditEventAction, path string, peerPID int, success bool, errStr string) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		return
	}
	logPath := filepath.Join(cfgDir, "audit.log")

	storePath := ""
	if p, err := store.GetStorePath(d.profile); err == nil {
		storePath = p
	}

	fp := ""
	if len(d.masterKey) > 0 {
		fp = crypto.MasterKeyFingerprint(d.masterKey)
	}

	valLen := 0
	ver := 0
	if d.secretsStore != nil && d.secretsStore.Secrets != nil && path != "" {
		if s, ok := d.secretsStore.Secrets[store.SecretKey(path)]; ok {
			valLen = len(s.Value)
			ver = s.Version
		}
	}

	procName := getProcessName(peerPID)

	prof := d.profile
	if prof == "" {
		prof = "default"
	}

	entry := AuditLogEntry{
		Timestamp:       time.Now().Format(time.RFC3339),
		Action:          action,
		Profile:         prof,
		StoreFilePath:   storePath,
		Path:            path,
		MasterKeySHA256: fp,
		PeerPID:         peerPID,
		ProcessName:     procName,
		ClientMode:      "daemon",
		ValueLength:     valLen,
		SecretVersion:   ver,
		Success:         success,
		Error:           errStr,
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

func (d *Daemon) ensureStoreInitialized() {
	if d.secretsStore == nil {
		d.secretsStore = &store.EncryptedStore{Secrets: make(map[store.SecretKey]store.SecretEntry)}
	}
	if d.secretsStore.Secrets == nil {
		d.secretsStore.Secrets = make(map[store.SecretKey]store.SecretEntry)
	}
}

func (d *Daemon) resolveSecret(path string, extendsProfile string) (store.SecretEntry, bool) {
	if d.secretsStore != nil && d.secretsStore.Secrets != nil {
		entry, exists := d.secretsStore.Secrets[store.SecretKey(path)]
		if exists && entry.DeletedAt == nil {
			return entry, true
		}
	}
	if extendsProfile != "" && extendsProfile != d.profile {
		parentStore, err := store.LoadStore(extendsProfile, d.masterKey)
		if err == nil && parentStore != nil && parentStore.Secrets != nil {
			entry, exists := parentStore.Secrets[store.SecretKey(path)]
			if exists && entry.DeletedAt == nil {
				return entry, true
			}
		}
	}
	return store.SecretEntry{}, false
}

func (d *Daemon) resolveAllSecrets(extendsProfile string, includeTrash bool) map[string]store.SecretEntry {
	allocCap := 0
	if d.secretsStore != nil && d.secretsStore.Secrets != nil {
		allocCap += len(d.secretsStore.Secrets)
	}
	res := make(map[string]store.SecretEntry, allocCap)
	if extendsProfile != "" && extendsProfile != d.profile {
		parentStore, err := store.LoadStore(extendsProfile, d.masterKey)
		if err == nil && parentStore != nil && parentStore.Secrets != nil {
			for k, v := range parentStore.Secrets {
				if includeTrash || v.DeletedAt == nil {
					res[string(k)] = v
				}
			}
		}
	}
	if d.secretsStore != nil && d.secretsStore.Secrets != nil {
		for k, v := range d.secretsStore.Secrets {
			if includeTrash || v.DeletedAt == nil {
				res[string(k)] = v
			}
		}
	}
	return res
}
