package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
	"sort"
	"strings"
	"time"
)

// GUIStatusResponseDTO represents the JSON payload for /api/status.
type GUIStatusResponseDTO struct {
	Profile            string         `json:"profile"`
	Unlocked           bool           `json:"unlocked"`
	Version            string         `json:"version"`
	DatabaseFile       string         `json:"database_file"`
	DatabasePath       string         `json:"database_path"`
	DatabaseSize       string         `json:"database_size"`
	DatabaseModified   string         `json:"database_modified"`
	ProfileTier        string         `json:"profile_tier"`
	IsV2               bool           `json:"is_v2"`
	VaultSchema        string         `json:"vault_schema"`
	AvailableDatabases []DatabaseInfo `json:"available_databases"`
	Error              string         `json:"error,omitempty"`
}

// GUIUnlockResponseDTO represents the JSON payload for /api/unlock.
type GUIUnlockResponseDTO struct {
	Profile  string `json:"profile"`
	Unlocked bool   `json:"unlocked"`
	Error    string `json:"error,omitempty"`
}

// GUISecretsListDTO represents the JSON payload for /api/secrets.
type GUISecretsListDTO struct {
	Profile string       `json:"profile"`
	Count   int          `json:"count"`
	Secrets []SecretItem `json:"secrets"`
}

type SecretItem struct {
	Key          store.SecretKey `json:"key"`
	Value        string          `json:"value"`
	Comment      string          `json:"comment,omitempty"`
	Created      string          `json:"created"`
	LastModified string          `json:"last_modified"`
	LastAccessed string          `json:"last_accessed"`
	AccessCount  uint64          `json:"access_count"`
	Version      int             `json:"version"`
	IsStale      bool            `json:"is_stale"`
}

func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host != "127.0.0.1:9876" && host != "localhost:9876" && !strings.HasPrefix(host, "127.0.0.1:") && !strings.HasPrefix(host, "localhost:") {
			http.Error(w, "403 Forbidden: Invalid Host Header", http.StatusForbidden)
			return
		}

		origin := r.Header.Get("Origin")
		if origin != "" && !strings.HasPrefix(origin, "http://127.0.0.1:") && !strings.HasPrefix(origin, "http://localhost:") {
			http.Error(w, "403 Forbidden: Cross-Origin Requests Blocked", http.StatusForbidden)
			return
		}
		secFetchSite := r.Header.Get("Sec-Fetch-Site")
		if secFetchSite != "" && secFetchSite != "same-origin" && secFetchSite != "none" {
			http.Error(w, "403 Forbidden: Cross-Site Request Blocked", http.StatusForbidden)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/api/") {
			clientToken := r.Header.Get("X-GUI-Token")
			if clientToken == "" {
				if cookie, err := r.Cookie("sec_gui_auth"); err == nil {
					clientToken = cookie.Value
				}
			}
			if clientToken == "" || clientToken != activeGUIToken {
				http.Error(w, "403 Forbidden: Invalid or missing GUI launch token", http.StatusForbidden)
				return
			}

			clientTabID := r.Header.Get("X-Tab-ID")
			if clientTabID != "" {
				tabMutex.Lock()
				now := time.Now()
				if activeTabID != "" && now.Sub(lastTabHeartbeat) > 6*time.Second {
					activeTabID = ""
				}
				if activeTabID == "" {
					activeTabID = clientTabID
					lastTabHeartbeat = now
				} else if activeTabID != clientTabID {
					tabMutex.Unlock()
					http.Error(w, "403 Forbidden: Multi-tab access blocked. Vault Inspector is active in another browser tab.", http.StatusForbidden)
					return
				} else {
					lastTabHeartbeat = now
				}
				tabMutex.Unlock()
			}
		}

		if r.URL.Path == "/" {
			qToken := r.URL.Query().Get("gui_token")
			if qToken != "" {
				tokenMutex.Lock()
				if guiTokenConsumed || qToken != activeGUIToken {
					tokenMutex.Unlock()
					http.Error(w, "403 Forbidden: Single-use GUI launch token has already been consumed or is invalid. Launch sec-agent gui again to open a new session.", http.StatusForbidden)
					return
				}
				guiTokenConsumed = true
				tokenMutex.Unlock()

				// #nosec G124
				http.SetCookie(w, &http.Cookie{
					Name:     "sec_gui_auth",
					Value:    activeGUIToken,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
			} else {
				cookie, err := r.Cookie("sec_gui_auth")
				if err != nil || cookie.Value != activeGUIToken {
					http.Error(w, "403 Forbidden: Access denied. Please launch sec-agent gui to open an authenticated session.", http.StatusForbidden)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func handleApiHeartbeat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleApiDatabases(w http.ResponseWriter, r *http.Request) {
	dbs, err := discoverDatabases()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dbs)
}

func handleApiStatus(activeProfile string, w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("profile")
	if p == "" {
		p = activeProfile
	}
	tok := getGUIToken(store.ProfileName(p))
	resp, err := queryDaemon(p, daemon.IPCRequest{Action: daemon.IPCActionBackup, Token: tok})
	unlocked := (err == nil && resp != nil && resp.Success)

	storePath, _ := store.GetStorePath(p)
	dbFile := filepath.Base(storePath)
	sizeStr := "Unknown"
	modStr := "Unknown"
	// #nosec G703
	if fi, err := os.Stat(storePath); err == nil {
		sizeStr = formatBytes(fi.Size())
		modStr = fi.ModTime().Format("2006-01-02 15:04:05")
	}

	dbs, _ := discoverDatabases()

	tierStr := getProfileEnvTier(store.ProfileName(p))
	if tierStr == "" {
		tierStr = config.TierDev
	}

	isV2 := store.IsV2Vault(storePath)
	schemaStr := "v1.0 Legacy"
	if isV2 {
		schemaStr = "v2.0 Dual-Slot (Hardened)"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(GUIStatusResponseDTO{
		Profile:            p,
		Unlocked:           unlocked,
		Version:            guiVersion,
		DatabaseFile:       dbFile,
		DatabasePath:       storePath,
		DatabaseSize:       sizeStr,
		DatabaseModified:   modStr,
		ProfileTier:        strings.ToUpper(tierStr.String()),
		IsV2:               isV2,
		VaultSchema:        schemaStr,
		AvailableDatabases: dbs,
		Error:              fmt.Sprintf("%v", err),
	})
}

func handleApiUnlock(activeProfile string, w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("profile")
	if p == "" {
		p = activeProfile
	}
	resp, err := ensureUnlocked(p)
	unlocked := (err == nil && resp != nil && resp.Success)
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	} else if resp != nil && !resp.Success {
		errMsg = resp.Error
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(GUIUnlockResponseDTO{
		Profile:  p,
		Unlocked: unlocked,
		Error:    errMsg,
	})
}

func handleApiShutdown(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "server shutting down"})
	go func() {
		time.Sleep(200 * time.Millisecond)
		os.Exit(0)
	}()
}

func handleApiSecrets(activeProfile string, w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("profile")
	if p == "" {
		p = activeProfile
	}
	tok := getGUIToken(store.ProfileName(p))
	resp, err := queryDaemon(p, daemon.IPCRequest{Action: daemon.IPCActionBackup, Token: tok})
	if err != nil || resp == nil || !resp.Success {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(GUIUnlockResponseDTO{Profile: p, Unlocked: false, Error: "Session locked"})
		return
	}

	now := time.Now()
	var list []SecretItem
	for k, v := range resp.Secrets {
		if strings.HasPrefix(k, "__") {
			continue
		}
		lastAcc := "Never"
		stale := false
		if !v.LastAccessed.IsZero() {
			lastAcc = v.LastAccessed.Format("2006-01-02 15:04:05")
			if now.Sub(v.LastAccessed) > 30*24*time.Hour {
				stale = true
			}
		} else {
			stale = true
		}

		list = append(list, SecretItem{
			Key:          store.SecretKey(k),
			Value:        v.Value,
			Comment:      v.Comment,
			Created:      v.Created.Format("2006-01-02 15:04:05"),
			LastModified: v.LastModified.Format("2006-01-02 15:04:05"),
			LastAccessed: lastAcc,
			AccessCount:  v.AccessCount,
			Version:      v.Version,
			IsStale:      stale,
		})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Key < list[j].Key
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(GUISecretsListDTO{
		Profile: p,
		Count:   len(list),
		Secrets: list,
	})
}
