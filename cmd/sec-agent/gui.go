package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"secure_secrets/internal/biometrics"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var guiVersion = Version
var activeGUIToken string
var guiTokenConsumed bool
var tokenMutex sync.Mutex

var activeTabID string
var lastTabHeartbeat time.Time
var tabMutex sync.Mutex

type DatabaseInfo struct {
	Profile  string `json:"profile"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Size     string `json:"size"`
	Modified string `json:"modified"`
}

func generateGUIToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func discoverDatabases() ([]DatabaseInfo, error) {
	dir, err := config.GetConfigDir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var list []DatabaseInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "secrets") && strings.HasSuffix(name, ".enc") {
			profile := "default"
			if name != "secrets.enc" {
				profile = strings.TrimPrefix(name, "secrets_")
				profile = strings.TrimSuffix(profile, ".enc")
			}

			fullPath := filepath.Join(dir, name)
			info, err := entry.Info()
			sizeStr := "0 B"
			modStr := ""
			if err == nil {
				sizeStr = formatBytes(info.Size())
				modStr = info.ModTime().Format("2006-01-02 15:04:05")
			}

			list = append(list, DatabaseInfo{
				Profile:  profile,
				Filename: name,
				Path:     fullPath,
				Size:     sizeStr,
				Modified: modStr,
			})
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Profile < list[j].Profile
	})

	return list, nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
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

	if err := ensureDaemonRunning(profile); err != nil {
		return nil, fmt.Errorf("daemon is not running: %w", err)
	}

	if os.Getenv("SEC_TEST_MODE") != "1" {
		if !biometrics.Authenticate("Unlock sec-agent vault session") {
			return nil, fmt.Errorf("Biometric authentication failed or cancelled")
		}
	}

	getter := func() ([]byte, error) {
		if profile == "" || profile == "default" {
			return keychain.Get("sec-session", "master")
		}
		return keychain.Get("sec-session:profile_"+profile, "master")
	}
	setter := func(k []byte) error {
		if profile == "" || profile == "default" {
			return keychain.Set("sec-session", "master", k)
		}
		return keychain.Set("sec-session:profile_"+profile, "master", k)
	}

	masterKey, err := store.InitializeMasterKey(profile, getter, setter)
	if err != nil {
		return nil, fmt.Errorf("master key initialization failed: %w", err)
	}

	resp, err = queryDaemon(profile, daemon.IPCRequest{
		Action: "open",
		Key:    masterKey,
		TTL:    "8h",
	})
	if err != nil {
		return nil, fmt.Errorf("daemon IPC error: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("unlock failed: %s", resp.Error)
	}

	if resp.Token != "" {
		_ = config.SaveSessionToken(profile, resp.Token)
		_ = os.Setenv("SEC_SESSION_TOKEN", resp.Token)
	}

	return resp, nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		// #nosec G204 G702
		cmd = exec.Command("open", url)
	default:
		// #nosec G204 G702
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
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

func runGUIServer(activeProfile string, port int) {
	activeGUIToken = generateGUIToken()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/databases", func(w http.ResponseWriter, r *http.Request) {
		dbs, err := discoverDatabases()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(dbs)
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("profile")
		if p == "" {
			p = activeProfile
		}
		tok := config.LoadSessionToken(p)
		resp, err := queryDaemon(p, daemon.IPCRequest{Action: "ping", Token: tok})
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

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"profile":             p,
			"unlocked":            unlocked,
			"version":             guiVersion,
			"database_file":       dbFile,
			"database_path":       storePath,
			"database_size":       sizeStr,
			"database_modified":   modStr,
			"available_databases": dbs,
			"error":               fmt.Sprintf("%v", err),
		})
	})

	mux.HandleFunc("/api/unlock", func(w http.ResponseWriter, r *http.Request) {
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
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"profile":  p,
			"unlocked": unlocked,
			"error":    errMsg,
		})
	})

	mux.HandleFunc("/api/shutdown", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "server shutting down"})
		go func() {
			time.Sleep(200 * time.Millisecond)
			os.Exit(0)
		}()
	})

	mux.HandleFunc("/api/secrets", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("profile")
		if p == "" {
			p = activeProfile
		}
		tok := config.LoadSessionToken(p)
		resp, err := queryDaemon(p, daemon.IPCRequest{Action: "backup", Token: tok})
		if err != nil || resp == nil || !resp.Success {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "Session locked"})
			return
		}

		type SecretItem struct {
			Key          string `json:"key"`
			Value        string `json:"value"`
			Comment      string `json:"comment,omitempty"`
			Created      string `json:"created"`
			LastModified string `json:"last_modified"`
			LastAccessed string `json:"last_accessed"`
			AccessCount  uint64 `json:"access_count"`
			Version      int    `json:"version"`
			IsStale      bool   `json:"is_stale"`
		}

		now := time.Now()
		var list []SecretItem
		for k, v := range resp.Secrets {
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
				Key:          k,
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
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"profile": p,
			"count":   len(list),
			"secrets": list,
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(guiHTMLContent))
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("🔒 sec-agent gui %s (Hardened Visual Inspector)\n", guiVersion)
	fmt.Printf("Serving GUI interface at: http://%s\n", addr)
	fmt.Println("Status: 🛡️ Authenticated GUI Session Active (Token-Protected)")
	fmt.Println("Press \"🛑 Stop GUI\" in browser header to shut down.")

	launchURL := fmt.Sprintf("http://%s/?gui_token=%s", addr, activeGUIToken)
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(launchURL)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigChan
		fmt.Println("\n🛑 sec-agent gui server stopped gracefully.")
		os.Exit(0)
	}()

	server := &http.Server{
		Addr:              addr,
		Handler:           securityMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("Server error: %v\n", err)
	}
}

const guiHTMLContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>sec-agent | Vault Inspector</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --panel: rgba(18, 24, 38, 0.75);
      --panel-border: rgba(255, 255, 255, 0.08);
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.25);
      --emerald: #34d399;
      --rose: #fb7185;
      --amber: #fbbf24;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      background-image: 
        radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.08) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(52, 211, 153, 0.05) 0px, transparent 50%);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    header {
      background: var(--panel);
      backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--panel-border);
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      font-size: 1.25rem;
      letter-spacing: -0.02em;
    }
    .logo span {
      background: linear-gradient(135deg, var(--accent), var(--emerald));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .header-controls {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .db-select {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--panel-border);
      color: var(--text);
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 0.9rem;
      font-family: var(--font-mono);
      outline: none;
      cursor: pointer;
    }

    .status-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 0.85rem;
      font-weight: 500;
      background: rgba(52, 211, 153, 0.1);
      border: 1px solid rgba(52, 211, 153, 0.2);
      color: var(--emerald);
    }
    .status-pill.locked {
      background: rgba(251, 113, 133, 0.1);
      border-color: rgba(251, 113, 133, 0.2);
      color: var(--rose);
    }

    .btn-unlock {
      background: linear-gradient(135deg, #0284c7, #0d9488);
      color: white;
      border: none;
      padding: 8px 18px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 0.9rem;
      cursor: pointer;
      box-shadow: 0 4px 14px rgba(2, 132, 199, 0.3);
      transition: all 0.2s ease;
    }
    .btn-unlock:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(2, 132, 199, 0.4);
    }

    main {
      flex: 1;
      padding: 32px;
      max-width: 1400px;
      margin: 0 auto;
      width: 100%;
    }

    .db-banner {
      background: var(--panel);
      backdrop-filter: blur(12px);
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      padding: 16px 24px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.9rem;
    }
    .db-path {
      font-family: var(--font-mono);
      color: var(--accent);
      font-size: 0.85rem;
      margin-top: 4px;
      word-break: break-all;
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 20px;
      margin-bottom: 32px;
    }
    .metric-card {
      background: var(--panel);
      backdrop-filter: blur(12px);
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      padding: 20px;
    }
    .metric-title {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .metric-value {
      font-size: 1.8rem;
      font-weight: 700;
    }

    .search-bar-container {
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
    }
    .search-input {
      flex: 1;
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 10px;
      padding: 12px 20px;
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.2s;
    }
    .search-input:focus {
      border-color: var(--accent);
    }

    .table-container {
      background: var(--panel);
      backdrop-filter: blur(16px);
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      overflow: hidden;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }
    th {
      background: rgba(255, 255, 255, 0.03);
      padding: 14px 20px;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      border-bottom: 1px solid var(--panel-border);
    }
    td {
      padding: 16px 20px;
      border-bottom: 1px solid var(--panel-border);
      font-size: 0.9rem;
    }
    tr:hover {
      background: rgba(255, 255, 255, 0.02);
      cursor: pointer;
    }

    .key-code {
      font-family: var(--font-mono);
      font-weight: 500;
      color: var(--accent);
    }

    .badge {
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 600;
      display: inline-block;
    }
    .badge-ver { background: rgba(56, 189, 248, 0.15); color: var(--accent); }
    .badge-stale { background: rgba(251, 191, 36, 0.15); color: var(--amber); }

    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(8px);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s ease;
    }
    .modal-overlay.active {
      opacity: 1;
      pointer-events: auto;
    }

    .modal-card {
      background: #0f172a;
      border: 1px solid var(--panel-border);
      border-radius: 16px;
      width: 90%;
      max-width: 560px;
      padding: 28px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }
    .modal-title {
      font-size: 1.1rem;
      font-family: var(--font-mono);
      color: var(--accent);
    }

    .value-box {
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid var(--panel-border);
      border-radius: 8px;
      padding: 14px;
      font-family: var(--font-mono);
      font-size: 0.95rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .btn-action {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text);
      border: 1px solid var(--panel-border);
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 0.85rem;
      cursor: pointer;
    }
    .btn-action:hover { background: rgba(255, 255, 255, 0.15); }
  </style>
</head>
<body>

  <header>
    <div class="logo">
      <span>🔒 sec-agent</span>
      <span class="badge badge-ver" id="guiVersionBadge">v2.1.1</span>
      <span style="color: var(--text-muted); font-size: 0.9rem; font-weight: 400;">Vault Inspector</span>
    </div>

    <div class="header-controls">
      <select id="dbSelect" class="db-select" onchange="changeProfile(this.value)">
        <option value="default">💾 secrets.enc (default)</option>
      </select>

      <div id="statusPill" class="status-pill">
        <span>🟢 Active Session</span>
      </div>

      <button id="unlockBtn" class="btn-unlock" onclick="triggerUnlock()" style="display: none;">
        🔓 Touch ID Unlock
      </button>

      <button class="btn-action" onclick="stopServer()" title="Shutdown GUI server">
        🛑 Stop GUI
      </button>
    </div>
  </header>

  <main>
    <div class="db-banner">
      <div>
        <div><b>Active Vault Database File:</b> <span id="bannerDbFile" style="font-family: var(--font-mono); color: var(--emerald);">secrets.enc</span></div>
        <div id="bannerDbPath" class="db-path">/Users/arjan/.config/sec-agent/secrets.enc</div>
      </div>
      <div style="text-align: right; color: var(--text-muted); font-size: 0.85rem;">
        <div>Size: <span id="bannerDbSize">0 B</span></div>
        <div>Modified: <span id="bannerDbModified">Never</span></div>
      </div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-title">Total Secrets</div>
        <div id="totalSecretsCount" class="metric-value">0</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Stale Credentials (>30d)</div>
        <div id="staleSecretsCount" class="metric-value" style="color: var(--amber);">0</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Active Profile</div>
        <div id="activeProfileName" class="metric-value" style="color: var(--accent);">default</div>
      </div>
    </div>

    <div class="search-bar-container">
      <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search secret keys or namespaces..." oninput="filterSecrets()">
    </div>

    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Secret Path</th>
            <th>Version</th>
            <th>Last Read</th>
            <th>Access Count</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody id="secretsTableBody">
          <tr>
            <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 32px;">Loading vault entries...</td>
          </tr>
        </tbody>
      </table>
    </div>
  </main>

  <div id="secretModal" class="modal-overlay">
    <div class="modal-card">
      <div class="modal-header">
        <div id="modalKey" class="modal-title">path/to/secret</div>
        <button class="btn-action" onclick="closeModal()">✕</button>
      </div>

      <div class="value-box">
        <span id="modalValue">••••••••••••</span>
        <div style="display: flex; gap: 8px;">
          <button class="btn-action" onclick="toggleReveal()">👁️</button>
          <button class="btn-action" onclick="copyValue()">📋 Copy</button>
        </div>
      </div>

      <div id="modalMeta" style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.6;">
      </div>
    </div>
  </div>

  <script>
    if (window.location.search.includes('gui_token=')) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    let tabID = sessionStorage.getItem('sec_tab_id');
    if (!tabID) {
      tabID = 'tab_' + Math.random().toString(36).substring(2, 15) + '_' + Date.now();
      sessionStorage.setItem('sec_tab_id', tabID);
    }

    let currentProfile = 'default';
    let secretsData = [];
    let activeSecret = null;
    let revealed = false;
    let idleTimer = null;

    function resetIdleTimer() {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        renderLockedState();
      }, 5 * 60 * 1000);
    }

    window.onload = resetIdleTimer;
    document.onmousemove = resetIdleTimer;
    document.onkeypress = resetIdleTimer;

    async function apiFetch(url, opts = {}) {
      opts.headers = opts.headers || {};
      opts.headers['X-Tab-ID'] = tabID;
      const res = await fetch(url, opts);
      if (res.status === 403) {
        const text = await res.text();
        if (text.includes('Multi-tab access blocked')) {
          renderTabLockedState();
        }
      }
      return res;
    }

    function renderTabLockedState() {
      document.body.innerHTML = '<div style="display:flex; flex-direction:column; justify-content:center; align-items:center; height:100vh; background:#090d16; color:#fb7185; font-family:sans-serif; text-align:center; padding:24px;">' +
        '<h1 style="font-size:2rem; margin-bottom:16px;">🔴 Multi-Tab Access Blocked</h1>' +
        '<p style="color:#94a3b8; max-width:520px; line-height:1.6; font-size:1.05rem;">sec-agent gui is strictly locked to your primary active browser tab for security.<br><br>Opening or pasting this URL into a second tab is disabled. Please switch back to your original active tab.</p>' +
        '</div>';
    }

    setInterval(async () => {
      try {
        await apiFetch('/api/heartbeat');
      } catch (e) {}
    }, 2000);

    async function loadStatus() {
      try {
        const res = await apiFetch('/api/status?profile=' + currentProfile);
        if (res.status === 403) return;
        const data = await res.json();
        const pill = document.getElementById('statusPill');
        const unlockBtn = document.getElementById('unlockBtn');
        document.getElementById('activeProfileName').innerText = currentProfile;
        document.getElementById('bannerDbFile').innerText = data.database_file || 'secrets.enc';
        document.getElementById('bannerDbPath').innerText = data.database_path || '';
        document.getElementById('bannerDbSize').innerText = data.database_size || '0 B';
        document.getElementById('bannerDbModified').innerText = data.database_modified || '';
        if (data.version) {
          document.getElementById('guiVersionBadge').innerText = data.version;
        }

        populateDbSelect(data.available_databases || []);

        if (data.unlocked) {
          pill.className = 'status-pill';
          pill.innerHTML = '<span>🟢 Active Session</span>';
          unlockBtn.style.display = 'none';
          loadSecrets();
        } else {
          pill.className = 'status-pill locked';
          pill.innerHTML = '<span>🔴 Vault Locked</span>';
          unlockBtn.style.display = 'inline-block';
          renderLockedState();
        }
      } catch (err) {
        console.error(err);
      }
    }

    function populateDbSelect(databases) {
      const dbSelect = document.getElementById('dbSelect');
      if (!databases || databases.length === 0) return;

      let html = '';
      for (let i = 0; i < databases.length; i++) {
        let db = databases[i];
        let selected = db.profile === currentProfile ? 'selected' : '';
        html += '<option value="' + db.profile + '" ' + selected + '>💾 ' + db.filename + ' (' + db.profile + ')</option>';
      }
      dbSelect.innerHTML = html;
    }

    async function triggerUnlock() {
      const pill = document.getElementById('statusPill');
      pill.innerHTML = '<span>⏳ Requesting Touch ID...</span>';
      try {
        const res = await apiFetch('/api/unlock?profile=' + currentProfile);
        if (res.status === 403) return;
        const data = await res.json();
        if (data.unlocked) {
          loadStatus();
        } else {
          alert('Unlock failed: ' + (data.error || 'Biometric authentication cancelled'));
          loadStatus();
        }
      } catch (err) {
        alert('Unlock error: ' + err);
      }
    }

    async function loadSecrets() {
      try {
        const res = await apiFetch('/api/secrets?profile=' + currentProfile);
        if (res.status === 401 || res.status === 403) {
          if (res.status === 401) renderLockedState();
          return;
        }
        const data = await res.json();
        secretsData = data.secrets || [];
        document.getElementById('totalSecretsCount').innerText = secretsData.length;
        document.getElementById('staleSecretsCount').innerText = secretsData.filter(s => s.is_stale).length;
        filterSecrets();
      } catch (err) {
        console.error(err);
      }
    }

    function renderLockedState() {
      const tbody = document.getElementById('secretsTableBody');
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--rose); padding: 32px;">Vault Session Locked. Click <b>"🔓 Touch ID Unlock"</b> to inspect credentials.</td></tr>';
    }

    function filterSecrets() {
      const q = document.getElementById('searchInput').value.toLowerCase();
      const filtered = secretsData.filter(s => s.key.toLowerCase().includes(q));
      const tbody = document.getElementById('secretsTableBody');

      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 32px;">No matching secrets found.</td></tr>';
        return;
      }

      let html = '';
      for (let i = 0; i < filtered.length; i++) {
        let s = filtered[i];
        let statusBadge = s.is_stale 
          ? '<span class="badge badge-stale">Stale</span>' 
          : '<span class="badge" style="background: rgba(52, 211, 153, 0.15); color: var(--emerald);">Active</span>';
        html += '<tr onclick="openModal(\'' + s.key + '\')">';
        html += '<td class="key-code">' + s.key + '</td>';
        html += '<td><span class="badge badge-ver">v' + s.version + '</span></td>';
        html += '<td>' + s.last_accessed + '</td>';
        html += '<td>' + s.access_count + '</td>';
        html += '<td>' + statusBadge + '</td>';
        html += '</tr>';
      }
      tbody.innerHTML = html;
    }

    function openModal(key) {
      activeSecret = secretsData.find(s => s.key === key);
      if (!activeSecret) return;

      revealed = false;
      document.getElementById('modalKey').innerText = activeSecret.key;
      document.getElementById('modalValue').innerText = '••••••••••••';
      let metaHtml = '<div><b>Version:</b> v' + activeSecret.version + '</div>' +
        '<div><b>Created:</b> ' + activeSecret.created + '</div>' +
        '<div><b>Last Modified:</b> ' + activeSecret.last_modified + '</div>' +
        '<div><b>Last Accessed:</b> ' + activeSecret.last_accessed + ' (Total Reads: ' + activeSecret.access_count + ')</div>';
      if (activeSecret.comment) {
        metaHtml += '<div style="margin-top: 8px;"><b>Comment:</b> ' + activeSecret.comment + '</div>';
      }
      document.getElementById('modalMeta').innerHTML = metaHtml;
      document.getElementById('secretModal').classList.add('active');
    }

    function closeModal() {
      document.getElementById('secretModal').classList.remove('active');
    }

    function toggleReveal() {
      if (!activeSecret) return;
      revealed = !revealed;
      document.getElementById('modalValue').innerText = revealed ? activeSecret.value : '••••••••••••';
    }

    function copyValue() {
      if (!activeSecret) return;
      navigator.clipboard.writeText(activeSecret.value);
      alert('Secret copied to clipboard! Clipboard will auto-wipe after 15s.');
    }

    function changeProfile(p) {
      currentProfile = p;
      loadStatus();
    }

    async function stopServer() {
      if (confirm('Are you sure you want to stop the sec-agent-gui server?')) {
        try {
          await apiFetch('/api/shutdown', { method: 'POST' });
        } catch (e) {}
        document.body.innerHTML = '<div style="display:flex; justify-content:center; align-items:center; height:100vh; font-family:sans-serif; color:#94a3b8;"><h2>🛑 sec-agent gui Server Stopped. You may close this tab.</h2></div>';
      }
    }

    loadStatus();
  </script>
</body>
</html>
`
