package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"secure_secrets/internal/daemon"
)

type tempFileEntry struct {
	envKey   string
	filePath string
}

type tempFileManager struct {
	mu      sync.Mutex
	entries []tempFileEntry
	cleaned bool
}

func newTempFileManager() *tempFileManager {
	return &tempFileManager{}
}

func (m *tempFileManager) CreateTempFile(envKey, content string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random suffix: %w", err)
	}
	randSuffix := hex.EncodeToString(b)
	tempFileName := fmt.Sprintf(".sec_tmp_%s_%s", envKey, randSuffix)
	tempFilePath := filepath.Clean(filepath.Join(os.TempDir(), tempFileName))

	// #nosec G304 G306 G703
	if err := os.WriteFile(tempFilePath, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("failed to write temporary file %s: %w", tempFilePath, err)
	}

	m.mu.Lock()
	m.entries = append(m.entries, tempFileEntry{envKey: envKey, filePath: tempFilePath})
	m.mu.Unlock()

	return tempFilePath, nil
}

func (m *tempFileManager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cleaned {
		return
	}
	m.cleaned = true

	for _, entry := range m.entries {
		// Zero-fill file contents before removal
		// #nosec G304 G703
		if data, err := os.ReadFile(entry.filePath); err == nil {
			zeroes := make([]byte, len(data))
			// #nosec G304 G306 G703
			_ = os.WriteFile(entry.filePath, zeroes, 0600)
		}
		_ = os.Remove(entry.filePath)
	}
}

func (m *tempFileManager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func resolveTempFileTarget(profile string, envKey, target string, wsCfg *WorkspaceConfig) (string, error) {
	// 1. Direct secret lookup in active profile
	getResp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: "get",
		Path:   target,
	})
	if err == nil && getResp != nil && getResp.Success {
		return getResp.Value, nil
	}

	// 2. Inline template with {{...}}
	if strings.Contains(target, "{{") {
		rendered, renderErr := renderStreamTemplate(profile, target, wsCfg, func(p string) (map[string]string, error) {
			secMap := make(map[string]string)
			if backupResp, bErr := queryDaemon(p, daemon.IPCRequest{Action: "backup"}); bErr == nil && backupResp != nil && backupResp.Success {
				for k, entry := range backupResp.Secrets {
					secMap[k] = entry.Value
				}
			}
			return secMap, nil
		})
		if renderErr != nil {
			return "", fmt.Errorf("failed to render inline template for %s: %w", envKey, renderErr)
		}
		return rendered, nil
	}

	// 3. Template file on disk
	cleaned := filepath.Clean(target)
	if fileInfo, statErr := os.Stat(cleaned); statErr == nil && !fileInfo.IsDir() {
		// #nosec G304
		tmplBytes, rErr := os.ReadFile(cleaned)
		if rErr != nil {
			return "", fmt.Errorf("failed to read template file %s: %w", cleaned, rErr)
		}
		rendered, renderErr := renderStreamTemplate(profile, string(tmplBytes), wsCfg, func(p string) (map[string]string, error) {
			secMap := make(map[string]string)
			if backupResp, bErr := queryDaemon(p, daemon.IPCRequest{Action: "backup"}); bErr == nil && backupResp != nil && backupResp.Success {
				for k, entry := range backupResp.Secrets {
					secMap[k] = entry.Value
				}
			}
			return secMap, nil
		})
		if renderErr != nil {
			return "", fmt.Errorf("failed to render template file %s: %w", cleaned, renderErr)
		}
		return rendered, nil
	}

	// 4. If getResp reported an error from daemon
	if getResp != nil && !getResp.Success {
		return "", fmt.Errorf("%s", getResp.Error)
	}

	return "", fmt.Errorf("secret or template file %q for %s not found", target, envKey)
}
