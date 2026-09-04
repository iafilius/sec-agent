package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DatabaseInfo represents metadata for an encrypted vault database file.
type DatabaseInfo struct {
	Profile  string `json:"profile"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Size     string `json:"size"`
	Modified string `json:"modified"`
}

// DiscoverDatabases scans the user configuration directory for all profile databases.
func DiscoverDatabases() ([]DatabaseInfo, error) {
	dir, err := GetConfigDir()
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
				sizeStr = FormatBytes(info.Size())
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

// FormatBytes converts a byte count into a human-readable string.
func FormatBytes(b int64) string {
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
