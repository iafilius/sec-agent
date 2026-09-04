package main

import (
	"secure_secrets/internal/config"
	"secure_secrets/internal/store"
)

// DatabaseInfo represents metadata for an encrypted vault database file in GUI payloads.
type DatabaseInfo struct {
	Profile  store.ProfileName `json:"profile"`
	Filename string            `json:"filename"`
	Path     string            `json:"path"`
	Size     string            `json:"size"`
	Modified string            `json:"modified"`
}

func discoverDatabases() ([]DatabaseInfo, error) {
	rawList, err := config.DiscoverDatabases()
	if err != nil {
		return nil, err
	}
	res := make([]DatabaseInfo, 0, len(rawList))
	for _, item := range rawList {
		res = append(res, DatabaseInfo{
			Profile:  store.ProfileName(item.Profile),
			Filename: item.Filename,
			Path:     item.Path,
			Size:     item.Size,
			Modified: item.Modified,
		})
	}
	return res, nil
}

func formatBytes(b int64) string {
	return config.FormatBytes(b)
}
