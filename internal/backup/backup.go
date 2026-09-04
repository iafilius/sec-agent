package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"secure_secrets/internal/store"
	"strings"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

// BackupFormat represents a supported backup/export file format.
type BackupFormat string

const (
	FormatKdbx   BackupFormat = "kdbx"
	FormatDotenv BackupFormat = "dotenv"
	FormatJSON   BackupFormat = "json"
	FormatEnv    BackupFormat = "env"
)

// Validate checks whether the backup format is supported.
func (f BackupFormat) Validate() error {
	switch f {
	case FormatKdbx, FormatDotenv, FormatJSON, FormatEnv:
		return nil
	default:
		return fmt.Errorf("unsupported backup format: %q", f)
	}
}

// ExportToKdbx exports a map of secrets (including comments and metadata) to a new KeePassXC KDBX file.
func ExportToKdbx(filePath string, password string, secrets map[store.SecretKey]store.SecretEntry) error {
	dir := filepath.Dir(filePath)
	// Create temp file in same directory
	// #nosec G304 G703
	tmpFile, err := os.CreateTemp(dir, "backup.*.kdbx.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary backup file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	// Restrict permissions to owner-only
	if err := tmpFile.Chmod(0600); err != nil {
		return fmt.Errorf("failed to set permissions on temp file: %w", err)
	}

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)

	// Create root group
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Secrets Backup"

	for k, entryVal := range secrets {
		entry := gokeepasslib.NewEntry()
		
		// Set Title
		entry.Values = append(entry.Values, gokeepasslib.ValueData{
			Key: "Title",
			Value: gokeepasslib.V{
				Content: string(k),
			},
		})

		// Set Password
		entry.Values = append(entry.Values, gokeepasslib.ValueData{
			Key: "Password",
			Value: gokeepasslib.V{
				Content:   entryVal.Value,
				Protected: wrappers.NewBoolWrapper(true),
			},
		})

		// Set Comment as Notes
		if entryVal.Comment != "" {
			entry.Values = append(entry.Values, gokeepasslib.ValueData{
				Key: "Notes",
				Value: gokeepasslib.V{
					Content: entryVal.Comment,
				},
			})
		}

		// Set Metadata as custom fields
		for mk, mv := range entryVal.Metadata {
			// Avoid colliding with standard reserved fields
			safeKey := mk
			if safeKey == "Title" || safeKey == "Password" || safeKey == "Notes" {
				safeKey = "meta_" + safeKey
			}
			entry.Values = append(entry.Values, gokeepasslib.ValueData{
				Key: safeKey,
				Value: gokeepasslib.V{
					Content: mv,
				},
			})
		}

		// Set Timestamps
		if !entryVal.Created.IsZero() {
			entry.Times.CreationTime = &wrappers.TimeWrapper{
				Time:      entryVal.Created,
				Formatted: true,
			}
		}
		if !entryVal.LastModified.IsZero() {
			entry.Times.LastModificationTime = &wrappers.TimeWrapper{
				Time:      entryVal.LastModified,
				Formatted: true,
			}
		}
		if !entryVal.Expires.IsZero() {
			entry.Times.ExpiryTime = &wrappers.TimeWrapper{
				Time:      entryVal.Expires,
				Formatted: true,
			}
			entry.Times.Expires = wrappers.BoolWrapper{Bool: true}
		}

		rootGroup.Entries = append(rootGroup.Entries, entry)
	}

	db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}

	if err := db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("failed to lock protected entries: %w", err)
	}

	encoder := gokeepasslib.NewEncoder(tmpFile)
	if err := encoder.Encode(db); err != nil {
		return fmt.Errorf("failed to encode database to file: %w", err)
	}

	// Force storage device sync (fsync)
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp backup file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp backup file: %w", err)
	}

	// Atomically replace target backup file
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("failed to replace target backup file: %w", err)
	}

	// Sync parent directory metadata
	// #nosec G304 G703
	dirFile, err := os.Open(dir)
	if err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}

	return nil
}

// ImportFromKdbx decodes and extracts secrets from a KeePassXC KDBX file.
func ImportFromKdbx(filePath string, password string) (map[store.SecretKey]store.SecretEntry, error) {
	// #nosec G304
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()
	return ImportFromKdbxReader(file, password)
}

// ImportFromKdbxReader decodes and extracts secrets from an io.Reader (file or stdin stream).
func ImportFromKdbxReader(r io.Reader, password string) (map[store.SecretKey]store.SecretEntry, error) {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)

	decoder := gokeepasslib.NewDecoder(r)
	if err := decoder.Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode database: %w", err)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("failed to unlock protected entries: %w", err)
	}

	secrets := make(map[store.SecretKey]store.SecretEntry)

	var findEntries func(gokeepasslib.Group) []gokeepasslib.Entry
	findEntries = func(group gokeepasslib.Group) []gokeepasslib.Entry {
		entries := make([]gokeepasslib.Entry, 0)
		entries = append(entries, group.Entries...)
		for _, subGroup := range group.Groups {
			entries = append(entries, findEntries(subGroup)...)
		}
		return entries
	}

	var allEntries []gokeepasslib.Entry
	for _, rootGroup := range db.Content.Root.Groups {
		allEntries = append(allEntries, findEntries(rootGroup)...)
	}

	for _, entry := range allEntries {
		title := ""
		passwordVal := ""
		comment := ""
		metadata := make(map[string]string)

		for _, valData := range entry.Values {
			key := valData.Key
			content := valData.Value.Content

			switch key {
			case "Title":
				title = content
			case "Password":
				passwordVal = content
			case "Notes":
				comment = content
			case "UserName", "URL":
				if content != "" {
					metadata[strings.ToLower(key)] = content
				}
			default:
				cleanKey := key
				if strings.HasPrefix(cleanKey, "meta_") {
					cleanKey = cleanKey[5:]
				}
				metadata[cleanKey] = content
			}
		}

		if title != "" {
			created := time.Now()
			lastModified := time.Now()
			var expires time.Time

			if entry.Times.CreationTime != nil && !entry.Times.CreationTime.Time.IsZero() {
				created = entry.Times.CreationTime.Time
			}
			if entry.Times.LastModificationTime != nil && !entry.Times.LastModificationTime.Time.IsZero() {
				lastModified = entry.Times.LastModificationTime.Time
			}
			if entry.Times.Expires.Bool && entry.Times.ExpiryTime != nil {
				expires = entry.Times.ExpiryTime.Time
			}

			secrets[store.SecretKey(title)] = store.SecretEntry{
				Value:        passwordVal,
				Comment:      comment,
				Metadata:     metadata,
				Created:      created,
				LastModified: lastModified,
				Expires:      expires,
			}
		}
	}

	return secrets, nil
}

func sanitizeRecordSlug(title string) string {
	s := strings.ToLower(strings.TrimSpace(title))
	var buf strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '/' {
			buf.WriteRune(r)
		} else if r == ' ' || r == '.' || r == ':' {
			buf.WriteRune('_')
		}
	}
	res := strings.Trim(buf.String(), "_")
	if res == "" {
		res = "record"
	}
	return res
}

// ImportFromKdbxFullMetadata decodes and extracts full sub-namespace records from a KDBX file.
func ImportFromKdbxFullMetadata(filePath string, password string) (map[string]store.SecretEntry, error) {
	// #nosec G304
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()
	return ImportFromKdbxFullMetadataReader(file, password)
}

// ImportFromKdbxFullMetadataReader decodes and extracts full sub-namespace records from an io.Reader (file or stdin stream).
func ImportFromKdbxFullMetadataReader(r io.Reader, password string) (map[string]store.SecretEntry, error) {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)

	decoder := gokeepasslib.NewDecoder(r)
	if err := decoder.Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode database: %w", err)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("failed to unlock protected entries: %w", err)
	}

	secrets := make(map[string]store.SecretEntry)

	var findEntries func(gokeepasslib.Group) []gokeepasslib.Entry
	findEntries = func(group gokeepasslib.Group) []gokeepasslib.Entry {
		entries := make([]gokeepasslib.Entry, 0)
		entries = append(entries, group.Entries...)
		for _, subGroup := range group.Groups {
			entries = append(entries, findEntries(subGroup)...)
		}
		return entries
	}

	var allEntries []gokeepasslib.Entry
	for _, rootGroup := range db.Content.Root.Groups {
		allEntries = append(allEntries, findEntries(rootGroup)...)
	}

	for _, entry := range allEntries {
		title := ""
		passwordVal := ""
		usernameVal := ""
		urlVal := ""
		notesVal := ""
		customAttrs := make(map[string]string)

		for _, valData := range entry.Values {
			key := valData.Key
			content := valData.Value.Content

			switch key {
			case "Title":
				title = content
			case "Password":
				passwordVal = content
			case "UserName":
				usernameVal = content
			case "URL":
				urlVal = content
			case "Notes":
				notesVal = content
			default:
				cleanKey := key
				if strings.HasPrefix(cleanKey, "meta_") {
					cleanKey = cleanKey[5:]
				}
				if content != "" {
					customAttrs[strings.ToLower(cleanKey)] = content
				}
			}
		}

		if title != "" {
			slug := sanitizeRecordSlug(title)
			created := time.Now()
			lastModified := time.Now()
			var expires time.Time

			if entry.Times.CreationTime != nil && !entry.Times.CreationTime.Time.IsZero() {
				created = entry.Times.CreationTime.Time
			}
			if entry.Times.LastModificationTime != nil && !entry.Times.LastModificationTime.Time.IsZero() {
				lastModified = entry.Times.LastModificationTime.Time
			}
			if entry.Times.Expires.Bool && entry.Times.ExpiryTime != nil {
				expires = entry.Times.ExpiryTime.Time
			}

			// Store sub-namespace keys
			secrets[slug+"/password"] = store.SecretEntry{
				Value:        passwordVal,
				Comment:      notesVal,
				Created:      created,
				LastModified: lastModified,
				Expires:      expires,
			}
			if usernameVal != "" {
				secrets[slug+"/username"] = store.SecretEntry{Value: usernameVal, Created: created, LastModified: lastModified}
			}
			if urlVal != "" {
				secrets[slug+"/url"] = store.SecretEntry{Value: urlVal, Created: created, LastModified: lastModified}
			}
			if notesVal != "" {
				secrets[slug+"/notes"] = store.SecretEntry{Value: notesVal, Created: created, LastModified: lastModified}
			}
			for ak, av := range customAttrs {
				secrets[slug+"/"+ak] = store.SecretEntry{Value: av, Created: created, LastModified: lastModified}
			}
		}
	}

	return secrets, nil
}

