package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"

	"golang.org/x/crypto/ssh"
)

// sshStdioHandshake is the 1-line JSON control header sent by `sec ssh-stdio`
// over the ephemeral local Unix domain socket before raw rsync protocol streaming begins.
type sshStdioHandshake struct {
	Args []string `json:"args"`
}

// remoteCommandRunner abstracts executing the rewritten remote `rsync --server` command
// over an in-memory Go `ssh.Session` (or an in-process mock during unit tests).
type remoteCommandRunner func(remoteCmd string, stdin io.Reader, stdout, stderr io.Writer) error

// isStealthBackupSubcommand returns true when sub is a subcommand of the stealth
// multi-folder rsync backup subsystem (`sec backup <subcommand>`).
func isStealthBackupSubcommand(sub string) bool {
	switch sub {
	case "init", "add-folder", "remove-folder", "show", "jobs", "run", "ssh-stdio":
		return true
	default:
		return false
	}
}

// shellQuotePOSIX wraps a string in POSIX single quotes, escaping any internal single quotes.
func shellQuotePOSIX(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func printStealthBackupUsage() {
	fmt.Println("Usage:")
	fmt.Println("  sec backup init <name> --target <ssh-target-or-user@host> --remote-base <path> [--local-base <path>] [--ssh-key-secret <vault-key>] [--ssh-password-key <vault-key>] [--port <port>] [--remote-rsync <path>] [--modify-window <sec>] [--partial-dir <dir>] [--exclude <pattern>...] [--folder <folder>...]")
	fmt.Println("  sec backup add-folder <name> <folder> [--dest <remote-folder-name>] [--history-prefix <prefix>] [--slug <slug>]")
	fmt.Println("  sec backup remove-folder <name> <folder>")
	fmt.Println("  sec backup show <name>")
	fmt.Println("  sec backup jobs")
	fmt.Println("  sec backup run <name> [<folder-filter>] [--dry-run] [--no-trace] [--trace] [--tofu] [--insecure]")
	fmt.Println("  sec backup <export|import|list> [<file.kdbx>]")
}

func handleStealthBackup(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printStealthBackupUsage()
		return
	}

	switch args[0] {
	case "init":
		handleStealthBackupInit(profile, args[1:])
	case "add-folder":
		handleStealthBackupAddFolder(profile, args[1:])
	case "remove-folder":
		handleStealthBackupRemoveFolder(profile, args[1:])
	case "show":
		handleStealthBackupShow(profile, args[1:])
	case "jobs", "list":
		handleStealthBackupJobs(profile, args[1:])
	case "run":
		handleStealthBackupRun(profile, args[1:])
	case "ssh-stdio":
		os.Exit(runInternalSSHStdio(args[1:]))
	default:
		printStealthBackupUsage()
		os.Exit(2)
	}
}

func expandLocalBasePath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		trimmed = "~"
	}
	if trimmed == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return trimmed
	}
	if strings.HasPrefix(trimmed, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, strings.TrimPrefix(trimmed, "~/"))
		}
	}
	return filepath.Clean(trimmed)
}

func saveStealthBackupManifest(profile string, manifest store.BackupManifest, noTrace bool) {
	manifest.ApplyDefaults()
	if err := manifest.Validate(); err != nil {
		fail("INVALID_BACKUP_MANIFEST", err, "")
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fail("SERIALIZATION_FAILED", fmt.Errorf("failed to marshal backup manifest: %w", err), "")
	}

	req := daemon.IPCRequest{
		Action:      daemon.IPCActionSet,
		Path:        string(manifest.Name.VaultKey()),
		Value:       string(data),
		Comment:     fmt.Sprintf("Stealth Backup Manifest (%s)", manifest.Name),
		Description: fmt.Sprintf("Multi-folder stealth rsync backup manifest for %s", manifest.Name),
		Metadata: map[string]string{
			"secret_type": "backup_manifest",
		},
		NoTrace: noTrace,
	}

	resp, err := queryDaemon(profile, req)
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("failed to save backup manifest %q: %s", manifest.Name, resp.Error), rem)
	}
}

func loadStealthBackupManifest(profile string, rawName string, noTrace bool) (store.BackupManifest, error) {
	jobName, err := store.NewBackupJobName(rawName)
	if err != nil {
		return store.BackupManifest{}, err
	}

	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:  daemon.IPCActionGet,
		Path:    string(jobName.VaultKey()),
		NoTrace: noTrace,
	})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		if strings.Contains(strings.ToLower(resp.Error), "not found") {
			return store.BackupManifest{}, fmt.Errorf("%w: backup job %q (%s) not found in profile %q", store.ErrSecretNotFound, jobName, jobName.VaultKey(), profile)
		}
		return store.BackupManifest{}, fmt.Errorf("failed to load backup job %q: %s", jobName, resp.Error)
	}

	var manifest store.BackupManifest
	if err := json.Unmarshal([]byte(resp.Value), &manifest); err != nil {
		return store.BackupManifest{}, fmt.Errorf("%w: failed to parse manifest JSON at %s: %v", store.ErrInvalidBackupManifest, jobName.VaultKey(), err)
	}
	if manifest.Name == "" {
		manifest.Name = jobName
	}
	manifest.ApplyDefaults()
	if err := manifest.Validate(); err != nil {
		return store.BackupManifest{}, err
	}
	return manifest, nil
}

func handleStealthBackupInit(profile string, args []string) {
	var rawName, target, localBase, remoteBase, sshKeySecret, sshPasswordKey, remoteRsync, partialDir string
	var port, modifyWindow int
	var excludes []string
	var folders []store.BackupFolderSpec

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			printStealthBackupUsage()
			return
		}
		switch {
		case a == "--target" && i+1 < len(args):
			target = args[i+1]
			i++
		case strings.HasPrefix(a, "--target="):
			target = strings.TrimPrefix(a, "--target=")
		case a == "--local-base" && i+1 < len(args):
			localBase = args[i+1]
			i++
		case strings.HasPrefix(a, "--local-base="):
			localBase = strings.TrimPrefix(a, "--local-base=")
		case a == "--remote-base" && i+1 < len(args):
			remoteBase = args[i+1]
			i++
		case strings.HasPrefix(a, "--remote-base="):
			remoteBase = strings.TrimPrefix(a, "--remote-base=")
		case (a == "--ssh-key-secret" || a == "--key-secret") && i+1 < len(args):
			sshKeySecret = args[i+1]
			i++
		case strings.HasPrefix(a, "--ssh-key-secret="):
			sshKeySecret = strings.TrimPrefix(a, "--ssh-key-secret=")
		case strings.HasPrefix(a, "--key-secret="):
			sshKeySecret = strings.TrimPrefix(a, "--key-secret=")
		case a == "--ssh-password-key" && i+1 < len(args):
			sshPasswordKey = args[i+1]
			i++
		case strings.HasPrefix(a, "--ssh-password-key="):
			sshPasswordKey = strings.TrimPrefix(a, "--ssh-password-key=")
		case (a == "--port" || a == "-p") && i+1 < len(args):
			p, err := strconv.Atoi(args[i+1])
			if err != nil || p <= 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid SSH port %q", args[i+1]), "")
			}
			port = p
			i++
		case strings.HasPrefix(a, "--port="):
			pStr := strings.TrimPrefix(a, "--port=")
			p, err := strconv.Atoi(pStr)
			if err != nil || p <= 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid SSH port %q", pStr), "")
			}
			port = p
		case a == "--remote-rsync" && i+1 < len(args):
			remoteRsync = args[i+1]
			i++
		case strings.HasPrefix(a, "--remote-rsync="):
			remoteRsync = strings.TrimPrefix(a, "--remote-rsync=")
		case a == "--modify-window" && i+1 < len(args):
			mw, err := strconv.Atoi(args[i+1])
			if err != nil || mw < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid modify-window %q", args[i+1]), "")
			}
			modifyWindow = mw
			i++
		case strings.HasPrefix(a, "--modify-window="):
			mwStr := strings.TrimPrefix(a, "--modify-window=")
			mw, err := strconv.Atoi(mwStr)
			if err != nil || mw < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid modify-window %q", mwStr), "")
			}
			modifyWindow = mw
		case a == "--partial-dir" && i+1 < len(args):
			partialDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--partial-dir="):
			partialDir = strings.TrimPrefix(a, "--partial-dir=")
		case a == "--exclude" && i+1 < len(args):
			excludes = append(excludes, args[i+1])
			i++
		case strings.HasPrefix(a, "--exclude="):
			excludes = append(excludes, strings.TrimPrefix(a, "--exclude="))
		case a == "--folder" && i+1 < len(args):
			folders = append(folders, store.BackupFolderSpec{Source: args[i+1]})
			i++
		case strings.HasPrefix(a, "--folder="):
			folders = append(folders, store.BackupFolderSpec{Source: strings.TrimPrefix(a, "--folder=")})
		case !strings.HasPrefix(a, "-") && rawName == "":
			rawName = a
		}
	}

	jobName, err := store.NewBackupJobName(rawName)
	if err != nil {
		fail("INVALID_ARGUMENTS", err, "Usage: sec backup init <name> --target <ssh-target-or-user@host> --remote-base <path> [--local-base <path>]")
	}
	if strings.TrimSpace(target) == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("--target is required for 'sec backup init'"), "Pass --target <ssh-target-or-user@host>")
	}
	if strings.TrimSpace(remoteBase) == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("--remote-base is required for 'sec backup init'"), "Pass --remote-base <remote-path>")
	}

	expandedLocalBase := expandLocalBasePath(localBase)

	manifest := store.BackupManifest{
		Name:           jobName,
		SSHTarget:      strings.TrimSpace(target),
		SSHKeySecret:   strings.TrimSpace(sshKeySecret),
		SSHPasswordKey: strings.TrimSpace(sshPasswordKey),
		SSHPort:        port,
		LocalBase:      expandedLocalBase,
		RemoteBase:     strings.TrimSpace(remoteBase),
		RemoteRsyncBin: strings.TrimSpace(remoteRsync),
		ModifyWindow:   modifyWindow,
		PartialDir:     strings.TrimSpace(partialDir),
		Excludes:       excludes,
		Folders:        folders,
	}
	manifest.ApplyDefaults()
	if err := manifest.Validate(); err != nil {
		fail("INVALID_BACKUP_MANIFEST", err, "")
	}

	saveStealthBackupManifest(profile, manifest, true)
	fmt.Printf("[✓] Initialized stealth backup manifest %q at vault path %s (profile %q)\n", manifest.Name, manifest.Name.VaultKey(), profile)
	fmt.Printf("    SSH Target:  %s\n", manifest.SSHTarget)
	fmt.Printf("    Local Base:  %s\n", manifest.LocalBase)
	fmt.Printf("    Remote Base: %s\n", manifest.RemoteBase)
	if len(manifest.Folders) > 0 {
		fmt.Printf("    Folders:     %d configured\n", len(manifest.Folders))
	} else {
		fmt.Printf("    Next step:   sec backup add-folder %s \"<Folder Name>\"\n", manifest.Name)
	}
}

func handleStealthBackupAddFolder(profile string, args []string) {
	var rawName, folderSrc, dest, historyPrefix, slug string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup add-folder <name> <folder> [--dest <remote-folder-name>] [--history-prefix <prefix>] [--slug <slug>]")
			return
		}
		switch {
		case a == "--dest" && i+1 < len(args):
			dest = args[i+1]
			i++
		case strings.HasPrefix(a, "--dest="):
			dest = strings.TrimPrefix(a, "--dest=")
		case a == "--history-prefix" && i+1 < len(args):
			historyPrefix = args[i+1]
			i++
		case strings.HasPrefix(a, "--history-prefix="):
			historyPrefix = strings.TrimPrefix(a, "--history-prefix=")
		case a == "--slug" && i+1 < len(args):
			slug = args[i+1]
			i++
		case strings.HasPrefix(a, "--slug="):
			slug = strings.TrimPrefix(a, "--slug=")
		case !strings.HasPrefix(a, "-"):
			if rawName == "" {
				rawName = a
			} else if folderSrc == "" {
				folderSrc = a
			}
		}
	}

	if rawName == "" || folderSrc == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("both <name> and <folder> are required"), "Usage: sec backup add-folder <name> <folder> [--dest <remote-folder-name>] [--history-prefix <prefix>] [--slug <slug>]")
	}

	manifest, err := loadStealthBackupManifest(profile, rawName, true)
	if err != nil {
		code := "BACKUP_MANIFEST_ERROR"
		if errors.Is(err, store.ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		fail(code, err, fmt.Sprintf("Run 'sec backup init %s --target <target> --remote-base <path>' first.", rawName))
	}

	spec := store.BackupFolderSpec{
		Source:        folderSrc,
		Dest:          strings.TrimSpace(dest),
		HistoryPrefix: strings.TrimSpace(historyPrefix),
		Slug:          strings.TrimSpace(slug),
	}
	if err := spec.Validate(); err != nil {
		fail("INVALID_ARGUMENTS", err, "")
	}

	updated := false
	for i, existing := range manifest.Folders {
		if existing.Source == spec.Source || existing.EffectiveDestName() == spec.EffectiveDestName() {
			manifest.Folders[i] = spec
			updated = true
			break
		}
	}
	if !updated {
		manifest.Folders = append(manifest.Folders, spec)
	}

	saveStealthBackupManifest(profile, manifest, true)

	now := time.Now()
	dateStr := now.Format("2006-01-02")
	datetimeStr := now.Format("2006-01-02_1504")

	actionVerb := "Added"
	if updated {
		actionVerb = "Updated"
	}
	fmt.Printf("[✓] %s folder %q in backup job %q (%s)\n", actionVerb, spec.Source, manifest.Name, manifest.Name.VaultKey())
	fmt.Printf("    Local Source: %s\n", spec.ResolveLocalDir(manifest.LocalBase))
	fmt.Printf("    Destination:  %s\n", spec.DeriveRemoteDest(manifest.RemoteBase))
	fmt.Printf("    History Dir:  %s\n", spec.DeriveHistoryDir(manifest.RemoteBase, dateStr))
	fmt.Printf("    Remote Log:   %s\n", spec.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr))
}

func handleStealthBackupRemoveFolder(profile string, args []string) {
	var rawName, folderTarget string
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup remove-folder <name> <folder>")
			return
		}
		if !strings.HasPrefix(a, "-") {
			if rawName == "" {
				rawName = a
			} else if folderTarget == "" {
				folderTarget = a
			}
		}
	}

	if rawName == "" || folderTarget == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("both <name> and <folder> are required"), "Usage: sec backup remove-folder <name> <folder>")
	}

	manifest, err := loadStealthBackupManifest(profile, rawName, true)
	if err != nil {
		code := "BACKUP_MANIFEST_ERROR"
		if errors.Is(err, store.ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		fail(code, err, "")
	}

	var kept []store.BackupFolderSpec
	removed := false
	for _, f := range manifest.Folders {
		if f.Source == folderTarget || f.Dest == folderTarget || f.EffectiveDestName() == folderTarget || f.DeriveSlug() == folderTarget {
			removed = true
			continue
		}
		kept = append(kept, f)
	}

	if !removed {
		fail("FOLDER_NOT_FOUND", fmt.Errorf("folder %q not found in backup job %q", folderTarget, manifest.Name), "")
	}

	manifest.Folders = kept
	saveStealthBackupManifest(profile, manifest, true)
	fmt.Printf("[✓] Removed folder %q from backup job %q (%d folders remaining)\n", folderTarget, manifest.Name, len(manifest.Folders))
}

func handleStealthBackupShow(profile string, args []string) {
	var rawName string
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup show <name>")
			return
		}
		if !strings.HasPrefix(a, "-") && rawName == "" {
			rawName = a
		}
	}
	if rawName == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("backup job <name> is required"), "Usage: sec backup show <name>")
	}

	manifest, err := loadStealthBackupManifest(profile, rawName, true)
	if err != nil {
		code := "BACKUP_MANIFEST_ERROR"
		if errors.Is(err, store.ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		fail(code, err, "")
	}

	now := time.Now()
	dateStr := now.Format("2006-01-02")
	datetimeStr := now.Format("2006-01-02_1504")

	fmt.Printf("Stealth Backup Job: %s (%s)\n", manifest.Name, manifest.Name.VaultKey())
	fmt.Printf("  SSH Target:     %s\n", manifest.SSHTarget)
	if manifest.SSHPort > 0 {
		fmt.Printf("  SSH Port:       %d\n", manifest.SSHPort)
	}
	if manifest.SSHKeySecret != "" {
		fmt.Printf("  SSH Key Secret: %s\n", manifest.SSHKeySecret)
	}
	if manifest.SSHPasswordKey != "" {
		fmt.Printf("  Password Key:   %s\n", manifest.SSHPasswordKey)
	}
	fmt.Printf("  Local Base:     %s\n", manifest.LocalBase)
	fmt.Printf("  Remote Base:    %s\n", manifest.RemoteBase)
	fmt.Printf("  Remote Rsync:   %s\n", manifest.RemoteRsyncBin)
	fmt.Printf("  Modify Window:  %ds\n", manifest.ModifyWindow)
	fmt.Printf("  Partial Dir:    %s\n", manifest.PartialDir)
	fmt.Printf("  Excludes:       %s\n", strings.Join(manifest.Excludes, ", "))
	fmt.Printf("  Folders (%d):\n", len(manifest.Folders))
	if len(manifest.Folders) == 0 {
		fmt.Println("    (none configured — add with 'sec backup add-folder <name> <folder>')")
		return
	}
	for i, f := range manifest.Folders {
		fmt.Printf("    [%d] %s (slug: %s, prefix: %s)\n", i+1, f.Source, f.DeriveSlug(), f.DeriveHistoryPrefix())
		fmt.Printf("        Local Path:  %s\n", f.ResolveLocalDir(manifest.LocalBase))
		fmt.Printf("        Destination: %s\n", f.DeriveRemoteDest(manifest.RemoteBase))
		fmt.Printf("        History Dir: %s\n", f.DeriveHistoryDir(manifest.RemoteBase, dateStr))
		fmt.Printf("        Remote Log:  %s\n", f.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr))
	}
}

func collectStealthBackupManifests(profile string) ([]store.BackupManifest, error) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: daemon.IPCActionBackup,
	})
	if err == nil && resp != nil && resp.Success && len(resp.Secrets) > 0 {
		var keys []string
		for k := range resp.Secrets {
			if strings.HasPrefix(k, "backup/") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var manifests []store.BackupManifest
		for _, k := range keys {
			entry := resp.Secrets[k]
			var m store.BackupManifest
			if json.Unmarshal([]byte(entry.Value), &m) == nil {
				if m.Name == "" {
					m.Name = store.BackupJobName(strings.TrimPrefix(k, "backup/"))
				}
				m.ApplyDefaults()
				manifests = append(manifests, m)
			}
		}
		return manifests, nil
	}

	// Fallback to IPCActionList with Path: "backup/"
	listResp, listErr := queryDaemon(profile, daemon.IPCRequest{
		Action:   daemon.IPCActionList,
		Path:     "backup/",
		IsPrefix: true,
		NoTrace:  true,
	})
	if listErr != nil {
		return nil, listErr
	}
	if !listResp.Success {
		return nil, fmt.Errorf("%s", listResp.Error)
	}

	var keys []string
	for _, line := range strings.Split(listResp.Value, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "backup/") {
			keys = append(keys, trimmed)
		}
	}
	sort.Strings(keys)

	var manifests []store.BackupManifest
	for _, k := range keys {
		rawName := strings.TrimPrefix(k, "backup/")
		if m, mErr := loadStealthBackupManifest(profile, rawName, true); mErr == nil {
			manifests = append(manifests, m)
		}
	}
	return manifests, nil
}

func printStealthBackupJobsSection(profile string) {
	manifests, err := collectStealthBackupManifests(profile)
	if err != nil {
		return
	}
	fmt.Printf("\nStealth Rsync Backup Jobs (profile %q):\n", profile)
	if len(manifests) == 0 {
		fmt.Println("  (no stealth backup jobs configured under backup/*)")
		return
	}
	for _, m := range manifests {
		var folderNames []string
		for _, f := range m.Folders {
			folderNames = append(folderNames, f.Source)
		}
		folderSummary := "(no folders)"
		if len(folderNames) > 0 {
			folderSummary = strings.Join(folderNames, ", ")
		}
		fmt.Printf("  • %-16s target=%s  remote=%s  folders=[%s]\n", m.Name, m.SSHTarget, m.RemoteBase, folderSummary)
	}
}

func handleStealthBackupJobs(profile string, args []string) {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup jobs")
			return
		}
	}
	manifests, err := collectStealthBackupManifests(profile)
	if err != nil {
		failDaemonNotRunning(profile)
	}
	fmt.Printf("Stealth Rsync Backup Jobs in profile %q:\n", profile)
	if len(manifests) == 0 {
		fmt.Println("  (none configured — run 'sec backup init <name> --target <target> --remote-base <path>')")
		return
	}
	for _, m := range manifests {
		var folderNames []string
		for _, f := range m.Folders {
			folderNames = append(folderNames, f.Source)
		}
		folderSummary := "(no folders)"
		if len(folderNames) > 0 {
			folderSummary = strings.Join(folderNames, ", ")
		}
		fmt.Printf("  • %-16s target=%s  remote=%s  folders=[%s]\n", m.Name, m.SSHTarget, m.RemoteBase, folderSummary)
	}
}

type resolvedStealthSSHConfig struct {
	TargetName string
	Host       string
	User       string
	Port       int
	Password   string
	KeyBytes   []byte
	Passphrase string
}

func resolveStealthSSHTarget(profile string, manifest store.BackupManifest, noTrace bool) (*resolvedStealthSSHConfig, error) {
	targetName := strings.TrimSpace(manifest.SSHTarget)
	var resolvedHost, resolvedUser, resolvedPassword string
	resolvedPort := 22
	sshKeySecret := strings.TrimSpace(manifest.SSHKeySecret)
	sshPasswordKey := strings.TrimSpace(manifest.SSHPasswordKey)
	sshKeyPath := ""
	sshPassphraseKey := ""

	getSecretNoTrace := func(vaultPath string) (string, bool) {
		if strings.TrimSpace(vaultPath) == "" {
			return "", false
		}
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action:  daemon.IPCActionGet,
			Path:    vaultPath,
			NoTrace: noTrace,
		})
		if err != nil || resp == nil || !resp.Success || resp.Value == "" {
			return "", false
		}
		return resp.Value, true
	}

	// 1. Check .secrc for target configuration
	wsCfg := loadWorkspaceConfig()
	if wsCfg != nil && wsCfg.SSHTargets != nil && targetName != "" {
		if tgt, ok := wsCfg.SSHTargets[targetName]; ok {
			resolvedHost = tgt.Host
			resolvedUser = tgt.User
			if tgt.Port > 0 {
				resolvedPort = tgt.Port
			}
			if tgt.IdentityFile != "" && sshKeyPath == "" {
				sshKeyPath = tgt.IdentityFile
			}
			if tgt.KeySecret != "" && sshKeySecret == "" {
				ks := strings.TrimSpace(tgt.KeySecret)
				if !strings.Contains(ks, "/") {
					ks = "ssh/shared/" + ks + "/private_key"
				}
				sshKeySecret = ks
			}
			if tgt.PassphraseKey != "" && sshPassphraseKey == "" {
				sshPassphraseKey = tgt.PassphraseKey
			}
			if tgt.PasswordKey != "" && sshPasswordKey == "" {
				sshPasswordKey = tgt.PasswordKey
			}
		}
	}

	if sshPasswordKey != "" {
		if val, ok := getSecretNoTrace(sshPasswordKey); ok {
			resolvedPassword = val
		}
	}

	// 2. Check active profile vault for ssh/<targetName>/... or ssh/...
	var prefixes []string
	if targetName != "" && !strings.Contains(targetName, "@") {
		prefixes = append(prefixes, "ssh/"+targetName+"/")
	}
	prefixes = append(prefixes, "ssh/")

	for _, pfx := range prefixes {
		if resolvedHost == "" {
			if val, ok := getSecretNoTrace(pfx + "host"); ok {
				resolvedHost = strings.TrimSpace(val)
			}
		}
		if resolvedUser == "" {
			if val, ok := getSecretNoTrace(pfx + "user"); ok {
				resolvedUser = strings.TrimSpace(val)
			}
		}
		if resolvedPort == 22 {
			if val, ok := getSecretNoTrace(pfx + "port"); ok {
				if p, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && p > 0 {
					resolvedPort = p
				}
			}
		}
		if resolvedPassword == "" {
			if val, ok := getSecretNoTrace(pfx + "password"); ok {
				resolvedPassword = val
			}
		}
		if sshKeySecret == "" && sshKeyPath == "" {
			if val, ok := getSecretNoTrace(pfx + "private_key"); ok && val != "" {
				sshKeySecret = pfx + "private_key"
			} else if val, ok := getSecretNoTrace(pfx + "key_secret"); ok && val != "" {
				resolvedPtr := strings.TrimSpace(val)
				if !strings.Contains(resolvedPtr, "/") {
					resolvedPtr = "ssh/shared/" + resolvedPtr + "/private_key"
				}
				sshKeySecret = resolvedPtr
			} else if val, ok := getSecretNoTrace(pfx + "key"); ok && val != "" {
				if strings.HasPrefix(strings.TrimSpace(val), "-----BEGIN") {
					sshKeySecret = pfx + "key"
				} else {
					sshKeyPath = strings.TrimSpace(val)
				}
			}
		}
		if sshPassphraseKey == "" {
			if _, ok := getSecretNoTrace(pfx + "passphrase"); ok {
				sshPassphraseKey = pfx + "passphrase"
			}
		}
	}

	// 3. Parse user@host or direct host if resolvedHost is still empty
	if resolvedHost == "" {
		if strings.Contains(targetName, "@") {
			parts := strings.SplitN(targetName, "@", 2)
			if resolvedUser == "" {
				resolvedUser = parts[0]
			}
			resolvedHost = parts[1]
		} else if targetName != "" {
			resolvedHost = targetName
		}
	}

	if resolvedHost == "" {
		return nil, fmt.Errorf("unknown SSH target %q and not a valid user@host destination", targetName)
	}

	if manifest.SSHPort > 0 {
		resolvedPort = manifest.SSHPort
	}
	if resolvedUser == "" {
		if curUser, err := user.Current(); err == nil && curUser.Username != "" {
			resolvedUser = curUser.Username
		} else {
			resolvedUser = "root"
		}
	}

	var keyBytes []byte
	if sshKeySecret != "" {
		if val, ok := getSecretNoTrace(sshKeySecret); ok {
			keyBytes = []byte(val)
		} else {
			return nil, fmt.Errorf("failed to retrieve SSH private key secret %q from vault", sshKeySecret)
		}
	} else if sshKeyPath != "" {
		expandedKeyPath := expandLocalBasePath(sshKeyPath)
		// #nosec G304 G703
		if b, err := os.ReadFile(expandedKeyPath); err == nil {
			keyBytes = b
		} else if val, ok := getSecretNoTrace(sshKeyPath); ok {
			keyBytes = []byte(val)
		} else {
			return nil, fmt.Errorf("failed to read SSH private key %q: %w", sshKeyPath, err)
		}
	}

	passphrase := ""
	if sshPassphraseKey != "" {
		if val, ok := getSecretNoTrace(sshPassphraseKey); ok {
			passphrase = val
		}
	}

	return &resolvedStealthSSHConfig{
		TargetName: targetName,
		Host:       resolvedHost,
		User:       resolvedUser,
		Port:       resolvedPort,
		Password:   resolvedPassword,
		KeyBytes:   keyBytes,
		Passphrase: passphrase,
	}, nil
}

func dialStealthSSHClient(profile string, cfg *resolvedStealthSSHConfig, opts hostKeyOptions) (*ssh.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil SSH configuration")
	}

	var authMethods []ssh.AuthMethod
	if len(cfg.KeyBytes) > 0 {
		var signer ssh.Signer
		var err error
		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(cfg.KeyBytes, []byte(cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(cfg.KeyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse vault SSH private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no vault SSH credentials (private_key or password) found for target %q", cfg.TargetName)
	}

	pinTarget := cfg.TargetName
	if strings.Contains(pinTarget, "@") {
		pinTarget = ""
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: vaultHostKeyCallback(profile, pinTarget, cfg.Host, cfg.Port, opts),
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH server at %s: %w", addr, err)
	}
	return client, nil
}

// rewriteRemoteRsyncServerCommand intercepts the remote `rsync --server` argument vector
// passed by local `rsync` to `-e`, replaces the remote `rsync` binary with `manifest.RemoteRsyncBin`,
// injects `--log-file=<remoteLogPath>` and `-b --backup-dir=<remoteHistoryDir>` right after `--server`,
// replaces the opaque `"target"` destination with the real remote folder path, and prepends
// `mkdir -p <remoteHistoryDir> <remoteDest> && ` so parent/history directories always exist.
func rewriteRemoteRsyncServerCommand(clientArgs []string, manifest store.BackupManifest, folder store.BackupFolderSpec, now time.Time) string {
	manifest.ApplyDefaults()
	dateStr := now.Format("2006-01-02")
	datetimeStr := now.Format("2006-01-02_1504")

	remoteDest := folder.DeriveRemoteDest(manifest.RemoteBase)
	remoteHistoryDir := folder.DeriveHistoryDir(manifest.RemoteBase, dateStr)
	remoteLogPath := folder.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr)

	normalized := make([]string, 0, len(clientArgs))
	for _, a := range clientArgs {
		if strings.Contains(a, "--server") && strings.Contains(a, " ") {
			normalized = append(normalized, strings.Fields(a)...)
		} else {
			normalized = append(normalized, a)
		}
	}

	serverIdx := -1
	for i, a := range normalized {
		if a == "--server" {
			serverIdx = i
			break
		}
	}

	var tailArgs []string
	if serverIdx != -1 && serverIdx+1 < len(normalized) {
		tailArgs = append(tailArgs, normalized[serverIdx+1:]...)
	} else {
		tailArgs = []string{"-vlogDtprze.iLsfxCIvu", fmt.Sprintf("--modify-window=%d", manifest.ModifyWindow), fmt.Sprintf("--partial-dir=%s", manifest.PartialDir), ".", "target"}
	}

	if len(tailArgs) == 0 {
		tailArgs = []string{".", shellQuotePOSIX(remoteDest)}
	} else {
		tailArgs[len(tailArgs)-1] = shellQuotePOSIX(remoteDest)
	}

	var cmdParts []string
	cmdParts = append(cmdParts,
		shellQuotePOSIX(manifest.RemoteRsyncBin),
		"--server",
		"--log-file="+shellQuotePOSIX(remoteLogPath),
		"-b",
		"--backup-dir="+shellQuotePOSIX(remoteHistoryDir),
	)
	cmdParts = append(cmdParts, tailArgs...)

	remoteRsyncCmd := strings.Join(cmdParts, " ")
	return fmt.Sprintf("mkdir -p %s %s && %s",
		shellQuotePOSIX(remoteHistoryDir),
		shellQuotePOSIX(remoteDest),
		remoteRsyncCmd,
	)
}

func shellQuoteIfNeeded(s string) string {
	if strings.ContainsAny(s, " \t\"'\\") {
		return shellQuotePOSIX(s)
	}
	return s
}

// buildLocalStealthRsyncArgs constructs the local `rsync` command-line argument slice.
// By setting `cmd.Dir = localDir`, passing excludes via `/dev/fd/3`, and routing over
// `-e "<selfExe> ssh-stdio" . sync:target`, zero folder names, volume paths, usernames,
// or IP addresses ever appear in the local host's `ps aux` process table.
func buildLocalStealthRsyncArgs(manifest store.BackupManifest, selfExe string, dryRun bool) []string {
	manifest.ApplyDefaults()
	args := []string{
		"-rtv",
		"--progress",
		fmt.Sprintf("--partial-dir=%s", manifest.PartialDir),
		fmt.Sprintf("--modify-window=%d", manifest.ModifyWindow),
	}
	if dryRun {
		args = append(args, "--dry-run")
	}
	if len(manifest.Excludes) > 0 {
		args = append(args, "--exclude-from=/dev/fd/3")
	}
	rshCmd := fmt.Sprintf("%s ssh-stdio", shellQuoteIfNeeded(selfExe))
	args = append(args, "-e", rshCmd, ".", "sync:target")
	return args
}

// startStealthStdioBridge starts an ephemeral Unix domain socket listener (0600 in a private temp dir)
// for a single folder synchronization session. When the local `ssh-stdio` helper connects and sends
// its 1-line JSON argument header, the bridge rewrites the remote `rsync --server` command and streams
// stdin/stdout bi-directionally through `runner`.
func startStealthStdioBridge(manifest store.BackupManifest, folder store.BackupFolderSpec, now time.Time, runner remoteCommandRunner) (sockPath string, waitErr func() error, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "sec_stdio_*")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to create ephemeral stdio socket dir: %w", err)
	}

	sockPath = filepath.Join(tmpDir, "s.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, nil, fmt.Errorf("failed to listen on ephemeral unix socket %s: %w", sockPath, err)
	}
	// #nosec G302
	if err := os.Chmod(sockPath, 0600); err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(tmpDir)
		return "", nil, nil, fmt.Errorf("failed to set 0600 permissions on %s: %w", sockPath, err)
	}

	errCh := make(chan error, 1)
	var once sync.Once

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		headerLine, readErr := br.ReadBytes('\n')
		if readErr != nil {
			errCh <- fmt.Errorf("failed reading ssh-stdio handshake header: %w", readErr)
			return
		}

		var hs sshStdioHandshake
		if unmarshalErr := json.Unmarshal(headerLine, &hs); unmarshalErr != nil {
			errCh <- fmt.Errorf("invalid ssh-stdio handshake JSON: %w", unmarshalErr)
			return
		}

		remoteCmd := rewriteRemoteRsyncServerCommand(hs.Args, manifest, folder, now)
		runErr := runner(remoteCmd, br, conn, os.Stderr)
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
		errCh <- runErr
	}()

	waitErr = func() error {
		select {
		case e := <-errCh:
			return e
		case <-time.After(2 * time.Second):
			return nil
		}
	}

	cleanup = func() {
		once.Do(func() {
			_ = listener.Close()
			_ = os.RemoveAll(tmpDir)
		})
	}

	return sockPath, waitErr, cleanup, nil
}

// runSSHStdioClient connects to `sockPath`, sends the 1-line JSON argument handshake,
// and bi-directionally copies stdin -> conn (half-closing write on EOF) and conn -> stdout.
func runSSHStdioClient(sockPath string, args []string, stdin io.Reader, stdout io.Writer) error {
	if strings.TrimSpace(sockPath) == "" {
		return fmt.Errorf("SEC_STDIO_SOCK is not set")
	}
	// #nosec G704
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("failed to connect to SEC_STDIO_SOCK (%s): %w", sockPath, err)
	}
	defer conn.Close()

	headerBytes, err := json.Marshal(sshStdioHandshake{Args: args})
	if err != nil {
		return fmt.Errorf("failed to marshal ssh-stdio handshake: %w", err)
	}
	headerBytes = append(headerBytes, '\n')
	if _, err := conn.Write(headerBytes); err != nil {
		return fmt.Errorf("failed to send ssh-stdio handshake: %w", err)
	}

	go func() {
		if stdin != nil {
			_, _ = io.Copy(conn, stdin)
		}
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()

	if stdout != nil {
		if _, err := io.Copy(stdout, conn); err != nil {
			return fmt.Errorf("error streaming from ssh-stdio socket: %w", err)
		}
	}
	return nil
}

// runInternalSSHStdio is the entrypoint for `sec ssh-stdio` (and `sec backup ssh-stdio`)
// invoked by local `rsync -e "<selfExe> ssh-stdio"`.
func runInternalSSHStdio(args []string) int {
	sockPath := os.Getenv("SEC_STDIO_SOCK")
	if err := runSSHStdioClient(sockPath, args, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "sec ssh-stdio error: %v\n", err)
		return 1
	}
	return 0
}

func findLocalRsyncBinary() (string, error) {
	if custom := strings.TrimSpace(os.Getenv("SEC_LOCAL_RSYNC_BIN")); custom != "" {
		return custom, nil
	}
	for _, candidate := range []string{"/opt/homebrew/bin/rsync", "/usr/local/bin/rsync"} {
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate, nil
		}
	}
	return exec.LookPath("rsync")
}

func handleStealthBackupRun(profile string, args []string) {
	var rawName, folderFilter string
	dryRun := false
	noTrace := true
	trustOnFirstUse := false
	insecureHostKey := false
	updateHostKey := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup run <name> [<folder-filter>] [--dry-run] [--no-trace] [--trace] [--tofu] [--insecure]")
			return
		}
		switch a {
		case "--dry-run", "-n":
			dryRun = true
		case "--no-trace":
			noTrace = true
		case "--trace":
			noTrace = false
		case "--tofu", "--trust-first-use":
			trustOnFirstUse = true
		case "--insecure", "--no-verify":
			insecureHostKey = true
		case "--update-host-key":
			updateHostKey = true
		default:
			if !strings.HasPrefix(a, "-") {
				if rawName == "" {
					rawName = a
				} else if folderFilter == "" {
					folderFilter = a
				}
			}
		}
	}

	if rawName == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("backup job <name> is required"), "Usage: sec backup run <name> [<folder-filter>] [--dry-run] [--no-trace] [--trace] [--tofu] [--insecure]")
	}

	manifest, err := loadStealthBackupManifest(profile, rawName, noTrace)
	if err != nil {
		code := "BACKUP_MANIFEST_ERROR"
		if errors.Is(err, store.ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		fail(code, err, "")
	}

	if len(manifest.Folders) == 0 {
		fail("EMPTY_BACKUP_FOLDERS", fmt.Errorf("backup job %q has no folders configured", manifest.Name), fmt.Sprintf("Run 'sec backup add-folder %s \"<folder>\"' first.", manifest.Name))
	}

	var selectedFolders []store.BackupFolderSpec
	for _, f := range manifest.Folders {
		if folderFilter == "" ||
			f.Source == folderFilter ||
			f.Dest == folderFilter ||
			f.EffectiveDestName() == folderFilter ||
			f.DeriveSlug() == folderFilter ||
			strings.EqualFold(f.DeriveHistoryPrefix(), folderFilter) {
			selectedFolders = append(selectedFolders, f)
		}
	}
	if len(selectedFolders) == 0 {
		fail("FOLDER_NOT_FOUND", fmt.Errorf("no folder matching %q found in backup job %q", folderFilter, manifest.Name), "")
	}

	localRsyncBin, err := findLocalRsyncBinary()
	if err != nil {
		fail("RSYNC_NOT_FOUND", fmt.Errorf("local 'rsync' binary not found on PATH: %w", err), "Install rsync (e.g., 'brew install rsync')")
	}

	selfExe, err := os.Executable()
	if err != nil {
		fail("EXECUTABLE_NOT_FOUND", fmt.Errorf("failed to determine current executable path: %w", err), "")
	}

	sshCfg, err := resolveStealthSSHTarget(profile, manifest, noTrace)
	if err != nil {
		fail("SSH_TARGET_ERROR", err, "Configure target credentials in vault via 'sec ssh init <target>'")
	}

	hkOpts := hostKeyOptions{
		insecure:        insecureHostKey,
		trustOnFirstUse: trustOnFirstUse,
		updateHostKey:   updateHostKey,
		noTrace:         noTrace,
	}

	sshClient, err := dialStealthSSHClient(profile, sshCfg, hkOpts)
	if err != nil {
		fail("SSH_CONNECT_FAILED", err, "")
	}
	defer sshClient.Close()

	for idx, folder := range selectedFolders {
		now := time.Now()
		dateStr := now.Format("2006-01-02")
		datetimeStr := now.Format("2006-01-02_1504")

		localDir := folder.ResolveLocalDir(manifest.LocalBase)
		remoteDest := folder.DeriveRemoteDest(manifest.RemoteBase)
		remoteHistoryDir := folder.DeriveHistoryDir(manifest.RemoteBase, dateStr)
		remoteLogPath := folder.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr)

		// #nosec G703
		if fi, statErr := os.Stat(localDir); statErr != nil || !fi.IsDir() {
			fail("LOCAL_FOLDER_NOT_FOUND", fmt.Errorf("local source directory does not exist for folder %q: %s", folder.Source, localDir), "")
		}

		fmt.Printf("[%d/%d] Synchronizing folder (stealth transport)...\n", idx+1, len(selectedFolders))
		if Verbose {
			fmt.Fprintf(os.Stderr, "[VERBOSE] Remote Dest: %s | History: %s | Log: %s\n", remoteDest, remoteHistoryDir, remoteLogPath)
		}

		sshRunner := func(remoteCmd string, stdin io.Reader, stdout, stderr io.Writer) error {
			session, sErr := sshClient.NewSession()
			if sErr != nil {
				return fmt.Errorf("failed to create SSH session: %w", sErr)
			}
			defer session.Close()

			sessStdin, pErr := session.StdinPipe()
			if pErr != nil {
				return fmt.Errorf("failed to create SSH session stdin pipe: %w", pErr)
			}
			session.Stdout = stdout
			session.Stderr = stderr

			if startErr := session.Start(remoteCmd); startErr != nil {
				return fmt.Errorf("failed to start remote rsync server: %w", startErr)
			}

			go func() {
				_, _ = io.Copy(sessStdin, stdin)
				_ = sessStdin.Close()
			}()

			return session.Wait()
		}

		sockPath, waitBridgeErr, cleanupBridge, bErr := startStealthStdioBridge(manifest, folder, now, sshRunner)
		if bErr != nil {
			fail("STDIO_BRIDGE_FAILED", bErr, "")
		}

		excludePipeRead, excludePipeWrite, pErr := os.Pipe()
		if pErr != nil {
			cleanupBridge()
			fail("PIPE_CREATION_FAILED", fmt.Errorf("failed to create anonymous exclude pipe: %w", pErr), "")
		}
		excludeContent := strings.Join(manifest.Excludes, "\n") + "\n"
		go func(w *os.File, payload string) {
			_, _ = w.WriteString(payload)
			_ = w.Close()
		}(excludePipeWrite, excludeContent)

		rsyncArgs := buildLocalStealthRsyncArgs(manifest, selfExe, dryRun)
		// #nosec G204 G702
		cmd := exec.Command(localRsyncBin, rsyncArgs...)
		cmd.Dir = localDir
		cmd.ExtraFiles = []*os.File{excludePipeRead}
		cmd.Env = append(os.Environ(), fmt.Sprintf("SEC_STDIO_SOCK=%s", sockPath))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		runErr := cmd.Run()
		_ = excludePipeRead.Close()
		bridgeErr := waitBridgeErr()
		cleanupBridge()

		if runErr != nil {
			if bridgeErr != nil {
				fail("BACKUP_SYNC_FAILED", fmt.Errorf("rsync failed for folder %q: %v (remote: %v)", folder.Source, runErr, bridgeErr), "")
			}
			fail("BACKUP_SYNC_FAILED", fmt.Errorf("rsync failed for folder %q: %w", folder.Source, runErr), "")
		}
	}

	fmt.Printf("[✓] Completed stealth backup job %q (%d folder(s) synchronized)\n", manifest.Name, len(selectedFolders))
}
