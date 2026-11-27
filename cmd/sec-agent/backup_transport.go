package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sshStdioHandshake is the 1-line JSON control header sent by `sec ssh-stdio`
// over the ephemeral local Unix domain socket before raw rsync protocol streaming begins.
type sshStdioHandshake struct {
	Args []string `json:"args"`
}

// remoteCommandRunner abstracts executing the rewritten remote `rsync --server` command
// over an in-memory Go `ssh.Session` (or an in-process mock during unit tests).
type remoteCommandRunner func(remoteCmd string, stdin io.Reader, stdout, stderr io.Writer) error

type resolvedStealthSSHConfig struct {
	TargetName          string
	Host                string
	User                string
	Port                int
	Password            string
	KeyBytes            []byte
	Passphrase          string
	ServerAliveInterval int
	ServerAliveCountMax int
}

func resolveStealthSSHTarget(profile string, manifest store.BackupManifest, noTrace bool) (*resolvedStealthSSHConfig, error) {
	targetName := strings.TrimSpace(manifest.SSHTarget)
	var resolvedHost, resolvedUser, resolvedPassword string
	resolvedPort := 22
	var resolvedServerAliveInterval, resolvedServerAliveCountMax int
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

	// 2. Check active profile vault for ssh/<targetName>/..., ssh/<host>/... (for user@host targets), or ssh/...
	var prefixes []string
	if targetName != "" {
		prefixes = append(prefixes, "ssh/"+targetName+"/")
		if strings.Contains(targetName, "@") {
			if hostPart := strings.TrimSpace(strings.SplitN(targetName, "@", 2)[1]); hostPart != "" {
				prefixes = append(prefixes, "ssh/"+hostPart+"/")
			}
		}
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
		if resolvedServerAliveInterval == 0 {
			if val, ok := getSecretNoTrace(pfx + "server_alive_interval"); ok {
				if sai, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && sai > 0 {
					resolvedServerAliveInterval = sai
				}
			}
		}
		if resolvedServerAliveCountMax == 0 {
			if val, ok := getSecretNoTrace(pfx + "server_alive_count_max"); ok {
				if sac, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && sac > 0 {
					resolvedServerAliveCountMax = sac
				}
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
		if Verbose {
			return nil, fmt.Errorf("unknown SSH target %q and not a valid user@host destination", targetName)
		}
		return nil, fmt.Errorf("unknown SSH target and not a valid destination")
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
		TargetName:          targetName,
		Host:                resolvedHost,
		User:                resolvedUser,
		Port:                resolvedPort,
		Password:            resolvedPassword,
		KeyBytes:            keyBytes,
		Passphrase:          passphrase,
		ServerAliveInterval: resolvedServerAliveInterval,
		ServerAliveCountMax: resolvedServerAliveCountMax,
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
		if Verbose {
			return nil, fmt.Errorf("no vault SSH credentials (private_key or password) found for target %q", cfg.TargetName)
		}
		return nil, fmt.Errorf("no vault SSH credentials (private_key or password) found for configured target")
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
		if Verbose {
			return nil, fmt.Errorf("failed to dial SSH server at %s: %w", addr, err)
		}
		return nil, fmt.Errorf("failed to dial SSH server: %s", redactBackupOutputLine(err.Error()))
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
	if folder.Sparse {
		hasSparse := false
		for _, ta := range tailArgs {
			if ta == "--sparse" || ta == "-S" {
				hasSparse = true
				break
			}
		}
		if !hasSparse {
			cmdParts = append(cmdParts, "--sparse")
		}
	}
	if effTimeout := folder.EffectiveTimeout(manifest.Timeout); effTimeout > 0 {
		hasTimeout := false
		for _, ta := range tailArgs {
			if strings.HasPrefix(ta, "--timeout=") {
				hasTimeout = true
				break
			}
		}
		if !hasTimeout {
			cmdParts = append(cmdParts, fmt.Sprintf("--timeout=%d", effTimeout))
		}
	}
	cmdParts = append(cmdParts, tailArgs...)

	remoteRsyncCmd := strings.Join(cmdParts, " ")
	return fmt.Sprintf("mkdir -p %s %s && %s",
		shellQuotePOSIX(remoteHistoryDir),
		shellQuotePOSIX(remoteDest),
		remoteRsyncCmd,
	)
}

// buildLocalStealthRsyncArgs constructs a minimal local `rsync` command-line argument slice.
// By setting `cmd.Dir = localDir`, moving transport (`RSYNC_RSH`) and partial-dir (`RSYNC_PARTIAL_DIR`)
// into `cmd.Env`, passing excludes via `/dev/fd/3`, and using compact flags + opaque `. s:t`,
// zero folder names, volume paths, usernames, IP addresses, or verbose transport options
// appear in the local host's `ps aux` process table.
// In normal mode (`!verbose`), `-v` and `--progress` are omitted and `--stats` is used so
// filenames are never emitted over stdout; per-file output (`-rtvP`) is gated behind `--verbose`.
func buildLocalStealthRsyncArgs(manifest store.BackupManifest, selfExe string, dryRun bool, verbose bool, folders ...store.BackupFolderSpec) []string {
	_ = selfExe
	manifest.ApplyDefaults()
	var activeFolder store.BackupFolderSpec
	if len(folders) > 0 {
		activeFolder = folders[0]
	} else if len(manifest.Folders) == 1 {
		activeFolder = manifest.Folders[0]
	}

	shortFlags := "-rt"
	if verbose {
		shortFlags = "-rtvP"
	}
	if activeFolder.Sparse {
		shortFlags += "S"
	}
	if dryRun {
		shortFlags += "n"
	}
	args := []string{shortFlags}
	if !verbose {
		args = append(args, "--partial", "--stats")
		if npDur, npErr := manifest.EffectiveNoProgressTimeout(); npErr == nil && npDur > 0 {
			args = append(args, "--info=name0,flist2,progress2")
		}
	}
	if effTimeout := activeFolder.EffectiveTimeout(manifest.Timeout); effTimeout > 0 {
		args = append(args, fmt.Sprintf("--timeout=%d", effTimeout))
	}
	args = append(args, fmt.Sprintf("--modify-window=%d", manifest.ModifyWindow))
	if len(activeFolder.EffectiveExcludes(manifest.Excludes)) > 0 {
		args = append(args, "--exclude-from=/dev/fd/3")
	}
	args = append(args, ".", "s:t")
	return args
}

// buildLocalStealthRsyncEnv builds the subprocess environment for local `rsync`,
// passing the stealth transport (`RSYNC_RSH`), partial-dir (`RSYNC_PARTIAL_DIR`),
// and ephemeral stdio socket (`SEC_STDIO_SOCK`) privately via environment variables
// rather than process argv.
func buildLocalStealthRsyncEnv(manifest store.BackupManifest, selfExe string, sockPath string) []string {
	manifest.ApplyDefaults()
	rshCmd := fmt.Sprintf("%s ssh-stdio", shellQuoteIfNeeded(selfExe))
	env := make([]string, 0, len(os.Environ())+3)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "RSYNC_RSH=") ||
			strings.HasPrefix(kv, "RSYNC_PARTIAL_DIR=") ||
			strings.HasPrefix(kv, "SEC_STDIO_SOCK=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		fmt.Sprintf("SEC_STDIO_SOCK=%s", sockPath),
		fmt.Sprintf("RSYNC_RSH=%s", rshCmd),
	)
	if strings.TrimSpace(manifest.PartialDir) != "" {
		env = append(env, fmt.Sprintf("RSYNC_PARTIAL_DIR=%s", manifest.PartialDir))
	}
	return env
}

// shellQuoteRemotePath quotes a remote POSIX path for `sh -c`, preserving
// tilde expansion (`~/` -> `"$HOME/"'...'`) so remote Linux/macOS shells expand
// `$HOME` safely even when the path contains spaces or quotes.
func shellQuoteRemotePath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "~" || trimmed == "~/" {
		return `"$HOME/"`
	}
	if strings.HasPrefix(trimmed, "~/") {
		rest := strings.TrimPrefix(trimmed, "~/")
		return `"$HOME/"` + shellQuotePOSIX(rest)
	}
	return shellQuotePOSIX(trimmed)
}

// rewriteRemoteRsyncPullCommand intercepts the remote `rsync --server --sender` command
// for `transport: "ssh-pull"`, replaces the remote `rsync` binary with `manifest.RemoteRsyncBin`
// (default `"rsync"` for Linux/macOS compatibility), replaces the opaque `"t/"` source with
// the real remote source path (safely expanding `~/` via `"$HOME/"`), and executes strictly
// read-only on the remote host (all history & logs live on the local destination volume).
func rewriteRemoteRsyncPullCommand(clientArgs []string, manifest store.BackupManifest, folder store.BackupFolderSpec) string {
	manifest.ApplyDefaults()
	remoteSrc := folder.ResolveRemoteSource(manifest.LocalBase)

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
		tailArgs = []string{"--sender", "-rt", ".", "t/"}
	}

	if len(tailArgs) == 0 {
		tailArgs = []string{"--sender", ".", shellQuoteRemotePath(remoteSrc)}
	} else {
		tailArgs[len(tailArgs)-1] = shellQuoteRemotePath(remoteSrc)
	}

	var cmdParts []string
	cmdParts = append(cmdParts, shellQuotePOSIX(manifest.RemoteRsyncBin), "--server")
	if effTimeout := folder.EffectiveTimeout(manifest.Timeout); effTimeout > 0 {
		hasTimeout := false
		for _, ta := range tailArgs {
			if strings.HasPrefix(ta, "--timeout=") {
				hasTimeout = true
				break
			}
		}
		if !hasTimeout {
			cmdParts = append(cmdParts, fmt.Sprintf("--timeout=%d", effTimeout))
		}
	}
	cmdParts = append(cmdParts, tailArgs...)
	return strings.Join(cmdParts, " ")
}

// buildStealthSSHPullRsyncArgs constructs the opaque local `rsync` argument slice for
// `transport: "ssh-pull"` running inside an ephemeral 0700 stage directory (`cmd.Dir = stageDir`).
// Source is opaque `s:t/` (rewritten over the encrypted Go SSH bridge), destination is `d/`,
// local history is `<stageDir>/h`, and local log is `l`, keeping remote host, username,
// remote paths, local volume names, folder names, and log names 100% out of `ps aux`.
func buildStealthSSHPullRsyncArgs(manifest store.BackupManifest, folder store.BackupFolderSpec, stageDir string, hasHistory, hasLog, dryRun, verbose bool) []string {
	manifest.ApplyDefaults()

	shortFlags := "-rt"
	if verbose {
		shortFlags = "-rtvP"
	}
	if folder.Sparse {
		shortFlags += "S"
	}
	if dryRun {
		shortFlags += "n"
	}
	args := []string{shortFlags}
	if !verbose {
		args = append(args, "--partial", "--stats")
		if npDur, npErr := manifest.EffectiveNoProgressTimeout(); npErr == nil && npDur > 0 {
			args = append(args, "--info=name0,flist2,progress2")
		}
	}
	if effTimeout := folder.EffectiveTimeout(manifest.Timeout); effTimeout > 0 {
		args = append(args, fmt.Sprintf("--timeout=%d", effTimeout))
	}
	args = append(args, fmt.Sprintf("--modify-window=%d", manifest.ModifyWindow))
	if hasHistory {
		args = append(args, "-b", "--backup-dir="+filepath.Join(stageDir, "h"))
	}
	if hasLog && !dryRun {
		args = append(args, "--log-file=l")
	}
	if len(folder.EffectiveExcludes(manifest.Excludes)) > 0 {
		args = append(args, "--exclude-from=/dev/fd/3")
	}
	args = append(args, "s:t/", "d/")
	return args
}

// prepareLocalRsyncStageDir creates an ephemeral mode-0700 staging directory
// containing short opaque symlinks (s -> localDir when non-empty, d -> destDir,
// h -> historyDir, l -> destLogPath) so local and ssh-pull `rsync` runs keep
// volume names, base folders, source/dest folder names, history dates, and
// log filenames completely out of `ps aux` / `pstree`.
func prepareLocalRsyncStageDir(localDir, destDir, historyDir, destLogPath string, dryRun bool) (stageDir string, cleanup func(), err error) {
	// #nosec G301
	stageDir, err = os.MkdirTemp("/tmp", "s")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create ephemeral local rsync stage dir: %w", err)
	}
	cleanup = func() {
		// #nosec G703
		_ = os.RemoveAll(stageDir)
	}
	// #nosec G302 G703
	if chmodErr := os.Chmod(stageDir, 0700); chmodErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to harden stage dir permissions: %w", chmodErr)
	}

	if strings.TrimSpace(localDir) != "" {
		if symErr := os.Symlink(localDir, filepath.Join(stageDir, "s")); symErr != nil {
			cleanup()
			return "", nil, fmt.Errorf("failed to create source symlink: %w", symErr)
		}
	}
	if symErr := os.Symlink(destDir, filepath.Join(stageDir, "d")); symErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to create destination symlink: %w", symErr)
	}
	if strings.TrimSpace(historyDir) != "" {
		if symErr := os.Symlink(historyDir, filepath.Join(stageDir, "h")); symErr != nil {
			cleanup()
			return "", nil, fmt.Errorf("failed to create history symlink: %w", symErr)
		}
	}
	if strings.TrimSpace(destLogPath) != "" && !dryRun {
		// Pre-create the destination log file so the symlink target exists before rsync opens it.
		// #nosec G304 G703
		lf, openErr := os.OpenFile(destLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if openErr != nil {
			cleanup()
			return "", nil, fmt.Errorf("failed to pre-create destination log file: %w", openErr)
		}
		_ = lf.Close()
		if symErr := os.Symlink(destLogPath, filepath.Join(stageDir, "l")); symErr != nil {
			cleanup()
			return "", nil, fmt.Errorf("failed to create log symlink: %w", symErr)
		}
	}
	return stageDir, cleanup, nil
}

// buildDirectLocalRsyncArgs constructs the argument vector for direct local `rsync`
// (`transport: "local"`) running inside an ephemeral 0700 stage directory (`cmd.Dir = stageDir`).
// Source (`s/`), destination (`d/`), history (`<stageDir>/h`), and log (`l`) use opaque
// single-letter symlinks so zero volume names, folder names, history dates, or log filenames
// appear in `ps aux` or `pstree`.
func buildDirectLocalRsyncArgs(manifest store.BackupManifest, folder store.BackupFolderSpec, stageDir string, hasHistory, hasLog, dryRun, verbose bool) []string {
	manifest.ApplyDefaults()

	shortFlags := "-rt"
	if verbose {
		shortFlags = "-rtvP"
	}
	if folder.Sparse {
		shortFlags += "S"
	}
	if dryRun {
		shortFlags += "n"
	}
	args := []string{shortFlags}
	if !verbose {
		args = append(args, "--partial", "--stats")
		if npDur, npErr := manifest.EffectiveNoProgressTimeout(); npErr == nil && npDur > 0 {
			args = append(args, "--info=name0,flist2,progress2")
		}
	}
	if effTimeout := folder.EffectiveTimeout(manifest.Timeout); effTimeout > 0 {
		args = append(args, fmt.Sprintf("--timeout=%d", effTimeout))
	}
	args = append(args, fmt.Sprintf("--modify-window=%d", manifest.ModifyWindow))
	if hasHistory {
		args = append(args, "-b", "--backup-dir="+filepath.Join(stageDir, "h"))
	}
	if hasLog && !dryRun {
		args = append(args, "--log-file=l")
	}
	if len(folder.EffectiveExcludes(manifest.Excludes)) > 0 {
		args = append(args, "--exclude-from=/dev/fd/3")
	}
	args = append(args, "s/", "d/")
	return args
}

// buildDirectLocalRsyncEnv builds the subprocess environment for direct local `rsync`,
// stripping SSH bridge variables and passing `RSYNC_PARTIAL_DIR` via `cmd.Env`.
func buildDirectLocalRsyncEnv(manifest store.BackupManifest) []string {
	manifest.ApplyDefaults()
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "RSYNC_RSH=") ||
			strings.HasPrefix(kv, "RSYNC_PARTIAL_DIR=") ||
			strings.HasPrefix(kv, "SEC_STDIO_SOCK=") {
			continue
		}
		env = append(env, kv)
	}
	if strings.TrimSpace(manifest.PartialDir) != "" {
		env = append(env, fmt.Sprintf("RSYNC_PARTIAL_DIR=%s", manifest.PartialDir))
	}
	return env
}

// startStealthStdioBridge starts an ephemeral Unix domain socket listener (0600 in a private temp dir)
// for a single folder synchronization session. When the local `ssh-stdio` helper connects and sends
// its 1-line JSON argument header, the bridge rewrites the remote `rsync --server` command and streams
// stdin/stdout bi-directionally through `runner`. Optional `stderrWriters` lets callers route remote
// SSH stderr through a privacy-preserving redacting filter instead of raw os.Stderr.
func startStealthStdioBridge(manifest store.BackupManifest, folder store.BackupFolderSpec, now time.Time, runner remoteCommandRunner, stderrWriters ...io.Writer) (sockPath string, waitErr func() error, cleanup func(), err error) {
	remoteStderr := io.Writer(os.Stderr)
	if len(stderrWriters) > 0 && stderrWriters[0] != nil {
		remoteStderr = stderrWriters[0]
	}

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

		var remoteCmd string
		if manifest.EffectiveTransport() == store.BackupTransportSSHPull {
			remoteCmd = rewriteRemoteRsyncPullCommand(hs.Args, manifest, folder)
		} else {
			remoteCmd = rewriteRemoteRsyncServerCommand(hs.Args, manifest, folder, now)
		}
		runErr := runner(remoteCmd, br, conn, remoteStderr)
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

// rsyncIsOpenrsync reports whether bin is Apple's openrsync (protocol 29, shipped at /usr/bin/rsync).
// openrsync does not support server-side --log-file in the same way as GNU rsync (protocol 31+).
func rsyncIsOpenrsync(bin string) bool {
	if strings.TrimSpace(bin) == "" {
		return false
	}
	// #nosec G204 G702
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "openrsync")
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
