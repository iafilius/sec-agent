package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"

	"golang.org/x/crypto/ssh"
)

func TestRewriteRemoteRsyncServerCommand(t *testing.T) {
	manifest := store.BackupManifest{
		Name:           "work",
		SSHTarget:      "backupuser@10.0.0.50",
		LocalBase:      "/Users/backupuser",
		RemoteBase:     "/Volumes/BackupDrive/Work",
		RemoteRsyncBin: "/opt/homebrew/bin/rsync",
		ModifyWindow:   2,
		PartialDir:     ".rsync-partial",
		Excludes:       []string{".DS_Store", ".Trash*"},
	}
	folder := store.BackupFolderSpec{
		Source: "CloudFolder - Work",
	}
	fixedNow := time.Date(2026, 11, 15, 12, 5, 0, 0, time.UTC)

	clientArgs := []string{
		"rsync",
		"--server",
		"-vlogDtprze.iLsfxCIvu",
		"--modify-window=2",
		"--partial-dir=.rsync-partial",
		".",
		"target",
	}

	got := rewriteRemoteRsyncServerCommand(clientArgs, manifest, folder, fixedNow)

	want := "mkdir -p '/Volumes/BackupDrive/Work/CloudFolder-History/2026-11-15' '/Volumes/BackupDrive/Work/CloudFolder - Work/' && " +
		"'/opt/homebrew/bin/rsync' --server " +
		"--log-file='/Volumes/BackupDrive/Work/rsync_cloudfolder_2026-11-15_1205.log' " +
		"-b --backup-dir='/Volumes/BackupDrive/Work/CloudFolder-History/2026-11-15' " +
		"-vlogDtprze.iLsfxCIvu --modify-window=2 --partial-dir=.rsync-partial . " +
		"'/Volumes/BackupDrive/Work/CloudFolder - Work/'"

	if got != want {
		t.Fatalf("rewriteRemoteRsyncServerCommand mismatch:\n got: %s\nwant: %s", got, want)
	}

	// Verify when rsync passes the dummy host token "sync" before "rsync"
	withHostArgs := append([]string{"sync"}, clientArgs...)
	gotWithHost := rewriteRemoteRsyncServerCommand(withHostArgs, manifest, folder, fixedNow)
	if gotWithHost != want {
		t.Fatalf("rewriteRemoteRsyncServerCommand (with leading host token) mismatch:\n got: %s\nwant: %s", gotWithHost, want)
	}
}

func TestBuildLocalStealthRsyncArgsNoLeakage(t *testing.T) {
	manifest := store.BackupManifest{
		Name:           "work",
		SSHTarget:      "backupuser@10.0.0.50",
		LocalBase:      "/Users/backupuser",
		RemoteBase:     "/Volumes/BackupDrive/Work",
		RemoteRsyncBin: "/opt/homebrew/bin/rsync",
		ModifyWindow:   2,
		PartialDir:     ".rsync-partial",
		Excludes:       []string{".DS_Store", ".Trash*"},
		Folders: []store.BackupFolderSpec{
			{Source: "CloudFolder - Work"},
		},
	}

	args := buildLocalStealthRsyncArgs(manifest, "/usr/local/bin/sec-agent", false)
	joined := strings.Join(args, " ")

	forbiddenTokens := []string{
		"CloudFolder",
		"10.0.0.50",
		"backupuser",
		"BackupDrive",
		"CloudFolder-History",
	}

	for _, secretToken := range forbiddenTokens {
		if strings.Contains(joined, secretToken) {
			t.Errorf("local rsync args leaked sensitive token %q in argv: %v", secretToken, args)
		}
	}

	if !strings.Contains(joined, "--exclude-from=/dev/fd/3") {
		t.Errorf("expected --exclude-from=/dev/fd/3 in local rsync args, got: %v", args)
	}
	if args[len(args)-2] != "." || args[len(args)-1] != "sync:target" {
		t.Errorf("expected trailing args ['.', 'sync:target'], got: %v", args)
	}
}

func TestStealthSSHStdioBridgeEndToEnd(t *testing.T) {
	manifest := store.BackupManifest{
		Name:           "work",
		SSHTarget:      "backupuser@10.0.0.50",
		LocalBase:      "/Users/backupuser",
		RemoteBase:     "/Volumes/BackupDrive/Work",
		RemoteRsyncBin: "/opt/homebrew/bin/rsync",
		ModifyWindow:   2,
		PartialDir:     ".rsync-partial",
		Excludes:       []string{".DS_Store", ".Trash*"},
	}
	folder := store.BackupFolderSpec{
		Source: "CloudFolder - Work",
	}
	fixedNow := time.Date(2026, 11, 15, 12, 5, 0, 0, time.UTC)

	var capturedRemoteCmd string
	var capturedServerInput bytes.Buffer

	mockRunner := func(remoteCmd string, stdin io.Reader, stdout, stderr io.Writer) error {
		capturedRemoteCmd = remoteCmd
		if _, err := io.Copy(&capturedServerInput, stdin); err != nil {
			return err
		}
		_, err := stdout.Write([]byte("RSYNC_SERVER_ACK_OK\n"))
		return err
	}

	sockPath, waitErr, cleanup, err := startStealthStdioBridge(manifest, folder, fixedNow, mockRunner)
	if err != nil {
		t.Fatalf("startStealthStdioBridge failed: %v", err)
	}
	defer cleanup()

	clientArgs := []string{
		"sync",
		"rsync",
		"--server",
		"-vlogDtprze.iLsfxCIvu",
		"--modify-window=2",
		"--partial-dir=.rsync-partial",
		".",
		"target",
	}
	clientInput := bytes.NewBufferString("DELTA_STREAM_PAYLOAD_12345\n")
	var clientOutput bytes.Buffer

	if err := runSSHStdioClient(sockPath, clientArgs, clientInput, &clientOutput); err != nil {
		t.Fatalf("runSSHStdioClient failed: %v", err)
	}
	if err := waitErr(); err != nil {
		t.Fatalf("bridge runner returned error: %v", err)
	}

	if got := capturedServerInput.String(); got != "DELTA_STREAM_PAYLOAD_12345\n" {
		t.Errorf("server received stdin %q, want %q", got, "DELTA_STREAM_PAYLOAD_12345\n")
	}
	if got := clientOutput.String(); got != "RSYNC_SERVER_ACK_OK\n" {
		t.Errorf("client received stdout %q, want %q", got, "RSYNC_SERVER_ACK_OK\n")
	}
	if !strings.Contains(capturedRemoteCmd, "--backup-dir='/Volumes/BackupDrive/Work/CloudFolder-History/2026-11-15'") {
		t.Errorf("rewritten remote command missing --backup-dir: %s", capturedRemoteCmd)
	}
	if !strings.Contains(capturedRemoteCmd, "--log-file='/Volumes/BackupDrive/Work/rsync_cloudfolder_2026-11-15_1205.log'") {
		t.Errorf("rewritten remote command missing --log-file: %s", capturedRemoteCmd)
	}
	if !strings.HasSuffix(capturedRemoteCmd, "'/Volumes/BackupDrive/Work/CloudFolder - Work/'") {
		t.Errorf("rewritten remote command missing destination suffix: %s", capturedRemoteCmd)
	}
}

func TestBackupSubcommandClassifier(t *testing.T) {
	stealthSubs := []string{"init", "add-folder", "remove-folder", "show", "jobs", "run", "ssh-stdio"}
	for _, sub := range stealthSubs {
		if !isStealthBackupSubcommand(sub) {
			t.Errorf("expected isStealthBackupSubcommand(%q) to be true", sub)
		}
	}
	kdbxSubs := []string{"export", "import", "list", "my-vault.kdbx"}
	for _, sub := range kdbxSubs {
		if isStealthBackupSubcommand(sub) {
			t.Errorf("expected isStealthBackupSubcommand(%q) to be false", sub)
		}
	}
}

func TestBackupStealthManifestLifecycleNoTrace(t *testing.T) {
	tmpCfgDir, err := os.MkdirTemp("/tmp", "sec_bck_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpCfgDir)

	t.Setenv("SEC_CONFIG_DIR", tmpCfgDir)
	t.Setenv("SEC_TEST_MODE", "1")

	profile := "bcktest"
	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		t.Fatalf("GetSocketPath failed: %v", err)
	}
	defer os.Remove(sockPath)

	d, err := daemon.NewDaemon(profile, 5*time.Minute, Version)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}
	d.IsTestInstance = true
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	d.SetSessionTokenForTest("bck-test-token")
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"ssh/macmini/host":     {Value: "10.0.0.50"},
		"ssh/macmini/user":     {Value: "backupuser"},
		"ssh/macmini/password": {Value: "vault-ssh-pass"},
	})
	t.Setenv("SEC_SESSION_TOKEN", "bck-test-token")

	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	for i := 0; i < 40; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	handleStealthBackup(profile, []string{
		"init", "work",
		"--target", "macmini",
		"--local-base", "/Users/backupuser",
		"--remote-base", "/Volumes/BackupDrive/Work",
	})

	handleStealthBackup(profile, []string{
		"add-folder", "work", "CloudFolder - Work",
	})
	handleStealthBackup(profile, []string{
		"add-folder", "work", "Projects",
	})

	auditPath := filepath.Join(tmpCfgDir, "audit.log")
	_ = os.Remove(auditPath)

	manifest, err := loadStealthBackupManifest(profile, "work", true)
	if err != nil {
		t.Fatalf("loadStealthBackupManifest failed: %v", err)
	}
	if len(manifest.Folders) != 2 {
		t.Fatalf("expected 2 folders in manifest, got %d", len(manifest.Folders))
	}

	sshCfg, err := resolveStealthSSHTarget(profile, manifest, true)
	if err != nil {
		t.Fatalf("resolveStealthSSHTarget failed: %v", err)
	}
	if sshCfg.Host != "10.0.0.50" || sshCfg.User != "backupuser" || sshCfg.Password != "vault-ssh-pass" {
		t.Errorf("unexpected resolved SSH config: %+v", sshCfg)
	}

	// Verify NoTrace=true left zero GET entries in audit.log
	if data, err := os.ReadFile(auditPath); err == nil && len(data) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var entry daemon.AuditLogEntry
			if json.Unmarshal([]byte(line), &entry) == nil && entry.Action == daemon.AuditEventGet {
				t.Errorf("expected zero GET audit log entries with NoTrace: true, found: %s", line)
			}
		}
	}

	handleStealthBackup(profile, []string{
		"remove-folder", "work", "Projects",
	})
	manifestAfter, err := loadStealthBackupManifest(profile, "work", true)
	if err != nil {
		t.Fatalf("loadStealthBackupManifest after remove failed: %v", err)
	}
	if len(manifestAfter.Folders) != 1 || manifestAfter.Folders[0].Source != "CloudFolder - Work" {
		t.Errorf("unexpected folders after remove-folder: %+v", manifestAfter.Folders)
	}
}

func TestStealthBackupRunRealRsyncOverGoSSH(t *testing.T) {
	rsyncBin, err := findLocalRsyncBinary()
	if err != nil {
		t.Skipf("rsync binary not installed locally: %v", err)
	}

	// Build real sec-agent test binary so `rsync -e "<bin> ssh-stdio"` invokes the real binary
	tmpBinDir := t.TempDir()
	secBinPath := filepath.Join(tmpBinDir, "sec-agent")
	buildCmd := exec.Command("go", "build", "-o", secBinPath, ".")
	if out, bErr := buildCmd.CombinedOutput(); bErr != nil {
		t.Fatalf("failed to build sec-agent test binary: %v\nOutput: %s", bErr, out)
	}

	// Spin up an in-process Go SSH server supporting Ed25519 key auth that executes `req.Payload[4:]` via /bin/sh -c
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	clientSSHPub, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey failed: %v", err)
	}
	clientPEMBlock, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKey failed: %v", err)
	}
	clientKeyBytes := pem.EncodeToMemory(clientPEMBlock)

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host ed25519.GenerateKey failed: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey failed: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "backupuser" && bytes.Equal(pubKey.Marshal(), clientSSHPub.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("public key rejected")
		},
	}
	serverConfig.AddHostKey(hostSigner)

	sshListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer sshListener.Close()
	sshPort := sshListener.Addr().(*net.TCPAddr).Port

	var psSnapshotsMu sync.Mutex
	var liveClientRsyncLines []string

	go func() {
		for {
			nConn, acceptErr := sshListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				sConn, chans, reqs, sErr := ssh.NewServerConn(conn, serverConfig)
				if sErr != nil {
					return
				}
				defer sConn.Close()
				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					channel, requests, cErr := newChannel.Accept()
					if cErr != nil {
						return
					}
					go func(ch ssh.Channel, in <-chan *ssh.Request) {
						for req := range in {
							if req.Type == "exec" && len(req.Payload) >= 4 {
								cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
								remoteCmdStr := string(req.Payload[4 : 4+cmdLen])
								_ = req.Reply(true, nil)

								// Inspect the live kernel process table (ps) BEFORE starting the remote --server
								// process so we capture the exact local client rsync command line while in flight!
								if psOut, psErr := exec.Command("ps", "-Ao", "command=").Output(); psErr == nil {
									psSnapshotsMu.Lock()
									for _, line := range strings.Split(string(psOut), "\n") {
										if strings.Contains(line, "sync:target") {
											liveClientRsyncLines = append(liveClientRsyncLines, line)
										}
									}
									psSnapshotsMu.Unlock()
								}

								shCmd := exec.Command("/bin/sh", "-c", remoteCmdStr)
								inPipe, _ := shCmd.StdinPipe()
								shCmd.Stdout = ch
								shCmd.Stderr = ch.Stderr()
								if startErr := shCmd.Start(); startErr != nil {
									_ = ch.Close()
									return
								}
								go func() {
									_, _ = io.Copy(inPipe, ch)
									_ = inPipe.Close()
								}()
								runErr := shCmd.Wait()

								exitCode := uint32(0)
								if runErr != nil {
									if exitErr, ok := runErr.(*exec.ExitError); ok {
										exitCode = uint32(exitErr.ExitCode())
									} else {
										exitCode = 1
									}
								}
								var statusBuf [4]byte
								binary.BigEndian.PutUint32(statusBuf[:], exitCode)
								_, _ = ch.SendRequest("exit-status", false, statusBuf[:])
								_ = ch.Close()
								return
							}
							_ = req.Reply(false, nil)
						}
					}(channel, requests)
				}
			}(nConn)
		}
	}()

	// Set up test daemon with vault-stored SSH private key (zero private keys on disk)
	tmpCfgDir, err := os.MkdirTemp("/tmp", "sec_e2e_bck_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpCfgDir)

	profile := "e2ebck"
	t.Setenv("SEC_CONFIG_DIR", tmpCfgDir)
	t.Setenv("SEC_TEST_MODE", "1")
	t.Setenv("SEC_SESSION_TOKEN", "e2e-bck-token")

	d, err := daemon.NewDaemon(profile, 5*time.Minute, Version)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}
	d.IsTestInstance = true
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	d.SetSessionTokenForTest("e2e-bck-token")
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"ssh/bckhost/host":        {Value: "127.0.0.1"},
		"ssh/bckhost/user":        {Value: "backupuser"},
		"ssh/bckhost/port":        {Value: fmt.Sprintf("%d", sshPort)},
		"ssh/bckhost/private_key": {Value: string(clientKeyBytes)},
	})
	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	sockPath, _ := config.GetSocketPath(profile)
	for i := 0; i < 40; i++ {
		if _, sErr := os.Stat(sockPath); sErr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Prepare local source folder ("CloudFolder - Work") and remote base ("/Volumes/BackupDrive/Work" equivalent in tmpDir)
	localBase := filepath.Join(tmpBinDir, "local_home")
	localFolder := filepath.Join(localBase, "CloudFolder - Work")
	remoteBase := filepath.Join(tmpBinDir, "Volumes", "BackupDrive", "Work")
	if err := os.MkdirAll(localFolder, 0700); err != nil {
		t.Fatalf("MkdirAll localFolder failed: %v", err)
	}
	if err := os.MkdirAll(remoteBase, 0700); err != nil {
		t.Fatalf("MkdirAll remoteBase failed: %v", err)
	}

	// Create initial files in "CloudFolder - Work":
	// - document.txt (v1)
	// - .DS_Store (should be excluded by --exclude-from=/dev/fd/3)
	// - .Trash-1000 (should be excluded by --exclude-from=/dev/fd/3)
	if err := os.WriteFile(filepath.Join(localFolder, "document.txt"), []byte("version-1-initial-content\n"), 0600); err != nil {
		t.Fatalf("WriteFile document.txt failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localFolder, ".DS_Store"), []byte("junk-ds-store"), 0600); err != nil {
		t.Fatalf("WriteFile .DS_Store failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localFolder, ".Trash-1000"), []byte("junk-trash"), 0600); err != nil {
		t.Fatalf("WriteFile .Trash-1000 failed: %v", err)
	}

	// Initialize backup job and add folder via CLI binary
	runSecCLI := func(cliArgs ...string) string {
		fullArgs := append([]string{"--profile", profile}, cliArgs...)
		cmd := exec.Command(secBinPath, fullArgs...)
		cmd.Env = append(os.Environ(),
			"SEC_CONFIG_DIR="+tmpCfgDir,
			"SEC_TEST_MODE=1",
			"SEC_SESSION_TOKEN=e2e-bck-token",
			"SEC_LOCAL_RSYNC_BIN="+rsyncBin,
		)
		out, cErr := cmd.CombinedOutput()
		if cErr != nil {
			t.Fatalf("sec %v failed: %v\nOutput:\n%s", cliArgs, cErr, string(out))
		}
		return string(out)
	}

	runSecCLI("backup", "init", "work",
		"--target", "bckhost",
		"--local-base", localBase,
		"--remote-base", remoteBase,
		"--remote-rsync", rsyncBin,
		"--modify-window", "0",
	)
	runSecCLI("backup", "add-folder", "work", "CloudFolder - Work")

	// Clear audit.log before running `sec backup run` so we can verify zero GET traces
	auditPath := filepath.Join(tmpCfgDir, "audit.log")
	_ = os.Remove(auditPath)

	// Pass 1: Run initial stealth backup (with --tofu to pin host key into vault)
	runSecCLI("backup", "run", "work", "--tofu")

	// Verify destination file was synced
	remoteDestFile := filepath.Join(remoteBase, "CloudFolder - Work", "document.txt")
	gotV1, err := os.ReadFile(remoteDestFile)
	if err != nil {
		t.Fatalf("expected remote destination file %s to exist after Pass 1: %v", remoteDestFile, err)
	}
	if string(gotV1) != "version-1-initial-content\n" {
		t.Errorf("Pass 1 remote file content = %q, want %q", string(gotV1), "version-1-initial-content\n")
	}

	// Verify .DS_Store and .Trash-1000 were excluded via /dev/fd/3
	if _, err := os.Stat(filepath.Join(remoteBase, "CloudFolder - Work", ".DS_Store")); !os.IsNotExist(err) {
		t.Errorf("expected .DS_Store to be excluded by --exclude-from=/dev/fd/3, but it exists on remote")
	}
	if _, err := os.Stat(filepath.Join(remoteBase, "CloudFolder - Work", ".Trash-1000")); !os.IsNotExist(err) {
		t.Errorf("expected .Trash-1000 to be excluded by --exclude-from=/dev/fd/3, but it exists on remote")
	}

	// Pass 2: Modify document.txt locally (with updated mtime) and run `sec backup run work` again
	v2Content := []byte("version-2-updated-content-much-longer\n")
	if err := os.WriteFile(filepath.Join(localFolder, "document.txt"), v2Content, 0600); err != nil {
		t.Fatalf("WriteFile v2 document.txt failed: %v", err)
	}
	futureTime := time.Now().Add(10 * time.Second)
	_ = os.Chtimes(filepath.Join(localFolder, "document.txt"), futureTime, futureTime)

	_ = os.Remove(auditPath)
	runSecCLI("backup", "run", "work")

	// Verify remote destination now has v2
	gotV2, err := os.ReadFile(remoteDestFile)
	if err != nil {
		t.Fatalf("ReadFile remoteDestFile after Pass 2 failed: %v", err)
	}
	if string(gotV2) != string(v2Content) {
		t.Errorf("Pass 2 remote file content = %q, want %q", string(gotV2), string(v2Content))
	}

	// Verify Pass 1 version was backed up one level higher in <remoteBase>/CloudFolder-History/<YYYY-MM-DD>/document.txt!
	dateStr := time.Now().Format("2006-01-02")
	historyFile := filepath.Join(remoteBase, "CloudFolder-History", dateStr, "document.txt")
	gotHistory, err := os.ReadFile(historyFile)
	if err != nil {
		t.Fatalf("expected overwritten file to be backed up one level higher at %s: %v", historyFile, err)
	}
	if string(gotHistory) != "version-1-initial-content\n" {
		t.Errorf("history backup file content = %q, want %q", string(gotHistory), "version-1-initial-content\n")
	}

	// Verify remote log file was written one level higher in <remoteBase>/rsync_cloudfolder_<YYYY-MM-DD_HHMM>.log
	remoteEntries, err := os.ReadDir(remoteBase)
	if err != nil {
		t.Fatalf("ReadDir remoteBase failed: %v", err)
	}
	foundRemoteLog := false
	for _, e := range remoteEntries {
		if strings.HasPrefix(e.Name(), "rsync_cloudfolder_") && strings.HasSuffix(e.Name(), ".log") {
			foundRemoteLog = true
			break
		}
	}
	if !foundRemoteLog {
		t.Errorf("expected remote log file matching rsync_cloudfolder_*.log one level higher in %s", remoteBase)
	}

	// Verify Pass 2 left zero GET entries in local audit.log
	if data, err := os.ReadFile(auditPath); err == nil && len(data) > 0 {
		t.Errorf("expected zero audit.log entries during stealth Pass 2 run, found:\n%s", string(data))
	}

	// Verify live kernel process table (ps) captured during active rsync execution had zero sensitive path/host leaks
	psSnapshotsMu.Lock()
	capturedLines := append([]string(nil), liveClientRsyncLines...)
	psSnapshotsMu.Unlock()
	if len(capturedLines) == 0 {
		t.Fatalf("expected live ps snapshot to capture local client rsync process with sync:target")
	}
	for _, line := range capturedLines {
		for _, forbidden := range []string{"CloudFolder", "BackupDrive", "CloudFolder-History", "backupuser", ".DS_Store"} {
			if strings.Contains(line, forbidden) {
				t.Errorf("SECURITY LEAK IN LIVE PS OUTPUT: %q leaked sensitive token %q", line, forbidden)
			}
		}
	}
}
