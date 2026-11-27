package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"secure_secrets/internal/store"
)

func TestRewriteRemoteRsyncPullCommandAndZeroLeakArgs(t *testing.T) {
	m := store.BackupManifest{
		Name:       store.BackupJobName("remote-box"),
		Transport:  store.BackupTransportSSHPull,
		SSHTarget:  "remote-linux-host",
		LocalBase:  "~",
		RemoteBase: "/Volumes/SensitiveDisk/RemoteBox",
		Folders: []store.BackupFolderSpec{
			{Source: "Work Projects"},
		},
	}
	m.ApplyDefaults()

	// 1. Verify remote pull command rewrite safely expands ~/ via "$HOME/" and is read-only (no mkdir/backup-dir/log-file)
	rewritten := rewriteRemoteRsyncPullCommand([]string{"s", "rsync", "--server", "--sender", "-rt", ".", "t/"}, m, m.Folders[0])
	if !strings.HasPrefix(rewritten, `'rsync' --server --sender -rt . "$HOME/"'Work Projects/'`) {
		t.Errorf("unexpected rewritten remote pull command:\n%s", rewritten)
	}
	for _, forbidden := range []string{"mkdir", "--backup-dir", "--log-file", "SensitiveDisk"} {
		if strings.Contains(rewritten, forbidden) {
			t.Errorf("remote pull command should not contain %q: %s", forbidden, rewritten)
		}
	}

	// 2. Verify local pull rsync argv has zero host/volume/folder/log leakage
	args := buildStealthSSHPullRsyncArgs(m, m.Folders[0], "/tmp/s987654", true, true, false, false)
	joined := strings.Join(args, " ")
	for _, forbidden := range []string{"remote-linux-host", "SensitiveDisk", "RemoteBox", "Work Projects", "History", "rsync_work"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("LEAK: ssh-pull rsync argv exposed %q: %s", forbidden, joined)
		}
	}
	for _, required := range []string{"--backup-dir=/tmp/s987654/h", "--log-file=l", "--exclude-from=/dev/fd/3", "s:t/", "d/"} {
		if !strings.Contains(joined, required) {
			t.Errorf("expected ssh-pull rsync argv to contain %q, got: %s", required, joined)
		}
	}
}

func TestStealthSSHPullRealRsyncOverGoSSH(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync binary not available in PATH")
	}

	// Build real CLI binary so `RSYNC_RSH="<bin> ssh-stdio"` works in-process
	binPath := filepath.Join(t.TempDir(), "sec-agent-pull-test")
	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		t.Fatalf("failed building test binary: %v\n%s", err, string(out))
	}

	// Simulated remote home directory with `work/` folder
	remoteHome := t.TempDir()
	remoteWork := filepath.Join(remoteHome, "work")
	if err := os.MkdirAll(filepath.Join(remoteWork, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remoteWork, "sub", "hello.txt"), []byte("from-remote-v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remoteWork, ".DS_Store"), []byte("skip"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Local destination base
	localDestBase := t.TempDir()

	// Spin up an in-process Go SSH server executing commands with HOME=remoteHome
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &ssh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, chans, reqs, hErr := ssh.NewServerConn(c, serverCfg)
				if hErr != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, chErr := newChan.Accept()
					if chErr != nil {
						continue
					}
					go func(channel ssh.Channel, in <-chan *ssh.Request) {
						defer channel.Close()
						for req := range in {
							if req.Type == "exec" && len(req.Payload) >= 4 {
								cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
								cmdStr := string(req.Payload[4 : 4+cmdLen])
								_ = req.Reply(true, nil)

								shCmd := exec.Command("/bin/sh", "-c", cmdStr)
								shCmd.Env = append(os.Environ(), "HOME="+remoteHome)
								inPipe, _ := shCmd.StdinPipe()
								shCmd.Stdout = channel
								shCmd.Stderr = channel.Stderr()
								if sErr := shCmd.Start(); sErr != nil {
									_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
									return
								}
								go func() {
									_, _ = io.Copy(inPipe, channel)
									_ = inPipe.Close()
								}()
								exitCode := uint32(0)
								if wErr := shCmd.Wait(); wErr != nil {
									exitCode = 1
								}
								_, _ = channel.SendRequest("exit-status", false, []byte{
									byte(exitCode >> 24), byte(exitCode >> 16), byte(exitCode >> 8), byte(exitCode),
								})
								return
							}
						}
					}(ch, chReqs)
				}
			}(conn)
		}
	}()

	// Dial our in-process SSH server
	sshClient, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "testuser",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh.Dial failed: %v", err)
	}
	t.Cleanup(func() { _ = sshClient.Close() })

	// Also avoid unused pem import check by validating key block roundtrip
	_ = pem.Block{}

	manifest := store.BackupManifest{
		Name:       store.BackupJobName("pull-e2e"),
		Transport:  store.BackupTransportSSHPull,
		SSHTarget:  "remote-box",
		LocalBase:  "~",
		RemoteBase: localDestBase,
		Folders:    []store.BackupFolderSpec{{Source: "work"}},
	}
	manifest.ApplyDefaults()

	runPull := func() {
		t.Helper()
		folder := manifest.Folders[0]
		now := time.Now()
		destDir := folder.DeriveRemoteDest(manifest.RemoteBase)
		historyDir := folder.DeriveHistoryDir(manifest.RemoteBase, now.Format("2006-01-02"))
		destLogPath := folder.DeriveRemoteLogPath(manifest.RemoteBase, now.Format("2006-01-02_1504"))
		_ = os.MkdirAll(destDir, 0o750)
		_ = os.MkdirAll(historyDir, 0o750)

		stageDir, cleanupStage, sErr := prepareLocalRsyncStageDir("", destDir, historyDir, destLogPath, false)
		if sErr != nil {
			t.Fatalf("prepareLocalRsyncStageDir failed: %v", sErr)
		}
		defer cleanupStage()

		sshRunner := func(remoteCmd string, stdin io.Reader, stdout, stderr io.Writer) error {
			sess, err := sshClient.NewSession()
			if err != nil {
				return err
			}
			defer sess.Close()
			sp, err := sess.StdinPipe()
			if err != nil {
				return err
			}
			sess.Stdout = stdout
			sess.Stderr = stderr
			if err := sess.Start(remoteCmd); err != nil {
				return err
			}
			go func() {
				_, _ = io.Copy(sp, stdin)
				_ = sp.Close()
			}()
			return sess.Wait()
		}

		sockPath, waitBridge, cleanupBridge, bErr := startStealthStdioBridge(manifest, folder, now, sshRunner)
		if bErr != nil {
			t.Fatalf("startStealthStdioBridge failed: %v", bErr)
		}
		defer cleanupBridge()

		exR, exW, _ := os.Pipe()
		go func() {
			_, _ = exW.WriteString(strings.Join(folder.EffectiveExcludes(manifest.Excludes), "\n") + "\n")
			_ = exW.Close()
		}()

		rsyncArgs := buildStealthSSHPullRsyncArgs(manifest, folder, stageDir, true, true, false, false)
		cmd := exec.Command("rsync", rsyncArgs...)
		cmd.Dir = stageDir
		cmd.ExtraFiles = []*os.File{exR}
		cmd.Env = buildLocalStealthRsyncEnv(manifest, binPath, sockPath)
		out, runErr := cmd.CombinedOutput()
		_ = exR.Close()
		if runErr != nil {
			t.Fatalf("ssh-pull rsync failed: %v\nbridgeErr=%v\nOutput:\n%s", runErr, waitBridge(), string(out))
		}
		if bErr := waitBridge(); bErr != nil {
			t.Fatalf("ssh-pull bridge error: %v", bErr)
		}
	}

	// Pull #1: sync remote ~/work -> localDestBase/work/
	runPull()
	got1, err := os.ReadFile(filepath.Join(localDestBase, "work", "sub", "hello.txt"))
	if err != nil || string(got1) != "from-remote-v1\n" {
		t.Fatalf("expected pulled file from-remote-v1, got %q err=%v", string(got1), err)
	}
	if _, err := os.Stat(filepath.Join(localDestBase, "work", ".DS_Store")); !os.IsNotExist(err) {
		t.Fatalf("expected .DS_Store excluded on pull")
	}

	// Pull #2: update remote file (different length) -> verify local -History preserves v1 & local log exists
	if err := os.WriteFile(filepath.Join(remoteWork, "sub", "hello.txt"), []byte("from-remote-v2-updated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runPull()
	got2, err := os.ReadFile(filepath.Join(localDestBase, "work", "sub", "hello.txt"))
	if err != nil || string(got2) != "from-remote-v2-updated\n" {
		t.Fatalf("expected updated pulled file v2, got %q err=%v", string(got2), err)
	}
	histMatches, _ := filepath.Glob(filepath.Join(localDestBase, "work-History", "*", "sub", "hello.txt"))
	if len(histMatches) == 0 {
		t.Fatalf("expected local work-History/<YYYY-MM-DD>/sub/hello.txt preserving v1")
	}
	logMatches, _ := filepath.Glob(filepath.Join(localDestBase, "rsync_work_*.log"))
	if len(logMatches) == 0 {
		t.Fatalf("expected local rsync_work_*.log in %s", localDestBase)
	}
}
