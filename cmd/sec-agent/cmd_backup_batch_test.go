package main

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"secure_secrets/internal/store"
)

func TestBatchBackoffDoublesAndCaps(t *testing.T) {
	oldBase, oldMax := batchRetryBaseDelay, batchRetryMaxDelay
	t.Cleanup(func() { batchRetryBaseDelay, batchRetryMaxDelay = oldBase, oldMax })
	batchRetryBaseDelay = 10 * time.Second
	batchRetryMaxDelay = 30 * time.Second

	want := []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		if got := batchBackoff(i + 1); got != w {
			t.Errorf("batchBackoff(%d) = %s, want %s", i+1, got, w)
		}
	}
}

func testBatch(maxAttempts int) store.BackupBatch {
	return store.BackupBatch{
		Name:        "test-batch",
		SSHTarget:   "user@backup.example",
		MaxAttempts: maxAttempts,
		Jobs: []store.BackupBatchJob{{
			Name:      "docs",
			Source:    "/src/docs",
			Dest:      "/dst/docs",
			BackupDir: "/bak/{date}",
			LogFile:   "/log/docs_{datetime}.log",
		}},
	}
}

func stubRsync(t *testing.T, results ...error) *int {
	t.Helper()
	oldRunner, oldBase := batchRsyncRunner, batchRetryBaseDelay
	t.Cleanup(func() { batchRsyncRunner, batchRetryBaseDelay = oldRunner, oldBase })
	batchRetryBaseDelay = time.Millisecond
	calls := 0
	batchRsyncRunner = func(args []string, _ batchSSHAuth) error {
		idx := calls
		calls++
		if idx < len(results) {
			return results[idx]
		}
		return nil
	}
	return &calls
}

func TestRunBatchJobWithRetrySucceedsAfterFailures(t *testing.T) {
	calls := stubRsync(t, errors.New("transient"), errors.New("transient"))
	batch := testBatch(5)
	if err := runBatchJobWithRetry(batch, batch.Jobs[0], time.Now(), make(chan struct{}), batchSSHAuth{}); err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if *calls != 3 {
		t.Errorf("rsync calls = %d, want 3", *calls)
	}
}

func TestRunBatchJobWithRetryGivesUpAfterMaxAttempts(t *testing.T) {
	calls := stubRsync(t, errors.New("a"), errors.New("b"), errors.New("c"))
	batch := testBatch(3)
	err := runBatchJobWithRetry(batch, batch.Jobs[0], time.Now(), make(chan struct{}), batchSSHAuth{})
	if err == nil {
		t.Fatal("expected failure after max attempts")
	}
	if *calls != 3 {
		t.Errorf("rsync calls = %d, want 3", *calls)
	}
}

func TestBuildBatchRsyncArgsExpandsDateOnceAndQuotesDest(t *testing.T) {
	when := time.Date(2026, 3, 14, 9, 5, 0, 0, time.Local)
	batch := testBatch(5)
	batch.Jobs[0].Dest = "/dst/OneDrive - Example/"
	args := buildBatchRsyncArgs(batch, batch.Jobs[0], when)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--backup-dir=/bak/2026-03-14") {
		t.Errorf("backup-dir date not expanded: %s", joined)
	}
	if !strings.Contains(joined, "--log-file='/log/docs_2026-03-14_0905.log'") {
		t.Errorf("log-file datetime not expanded/quoted: %s", joined)
	}
	if args[len(args)-1] != "user@backup.example:'/dst/OneDrive - Example/'" {
		t.Errorf("remote destination not quoted: %q", args[len(args)-1])
	}
	if args[len(args)-2] != "/src/docs/" {
		t.Errorf("source should end with slash: %q", args[len(args)-2])
	}
	if !strings.Contains(joined, "--exclude=.DS_Store") {
		t.Errorf("default excludes missing: %s", joined)
	}
}

func TestBuildBatchRsyncArgsAlwaysExcludesAppleDouble(t *testing.T) {
	when := time.Date(2026, 3, 14, 9, 5, 0, 0, time.Local)
	batch := testBatch(5)
	batch.Jobs[0].Excludes = []string{"/TV/"}
	joined := strings.Join(buildBatchRsyncArgs(batch, batch.Jobs[0], when), " ")

	if !strings.Contains(joined, "--exclude=/TV/ --exclude=._*") {
		t.Errorf("._* missing for job with explicit excludes: %s", joined)
	}
}

func TestBuildBatchRsyncArgsDetectsStalls(t *testing.T) {
	when := time.Date(2026, 3, 14, 9, 5, 0, 0, time.Local)
	batch := testBatch(5)
	args := buildBatchRsyncArgs(batch, batch.Jobs[0], when)
	if !slices.Contains(args, "--timeout=600") {
		t.Fatalf("rsync I/O timeout missing: %v", args)
	}
	idx := slices.Index(args, "-e")
	if idx < 0 || !strings.Contains(args[idx+1], "ServerAliveInterval=30") {
		t.Fatalf("ssh keepalive missing from -e: %v", args)
	}
}

func TestBuildBatchRsyncArgsSparseOnlyWhenEnabled(t *testing.T) {
	when := time.Date(2026, 3, 14, 9, 5, 0, 0, time.Local)
	batch := testBatch(5)
	if strings.Contains(strings.Join(buildBatchRsyncArgs(batch, batch.Jobs[0], when), " "), "--sparse") {
		t.Fatal("--sparse set for job without sparse flag")
	}
	batch.Jobs[0].Sparse = true
	if !slices.Contains(buildBatchRsyncArgs(batch, batch.Jobs[0], when), "--sparse") {
		t.Fatal("--sparse missing for job with sparse flag")
	}
}

func TestBatchAskPassEchoesPasswordFromEnvOnly(t *testing.T) {
	script, cleanup, err := writeBatchAskPass()
	if err != nil {
		t.Fatalf("writeBatchAskPass: %v", err)
	}
	defer cleanup()

	const password = "p@ss word'with\"quotes"
	cmd := exec.Command("/bin/sh", script, "Password:")
	cmd.Env = []string{batchPasswordEnv + "=" + password}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("askpass run: %v", err)
	}
	if got := strings.TrimSuffix(string(out), "\n"); got != password {
		t.Errorf("askpass output = %q, want %q", got, password)
	}
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read askpass: %v", err)
	}
	if strings.Contains(string(body), password) {
		t.Error("askpass helper must not contain the password")
	}
}
