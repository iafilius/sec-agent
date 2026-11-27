package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneSnapshotsRetentionAndOrphanCleanup(t *testing.T) {
	tmpCfg := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tmpCfg)

	profile := "retention-test"
	snapDir, err := GetSnapshotDir(profile)
	if err != nil {
		t.Fatalf("GetSnapshotDir failed: %v", err)
	}
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create 30 snapshots with ascending timestamps
	baseTime := time.Now().Add(-1 * time.Hour)
	for i := 1; i <= 30; i++ {
		id := fmt.Sprintf("snap-20261125-%06d-000", i)
		encPath := filepath.Join(snapDir, id+".enc")
		metaPath := filepath.Join(snapDir, id+".meta.json")
		if err := os.WriteFile(encPath, []byte("enc"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(metaPath, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		ts := baseTime.Add(time.Duration(i) * time.Second)
		_ = os.Chtimes(encPath, ts, ts)
		_ = os.Chtimes(metaPath, ts, ts)
	}
	// Also create an orphaned .meta.json without .enc
	orphanMeta := filepath.Join(snapDir, "snap-orphan.meta.json")
	if err := os.WriteFile(orphanMeta, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Prune keeping newest 10
	deleted, err := PruneSnapshots(profile, 10)
	if err != nil {
		t.Fatalf("PruneSnapshots failed: %v", err)
	}
	if deleted != 20 {
		t.Fatalf("expected 20 deleted snapshots, got %d", deleted)
	}

	entries, err := os.ReadDir(snapDir)
	if err != nil {
		t.Fatal(err)
	}
	// 10 .enc + 10 .meta.json = 20 files total (orphan removed too)
	if len(entries) != 20 {
		t.Fatalf("expected 20 files remaining (10 pairs), got %d", len(entries))
	}
	if _, err := os.Stat(orphanMeta); !os.IsNotExist(err) {
		t.Errorf("expected orphan meta file to be removed")
	}
	// Verify newest (#30) kept and oldest (#1) deleted
	if _, err := os.Stat(filepath.Join(snapDir, "snap-20261125-000030-000.enc")); err != nil {
		t.Errorf("expected newest snapshot #30 to be kept, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "snap-20261125-000001-000.enc")); !os.IsNotExist(err) {
		t.Errorf("expected oldest snapshot #1 to be pruned")
	}

	// Verify SEC_MAX_SNAPSHOTS env override
	t.Setenv("SEC_MAX_SNAPSHOTS", "5")
	if got := EffectiveMaxSnapshots(); got != 5 {
		t.Errorf("expected EffectiveMaxSnapshots()=5, got %d", got)
	}
	if _, err := PruneAllSnapshots(0); err != nil {
		t.Fatalf("PruneAllSnapshots failed: %v", err)
	}
	entries2, _ := os.ReadDir(snapDir)
	if len(entries2) != 10 {
		t.Fatalf("expected 10 files remaining (5 pairs) after PruneAllSnapshots, got %d", len(entries2))
	}
}
