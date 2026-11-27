package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"secure_secrets/internal/store"
	"strconv"
	"strings"
	"sync"
)

var (
	reQuotedSegment = regexp.MustCompile(`"[^"\r\n]+"`)
	reUserAtHost    = regexp.MustCompile(`\b[A-Za-z0-9._-]+@[A-Za-z0-9.-]+(?::\d+)?\b`)
	reIPv4Addr      = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`)
	reAbsOrHomePath = regexp.MustCompile(`(^|[\s(\['=])(?:~/|/)[^\s:,"')\]]+`)
	reStatsNumber   = regexp.MustCompile(`:\s*([0-9,]+)`)
)

// safeFolderAlias returns a privacy-preserving display label for a backup folder:
// its explicit alias Name if configured, otherwise its derived slug (never raw Source or localDir).
func safeFolderAlias(folder store.BackupFolderSpec) string {
	if n := strings.TrimSpace(folder.Name); n != "" {
		return n
	}
	return folder.DeriveSlug()
}

// redactBackupOutputLine scrubs filesystem paths, quoted filenames, user@host tokens, and
// IPv4 addresses from rsync/SSH error lines while preserving error classes and exit codes.
func redactBackupOutputLine(line string) string {
	suffix := ""
	body := line
	if strings.HasSuffix(body, "\n") {
		suffix = "\n"
		body = strings.TrimSuffix(body, "\n")
	}
	if strings.TrimSpace(body) == "" {
		return line
	}
	body = reQuotedSegment.ReplaceAllString(body, `"<path>"`)
	body = reUserAtHost.ReplaceAllString(body, "<host>")
	body = reIPv4Addr.ReplaceAllString(body, "<host>")
	body = reAbsOrHomePath.ReplaceAllString(body, "${1}<path>")
	return body + suffix
}

// openHardenedBackupLogFile creates parent directories with 0700 permissions and opens/creates
// the local backup log file with strict 0600 permissions.
func openHardenedBackupLogFile(rawPath string) (*os.File, string, error) {
	expanded := expandLocalBasePath(rawPath)
	if strings.TrimSpace(expanded) == "" {
		return nil, "", fmt.Errorf("log file path cannot be empty")
	}
	dir := filepath.Dir(expanded)
	// #nosec G301 G703
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to create log directory: %w", err)
	}
	// #nosec G302 G703
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to harden log directory permissions to 0700: %w", err)
	}
	// #nosec G304 G703
	f, err := os.OpenFile(expanded, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open log file: %w", err)
	}
	// #nosec G302 G703
	if err := os.Chmod(expanded, 0600); err != nil {
		_ = f.Close()
		return nil, "", fmt.Errorf("failed to harden log file permissions to 0600: %w", err)
	}
	return f, expanded, nil
}

// rsyncStdoutStatsWriter consumes local rsync stdout.
// In normal mode (!verbose), zero raw lines are forwarded; instead, `--stats` transfer counters
// (compatible with both GNU rsync and macOS openrsync) are parsed in memory.
// In verbose mode, raw stdout is forwarded to dst.
type rsyncStdoutStatsWriter struct {
	mu                sync.Mutex
	dst               io.Writer
	verbose           bool
	buf               []byte
	transferredFiles  int
	totalFiles        int
	skippedNonRegular int
	tracker           *backupProgressTracker
}

func newRsyncStdoutStatsWriter(dst io.Writer, verbose bool, trackers ...*backupProgressTracker) *rsyncStdoutStatsWriter {
	var tr *backupProgressTracker
	if len(trackers) > 0 {
		tr = trackers[0]
	}
	return &rsyncStdoutStatsWriter{dst: dst, verbose: verbose, tracker: tr}
}

func (w *rsyncStdoutStatsWriter) parseStatsLine(line string) {
	if w.tracker != nil {
		w.tracker.RecordProgressLine(line)
	}
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "skipping non-regular file") {
		w.skippedNonRegular++
		return
	}
	if strings.HasPrefix(lower, "number of regular files transferred:") ||
		strings.HasPrefix(lower, "number of files transferred:") {
		if m := reStatsNumber.FindStringSubmatch(trimmed); len(m) == 2 {
			if n, err := strconv.Atoi(strings.ReplaceAll(m[1], ",", "")); err == nil {
				w.transferredFiles = n
			}
		}
	} else if strings.HasPrefix(lower, "number of files:") {
		if m := reStatsNumber.FindStringSubmatch(trimmed); len(m) == 2 {
			if n, err := strconv.Atoi(strings.ReplaceAll(m[1], ",", "")); err == nil {
				w.totalFiles = n
			}
		}
	}
}

func (w *rsyncStdoutStatsWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.verbose && w.dst != nil {
		if _, err := w.dst.Write(p); err != nil {
			return 0, err
		}
	}
	w.buf = append(w.buf, p...)
	for {
		idx := strings.IndexAny(string(w.buf), "\r\n")
		if idx == -1 {
			break
		}
		line := string(w.buf[:idx+1])
		w.buf = w.buf[idx+1:]
		w.parseStatsLine(line)
	}
	return len(p), nil
}

func (w *rsyncStdoutStatsWriter) Flush() (transferred int, total int, skippedNonRegular int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.parseStatsLine(string(w.buf))
		w.buf = nil
	}
	return w.transferredFiles, w.totalFiles, w.skippedNonRegular
}

const maxExclusionCandidates = 100

// backupExclusionReport summarizes permission/TCC/open errors observed on rsync stderr.
type backupExclusionReport struct {
	PermissionTCCCount int
	IOAccessCount      int
	Candidates         []string
}

// normalizeExclusionCandidatePath converts an absolute rsync sender/receiver path
// (such as "/home/user/work/sub/file" or "/Users/user/work/sub/file") into a path
// relative to the backup folder's transfer root ("sub/file") so `--exclude` suggestions
// match rsync's transfer-root-relative pattern semantics directly.
func normalizeExclusionCandidatePath(rawPath, localDir, folderSource string) string {
	p := strings.TrimSpace(strings.TrimPrefix(rawPath, "./"))
	if p == "" {
		return ""
	}
	if ld := strings.TrimRight(strings.TrimSpace(localDir), "/"); ld != "" {
		if strings.HasPrefix(p, ld+"/") {
			return strings.TrimPrefix(p, ld+"/")
		}
	}
	// For remote ssh-pull paths (e.g. "/home/<user>/work/sub/file" when folderSource is "work" or "~/work"),
	// strip up through the trailing folder source component.
	srcRel := strings.Trim(strings.TrimPrefix(strings.TrimSpace(folderSource), "~/"), "/")
	if srcRel != "" && srcRel != "~" && srcRel != "." && strings.HasPrefix(p, "/") {
		marker := "/" + srcRel + "/"
		if idx := strings.Index(p, marker); idx != -1 {
			if rel := strings.TrimLeft(p[idx+len(marker):], "/"); rel != "" {
				return rel
			}
		}
	}
	return p
}

func (r backupExclusionReport) TotalErrors() int {
	return r.PermissionTCCCount + r.IOAccessCount
}

// rsyncRedactingStderrWriter filters noisy informational "skipping non-regular file" lines
// emitted by rsync for symlinks/sockets, classifies exclusion-candidate errors (TCC/permission/open),
// and redacts paths/hosts on remaining error lines when not in Verbose mode.
type rsyncRedactingStderrWriter struct {
	mu                 sync.Mutex
	dst                io.Writer
	verbose            bool
	buf                []byte
	skippedNonRegular  int
	permissionTCCCount int
	ioAccessCount      int
	candidates         []string
	candidateSeen      map[string]bool
}

// rsyncStderrFilterWriter is kept as a type alias for backward compatibility with internal callers/tests.
type rsyncStderrFilterWriter = rsyncRedactingStderrWriter

func newRsyncStderrFilterWriter(dst io.Writer, verbose bool) *rsyncRedactingStderrWriter {
	return &rsyncRedactingStderrWriter{dst: dst, verbose: verbose}
}

func (w *rsyncRedactingStderrWriter) inspectExclusionCandidateLocked(line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}
	lower := strings.ToLower(trimmed)

	isPerm := strings.Contains(lower, "operation not permitted") ||
		strings.Contains(lower, "permission denied")
	isIO := strings.Contains(lower, "opendir ") && strings.Contains(lower, " failed") ||
		strings.Contains(lower, "send_files failed to open") ||
		strings.Contains(lower, "mkstemp ") && strings.Contains(lower, " failed") ||
		strings.Contains(lower, "cannot delete non-empty directory")

	if !isPerm && !isIO {
		return
	}
	if isPerm {
		w.permissionTCCCount++
	} else {
		w.ioAccessCount++
	}

	if len(w.candidates) >= maxExclusionCandidates {
		return
	}
	if match := reQuotedSegment.FindString(trimmed); match != "" {
		rawPath := strings.Trim(match, `"`)
		rawPath = strings.TrimPrefix(rawPath, "./")
		rawPath = strings.TrimSpace(rawPath)
		if rawPath != "" && rawPath != "." {
			if w.candidateSeen == nil {
				w.candidateSeen = make(map[string]bool)
			}
			if !w.candidateSeen[rawPath] {
				w.candidateSeen[rawPath] = true
				w.candidates = append(w.candidates, rawPath)
			}
		}
	}
}

func (w *rsyncRedactingStderrWriter) processLineLocked(line string) {
	if !w.verbose && strings.HasPrefix(strings.TrimSpace(line), "skipping non-regular file") {
		w.skippedNonRegular++
		return
	}
	w.inspectExclusionCandidateLocked(line)
	if w.dst != nil {
		if w.verbose {
			_, _ = io.WriteString(w.dst, line)
		} else {
			_, _ = io.WriteString(w.dst, redactBackupOutputLine(line))
		}
	}
}

func (w *rsyncRedactingStderrWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		idx := strings.IndexByte(string(w.buf), '\n')
		if idx == -1 {
			break
		}
		line := string(w.buf[:idx+1])
		w.buf = w.buf[idx+1:]
		w.processLineLocked(line)
	}
	return len(p), nil
}

func (w *rsyncRedactingStderrWriter) Flush() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		line := string(w.buf)
		w.buf = nil
		w.processLineLocked(line)
	}
	return w.skippedNonRegular
}

func (w *rsyncRedactingStderrWriter) FlushExclusionReport() backupExclusionReport {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		line := string(w.buf)
		w.buf = nil
		w.processLineLocked(line)
	}
	cands := make([]string, len(w.candidates))
	copy(cands, w.candidates)
	return backupExclusionReport{
		PermissionTCCCount: w.permissionTCCCount,
		IOAccessCount:      w.ioAccessCount,
		Candidates:         cands,
	}
}
