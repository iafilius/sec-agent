package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"secure_secrets/internal/store"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// getPeerPID returns the Unix socket client PID.
func getPeerPID(conn *net.UnixConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var peerPID int
	var sysErr error
	err = rawConn.Control(func(fd uintptr) {
		peerPID, sysErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil {
		return 0, err
	}
	if sysErr != nil {
		return 0, sysErr
	}
	return peerPID, nil
}

// isHijacked checks if the client connection is running via SSH or active screen sharing.
// It returns the matched signal as a reason string for audit logging, or "" when not hijacked.
// remotepairingd is intentionally excluded: it's Apple's Continuity/RemotePairing daemon and
// runs persistently on most Macs regardless of any active remote-control session.
func (d *Daemon) isHijacked(peerPID int) (bool, string) {
	sharingServices := []string{"screensharingd", "AppleVNCServer"}
	for _, svc := range sharingServices {
		// #nosec G204
		cmd := exec.Command("pgrep", svc)
		if err := cmd.Run(); err == nil {
			return true, fmt.Sprintf("process_match:%s", svc)
		}
	}

	// #nosec G204
	envOut, err := exec.Command("ps", "e", "-ww", "-p", strconv.Itoa(peerPID)).Output()
	if err == nil {
		envStr := string(envOut)
		for _, sshVar := range []string{"SSH_CLIENT=", "SSH_TTY=", "SSH_CONNECTION="} {
			if strings.Contains(envStr, sshVar) {
				return true, fmt.Sprintf("ssh_env:%s pid=%d", strings.TrimSuffix(sshVar, "="), peerPID)
			}
		}
	}

	currentPID := peerPID
	for currentPID > 1 {
		// #nosec G204
		out, err := exec.Command("ps", "-o", "ppid=,comm=", "-p", strconv.Itoa(currentPID)).Output()
		if err != nil {
			break
		}

		parts := strings.Fields(string(out))
		if len(parts) < 2 {
			break
		}

		ppidVal, err := strconv.Atoi(parts[0])
		if err != nil {
			break
		}

		comm := parts[1]
		if strings.Contains(strings.ToLower(comm), "sshd") {
			return true, fmt.Sprintf("ssh_ancestry:%s pid=%d", comm, currentPID)
		}

		currentPID = ppidVal
	}

	return false, ""
}

func (d *Daemon) sendError(c net.Conn, msg string) {
	resp := IPCResponse{
		Success: false,
		Error:   msg,
	}
	_ = json.NewEncoder(c).Encode(resp)
}

func (d *Daemon) sendErrorCode(c net.Conn, msg string, code store.ErrorCode) {
	resp := IPCResponse{
		Success:   false,
		Error:     msg,
		ErrorCode: code,
	}
	_ = json.NewEncoder(c).Encode(resp)
}

func (d *Daemon) handleConnection(c net.Conn) {
	defer c.Close()

	unixConn, ok := c.(*net.UnixConn)
	if !ok {
		return
	}

	peerPID, err := getPeerPID(unixConn)
	if err != nil {
		d.sendError(c, fmt.Sprintf("failed to resolve peer PID: %v", err))
		return
	}

	if hijacked, reason := d.isHijacked(peerPID); hijacked {
		d.mu.Lock()
		d.wipeMemory()
		d.mu.Unlock()
		d.logAudit(AuditEventHijack, "", peerPID, false, reason)
		d.sendError(c, "ACCESS DENIED: Remote session hijacking or screen sharing detected.")
		return
	}

	decoder := json.NewDecoder(c)
	var req IPCRequest
	if err := decoder.Decode(&req); err != nil {
		if err != io.EOF {
			d.sendError(c, "invalid request encoding")
		}
		return
	}

	if err := req.Validate(); err != nil {
		d.sendError(c, err.Error())
		return
	}

	d.processRequest(c, req, peerPID)
}
