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

// isHijacked checks if the client connection is running via SSH or Screensharing is active.
func (d *Daemon) isHijacked(peerPID int) bool {
	sharingServices := []string{"screensharingd", "AppleVNCServer", "remotepairingd"}
	for _, svc := range sharingServices {
		// #nosec G204
		cmd := exec.Command("pgrep", svc)
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	// #nosec G204
	envOut, err := exec.Command("ps", "e", "-ww", "-p", strconv.Itoa(peerPID)).Output()
	if err == nil {
		envStr := string(envOut)
		if strings.Contains(envStr, "SSH_CLIENT=") ||
			strings.Contains(envStr, "SSH_TTY=") ||
			strings.Contains(envStr, "SSH_CONNECTION=") {
			return true
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
			return true
		}

		currentPID = ppidVal
	}

	return false
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

	if d.isHijacked(peerPID) {
		d.mu.Lock()
		d.wipeMemory()
		d.mu.Unlock()
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
