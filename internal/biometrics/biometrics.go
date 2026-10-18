package biometrics

/*
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation -framework AppKit
#include <stdlib.h>

// Forward declarations of helper functions defined in biometrics.m
int authenticate_biometrics(const char* reason, double timeoutSeconds);
int play_biometric_sound(void);
*/
import "C"
import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"
)

// AuthResult represents the outcome of a biometric authentication attempt.
type AuthResult int

const (
	// AuthSuccess indicates the user successfully authorized via biometrics or OS passcode.
	AuthSuccess AuthResult = 0
	// ErrUserCanceled indicates the operator explicitly clicked Cancel or pressed Escape.
	ErrUserCanceled AuthResult = 1
	// ErrUnavailable indicates biometric authentication is not enrolled, supported, or available.
	ErrUnavailable AuthResult = 2
	// ErrTimeout indicates the prompt timed out before the operator interacted with the sensor.
	ErrTimeout AuthResult = 4
	// ErrLockout indicates macOS locked biometrics due to excessive failures, requiring password login.
	ErrLockout AuthResult = 5
	// ErrAuthFailed indicates the biometric sensor rejected the presented finger without successful match.
	ErrAuthFailed AuthResult = 6
)

// ExitCode maps the AuthResult directly to standard process exit codes.
func (r AuthResult) ExitCode() int {
	return int(r)
}

func (r AuthResult) String() string {
	switch r {
	case AuthSuccess:
		return "success"
	case ErrUserCanceled:
		return "canceled by user"
	case ErrUnavailable:
		return "biometrics unavailable"
	case ErrTimeout:
		return "biometric prompt timed out (operator away)"
	case ErrLockout:
		return "biometrics locked out (password required)"
	case ErrAuthFailed:
		return "biometric verification failed"
	default:
		return fmt.Sprintf("unknown biometric error (%d)", int(r))
	}
}

// Hook for mocking in unit tests
var authHook func(reason string, timeout time.Duration) (AuthResult, bool)

// SetAuthHook registers a mock hook for tests. Pass nil to restore native evaluation.
func SetAuthHook(hook func(reason string, timeout time.Duration) (AuthResult, bool)) {
	authHook = hook
}

// PlayAlertSound triggers the native macOS Pop chime asynchronously.
// Returns true if played, false if suppressed by SEC_NO_SOUND or SEC_TEST_MODE.
func PlayAlertSound() bool {
	return int(C.play_biometric_sound()) == 1
}

// ShowDesktopNotification posts an asynchronous desktop notification banner on macOS.
func ShowDesktopNotification(title, message string) {
	if os.Getenv("SEC_NO_SOUND") == "1" || os.Getenv("SEC_TEST_MODE") == "1" {
		return
	}
	go func() {
		// Escape quotes for AppleScript string literal
		cleanTitle := strings.ReplaceAll(title, `"`, `\"`)
		cleanMsg := strings.ReplaceAll(message, `"`, `\"`)
		script := fmt.Sprintf(`display notification "%s" with title "%s"`, cleanMsg, cleanTitle)
		// #nosec G204
		cmd := exec.Command("osascript", "-e", script)
		_ = cmd.Run()
	}()
}

// FormatReason builds a standardized, action-focused versioned biometric prompt string.
func FormatReason(version, action, profile string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		v = "v2.14.2"
	}
	p := strings.TrimSpace(profile)
	if p == "" {
		p = "default"
	}
	switch action {
	case "open", "unlock":
		return fmt.Sprintf("sec-agent %s: Unlock vault for profile '%s'", v, p)
	case "switch":
		return fmt.Sprintf("sec-agent %s: Switch to profile '%s'", v, p)
	case "gui":
		return fmt.Sprintf("sec-agent %s: Unlock vault for Web GUI (profile: '%s')", v, p)
	case "create_profile":
		return fmt.Sprintf("sec-agent %s: Authorize creation of profile '%s'", v, p)
	case "migrate_v2":
		return fmt.Sprintf("sec-agent %s: Authorize v2.0 vault migration", v)
	default:
		if p != "" && p != "default" {
			return fmt.Sprintf("sec-agent %s: %s (profile: '%s')", v, action, p)
		}
		return fmt.Sprintf("sec-agent %s: %s", v, action)
	}
}

// AuthenticateWithTimeout prompts the user for Touch ID or password fallback with a specified timeout.
func AuthenticateWithTimeout(reason string, timeout time.Duration) AuthResult {
	if authHook != nil {
		if res, handled := authHook(reason, timeout); handled {
			return res
		}
	}

	if val := os.Getenv("SEC_TEST_BIOMETRICS_RESULT"); val != "" {
		switch strings.ToLower(val) {
		case "timeout":
			return ErrTimeout
		case "cancel", "canceled":
			return ErrUserCanceled
		case "lockout":
			return ErrLockout
		case "failed":
			return ErrAuthFailed
		case "unavailable":
			return ErrUnavailable
		case "success":
			return AuthSuccess
		}
	}

	if os.Getenv("SEC_TEST_MODE") == "1" {
		return AuthSuccess
	}

	timeoutSec := timeout.Seconds()
	if timeoutSec <= 0 {
		timeoutSec = 120.0
	}

	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	res := C.authenticate_biometrics(cReason, C.double(timeoutSec))
	return AuthResult(res)
}

// Authenticate prompts the user for Touch ID with the default 120-second timeout.
// Returns true on success, false otherwise (for backwards compatibility).
func Authenticate(reason string) bool {
	return AuthenticateWithTimeout(reason, 120*time.Second) == AuthSuccess
}
