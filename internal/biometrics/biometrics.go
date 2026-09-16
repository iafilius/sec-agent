package biometrics

/*
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation -framework AppKit
#include <stdlib.h>

// Forward declarations of helper functions defined in biometrics.m
int authenticate_biometrics(const char* reason);
int play_biometric_sound(void);
*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"
)

// PlayAlertSound triggers the native macOS Pop chime asynchronously.
// Returns true if played, false if suppressed by SEC_NO_SOUND or SEC_TEST_MODE.
func PlayAlertSound() bool {
	return int(C.play_biometric_sound()) == 1
}

// FormatReason builds a standardized, action-focused versioned biometric prompt string.
func FormatReason(version, action, profile string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		v = "v2.13.2"
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

// Authenticate prompts the user for Touch ID or password fallback.
// Returns true if successful, false otherwise.
func Authenticate(reason string) bool {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	res := C.authenticate_biometrics(cReason)
	return int(res) == 1
}
