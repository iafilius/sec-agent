package biometrics

/*
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <stdlib.h>

// Forward declaration of our helper function defined in biometrics.m
int authenticate_biometrics(const char* reason);
*/
import "C"
import (
	"unsafe"
)

// Authenticate prompts the user for Touch ID or password fallback.
// Returns true if successful, false otherwise.
func Authenticate(reason string) bool {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	res := C.authenticate_biometrics(cReason)
	return int(res) == 1
}
