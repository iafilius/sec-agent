package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// Helper to set a generic password with ad-hoc safe permissions (BiometryAny - legacy/v1.0)
int set_secret(const char* service, const char* account, const unsigned char* secret, int secret_len) {
    CFStringRef cfService = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    CFStringRef cfAccount = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
    CFDataRef cfSecret = CFDataCreate(kCFAllocatorDefault, secret, secret_len);

    // First delete any existing item to avoid duplicate errors
    CFMutableDictionaryRef delQuery = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(delQuery, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(delQuery, kSecAttrService, cfService);
    CFDictionarySetValue(delQuery, kSecAttrAccount, cfAccount);
    SecItemDelete(delQuery);

    // Create adding query
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, cfService);
    CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
    CFDictionarySetValue(query, kSecValueData, cfSecret);

    CFErrorRef error = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryAny | kSecAccessControlUserPresence,
        &error
    );
    if (access != NULL) {
        CFDictionarySetValue(query, kSecAttrAccessControl, access);
        CFRelease(access);
    } else {
        CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
    }

    OSStatus status = SecItemAdd(query, NULL);
    if (status == errSecDuplicateItem) {
        CFMutableDictionaryRef updateAttr = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(updateAttr, kSecValueData, cfSecret);
        status = SecItemUpdate(delQuery, updateAttr);
        CFRelease(updateAttr);
    }

    CFRelease(delQuery);
    CFRelease(cfService);
    CFRelease(cfAccount);
    CFRelease(cfSecret);
    CFRelease(query);

    return (int)status;
}

// Helper to set a generic password protected by BiometryCurrentSet (Slot 0 / v2.0).
// The Secure Enclave invalidates this item if any fingerprint is added or removed.
int set_secret_current_set(const char* service, const char* account, const unsigned char* secret, int secret_len) {
    CFStringRef cfService = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    CFStringRef cfAccount = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
    CFDataRef cfSecret = CFDataCreate(kCFAllocatorDefault, secret, secret_len);

    // First delete any existing item to avoid duplicate errors
    CFMutableDictionaryRef delQuery = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(delQuery, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(delQuery, kSecAttrService, cfService);
    CFDictionarySetValue(delQuery, kSecAttrAccount, cfAccount);
    SecItemDelete(delQuery);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, cfService);
    CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
    CFDictionarySetValue(query, kSecValueData, cfSecret);

    CFErrorRef error = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryCurrentSet | kSecAccessControlUserPresence,
        &error
    );
    if (access != NULL) {
        CFDictionarySetValue(query, kSecAttrAccessControl, access);
        CFRelease(access);
    } else {
        // Fallback: at minimum require device unlock (should not happen on modern macOS)
        CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
    }

    OSStatus status = SecItemAdd(query, NULL);
    if (status == errSecDuplicateItem) {
        CFMutableDictionaryRef updateAttr = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(updateAttr, kSecValueData, cfSecret);
        status = SecItemUpdate(delQuery, updateAttr);
        CFRelease(updateAttr);
    }

    CFRelease(delQuery);
    CFRelease(cfService);
    CFRelease(cfAccount);
    CFRelease(cfSecret);
    CFRelease(query);

    return (int)status;
}


int get_secret(const char* service, const char* account, unsigned char** out_bytes, int* out_len) {
    CFStringRef cfService = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    CFStringRef cfAccount = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, cfService);
    CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    CFRelease(cfService);
    CFRelease(cfAccount);
    CFRelease(query);

    if (status == errSecSuccess && result != NULL) {
        CFDataRef data = (CFDataRef)result;
        CFIndex len = CFDataGetLength(data);
        *out_len = (int)len;
        *out_bytes = malloc(len);
        memcpy(*out_bytes, CFDataGetBytePtr(data), len);
        CFRelease(result);
    } else {
        *out_len = 0;
        *out_bytes = NULL;
    }

    return (int)status;
}

// Helper to delete a secret
int delete_secret(const char* service, const char* account) {
    CFStringRef cfService = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    CFStringRef cfAccount = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, cfService);
    CFDictionarySetValue(query, kSecAttrAccount, cfAccount);

    OSStatus status = SecItemDelete(query);

    CFRelease(cfService);
    CFRelease(cfAccount);
    CFRelease(query);

    return (int)status;
}

// Helper to list accounts under a specific service
int list_secrets(const char* service, char*** out_accounts, int* out_count) {
    CFStringRef cfService = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, cfService);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    CFRelease(cfService);
    CFRelease(query);

    if (status == errSecSuccess && result != NULL) {
        CFArrayRef array = (CFArrayRef)result;
        CFIndex count = CFArrayGetCount(array);
        *out_count = (int)count;
        *out_accounts = malloc(sizeof(char*) * count);

        for (CFIndex i = 0; i < count; i++) {
            CFDictionaryRef dict = (CFDictionaryRef)CFArrayGetValueAtIndex(array, i);
            CFStringRef account = (CFStringRef)CFDictionaryGetValue(dict, kSecAttrAccount);
            CFIndex length = CFStringGetLength(account);
            CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
            char* buffer = malloc(maxSize);
            if (CFStringGetCString(account, buffer, maxSize, kCFStringEncodingUTF8)) {
                (*out_accounts)[i] = buffer;
            } else {
                (*out_accounts)[i] = strdup("");
            }
        }
        CFRelease(result);
    } else {
        *out_count = 0;
        *out_accounts = NULL;
    }

    return (int)status;
}
*/
import "C"
import (
	"flag"
	"fmt"
	"os"
	"strings"
	"unsafe"
)

// Common OSStatus codes mapped to friendly error messages.
const (
	ErrSecSuccess      = 0
	ErrSecItemNotFound = -25300
	ErrSecAuthFailed   = -25293
	ErrSecUserCanceled = -128
)

func isTestEnvironment() bool {
	if os.Getenv("SEC_TEST_MODE") == "1" {
		return true
	}
	if flag.Lookup("test.v") != nil {
		return true
	}
	return false
}

func sanitizeServiceName(service string) string {
	if isTestEnvironment() && !strings.HasPrefix(service, "sec-test-") {
		if strings.HasPrefix(service, "sec-session") {
			return "sec-test-session" + service[len("sec-session"):]
		}
		return "sec-test-" + service
	}
	return service
}

// Set stores a secret protected by Touch ID/biometrics.
func Set(service, account string, secret []byte) error {
	service = sanitizeServiceName(service)
	cService := C.CString(service)
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))

	var secretPtr *C.uchar
	if len(secret) > 0 {
		secretPtr = (*C.uchar)(unsafe.Pointer(&secret[0]))
	}

	status := C.set_secret(cService, cAccount, secretPtr, C.int(len(secret)))
	if status != ErrSecSuccess {
		return fmt.Errorf("keychain set failed with OSStatus %d", status)
	}
	return nil
}

// Get retrieves a secret, triggering a hardware Touch ID validation.
func Get(service, account string) ([]byte, error) {
	service = sanitizeServiceName(service)
	cService := C.CString(service)
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))

	var outBytes *C.uchar
	var outLen C.int

	status := C.get_secret(cService, cAccount, &outBytes, &outLen)
	if status != ErrSecSuccess {
		if status == ErrSecItemNotFound {
			return nil, fmt.Errorf("secret not found in keychain")
		}
		if status == ErrSecUserCanceled || status == ErrSecAuthFailed {
			return nil, fmt.Errorf("biometric authentication failed or canceled")
		}
		return nil, fmt.Errorf("keychain get failed with OSStatus %d", status)
	}
	defer C.free(unsafe.Pointer(outBytes))

	data := C.GoBytes(unsafe.Pointer(outBytes), outLen)
	return data, nil
}

// Delete removes a secret from the keychain.
func Delete(service, account string) error {
	service = sanitizeServiceName(service)
	cService := C.CString(service)
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))

	status := C.delete_secret(cService, cAccount)
	if status != ErrSecSuccess && status != ErrSecItemNotFound {
		return fmt.Errorf("keychain delete failed with OSStatus %d", status)
	}
	return nil
}

// List returns a list of account names stored under a specific service.
func List(service string) ([]string, error) {
	service = sanitizeServiceName(service)
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))

	var outAccounts **C.char
	var outCount C.int

	status := C.list_secrets(cService, &outAccounts, &outCount)
	if status != ErrSecSuccess {
		if status == ErrSecItemNotFound {
			return nil, nil // No items exist
		}
		return nil, fmt.Errorf("keychain list failed with OSStatus %d", status)
	}

	count := int(outCount)
	accountsSlice := (*[1 << 30]*C.char)(unsafe.Pointer(outAccounts))[:count:count]
	defer C.free(unsafe.Pointer(outAccounts))

	accounts := make([]string, count)
	for i := 0; i < count; i++ {
		accounts[i] = C.GoString(accountsSlice[i])
		C.free(unsafe.Pointer(accountsSlice[i]))
	}

	return accounts, nil
}

// SetCurrentSet stores a secret protected by kSecAccessControlBiometryCurrentSet.
// Unlike Set (which uses BiometryAny), this item is invalidated by the Secure Enclave
// the moment any fingerprint is added or removed in macOS System Settings.
// This is the Slot 0 entry point for the v2.0 Dual-Slot architecture.
func SetCurrentSet(service, account string, secret []byte) error {
	service = sanitizeServiceName(service)
	cService := C.CString(service)
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))

	var secretPtr *C.uchar
	if len(secret) > 0 {
		secretPtr = (*C.uchar)(unsafe.Pointer(&secret[0]))
	}

	status := C.set_secret_current_set(cService, cAccount, secretPtr, C.int(len(secret)))
	if status != ErrSecSuccess {
		return fmt.Errorf("keychain SetCurrentSet failed with OSStatus %d", status)
	}
	return nil
}

// GetKeychainAccessPair returns a centralized getter/setter closure pair for a profile.
// This guarantees that all entrypoints (CLI, Web GUI, Daemon) query and save master keys
// under identical service names and access control rules (BiometryCurrentSet).
func GetKeychainAccessPair(profile string) (getter func() ([]byte, error), setter func([]byte) error) {
	svc := "sec-session"
	if os.Getenv("SEC_TEST_MODE") == "1" {
		svc = "sec-test-session"
	}
	if profile != "" && profile != "default" {
		if os.Getenv("SEC_TEST_MODE") == "1" {
			svc = "sec-test-session:profile_" + profile
		} else {
			svc = "sec-session:profile_" + profile
		}
	}
	acc := "master"

	getter = func() ([]byte, error) {
		return Get(svc, acc)
	}
	setter = func(k []byte) error {
		return Set(svc, acc, k)
	}
	return getter, setter
}

