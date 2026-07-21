package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// Helper to set a generic password with ad-hoc safe permissions
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
    CFRelease(delQuery);

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

    CFRelease(cfService);
    CFRelease(cfAccount);
    CFRelease(cfSecret);
    CFRelease(query);

    return (int)status;
}

// Helper to retrieve a generic password
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
	"fmt"
	"unsafe"
)

// Common OSStatus codes mapped to friendly error messages.
const (
	ErrSecSuccess      = 0
	ErrSecItemNotFound = -25300
	ErrSecAuthFailed   = -25293
	ErrSecUserCanceled = -128
)

// Set stores a secret protected by Touch ID/biometrics.
func Set(service, account string, secret []byte) error {
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
