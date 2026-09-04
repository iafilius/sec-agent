package store

import (
	"errors"
)

// Domain sentinel errors for store operations.
var (
	ErrSecretNotFound     = errors.New("secret not found")
	ErrVaultLocked        = errors.New("vault session is locked")
	ErrMasterKeyMismatch  = errors.New("master key mismatch")
	ErrProfileNotFound    = errors.New("profile not found")
	ErrStoreUninitialized = errors.New("store is uninitialized")
	ErrPathEmpty          = errors.New("path cannot be empty")
	ErrSecretNotDeleted   = errors.New("secret is not deleted")
)

// ErrorCode represents a strongly-typed API error code for IPC and REST payloads.
type ErrorCode string

// #nosec G101
const (
	ErrCodeSecretNotFound   ErrorCode = "ERR_SECRET_NOT_FOUND"
	ErrCodeVaultLocked      ErrorCode = "ERR_VAULT_LOCKED"
	ErrCodeMasterKeyMismatch ErrorCode = "ERR_MASTER_KEY_MISMATCH"
	ErrCodeProfileNotFound  ErrorCode = "ERR_PROFILE_NOT_FOUND"
	ErrCodeInvalidToken     ErrorCode = "ERR_INVALID_TOKEN"
	ErrCodeAccessDenied     ErrorCode = "ERR_ACCESS_DENIED"
	ErrCodeInternalError    ErrorCode = "ERR_INTERNAL_ERROR"
)

// ToErrorCode maps a Go domain error to its corresponding ErrorCode string.
func ToErrorCode(err error) ErrorCode {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrSecretNotFound):
		return ErrCodeSecretNotFound
	case errors.Is(err, ErrVaultLocked):
		return ErrCodeVaultLocked
	case errors.Is(err, ErrMasterKeyMismatch):
		return ErrCodeMasterKeyMismatch
	case errors.Is(err, ErrProfileNotFound):
		return ErrCodeProfileNotFound
	default:
		return ErrCodeInternalError
	}
}
