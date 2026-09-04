package store

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Common validation errors for domain primitives.
var (
	ErrEmptySecretKey   = errors.New("secret key cannot be empty")
	ErrInvalidSecretKey = errors.New("secret key contains invalid control characters")
	ErrEmptyProfileName = errors.New("profile name cannot be empty")
	ErrInvalidProfile   = errors.New("profile name contains invalid characters")
	ErrEmptyLeaseID     = errors.New("lease ID cannot be empty")
	ErrInvalidScope     = errors.New("invalid secret scope (must be 'global' or 'workspace')")
)

// SecretScope represents the scope of secret storage.
type SecretScope string

const (
	ScopeGlobal    SecretScope = "global"
	ScopeWorkspace SecretScope = "workspace"
)

// String returns the string representation of SecretScope.
func (s SecretScope) String() string {
	return string(s)
}

// Validate checks whether the SecretScope is valid.
func (s SecretScope) Validate() error {
	switch strings.ToLower(string(s)) {
	case string(ScopeGlobal), string(ScopeWorkspace), "":
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrInvalidScope, string(s))
	}
}

// SecretKey represents a strongly-typed secret identifier.
type SecretKey string

// NewSecretKey creates and validates a new SecretKey.
func NewSecretKey(key string) (SecretKey, error) {
	sk := SecretKey(strings.TrimSpace(key))
	if err := sk.Validate(); err != nil {
		return "", err
	}
	return sk, nil
}

// String returns the underlying string value of SecretKey.
func (k SecretKey) String() string {
	return string(k)
}

// Validate checks whether the SecretKey satisfies domain constraints.
func (k SecretKey) Validate() error {
	s := string(k)
	if strings.TrimSpace(s) == "" {
		return ErrEmptySecretKey
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return ErrInvalidSecretKey
		}
	}
	return nil
}

// ProfileName represents a strongly-typed profile identifier.
type ProfileName string

// NewProfileName creates and validates a new ProfileName.
func NewProfileName(name string) (ProfileName, error) {
	pn := ProfileName(name)
	if err := pn.Validate(); err != nil {
		return "", err
	}
	return ProfileName(strings.TrimSpace(name)), nil
}

// String returns the underlying string value of ProfileName.
func (p ProfileName) String() string {
	return string(p)
}

// Validate checks whether the ProfileName satisfies domain constraints.
func (p ProfileName) Validate() error {
	s := string(p)
	if strings.TrimSpace(s) == "" {
		return ErrEmptyProfileName
	}
	if strings.Contains(s, "/") || strings.Contains(s, "\\") || strings.Contains(s, "..") {
		return fmt.Errorf("%w: profile name cannot contain path separators or relative path components ('..')", ErrInvalidProfile)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ErrInvalidProfile
		}
	}
	return nil
}

// LeaseID represents a strongly-typed lease identifier.
type LeaseID string

// NewLeaseID creates and validates a new LeaseID.
func NewLeaseID(id string) (LeaseID, error) {
	lid := LeaseID(strings.TrimSpace(id))
	if err := lid.Validate(); err != nil {
		return "", err
	}
	return lid, nil
}

// String returns the underlying string value of LeaseID.
func (l LeaseID) String() string {
	return string(l)
}

// Validate checks whether the LeaseID satisfies domain constraints.
func (l LeaseID) Validate() error {
	if strings.TrimSpace(string(l)) == "" {
		return ErrEmptyLeaseID
	}
	return nil
}
