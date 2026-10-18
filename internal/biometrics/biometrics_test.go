package biometrics

import (
	"testing"
	"time"
)

func TestFormatReason(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		action   string
		profile  string
		expected string
	}{
		{
			name:     "open default profile",
			version:  "v2.14.2",
			action:   "open",
			profile:  "default",
			expected: "sec-agent v2.14.2: Unlock vault for profile 'default'",
		},
		{
			name:     "open custom profile",
			version:  "v2.14.2",
			action:   "unlock",
			profile:  "production",
			expected: "sec-agent v2.14.2: Unlock vault for profile 'production'",
		},
		{
			name:     "switch profile",
			version:  "v2.14.2",
			action:   "switch",
			profile:  "work",
			expected: "sec-agent v2.14.2: Switch to profile 'work'",
		},
		{
			name:     "gui unlock",
			version:  "v2.14.2",
			action:   "gui",
			profile:  "default",
			expected: "sec-agent v2.14.2: Unlock vault for Web GUI (profile: 'default')",
		},
		{
			name:     "create profile",
			version:  "v2.14.2",
			action:   "create_profile",
			profile:  "dev",
			expected: "sec-agent v2.14.2: Authorize creation of profile 'dev'",
		},
		{
			name:     "migrate v2",
			version:  "v2.14.2",
			action:   "migrate_v2",
			profile:  "",
			expected: "sec-agent v2.14.2: Authorize v2.0 vault migration",
		},
		{
			name:     "empty version defaults safely",
			version:  "",
			action:   "open",
			profile:  "",
			expected: "sec-agent v2.14.2: Unlock vault for profile 'default'",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatReason(tc.version, tc.action, tc.profile)
			if got != tc.expected {
				t.Errorf("FormatReason(%q, %q, %q) = %q, expected %q", tc.version, tc.action, tc.profile, got, tc.expected)
			}
		})
	}
}

func TestPlayAlertSound(t *testing.T) {
	// Test suppression under SEC_TEST_MODE=1
	t.Setenv("SEC_TEST_MODE", "1")
	t.Setenv("SEC_NO_SOUND", "")
	if PlayAlertSound() {
		t.Errorf("expected PlayAlertSound to return false under SEC_TEST_MODE=1")
	}

	// Test suppression under SEC_NO_SOUND=1
	t.Setenv("SEC_TEST_MODE", "")
	t.Setenv("SEC_NO_SOUND", "1")
	if PlayAlertSound() {
		t.Errorf("expected PlayAlertSound to return false under SEC_NO_SOUND=1")
	}

	// Test execution when unsuppressed
	t.Setenv("SEC_TEST_MODE", "")
	t.Setenv("SEC_NO_SOUND", "")
	if !PlayAlertSound() {
		t.Errorf("expected PlayAlertSound to return true when unsuppressed")
	}
}

func TestAuthResultExitCodesAndString(t *testing.T) {
	cases := []struct {
		res      AuthResult
		exitCode int
		contains string
	}{
		{AuthSuccess, 0, "success"},
		{ErrUserCanceled, 1, "canceled"},
		{ErrUnavailable, 2, "unavailable"},
		{ErrTimeout, 4, "timed out"},
		{ErrLockout, 5, "locked out"},
		{ErrAuthFailed, 6, "failed"},
	}

	for _, c := range cases {
		if c.res.ExitCode() != c.exitCode {
			t.Errorf("expected %v.ExitCode() == %d, got %d", c.res, c.exitCode, c.res.ExitCode())
		}
		if len(c.res.String()) == 0 {
			t.Errorf("expected non-empty String() for %v", c.res)
		}
	}
}

func TestAuthenticateWithTimeoutAndHooks(t *testing.T) {
	// When SEC_TEST_MODE=1, should return AuthSuccess
	t.Setenv("SEC_TEST_MODE", "1")
	if res := AuthenticateWithTimeout("test reason", 5*time.Second); res != AuthSuccess {
		t.Errorf("expected AuthSuccess under SEC_TEST_MODE=1, got %v", res)
	}

	// Test custom auth hook
	t.Setenv("SEC_TEST_MODE", "")
	defer SetAuthHook(nil)

	SetAuthHook(func(reason string, timeout time.Duration) (AuthResult, bool) {
		if timeout == 42*time.Second {
			return ErrTimeout, true
		}
		return ErrLockout, true
	})

	if res := AuthenticateWithTimeout("hook test", 42*time.Second); res != ErrTimeout {
		t.Errorf("expected ErrTimeout from hook, got %v", res)
	}
	if res := AuthenticateWithTimeout("hook test", 10*time.Second); res != ErrLockout {
		t.Errorf("expected ErrLockout from hook, got %v", res)
	}
}

func TestShowDesktopNotification(t *testing.T) {
	t.Setenv("SEC_TEST_MODE", "1")
	// Should not crash or hang
	ShowDesktopNotification("sec-agent test", "test message")
}
