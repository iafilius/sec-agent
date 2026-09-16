package biometrics

import (
	"testing"
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
			version:  "v2.13.1",
			action:   "open",
			profile:  "default",
			expected: "sec-agent v2.13.1: Unlock vault for profile 'default'",
		},
		{
			name:     "open custom profile",
			version:  "v2.13.1",
			action:   "unlock",
			profile:  "production",
			expected: "sec-agent v2.13.1: Unlock vault for profile 'production'",
		},
		{
			name:     "switch profile",
			version:  "v2.13.1",
			action:   "switch",
			profile:  "work",
			expected: "sec-agent v2.13.1: Switch to profile 'work'",
		},
		{
			name:     "gui unlock",
			version:  "v2.13.1",
			action:   "gui",
			profile:  "default",
			expected: "sec-agent v2.13.1: Unlock vault for Web GUI (profile: 'default')",
		},
		{
			name:     "create profile",
			version:  "v2.13.1",
			action:   "create_profile",
			profile:  "dev",
			expected: "sec-agent v2.13.1: Authorize creation of profile 'dev'",
		},
		{
			name:     "migrate v2",
			version:  "v2.13.1",
			action:   "migrate_v2",
			profile:  "",
			expected: "sec-agent v2.13.1: Authorize v2.0 vault migration",
		},
		{
			name:     "empty version defaults safely",
			version:  "",
			action:   "open",
			profile:  "",
			expected: "sec-agent v2.13.1: Unlock vault for profile 'default'",
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
