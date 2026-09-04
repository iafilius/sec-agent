package audit

import "regexp"

// NamedPattern represents a labeled regex signature for known secret types.
type NamedPattern struct {
	Name  string
	Regex *regexp.Regexp
}

// DefaultSecretPatterns provides standard regex patterns for known cloud and API secrets.
var DefaultSecretPatterns = []NamedPattern{
	{Name: "AWS Access Key ID", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Name: "GitHub Personal Access Token", Regex: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`)},
	{Name: "Stripe Live Secret Key", Regex: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)},
	{Name: "Slack Webhook URL / Token", Regex: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+|xox[baprs]-[0-9a-zA-Z]{10,48}`)},
	{Name: "Database Connection URI", Regex: regexp.MustCompile(`(postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+`)},
	{Name: "Private Key Header", Regex: regexp.MustCompile(`-----BEGIN (?:RSA|EC|OPENSSH|DSA) PRIVATE KEY-----`)},
}
