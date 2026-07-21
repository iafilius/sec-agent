package daemon

import "secure_secrets/store"

// SetMasterKeyForTest is a test helper to inject the master key programmatically.
func (d *Daemon) SetMasterKeyForTest(key []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.masterKey = key
}

// SetSecretsForTest is a test helper to inject test secrets programmatically.
func (d *Daemon) SetSecretsForTest(secrets map[string]store.SecretEntry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.secretsStore == nil {
		d.secretsStore = &store.EncryptedStore{Secrets: make(map[string]store.SecretEntry)}
	}
	d.secretsStore.Secrets = secrets
}

// SetSessionTokenForTest injects a test session token.
func (d *Daemon) SetSessionTokenForTest(token string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessionToken = token
}

// GetSessionTokenForTest gets the active session token.
func (d *Daemon) GetSessionTokenForTest() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessionToken
}
