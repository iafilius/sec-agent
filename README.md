# sec-agent: Enclave-Bound Session Agent for Developer Secrets

`sec` is a fully local, offline-first credentials manager designed to protect local developer secrets (such as API keys, database credentials, and tokens) from session takeover vectors (e.g. hijacked terminal sessions, remote SSH attackers, or administrative screen monitoring). 

It functions exactly like `ssh-agent` or `gpg-agent` but is tailored specifically for application environment variables and configuration files.

---

## 🔒 Security Architecture

`sec` is built on a **secure-by-design** model:

```
                    [ ATTACKER IN SSH SESSION ]
                                 │
                        Queries Secret Store
                                 │
                                 ▼
               [ OS-LEVEL HARDWARE CRYPTO INTERCEPT ]
                                 │
                ┌─────────────────┴─────────────────┐
                ▼ (Remote/Hijacked Connection)      ▼ (Physical Console)
          [ Bypass Blocked ]                 [ Touch ID / PIN Prompt ]
                │                                   │
                ▼                                   ▼
           [ ACCESS DENIED ]                   [ ACCESS GRANTED ]
```

*   **Touch ID Physical Presence validation**: Encryption master keys are stored inside the macOS Secure Enclave (`SecAccessControl`). Decrypting them requires hardware-backed physical user presence contact with the Touch ID sensor, blocking remote attackers.
*   **Cryptographic Session Isolation**: Sourcing `sec open` generates a temporary random hex token in the shell context (`SEC_SESSION_TOKEN`). The background socket daemon enforces this token on all queries, preventing separate terminal processes or hijacked browsers from querying your secrets.
*   **Active Hijack Detection**: The daemon walks up the process tree on every connection. If it detects an active SSH session ancestry (`SSH_CLIENT`/`SSH_TTY`) or active screen-sharing (`screensharingd`), it immediately locks the database, flushes all keys from memory, and locks itself.
*   **Hardened Runtime Isolation**: The daemon executes under macOS Hardened Runtime protections with no debugging entitlements. System Integrity Protection (SIP) blocks standard user-space debuggers and memory readers (even root UID 0) from inspecting its memory.
*   **Offline First**: No cloud synchronization, no third-party APIs, and zero SaaS dependency.

---

## ⚙️ Installation & Build

Compile and sign the binary using the macOS Hardened Runtime:

```bash
# Build and codesign the binary
make build codesign

# Run security static analysis checks (vet, vulncheck, gosec)
make sec-check

# Run tests
make test
```

---

## 🚀 Quickstart Guide

### 1. Authorize / Start Daemon
Initialize the background daemon and unlock the Secure Enclave session.
```bash
eval $(sec open)
# Prompt: Touch ID request to authorize keychain access
```

### 2. Store and Retrieve Secrets
```bash
# Store a secret
sec set app-secrets/db-pass "my-super-secret-password"

# Retrieve a secret
sec get app-secrets/db-pass
# Output: my-super-secret-password
```

### 3. Run Applications (Frictionless Injection)
Instead of sourcing `.env` files, execute commands directly in a wrapped environment. `sec` automatically translates paths like `app-secrets/db-pass` to uppercase environment variables (`APP_SECRETS_DB_PASS`):
```bash
sec run -- go test -v ./...
# Executes test process with APP_SECRETS_DB_PASS available in memory
```

### 4. Lock Session
Wipe decrypted credentials from system memory and lock the daemon:
```bash
sec lock
# Session locked. Memory cache cleared.
```

---

## 🧹 Local Dotenv Migration

To clean up plaintext credentials in local folders, `sec migrate-local` automatically scans a dotenv file, securely stores all keys inside the enclave daemon, and replaces raw values with safe placeholders:

```bash
sec migrate-local .env --prefix app-secrets --profile my-project
```

#### Sanitized `.env` file output:
```ini
# Migrated to sec. Run your commands using: sec run --profile my-project -- <command>
DATABASE_PASSWORD="<migrated_to_sec>"
STRIPE_KEY="<migrated_to_sec>"
```
*Note: Since standard dotenv libraries do not override existing process variables, running your app via `sec run -- <app>` automatically overrides these placeholders in memory with the actual secrets, requiring **zero codebase modifications**.*

---

## 🚀 Compatibility & Exporters (Zero Platform Lock-In)

Your database contents belong to you. `sec` supports multiple export formats matching target secret vaults:

*   **Doppler JSON Map**: Dumps flat key-value configurations ready to upload:
    ```bash
    sec export --format doppler | doppler secrets upload
    ```
*   **AWS Secrets Manager Payload**: Dumps batch secret payloads:
    ```bash
    sec export --format aws
    ```
*   **KeePassXC Backup**: Exports the active session database to a standard encrypted `.kdbx` file:
    ```bash
    sec backup my_backup.kdbx
    ```
    You can restore it later via:
    ```bash
    sec restore my_backup.kdbx
    ```
