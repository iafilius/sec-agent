# sec-agent: Enclave-Bound Session Agent for Developer Secrets

[![Platform: macOS Only](https://img.shields.io/badge/Platform-macOS%20Only-blue.svg?style=flat-square&logo=apple)](https://www.apple.com/macos/)
[![Security: Hardware Enclave](https://img.shields.io/badge/Security-Secure%20Enclave-red.svg?style=flat-square)](https://developer.apple.com/documentation/security)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

`sec` is a fully local, offline-first credentials manager designed to protect local developer secrets (such as API keys, database credentials, and cloud tokens) from session takeover vectors (e.g. hijacked terminal sessions, remote SSH shell attackers, or administrative screen monitoring).

It functions similarly to `ssh-agent` or `gpg-agent`, but is engineered specifically for secure secret, variable, and key-value retrieval—completely eliminating the need for plaintext passwords or stored credentials on disk, even across local development environments.

> [!WARNING]
> **macOS Exclusivity**: This tool utilizes macOS-specific APIs, including LocalAuthentication (Touch ID/Apple Watch hardware prompts), Keychain Services (Secure Enclave master key storage), and macOS Hardened Runtime memory protections. It is not compatible with Windows or Linux.

---

## ⚠️ The Problem: Plaintext Dotenv Proliferation

In modern software development, hardcoding credentials in local `.env` files is incredibly common. What starts as a "temporary PoC or pre-prod password" often:
1.  **Accumulates over the years** across multiple project folders.
2.  **Leaks into shell history** log files (`.zsh_history`, `.bash_history`).
3.  **Gets committed accidentally** to public or private Git repositories.
4.  **Remains completely unencrypted**, leaving credentials accessible to any local process or remote SSH connection active on your machine.

---

## 🔒 Security Architecture

`sec` is built on a **secure-by-design** model to prevent credential leakage:

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

*   **Touch ID Physical Presence Gate**: Master encryption keys are stored inside the macOS Secure Enclave (`SecAccessControl`). Decrypting them requires hardware-backed physical user validation (Touch ID contact or Apple Watch click), instantly blocking remote attackers.
*   **Cryptographic Session Isolation**: Initializing `sec open` generates a temporary random session token in the active shell context (`SEC_SESSION_TOKEN`). The background socket daemon enforces this token on all queries, preventing separate terminal processes or browser processes from querying your secrets.
*   **Multi-Layer Session Hijacking Intercepts**: On every query request, the daemon walks the caller's process tree to block `sshd` shell parents. In addition, it inspects the client process's active environment variables using BSD `ps e -ww -p <PID>` to detect remote shell variables (`SSH_CLIENT`, `SSH_TTY`, `SSH_CONNECTION`). It also checks for active VNC graphical sharing (`AppleVNCServer`), Xcode remote debugging (`remotepairingd`), and native sharing (`screensharingd`). If detected, the daemon locks itself and wipes all memory cache keys instantly.
*   **Disaster-Proof Write Transactions**: All filesystem mutations (database saves, dotenv migrations, KeePassXC exports) utilize atomic sibling renames. The payload is written to a temporary file, flushed to storage blocks via `fsync()`, and atomically replaced. Profile-isolated backups of the last 10 database snapshots are rotated automatically under `~/.config/sec/backups/<profile>/`.
*   **Hardened Runtime Isolation**: The daemon executes under macOS Hardened Runtime protections with no debugging entitlements. System Integrity Protection (SIP) blocks standard user-space debuggers and memory readers (including root UID 0) from inspecting its memory.
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

---

## 🔍 Diagnostics Version Checks
The `sec version` command allows you to inspect compiled VCS commit history, build timestamps, and Go modules dependencies, and queries the background daemon to warn you if a client-daemon version mismatch exists:
```bash
sec version
```

---

## 📊 Tool Comparison Matrix (sec-agent vs. Enterprise Solutions)

| Feature | `sec-agent` | Delinea (Secret Server / DSV) | HashiCorp Vault | Doppler / Infisical | SOPS (Mozilla) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Focus** | Local macOS Developer Session & Workstation Security | Enterprise Privileged Access Management (PAM) | Enterprise / Production Infrastructure Vault | Cloud Team Secret Synchronization | GitOps Repository File Encryption |
| **Deployment Model** | **100% Offline** (Zero SaaS / Zero Server) | Enterprise Cloud SaaS or On-Prem IIS/SQL | Self-Hosted Cluster or Cloud SaaS | Cloud SaaS Platform | Local CLI (Key Server optional) |
| **Master Key Protection** | **macOS Secure Enclave** | Enterprise Tenant / Cloud Vault | Server Master Key / AppRole | Cloud Account Token | Local GPG / Age Key File |
| **Biometric Presence Gate** | **Touch ID / Apple Watch Hardware Sensor** | ❌ Software Auth Only | ❌ Software Auth Only | ❌ Software Auth Only | ❌ Software Auth Only |
| **Remote Session Hijack Intercept** | **Active BSD Process Tree & SSH/VNC Scanner** | ❌ None | ❌ None | ❌ None | ❌ None |
| **Zero-Codebase Dotenv Injection** | **Automatic `<migrated_to_sec>` Placeholder Override** | SDK / Custom API Scripts | Custom Agent / Template Injection | CLI Secret Ingestion | Manual Decrypt Scripting |

---

## 🏢 Corporate MDM & Workstation Security

In enterprise environments, developer laptops are often enrolled in Mobile Device Management (MDM) platforms (e.g. Jamf, Kandji, Microsoft Intune) with corporate endpoint detection and automated file inventory collection. Plaintext `.env` files lying around in workspace subdirectories pose a high risk of being indexed, backed up to unencrypted IT stores, or exposed during IT support remote sessions.

`sec-agent` addresses this threat model specifically for corporate workstations:

1.  **Hardware-Enforced Privacy**: Secrets are encrypted at rest using keys sealed inside the macOS Secure Enclave (`SecAccessControl`). Even if an MDM script or local admin process reads the database file (`secrets.enc`), it cannot decrypt the contents without physical Touch ID contact on the console.
2.  **Remote Administration Intercepts**: Active corporate remote support sessions (such as `screensharingd` or `AppleVNCServer`) and remote SSH administration sessions (`SSH_CLIENT`, `SSH_TTY`) are automatically intercepted. The daemon instantly locks itself and purges decrypted keys from RAM, preventing remote support engineers or administrative monitoring software from viewing your secrets.

