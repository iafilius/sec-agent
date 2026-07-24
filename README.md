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

### 💡 The "Secret Zero" Paradox Solved

Most secret management tools (Vault, Doppler, SOPS, 1Password CLI) suffer from the **"Secret Zero" Paradox**: to pull your encrypted secrets, they require a plaintext **API token**, **private key file**, or **bootstrap certificate** stored on your disk. They simply shift the vulnerability from a database password to a key file.

```
TRADITIONAL TOOLS (Vault, Doppler, SOPS, 1Password CLI)
[ Secret Vault ] ──▶ [ Plaintext Token / Key File on Disk ] ──▶ ❌ STOLEN BY ATTACKER / LOCAL SCRIPT

SEC-AGENT (Secure Enclave Model)
[ Encrypted Store ] ──▶ [ macOS Secure Enclave Hardware Chip ] ──▶ [ Touch ID Finger Sensor ] ──▶ ✅ HARDWARE LOCKED
```

* **No Plaintext Keys on Disk**: Zero secret key files, API tokens, or certificates sit anywhere on your filesystem.
* **Hardware-Anchored Silicon Storage**: Master keys are generated and sealed inside the **macOS Secure Enclave**. The master key never touches the disk.
* **Biometric Physical Presence Gate**: Decrypting secrets requires physical Touch ID sensor contact on the laptop console. Software scripts and remote attackers cannot fake physical presence.
* **Zero-Friction PoC/Dev Adoption**: Drop it into any local development project or PoC in 30 seconds with `sec migrate-local .env`—requiring **zero cloud setup, zero API tokens, and zero codebase modifications.**

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
*   **Disaster-Proof Write Transactions**: All filesystem mutations (database saves, dotenv migrations, KeePassXC exports) utilize atomic sibling renames. The payload is written to a temporary file, flushed to storage blocks via `fsync()`, and atomically replaced. Profile-isolated backups of the last 10 database snapshots are rotated automatically under `~/.config/sec-agent/backups/<profile>/`.
*   **SMP & Parallel Concurrency Resilient**: Built with goroutine-per-connection Unix sockets and `sync.Mutex` in-memory guards. Fully resistant to race conditions under high-throughput parallel execution (e.g. `make -j8`, concurrent `terraform plan`, or multi-agent AI swarm workloads).
*   **Hardened Runtime Isolation**: The daemon executes under macOS Hardened Runtime protections with no debugging entitlements. System Integrity Protection (SIP) blocks standard user-space debuggers and memory readers (including root UID 0) from inspecting its memory.
*   **Offline First**: No cloud synchronization, no third-party APIs, and zero SaaS dependency.

---

## ⚙️ Installation

### Option 1: Install via Homebrew (RECOMMENDED for macOS)
```bash
# Add Homebrew tap and install sec-agent
brew install iafilius/tap/sec-agent
```

### Option 2: Pre-built Signed Binary Release
Download the latest pre-compiled, macOS Hardened Runtime signed binary tarball from [GitHub Releases](https://github.com/iafilius/sec-agent/releases/latest):
```bash
# Extract and install binary to /usr/local/bin
tar -xzf sec-agent_v1.9.1_darwin_arm64.tar.gz
sudo mv sec-agent /usr/local/bin/
```

### Option 3: Build from Source
```bash
# Clone repository and compile with macOS Hardened Runtime signature
make build codesign

# Run security static analysis checks (vet, vulncheck, gosec)
make sec-check

# Run tests
make test
```

> [!NOTE]
> **Zero Name Collision**: The CLI binary executable is named **`sec-agent`** to avoid conflicts with Homebrew's existing Perl `sec` (Simple Event Correlator) package. If you do not have the Perl `sec` tool installed and prefer 3-letter typing, you can optionally add `alias sec=sec-agent` in your `~/.zshrc`.

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
# 1. Interactive Hidden Prompt (RECOMMENDED - No Shell History / ps aux leakage)
sec set app-secrets/db-pass
# Enter secret value: [hidden]
# Re-enter secret value: [hidden]

# 2. Pipe from Stdin
cat secret.txt | sec set app-secrets/db-pass --stdin

# 3. Direct Positional Value
sec set app-secrets/db-pass "my-super-secret-password"
```

> [!TIP]
> **Shell History & Process List Security**: Passing secret values directly as CLI command-line positional arguments can be recorded in shell history (`.zsh_history`, `.bash_history`) or inspected by non-root OS processes via `ps aux`. For sensitive production keys, **always use the interactive prompt (`sec set <path>`) or piped stdin (`--stdin`)**.

### 3. Run Applications (Frictionless Injection & Granular Scoping)
Instead of sourcing `.env` files, execute commands directly in a wrapped environment. `sec` automatically translates paths like `app-secrets/db-pass` to uppercase environment variables (`APP_SECRETS_DB_PASS`):
```bash
# Execute test process with secrets injected & auto-redacted in logs
sec run -- go test -v ./...

# Restrict injection strictly to specified keys (Principle of Least Privilege for AI subagents)
sec run --allow-keys VCO_URL,VCO_ENTERPRISE_ID -- make test-unit

# Inspect injection plan without executing command or prompting Touch ID
sec run --dry-run -- make testacc
```

### 4. Automated Token Rotation & Expiring Inventory
Register rotation hooks to rotate tokens in seconds and inspect expiring keys:
```bash
# Register token with custom rotation hook command
sec set velocloud-provider-dev/vco_token "..." --expires 30d \
  --rotate-cmd "sec run --profile velocloud-provider-dev -- curl -s -X POST \$VCO_URL/portal/rest/login/enterpriseLogin -d '{\"username\":\"admin\",\"password\":\"\$VCO_PASSWORD\"}' | jq -r .token" \
  --rotate-ttl 30d

# Trigger one-command token rotation
sec rotate velocloud-provider-dev/vco_token

# Inspect expiring keys across vault profiles
sec ls --expiring 14d
```

### 5. Global Workstation Status & Entropy Linter
Single-pane-of-glass status dump and side-channel safe entropy audit:
```bash
# Global status matrix across all vault profiles & background daemons
sec status --all

# Side-channel safe password entropy & weakness scan
sec check --scan-weak
```

### 6. Lock Session
Wipe decrypted credentials from system memory and lock the daemon:
```bash
sec lock
# Session locked. Memory cache cleared.
```

---

## 🧹 Local Dotenv Migration & Git Security Protocol

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

> [!CAUTION]
> **Git History Exposure Warning**:
> Running `sec migrate-local .env` sanitizes local disk files to `<migrated_to_sec>` placeholders. **However, if `.env` was previously committed to Git, those plaintext credentials STILL EXIST permanently in Git commit history!**
>
> **Remediation Protocol**:
> 1. **Rotate Credentials Immediately**: Assume any key ever committed to Git is compromised.
> 2. **Purge File from Git History**:
>    ```bash
>    pip install git-filter-repo
>    git filter-repo --path .env --invert-paths --force
>    git push origin --force --all --tags
>    ```
>    *Note: Force-pushing rewritten history requires **Repository Admin privileges** to bypass branch protection rules.*

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

## 🌍 Industry Context: How Developers Handle Secrets Today

In real-world software engineering, **developer credential hygiene is notoriously poor.** Security research from GitGuardian (*State of Secrets Sprawl*) reveals that **over 12 million plaintext secrets were leaked to GitHub in 2023 alone**, making exposed local credentials the **#1 vector for corporate security breaches**.

### The Developer Secret Hygiene Spectrum

| Level | Estimated Adoption | Typical Setup & Risk Profile |
| :--- | :--- | :--- |
| **❌ Tier 0: Plaintext `.env` / Shell Exports** | **~75 - 80%** *(Industry Norm)* | Plaintext `.env` files in root directories, `.zshrc`/`.bash_profile` exports, or hardcoded strings. Easily targeted by **InfoStealer malware** (RedLine, Raccoon, Vidar) searching local disks. |
| **⚠️ Tier 1: Cloud SaaS Secret Tools** | **~10 - 15%** | Doppler, Infisical. Centralized cloud sync, but introduces the **"Secret Zero" flaw** (storing unencrypted API token files on disk) and requires monthly SaaS subscriptions. |
| **🔑 Tier 2: Password Manager CLIs** | **~5 - 10%** | 1Password (`op run`), Bitwarden CLI. Improves local security via desktop vaults, but requires running heavy desktop GUI apps and lacks active session hijacking detection. |
| **🛡️ Tier 3: Hardware Enclave Agents** | **< 1 - 2%** *(sec-agent)* | **macOS Secure Enclave + Touch ID + Active Hijack Intercepts**. Zero plaintext files on disk, zero cloud dependencies, and zero SaaS lock-in. |

### Why `sec-agent` Fits Development & PoC Workflows
1. **Friction Always Defeats Security**: If a tool requires complex cloud setup or manual API integrations, developers bypass it and create a `.env` file. `sec-agent` provides a **30-second drop-in migration (`sec migrate-local .env`)** requiring zero codebase changes.
2. **Eliminating InfoStealer Risk**: Infostealers scan disk paths for `.env` files and shell history logs. By sanitizing `.env` files to `<migrated_to_sec>` placeholders and locking master keys inside Apple Silicon hardware, local secrets remain completely invisible to malware.

---

## 📊 Comprehensive Solution Comparison Matrix

| Feature | `sec-agent` | YubiKey / Hardware Keys (PKCS#11/PGP) | 1Password CLI / Bitwarden CLI | Delinea (Secret Server / DSV) | HashiCorp Vault | Doppler / Infisical | SOPS / Age (Mozilla) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Target** | **Local macOS Workstation & Session Agent** | Hardware Authentication & SSH/PGP Keys | Desktop Password Vault CLI Injection | Enterprise Privileged Access Management (PAM) | Enterprise / Infrastructure Production Vault | Cloud Team Secret Synchronization | GitOps Repository File Encryption |
| **Deployment Model** | **100% Offline** (Zero SaaS / Zero Server) | Local USB Hardware Dongle | Local App + Cloud SaaS Subscription | Enterprise Cloud SaaS or On-Prem IIS/SQL | Self-Hosted Cluster or Cloud SaaS | Cloud SaaS Platform | Local CLI (Key Server optional) |
| **Master Key Protection** | **macOS Secure Enclave (Silicon)** | USB Security Key Cryptographic Chip | Software Vault Key (Argon2 / Master Pass) | Enterprise Tenant / Cloud Vault | Server Master Key / AppRole | Cloud Account Token | Local GPG / Age Key File |
| **"Secret Zero" Disk Dependency** | **✅ Zero Plaintext Files (Hardware Sealed)** | ✅ Zero Key Files on Disk | ❌ Plaintext Session Token File | ❌ Plaintext Client ID / Token on Disk | ❌ Plaintext Vault Token / AppRole | ❌ Plaintext Service Token File | ❌ Plaintext GPG / Age Key File |
| **Hardware Biometric Gate** | **Built-in Touch ID / Apple Watch** | ⚠️ Physical Button Touch (External USB) | ⚠️ Desktop App Biometrics | ❌ Software Auth Only | ❌ Software Auth Only | ❌ Software Auth Only | ❌ Software Auth Only |
| **Remote Session Hijack Intercept** | **Active BSD Process Tree & SSH/VNC Scanner** | ❌ None (Triggers while plugged in) | ❌ None (CLI queryable during unlock) | ❌ None | ❌ None | ❌ None | ❌ None |
| **External Hardware Needed** | **❌ None (Uses Built-in Apple Silicon)** | ⚠️ Required (USB Dongle purchase/carrying) | ❌ None | ❌ None | ❌ None | ❌ None | ❌ None |
| **Zero-Codebase Dotenv Injection** | **Automatic `<migrated_to_sec>` Override** | ❌ Complex GPG / PKCS#11 Scripting | ⚠️ Manual `op run` Template Mapping | SDK / Custom API Scripts | Custom Agent / Template Injection | CLI Secret Ingestion | Manual Decrypt Scripting |

---

### 🔑 Hardware Security Breakdown: `sec-agent` vs. YubiKey & Security Dongles

Hardware security keys (such as YubiKeys using PGP or PKCS#11 modules) are often considered the gold standard for authentication, but face severe limitations when applied to developer local secret management:

1. **Zero External Hardware Friction**:
   * **YubiKey**: Requires purchasing, configuring, and carrying external USB-C dongles that can be lost, left at home, or broken in USB ports.
   * **`sec-agent`**: Leverages the **built-in macOS Secure Enclave** and **built-in Touch ID sensor** already present in Apple Silicon Macs—delivering enterprise-grade hardware cryptography out of the box with zero additional hardware cost.
2. **Active Hijacking Intercepts**:
   * **YubiKey**: A YubiKey has no process context or ancestry awareness. If a YubiKey remains plugged into a USB port with cached PIN entry, an attacker who gains remote SSH shell access or background process execution can issue `gpg` or `pkcs11-tool` commands to decrypt secrets without prompting for a physical touch button.
   * **`sec-agent`**: Actively scans the client's BSD process tree and environment variables (`SSH_CLIENT`, `SSH_TTY`, `AppleVNCServer`, `remotepairingd`). If an SSH or remote sharing session is detected, the daemon immediately self-locks and purges decrypted keys from RAM, neutralizing remote session takeover attempts.
3. **Seamless Local Pipelines, Terraform & Script Integration**:
   * **YubiKey High-Friction Workflow**: YubiKeys cannot natively inject environment variables into child process trees. To pass secrets into local build scripts, `.env` loaders, or Infrastructure-as-Code tools (e.g., Terraform `TF_VAR_db_password`, AWS credentials, Docker Compose), developers are forced to write custom wrapper scripts around `gpg --decrypt` or `pkcs11-tool`. Every execution forces constant physical button taps or PIN prompts. If a developer enables PIN/touch caching to avoid tap fatigue, it opens a severe vulnerability where background scripts or remote SSH shells can steal credentials from the cached YubiKey session.
   * **`sec-agent` Frictionless Experience**:
     * **Single Session Authorization**: Unlock your session once (`eval $(sec open)`) backed by a single Touch ID hardware check.
     * **Transparent Process Wrapper**: Execute any local pipeline, shell script, or Terraform command directly without modifying scripts or codebase files:
       ```bash
       sec run -- terraform plan
       sec run -- make deploy-staging
       sec run -- docker compose up
       ```
     * **Automatic Key-to-Env Mapping**: Secret paths (e.g. `tf-vars/db-password`) are automatically converted to uppercase environment variables (`TF_VARS_DB_PASSWORD` or `AWS_SECRET_ACCESS_KEY`) in child process memory.
     * **Zero-Codebase Dotenv Overrides**: Automatically overrides `<migrated_to_sec>` placeholders in `.env` files in memory—requiring **zero code changes** in your application or build pipelines.
     * **Uncompromised Security**: Even while the session is open, `sec-agent` continuously monitors the process tree and peer environment (`SSH_CLIENT`, `SSH_TTY`, `AppleVNCServer`). If a remote session attempts to query secrets, the daemon self-locks instantly.

---

## 🤖 AI Agent Integration (Bundled Agent Skill)

To make AI-assisted software development frictionless, `sec-agent` includes a pre-packaged **Agent Skill** (`docs/skills/sec-agent-integration/SKILL.md`). This enables AI coding assistants (such as Antigravity, Cursor, Claude Code, Windsurf, or custom agent frameworks) to use `sec` automatically across your project workspaces.

### Quick Skill Setup for AI Assistants:
Simply copy or link the bundled skill into your agent's skills directory:

```bash
# Register the bundled skill globally for your AI coding assistant
mkdir -p ~/.gemini/config/skills/sec-agent-integration
cp docs/skills/sec-agent-integration/SKILL.md ~/.gemini/config/skills/sec-agent-integration/
```

Once installed, your AI assistant will automatically:
* Check daemon lock status (`sec version`) and prompt for `eval $(sec open)` when needed.
* Wrap local test/build/deploy commands with `sec run -- <cmd>` to inject credentials in memory without creating plaintext `.env` files.
* Help migrate legacy `.env` files using `sec migrate-local`.

---

## 🏢 Corporate MDM & Workstation Security

In enterprise environments, developer laptops are often enrolled in Mobile Device Management (MDM) platforms (e.g. Jamf, Kandji, Microsoft Intune) with corporate endpoint detection and automated file inventory collection. Plaintext `.env` files lying around in workspace subdirectories pose a high risk of being indexed, backed up to unencrypted IT stores, or exposed during IT support remote sessions.

`sec-agent` addresses this threat model specifically for corporate workstations:

1.  **Hardware-Enforced Privacy**: Secrets are encrypted at rest using keys sealed inside the macOS Secure Enclave (`SecAccessControl`). Even if an MDM script or local admin process reads the database file (`secrets.enc`), it cannot decrypt the contents without physical Touch ID contact on the console.
2.  **Remote Administration Intercepts**: Active corporate remote support sessions (such as `screensharingd` or `AppleVNCServer`) and remote SSH administration sessions (`SSH_CLIENT`, `SSH_TTY`) are automatically intercepted. The daemon instantly locks itself and purges decrypted keys from RAM, preventing remote support engineers or administrative monitoring software from viewing your secrets.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
Copyright (c) 2026 Arjan Filius.

