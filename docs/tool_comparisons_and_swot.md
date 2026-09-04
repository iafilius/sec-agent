# 🛡️ Architecture & Tool Comparison: `sec-agent` vs `env`, `env -u`, `direnv`, macOS Keychain, GPG/Pass & SaaS CLIs

This document serves as the authoritative security comparison, threat model assessment, and SWOT analysis for `sec-agent` against standard UNIX and macOS secret injection tools.

---

## 📊 Summary Comparison Matrix

| Feature | Plaintext `.env` / `direnv` | `env -u <KEY>` / Env | macOS Keychain (`security`) | GPG & Pass | KeePassXC CLI | SaaS CLI (1Password/Doppler) | `sec-agent` Daemon |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Secret Storage** | Plaintext (`.env`) | Shell Environment | macOS Keychain | GPG `.gpg` files | `.kdbx` file | Cloud Backend | Hardware Enclave + RAM |
| **RAM Memory Isolation** | None | None | Per-query decrypt | `gpg-agent` RAM | Plaintext script hacks | Daemon RAM | Ephemeral locked RAM daemon |
| **Biometric Tap Prompts** | 0 taps | 0 taps | 1 popup **per query** | 0 (after PIN unlock) | 0 (Requires password) | 1 popup per session | **1 tap per 8h session** |
| **Process Listing (`ps` / `/proc`)**| Visible | Stripped for child | Visible in args | Visible in args | Visible in args | Visible in args | Protected (No plaintext in args) |
| **Subagent Lease Support**| ❌ No | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No | ✅ Yes (Self-Destructing Leases) |
| **Local Workstation RCE Risk**| 🔴 Critical | 🔴 High | ⚠️ Medium | ⚠️ Medium | ⚠️ Medium | ⚠️ Medium | ✅ Low (PID + Peer Auth) |

---

## 🥊 Detailed SWOT Analysis

### 1. `env -u <KEY>` (Environment Variable Stripping)

`env -u` is a POSIX utility flag (`/usr/bin/env -u VARIABLE`) used to unset specific environment variables before launching a child process.

```text
┌─────────────────────────────────────────────────────────────┐
│                 `env -u <KEY>` Mechanics                    │
├─────────────────────────────────────────────────────────────┤
│ Parent Shell (Contains Secret)                              │
│         │                                                   │
│         ├──► `env -u AWS_SECRET_ACCESS_KEY npm test`         │
│         │                                                   │
│         ▼                                                   │
│ Child Process (`npm test` launched without `AWS_SECRET_...`) │
└─────────────────────────────────────────────────────────────┘
```

#### **Strengths (S)**
- **POSIX Standard Builtin**: Supported natively across all UNIX, Linux, and macOS environments without installing third-party tools.
- **Child Process Environment Isolation**: Successfully prevents child processes (like untrusted sub-dependencies or test runners) from inheriting specified sensitive environment variables.

#### **Weaknesses (W)**
- **Parent Shell Vulnerability**: `env -u` only unsets keys for the specific command being executed; the parent shell environment block remains fully populated with plaintext secrets.
- **Manual Maintenance Burden**: Developers must explicitly maintain lists of every key to unset (`env -u KEY1 -u KEY2 -u KEY3`), leading to missed credentials as application schemas expand.
- **No Disk/Memory Protection**: Does not protect secrets stored in plaintext `.env` files or history logs (`~/.zsh_history`).

#### **Threats (T)**
- **Pre-Execution Exfiltration**: Malicious code or dependencies running inside the parent process *before* `env -u` is invoked can freely read `process.env`, `sysctl(KERN_PROCARGS2)` / `ps -E` on macOS, or `/proc/$PID/environ` on Linux.

---

### 2. macOS `env` & `direnv`

#### **Strengths (S)**
- **Zero Developer Friction**: Requires zero user interaction or biometric prompts (0 Touch ID taps).
- **POSIX Standard**: Available out of the box on every UNIX/macOS system.

#### **Weaknesses (W)**
- **Plaintext Disk Storage**: `.env` and `.envrc` store keys unencrypted on disk, frequently committed to public Git repos by accident.
- **Process Listing Leakage**: Secrets exported into subshell environment arrays remain inspectable by same-user processes via `ps -E` / `sysctl` on macOS, or `/proc/$PID/environ` on Linux.

#### **Threats (T)**
- **Workstation RCE & Dependency Exploitation**: Any untrusted npm script, PyPI package, VS Code extension, or AI coding agent executing shell commands can instantly read `.env` files via `fs.readFileSync('.env')` without root permissions.

---

### 3. macOS Keychain CLI (`security find-generic-password`)

#### **Strengths (S)**
- **Hardware-backed Storage**: Uses Apple's Keychain Services API protected by Secure Enclave hardware.
- **Native OS Tool**: Pre-installed on macOS (`/usr/bin/security`).

#### **Weaknesses (W)**
- **Biometric Prompt Fatigue**: Executing `security find-generic-password` in a script or shell hook triggers an OS Keychain popup dialog **every single time** a key is resolved.
- **System ACL Shell Hijacking**: Once an application (Terminal, iTerm2, VS Code) is granted access to a Keychain item, *any* process running inside that terminal window can query `security find-generic-password` without prompting for Touch ID again.

#### **Threats (T)**
- **Shell-level AI Agent Exfiltration**: If an AI coding agent or compromised npm dependency runs inside your authorized terminal application, macOS Keychain grants full access to all saved generic passwords with zero prompt warnings.

---

### 4. `sec-agent` (Ephemeral RAM Daemon + AES-256-GCM Vault)

#### **Strengths (S)**
- **Single Touch ID Tap per Session Window**: You unlock `sec-agent` **once** (`sec open`). The daemon holds the master key in locked RAM for an isolated TTL, requiring **zero extra biometric taps** for subsequent commands.
- **Socket Peer Credentials & PID Validation**: Uses OS peer PID and UID checks (`GetsockoptInt` / `unix.SO_PEERCRED`) to verify caller executable identity and process lineage before releasing keys.
- **Self-Destructing Subagent Leases (`sec lease`)**: Issues scoped, short-lived IPC lease tokens with strict TTL timers for AI subagents or worker threads.
- **Zero-Fill Memory Scrubbing**: When the session expires or is locked (`sec clear`), master keys and unencrypted secrets are zero-filled (`zeroBytes`) in daemon RAM.
- **Remote Hijack Block**: Actively detects and blocks secret queries originating from SSH sessions (`sshd`) or active VNC/Screensharing sessions.

#### **Weaknesses (W)**
- Requires installing the `sec-agent` CLI binary via Homebrew.

#### **Threats (T)**
- **Root-level RAM Dumps**: If an attacker gains full root/kernel privileges (`sudo`), RAM can theoretically be dumped during an active unlocked session window (mitigated by explicit session TTLs, `sec clear`, and macOS Hardened Runtime code signing).

---

## 🔒 Touch ID UX & Security Model FAQ

### Q1: Is `.env` "secure enough" as claimed in some web security guidelines (e.g. *Securing Laravel*)?
**In Production Web Servers: Yes. On Developer Workstations: No.**
Web server guidelines state `.env` is safe because it is placed outside the public web root (`/public`), preventing web browsers from downloading `.env` over HTTP GET requests. However, on a **developer workstation**, the threat is not HTTP web scraping—it is **local unprivileged code execution** (`npm install`, PyPI dependencies, malicious subagents). Any script executing under the developer's user account can read `.env` directly from disk without needing root access or web server HTTP requests.

### Q2: How does `env -u <KEY>` compare to `sec-agent`?
`env -u` is a useful POSIX mechanism for unsetting specific environment variables when spawning a child command. However, it leaves the parent shell's memory and disk `.env` files completely unencrypted and vulnerable to pre-execution exfiltration. `sec-agent` avoids plaintext disk storage entirely, encrypting keys at rest with Apple Secure Enclave (`BiometryCurrentSet`) and serving secret queries over an authenticated IPC socket with peer PID validation.

### Q3: How does `sec-agent` protect against AI subagent leaks?
`sec-agent` issues scoped, self-destructing IPC lease tokens (`sec lease <path> --ttl 5m`). Subagents can only access designated key paths for the duration of the TTL window, after which the lease self-destructs. Secrets are never exposed to the subagent's parent process environment block.

---

## 🚀 The Next Frontier: "Zero-ENV" Direct-to-Memory SDK Path

While `sec-agent` fortifies secret storage (AES-256-GCM + Touch ID RAM daemon), injecting secrets via environment variables (`ENV`) remains subject to fundamental OS process inspection risks (`ps aux`, `/proc`, crash dumps, unhandled logging).

To achieve **military-grade application security**, `sec-agent` outlines a future **Zero-ENV Architecture Roadmap** ([roadmap_zero_env_sdk_architecture.md](roadmap_zero_env_sdk_architecture.md)):
- Applications consume secrets directly via native SDK client libraries (Go, Node.js, Python, Rust).
- Secrets are fetched directly over an ephemeral local socket into private application RAM variable pointers (never populating `ENV` arrays).
- Applications are restricted strictly to their designated profile scope (never exposing the entire master vault).

