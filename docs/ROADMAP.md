# sec-agent Product & UX Architecture Roadmap

`sec-agent` is engineered to provide hardware-bound, Touch ID-gated secret management with zero friction for professional software developers. This roadmap outlines the strategic evolution of `sec-agent` across four key capability pillars designed to eliminate daily workflow friction, prevent credential leakage, enable short-lived cloud leases, and facilitate secure team collaboration.

---

## 🗺️ Strategic Vision Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│               sec-agent PROFESSIONAL UX & PRODUCT ROADMAP                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  [PHASE 1: IMMEDIATE FOCUS]                                                     │
│  Option A: Shell Auto-Profile & Seamless Prompt Ergonomics                      │
│  • Auto cd Profile Switch (.secrc detection)                                    │
│  • Instant Prompt Status Helper (Starship / P10k / Zsh / Fish)                  │
│  • Native direnv / mise Plugin Integration                                      │
│                                                                                 │
│  [PHASE 2: HARDENING & PREVENTION]                                              │
│  Option B: Git Pre-Commit Privacy Guard & IDE Proxy                             │
│  • Built-in `sec githook install` pre-commit scanner                            │
│  • IDE Debug Launch Socket Proxy (VS Code / Antigravity IDE)                    │
│                                                                                 │
│  [PHASE 3: CLOUD & CONTAINERS]                                                  │
│  Option C: Ephemeral Cloud & Container Leases                                   │
│  • Short-lived AWS STS / GCP / Azure IAM token derivation                       │
│  • Local Docker / Kubernetes socket mount secret injector                       │
│                                                                                 │
│  [PHASE 4: ZERO-TRUST SHARING]                                                  │
│  Option D: Ephemeral P2P Team Sharing & GitOps Envelopes                        │
│  • P2P Key-Wrapped Secret Export/Import (`sec share export`)                    │
│  • Repository-Bound Dual-Slot GitOps Envelopes (`.sec/vault.enc`)               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📍 Phase 1 (Immediate Focus): Option A — Shell Auto-Profile & Seamless Prompt Ergonomics

### Motivation & Problem Statement
Currently, switching vault profiles requires explicit flags (`--profile prod`) or manual shell environment exports (`eval $(sec open --profile prod)`). Developers working across multiple microservices or environment tiers (dev, staging, prod) experience cognitive overhead and risking running commands against the wrong target environment.

### Architectural Solution
1. **Automated Directory Profile Switching (`chpwd` hook)**:
   - When entering a directory containing `.secrc` or `sec.yaml`, the shell automatically detects the target profile (e.g. `profile: velocloud-provider-dev`) and updates `SEC_PROFILE`.
   - On exiting the directory tree, the context automatically reverts to `default`.
2. **Real-Time Shell Prompt Helper (`sec prompt`)**:
   - High-performance, zero-latency CLI command `sec prompt` optimized for prompt engines (Starship, Powerlevel10k, Oh-My-Zsh, Fish).
   - Outputs colorized or formatted status strings:
     - Unlocked: `🛡️ sec:dev`
     - Locked: `🔒 sec:prod (locked)`
     - Locked/Expired: `⚠️ sec:dev (expired)`
3. **Native `direnv` & `mise` Plugin Integration**:
   - `sec init-direnv`: Injects a native `use sec-agent [profile]` function into `~/.config/direnv/direnvrc`.
   - Secrets are injected into the process shell memory when entering the directory and purged immediately upon exiting—with **zero plaintext `.env` files written to disk**.

---

## 📍 Phase 2: Option B — Git Pre-Commit Privacy Guard & IDE Socket Proxy

### Motivation & Problem Statement
The primary vector for credential leakage is developers accidentally staging `.env` files or hardcoding raw API tokens/keys before running `git commit`.

### Architectural Solution
1. **Built-in Git Pre-Commit Privacy Guard (`sec githook install`)**:
   - Installs a zero-dependency, ultra-fast pre-commit binary scanner into `.git/hooks/pre-commit`.
   - Scans staged `git diff --cached` for high-entropy strings, AWS Access Keys (`AKIA...`), GitHub PATs (`ghp_...`), Private RSA/Ed25519 blocks, and `.env` file staging.
   - Blocks the commit immediately with remediation guidance: `Run 'sec migrate-local .env' to import into Touch ID storage.`
2. **IDE Launch Socket Proxy Protocol**:
   - Exposes a lightweight local Unix socket protocol allowing IDE debug runners (VS Code / Antigravity IDE) to query secrets dynamically during test execution without storing credentials in `launch.json` or `.vscode/settings.json`.

---

## 📍 Phase 3: Option C — Ephemeral Cloud & Container Leases

### Motivation & Problem Statement
Static long-lived cloud credentials stored in `~/.aws/credentials` or `~/.gcp/credentials.json` are primary targets for malware and session hijacking.

### Architectural Solution
1. **Short-Lived Cloud STS Token Generator (`sec aws login` / `sec gcp auth`)**:
   - Sealer root AWS IAM credentials inside the Touch ID vault.
   - When `sec aws login` is executed, the daemon requests short-lived 1-hour IAM STS session tokens (`AWS_SESSION_TOKEN`) from AWS STS via Touch ID prompt and injects them into process memory.
2. **Docker & Container Socket Injector**:
   - Ephemerally mounts secrets or daemon sockets into local Docker containers (`sec docker run -it node:18`) or local Kubernetes (`kind`/`k3d`) pods without baking environment variables into image layers or build logs.

---

## 📍 Phase 4: Option D — Ephemeral P2P Team Sharing & GitOps Envelopes

### Motivation & Problem Statement
Sharing development secrets across team members is currently done insecurely over Slack, email, or unencrypted pastebins.

### Architectural Solution
1. **Peer-to-Peer Ephemeral Key Wrapping (`sec share export / import`)**:
   - Each developer generates a local asymmetric identity keypair (`sec keygen`).
   - Developer A exports a secret payload encrypted specifically to Developer B's public key (`sec share export --key db/pass --to-pubkey <B_pubkey>`).
   - Developer B decrypts it using their Touch ID sensor on their local machine.
2. **Repository-Bound GitOps Envelopes (`.sec/vault.enc`)**:
   - Allows committing a repository-bound encrypted vault into Git (`.sec/vault.enc`).
   - Team members are added as authorized slots. Tapping Touch ID on a fresh git clone decrypts team development credentials seamlessly.
