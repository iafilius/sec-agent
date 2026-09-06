# Changelog

All notable changes to `sec-agent` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.10.0] - 2026-09-06

### Added & Enhanced
- **Native Pure Go SSH Client (`sec ssh`)**:
  - Replaced external `sshpass` requirement on macOS/Linux with native `golang.org/x/crypto/ssh` implementation.
  - Transparently injects passwords from active profile vault (`ssh/<target>/password` or companion `.secrc` mapping) into in-memory SSH client configuration.
  - Supports SSH private keys with optional passphrase unlocking.
  - Automatically allocates pseudo-terminal (PTY) in raw mode for interactive sessions or directly propagates remote command exit status.
- **SSH Target Onboarding Wizard (`sec ssh init <target>`)**:
  - Guided wizard to configure remote SSH host, username, port, and authentication method.
  - Securely stores credentials under `ssh/<target>/*` in the profile vault and binds target configuration to workspace `.secrc`.
  - Implemented target name validation (`validateSSHTargetName`), prohibiting slashes, spaces, and path traversals.
- **Guided Profile Onboarding Wizard (`sec profile new <name>`)**:
  - Interactive onboarding wizard creating dedicated profile vaults with Touch ID Secure Enclave binding and 24-word Argon2id recovery seed generation.
  - Generates companion `.secrc` binding the profile to the current project directory.
- **Profile Discovery Overview (`sec profile ls`)**:
  - Formatted tabular overview of all discovered profile databases, active profile indicator, and encrypted store paths.
- **Headless Pipe Secret Ingestion (`sec set <key> --stdin [--no-trim]`)**:
  - Stream secret ingestion via standard input without interactive prompt echoes.
  - Added `--no-trim` flag to strictly preserve leading and trailing whitespace/newlines for multiline PEM certificates, private keys, and structured payloads.
- **Dynamic Sliding-Window Stream Redaction (`sec run --redact`)**:
  - In-flight stdout and stderr secret scrubbing replacing active profile credentials with `[REDACTED_BY_SEC]`.
  - Implemented boundary margin buffering (`maxLen - 1`) ensuring secrets spanning across TCP chunks or pipe flushes are never leaked.
- **Automated AI Skill Upgrade Detection & Dynamic Re-Read Directive**:
  - `syncInstalledSkillsIfOutdated()` detects CLI upgrades and immediately synchronizes installed skill documents across global and workspace scopes.
  - Emits high-priority action directive to `os.Stderr` instructing AI pair programmers to re-read updated skills via `view_file` to eliminate knowledge drift.
- **Fast-Path Status Diagnostic Skill Reporting (`sec status --quick`)**:
  - Surfaces active AI skill document path, binary version, and synchronization status at Turn 1 in both text and JSON formats.
- **Framed ASCII Biometric Blocker Notice (Exit Code 78)**:
  - Standardized visual terminal banner and structured instructions whenever Touch ID authentication requires user physical interaction.

### Fixed & Hardened
- **Robust v2.0 Vault Detection (`internal/store/vault.go`)**:
  - Eliminated 1-in-256 false-positive flake where AES-GCM random ciphertext nonce starting with `0x7B` was mistaken for a v2.0 JSON envelope.
  - Upgraded `IsV2Vault` to rigorously validate `env.SchemaVersion == SchemaV2`.
- **Incomplete Vault Remediation (`cmd/sec-agent/cmd_import_export.go`)**:
  - Added detection for partial/corrupted vaults missing `slot1` recovery envelopes, preventing unrecoverable states during migration.
- **AI Context & Chat Hygiene**:
  - Redacted sensitive secret values from tabular display outputs and context summaries during AI agent pair programming sessions.

---

## [v2.2.0] - 2026-08-04

### Added & Security Architecture
- **v2.0 Dual-Slot Vault Architecture**: Introduced LUKS-style dual key-slot vault envelopes (`Slot 0` daily Touch ID + `Slot 1` offline 24-word Argon2id BIP39 recovery key).
- **Admin Password Reset & Fingerprint Injection Defense (`kSecAccessControlBiometryCurrentSet`)**: Configured macOS Keychain access control to `kSecAccessControlBiometryCurrentSet`. Secure Enclave hardware automatically invalidates and purges `Slot 0` if any fingerprint is added, removed, or modified by an administrator.
- **Argon2id Memory-Hard Key Derivation ($m=64\text{MB}, t=3, p=4$)**: Encrypted `Slot 1` with 256-bit AES-GCM using Argon2id derived from an offline 24-word BIP39 seed phrase.
- **Biometric Recovery Command (`sec session recover`)**: Added interactive TTY recovery workflow to unwrap `Slot 1` and re-bind Touch ID access to updated biometric sets.
- **Mandatory Biometric Verification Notice**: Added high-visibility warning in `sec session recover` instructing users to verify System Settings biometrics before re-enrolling Touch ID.
- **CGO Memory Pointer Safety**: Fixed double-free memory crash (`SIGTRAP`) in CoreFoundation query cleanup.
- **Non-Interactive AI / TTY Guard (`isatty`)**: Added execution checks blocking automated headless scripts and AI agents from generating or discarding recovery keys.
- **Atomic Two-Phase Migration (`sec migrate-v2`)**: Implemented atomic `.tmp` staging and inode swapping for seamless bulk profile upgrades.

---

## [v2.1.8] - 2026-07-27

### Fixed & Added
- **GPLv3 License Transition**: Updated repository license to **GNU General Public License v3.0 (`GPL-3.0-or-later`)** to ensure strong copyleft protections across all future releases and downstream distributions.
- **Web UI & Desktop App Architecture Documentation (`README.md`)**: Added comprehensive documentation for `SecAgent.app` and `sec-agent gui`, explaining single-tab security binding (`BroadcastChannel` & active heartbeat locking), in-browser biometric Touch ID unlock, multi-profile database selector, and logical record card view vs flat list switcher.
- **Logical Record Cards View (`cmd/sec-agent/gui.go`)**: Added automatic grouping of sub-attribute key paths into unified Record Cards with view mode toggle controls.

---

## [v2.1.7] - 2026-07-26

### Fixed & Added
- **Automatic Stale GUI Process Termination (`cmd/sec-agent/gui.go`)**: Added pre-launch HTTP `/api/shutdown` signaling in `killExistingGUIServer()` to gracefully terminate any legacy GUI server processes holding port 9876 prior to starting the new server.
- **Process Memory Purge**: Cleared all lingering background daemon and test server process instances from system RAM.

---

## [v2.1.6] - 2026-07-26

### Fixed & Added
- **GUI Cross-Profile Lock Isolation (`cmd/sec-agent/gui.go`)**: Eliminated process-wide `SEC_SESSION_TOKEN` environment variable mutation in `gui.go`, preventing session tokens from leaking across profile boundaries when switching database files.
- **Atomic DOM Lock Synchronization (`cmd/sec-agent/gui.go`)**: Updated `loadStatus()` to await `loadSecrets()` and trigger `renderLockedState()` atomically, ensuring header controls and table contents stay perfectly synchronized on `🔴 Vault Locked` with the `🔓 Touch ID Unlock` button.
- **Automated Integration Test Suite (`cmd/sec-agent/gui_test.go`)**: Added `TestGUIServerProfileSwitchingAndLockIsolation` using Go's `httptest.Server` to automatically test multi-profile database creation, status checks, secrets retrieval, and Touch ID unlock transitions.

---

## [v2.1.5] - 2026-07-26

### Fixed
- **In-Memory GUI Profile Session Token Retention (`cmd/sec-agent/gui.go`)**: Implemented thread-safe in-memory session token store (`var guiTokens = map[string]string`) in `sec-agent gui`. Session tokens issued upon Touch ID authentication are securely retained in RAM for each database profile (`default`, `velocloud-provider-dev`, etc.) without ever writing tokens to disk, enabling seamless Touch ID unlock and multi-profile database inspection.

---

## [v2.1.4] - 2026-07-26

### Fixed
- **GUI Vault Lock State Alignment (`cmd/sec-agent/gui.go`)**: Updated `/api/status` to query daemon `Action: "backup"` with the session token instead of `Action: "ping"`, ensuring `unlocked: true` is strictly returned only when vault credentials are decrypted and accessible.
- **Frontend Header Lock Synchronization (`cmd/sec-agent/gui.go`)**: Updated `renderLockedState()` JavaScript function to update `statusPill` to `🔴 Vault Locked` and display the **`🔓 Touch ID Unlock`** button whenever a locked response occurs.

---

## [v2.1.3] - 2026-07-26

### Fixed & Added
- **In-Process GUI Touch ID Unlock (`cmd/sec-agent/gui.go`)**: Refactored `ensureUnlocked()` to invoke `biometrics.Authenticate()` and `store.InitializeMasterKey()` directly in-process instead of spawning an external child process, fixing Touch ID unlock failures in the Web UI browser inspector.
- **Workspace Bundle Purge (`Makefile`)**: Updated `make install-app` target to purge transient workspace `.app` build directories after copying into `/Applications/SecAgent.app`, ensuring strictly 1 application bundle exists on disk without duplicate Launchpad or Spotlight icons.

---

## [v2.1.2] - 2026-07-26

### Added
- **Single macOS Application Bundle (`SecAgent.app`)**: Cleaned up build targets and `/Applications/` to ensure strictly a single `SecAgent.app` bundle exists without duplicate workspace build icons in Launchpad or Spotlight.
- **Web UI Browser Header Version Badge (`v2.1.2`)**: Dynamically renders version badge (`<span class="badge badge-ver">v2.1.2</span>`) in the Web UI navigation header bar (`http://127.0.0.1:9876`).

---

## [v2.1.1] - 2026-07-26

### Added
- **Standardized macOS Application Bundle (`SecAgent.app`)**: Renamed macOS Application Bundle from generic name to `SecAgent.app` matching exact tool name `sec-agent` / `SecAgent`.
- **High-Resolution App Icon (`assets/AppIcon.icns`)**: Generated multi-resolution `AppIcon.icns` covering Retina and standard macOS display resolutions (16x16 through 1024x1024 @2x).
- **Application Installer (`make install-app`)**: Added Makefile target to automatically package and install `SecAgent.app` to `/Applications/` while purging stale loose executable shortcuts.

---

## [v2.1.0] - 2026-07-26

### Added
- **In-Memory Daemon Hot-Reload (`sec restart --hot-reload` / `-H`)**: Seamlessly re-executes background daemon process binary images in memory via OS kernel pipe state handoffs (`unix.Pipe()`) during CLI updates without clearing active session state or requiring Touch ID re-authentication.
- **Zero-Friction Upgrade Flow**: CLI version mismatch diagnostics now suggest `sec restart --hot-reload` to hot-reload running daemons in RAM without dropping session locks.
- **Preserved Unwritten In-Memory Secrets**: In-memory secret payloads and session state tokens are inherited directly across kernel pipe file descriptors (`SEC_REEXEC_FD=3`) with zero disk exposure.

---

## [v2.0.0] - 2026-07-26

### Added
- **Subshell Daemon Socket Peer Authorization (`subshell-peer-authorization`)**: Kernel `LOCAL_PEERCRED` UID verification and daemon RAM state unlock authorization for subshells, IDE background processes, Makefiles, and AI tool calls without needing `SEC_SESSION_TOKEN` environment variable inheritance or disk token files.
- **Zero Plaintext Tokens on Disk**: Fully purged `session_*.token` files from disk (0 bytes written to disk).
- **Hardened Visual GUI Inspector (`sec-agent gui`)**: Single-binary visual interface with token-protected session auth and TTL countdown timer.
- **Vault Taxonomy Design & Workspace Migration Guide (`docs/VAULT_DESIGN_AND_PROJECT_MIGRATION_GUIDE.md`)**: 3-phase methodology (High-Level Schema Design → Per-Workspace Vault Isolation via `.secrc` `"prefix": ""` → Migration Cleanup Checklist).
- **AI Agent Skill Updates**: Updated embedded and global `sec-agent-integration` skill to v2.0.0 with subshell resolution and workspace isolation guidelines.

---

## [v1.9.0] - 2026-07-24

### Added
- **Workstation Shell History & Leak Audit (`sec check --leaks`)**: Read-only diagnostic scanner that auto-discovers `.zsh_history`, `.bash_history`, and `fish_history`.
- **Dual-Engine Scan Architecture**:
  - **Vault Exact Match Engine**: Cross-references active stored vault secrets verbatim against local shell history lines with 100% confidence and zero false positives.
  - **Regex Pattern Engine**: Scans for untracked third-party cloud keys (AWS `AKIA...`, GitHub `ghp_...`, Stripe `sk_live_...`, Slack webhooks, DB URIs) inspired by PassDetective.
- **Redacted Output**: Sanitizes all match previews (`[REDACTED_BY_SEC]`) to guarantee zero secret echo on terminal screens.
- **Actionable Remediation Commands**: Generates exact `sed` and `history -r` commands for safe history entry purging without modifying disk files automatically.

---

## [v1.8.0] - 2026-07-24

### Added
- **Granular Subprocess Key Scoping (`sec run --allow-keys K1,K2`)**: Restricts environment variable injection exclusively to specified keys or environment aliases.
- **Subprocess Injection Dry-Run (`sec run --dry-run`)**: Displays tabular preview of key mappings without executing child commands or requesting Touch ID.
- **Side-Channel Safe Entropy Linter (`sec check --scan-weak`)**: Evaluates stored secret values against Shannon entropy thresholds ($H < 3.0$) and dictionary defaults, outputting binary PASS/WEAK status without exposing raw values or entropy numbers.
- **Encrypted Vault Sync (`sec sync export / import`)**: End-to-end encrypted vault package export and import for non-production team distribution.

---

## [v1.7.0] - 2026-07-23

### Added
- **Global Workstation Status Dump (`sec status --all` / `sec status -a`)**: Single-pane-of-glass status matrix scanning all registered profiles, daemon PIDs, Touch ID lock states, environment tiers, total/expired key counts, and namespace prefixes.
- **AI & Developer Migration Example Prompts**: Added copy-pasteable prompt templates for folder and repository migration to `SKILL.md` and user documentation.
- **Git History Secret Cleanup Warning & Remediation Protocol**: Prominent caution alert and `git-filter-repo` purge protocol added to user guides.
- **Project Vault Governance Best Practices**: Guidelines for project-scoped profiles (`--profile <project>-<env>`), namespace prefixes (`--prefix <namespace>/`), and `.secrc` configuration.

---

## [v1.6.0] - 2026-07-23

### Added
- **Rotation Command Registration (`sec set --rotate-cmd "<cmd>"`)**: Store custom rotation script commands and rotation TTLs in secret entry metadata.
- **Automated Token Rotation (`sec rotate <path>`)**: Executes registered rotation hook in a memory-isolated container, captures stdout, updates secret value, and resets expiration timer.
- **Expiring Secrets Inventory (`sec ls --expiring [days]`)**: Filter flag listing all vault entries expiring within N days (default 7 days) with remaining time reports.

---

## [v1.5.0] - 2026-07-23

### Added
- **Automatic JWT Expiration Detection**: Automatically detects JSON Web Tokens (`eyJ...`), parses base64url payload `exp` claims, and sets entry expiration automatically upon `sec set`.
- **Proactive Token Expiration Warnings**: `sec status` and `sec check` render proactive warning alerts 7 days prior to entry expiration.
- **Live Child Process Stream Redactor (`sec run --redact`)**: Intercepts child stdout and stderr streams in real time and replaces secret value strings with `[REDACTED_BY_SEC]`.
- **Cross-Environment Profile Matrix Diffing (`sec diff-profiles <p1> <p2>`)**: Side-by-side key structural comparison matrix identifying matching and missing environment keys across profiles.
- **Time-Bound Secret Leases (`sec lease <path> --ttl <duration>`)**: Grants scoped, self-destructing temporary lease tokens (`lease:<path>:<id>`) for AI subagent delegation and temporary background task execution.
- **Remote Vault Sync Security Warning**: Architectural trade-off analysis documented in `docs/user_guide.md` and `README.md` rejecting unencrypted remote vault syncing (`sec sync`) in favor of local Apple Silicon Secure Enclave isolation.

---

## [v1.4.0] - 2026-07-23

### Added
- **Profile Environment Tagging (`sec profile set-env <tier>`)**: Bind explicit environment classifications (`dev`, `dta`/`staging`, `prod`) to vault profiles to prevent developer tool executions against production orchestrators.
- **Terminal Visual Color Badges**: ANSI color-coded environment headers displayed during `sec run`, `sec status`, `sec check`, and `sec doctor` (`🟢 [ENV: DEV]`, `🟡 [ENV: STAGING]`, `🔴 [ENV: PROD - CAUTION!]`).
- **Production Confirmation Guard (`--confirm-prod`)**: Explicit confirmation guard requiring `--confirm-prod` flag or Touch ID re-authentication before executing commands against a `prod` profile.

---

## [v1.3.0] - 2026-07-23

### Added
- **Vault Schema Linter (`sec check`)**: Pre-flight validation verifying required keys or environment variable aliases against templates (`.env.example`) or CLI lists (`--required`) before running long test suites or CI/CD pipelines.
- **Subprocess Heartbeat Keep-Alive (`sec run`)**: Background 15-minute heartbeat pings sent to the daemon while a child process spawned by `sec run` executes, preventing session lock timeouts during long dev servers (`npm run dev`) or multi-hour Terraform apply cycles.
- **Non-Interactive Clean Raw Output (`sec get -r` / `--raw`)**: Suppresses non-fatal stderr warnings and prints strictly raw secret string values without trailing newlines for clean shell variable assignment (`val=$(sec get path -r)`).
- **Non-Destructive Vault Merging (`sec restore --merge`)**: Merges partial KDBX backup entries into local vault profiles without overwriting existing local keys unless `--overwrite` is explicitly specified.
- **Single-Command Daemon Restart & Upgrade (`sec restart`)**: Atomic session lock, background daemon process termination, new daemon binary launch, and Touch ID unlock prompt in one step (`eval $(sec restart)`).
- **Shell Tab Completions (`sec completion <zsh|bash|fish>`)**: Native Zsh, Bash, and Fish shell tab completion scripts for subcommands, flags, and secret path prefixes.

---

## [v1.2.0] - 2026-07-23

### Added
- **Direct Environment Key Aliasing (`--env-alias`)**: Support storing explicit target environment variable names (e.g. `sec set bgp/pass "secret" --env-alias BGP_INBOUND_PASSWORD`) so third-party tools expecting exact variable names consume them directly.
- **Automatic Session Unlock Helper (`--auto-open` / `SEC_AUTO_OPEN`)**: Automatically triggers `sec open` Touch ID unlock inline when `sec run` or `sec get` encounters a locked daemon.
- **Workspace `.secrc` / `.sec.json` Config File**: Upward directory resolution for default `profile`, `prefix`, and `auto_open` settings.
- **Onboarding Template Exporter (`sec export --format template`)**: Generates sanitized `.env.example` templates with generic `<migrated_to_sec>` placeholders for onboarding developers safely.
- **Environment Key Path Diff (`sec diff`)**: Compares secret key paths between profiles or against local `.env` files without exposing raw values to terminal output.
- **Workstation Health Doctor (`sec doctor`)**: Automated diagnostic checks for Secure Enclave biometrics, Keychain access, socket permissions (`0600`), and Hardened Runtime code signatures.
- **Cryptographic Password Generator (`sec gen` / `sec generate`)**: Generates high-entropy random passwords via `crypto/rand` and saves them directly into the enclave store.
- **Secret Key Duplication (`sec cp` / `sec copy`)**: Duplicates single keys or entire namespace trees into a new target path.
- **Bulk Vault Payload Importer (`sec import`)**: Bulk imports Doppler, AWS Secrets Manager, or custom JSON key-value files into `sec`.
- **Programmatic Version JSON Output (`sec version --json`)**: Machine-readable JSON output for version, commit, and daemon status.

---

## [v1.1.0] - 2026-07-23

### Added
- **Batch Group Secret Loading (`sec load` & `sec run --group`)**: Load or run scoped groups by prefix in a single IPC call without creating plaintext `.env` files.
- **Atomic Secret Path Renaming & Refactoring (`sec mv` / `sec rename`)**: Single key and prefix namespace refactoring (`sec mv <old> <new> [--prefix]`) preserving metadata and creation timestamps.
- **Secret Path Tree Listing (`sec ls` / `sec list`)**: Inspect stored secret key paths without exposing secret values to stdout.
- **Single & Prefix Secret Deletion (`sec rm` / `sec delete`)**: Single key and batch prefix group removal.
- **Session & Environment Diagnostics (`sec status`)**: Comprehensive summary of active daemon health, TTLs, database size, and secret counts.
- **Structured Security Access Audit Logging (`sec audit` / `sec log`)**: Automatic JSON log records appended to `~/.config/sec/audit.log` tracking caller PIDs and actions.

---

## [v1.0.0] - 2026-07-23

### Added
- Core macOS Secure Enclave master key storage via Keychain `SecAccessControl`.
- Zero raw secrets on disk (AES-256-GCM authenticated encryption).
- Hardened Runtime code signing with Touch ID biometric authorization.
- Remote SSH and ScreenSharing process tree hijacking protection.
- Portable KeePassXC `.kdbx` file backup (`sec backup`) and restore (`sec restore`).
- Dotenv migration & sanitization utility (`sec migrate-local`).
- Profile isolation (`--profile <name>`).
- Built-in AI Agent Skill (`sec-agent-integration`) for autonomous pair programming assistants.
