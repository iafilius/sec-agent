# Changelog

All notable changes to `sec-agent` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.19.3] - 2026-11-18

### Added & Enhanced
- **Exit-Code-Aware `rsync` Retry Classification (`sec backup run` / `sec backup batch run`)**:
  - Treats `rsync` exit code `24` (partial transfer due to vanished source files) as non-fatal without retry.
  - Stops retrying immediately after Attempt 1 on `rsync` exit code `23` (partial transfer due to local permission/TCC error) and syntax/configuration exit codes (`1..6, 11, 13, 14`), avoiding multi-attempt directory tree re-walks on TCC-protected folders and continuing immediately to the next folder.
  - Continues retrying transient network, socket, SSH, and timeout failures (`10, 12, 30, 35, 255`) up to `max_attempts` with exponential backoff.
- **macOS `openrsync` Detection & Advisory Warning (`rsyncIsOpenrsync`)**:
  - Detects when local `rsync` is Apple's `openrsync` (protocol 29, `/usr/bin/rsync`) and emits a non-fatal hint recommending `brew install rsync`.
- **Legacy Batch JSON Key Normalization (`rsync_timeout`, `ssh_options`, `backup-batch/<name>`)**:
  - Automatically normalizes `"rsync_timeout"` into `Timeout` and parses `-o ServerAliveInterval=<N>` and `-o ServerAliveCountMax=<M>` from `"ssh_options"` into `ServerAliveInterval` and `ServerAliveCountMax`, and falls back to `backup-batch/<name>` when `backup/<name>` is not found in the vault.
- **Strict Non-Interactive `sec backup` Subcommand Routing & Test Isolation**:
  - Ensures `sec backup` subcommands (even with leading flags such as `--dry-run`) never fall through to the interactive KeePassXC `.kdbx` BIP39 mnemonic prompt unless `export` or a `.kdbx` filename is explicitly specified, and isolates `TestShellPromptAndInitDirenv` from host `~/.secrc` files.

## [v2.19.2] - 2026-11-18

### Added & Enhanced
- **Stealth Multi-Folder Backup Resilience & Vault-Driven Transport Tuning (`sec backup`, `sec backup batch`)**:
  - **Per-Folder Retry with Exponential Backoff (`max_attempts`)**: Automatically retries failed folder transfers up to `max_attempts` (default `5`), doubling backoff from `5s` up to a `30m` cap and re-establishing the in-memory Go SSH session on transient connection drops. Continues to remaining folders if one exhausts retries, prints a summary, and exits `1`.
  - **In-Flight Session Keepalive & Auto-Extension (`NoTrace: true`)**: Verifies the target vault profile is unlocked upfront and runs a `10m` background keepalive ticker that automatically extends the active daemon session (`8h`) whenever remaining TTL drops below `30m`.
  - **Vault-Driven `rsync --timeout` & In-Memory SSH `ServerAliveInterval` / `ServerAliveCountMax`**: Added `--timeout <sec>`, `--server-alive-interval <sec>`, and `--server-alive-count-max <count>` (configurable per folder, per job, or at `ssh/<target>/server_alive_*` in the vault, with zero hardcoded values in source code). Sends encrypted OpenSSH `keepalive@openssh.com` probes over the in-memory Go SSH connection without spawning `/usr/bin/ssh` or exposing `-o ServerAliveInterval` in `ps aux`.
  - **Sparse File Support (`--sparse`), Default AppleDouble (`._*`) Exclusion, `~/` Source Resolution & Declarative JSON Import (`--file` / `sec backup batch`)**: Added `--sparse` (`-S`), automatic macOS AppleDouble (`._*`) exclusion via `/dev/fd/3`, first-class `"~/"` / `"~"` home-directory source resolution with `--dest <remote-folder>`, `{date}` / `{datetime}` path templates, and `sec backup init <name> --file <json>` / `sec backup batch <define|list|show|run>`.
- **Unified Single-Line & Grid Recovery Mnemonic Output (`--no-single-line`)**:
  - Standardized `sec migrate-v2`, `sec enroll-recovery`, `sec session rotate-seed`, and `sec profile new` to print both the 4-column numbered grid and the single-line `📋 Raw Mnemonic` by default, added `--no-single-line` opt-out, and updated disaster recovery documentation.

## [v2.19.1] - 2026-11-15

### Added & Enhanced
- **Stealth Multi-Folder `rsync` Backup Runner (`sec backup init / add-folder / remove-folder / show / jobs / run`)**:
  - **Encrypted Multi-Folder Backup Manifests (`backup/<name>`)**: Store multi-folder `rsync` backup configurations (`SSHTarget`, `LocalBase`, `RemoteBase`, `RemoteRsync`, `ModifyWindow`, and folder lists with exclude rules) inside the encrypted vault.
  - **Zero Local `ps aux` Path & Host Leakage (`sec ssh-stdio` Bridge)**: Executes local `rsync` with `cmd.Dir` set to the source folder (`.`), exclude rules piped over `--exclude-from=/dev/fd/3`, and `-e "<sec-bin> ssh-stdio" . sync:target`. The parent `sec-agent` process bridges an ephemeral `0600` Unix socket over an in-memory Go SSH session (`golang.org/x/crypto/ssh`) and rewrites the remote `rsync --server` command inside the encrypted SSH channel.
  - **Automatic "One Level Higher" History & Log Derivation**: Automatically derives `<remote_base>/<folder>/`, `<remote_base>/<Prefix>-History/<YYYY-MM-DD>`, and `<remote_base>/rsync_<slug>_<YYYY-MM-DD_HHMM>.log` one level higher inside `remote_base` (with optional `--history-name` and `--log-prefix` overrides).
  - **Diskless Vault SSH Authentication**: Supports both vault-stored SSH passwords (`ssh/<target>/password`) and vault-stored SSH private keys (`ssh/<target>/private_key` or shared keys) with vault-pinned host key fingerprints (`ssh/<target>/host_fingerprint`), leaving zero keys or `~/.ssh/known_hosts` entries on the host.
- **Zero-Trace Command & Script Runner (`sec exec`)**:
  - **Vault-Stored Executable Scripts (`exec/<name>`)**: Added `sec exec save <name> [--stdin]`, `sec exec show <name>`, `sec exec list`, `sec exec rm <name>`, and `sec exec <name> [-- <args...>]`.
  - **In-Memory Stdin Pipe Execution**: Feeds script bodies over an in-memory `stdin` pipe to `/bin/sh -s -- <args...>` with active stdout/stderr secret redaction and zero temporary `.sh` files or command-line script arguments in `ps aux`.
- **Daemon `NoTrace` Audit & Access-Count Suppression**:
  - Added `NoTrace bool` to `daemon.IPCRequest` (and wired it into `sec exec`, `sec backup`, and `vaultHostKeyCallback`) to suppress `audit.log` `GET` entries and `AccessCount`/`LastAccessed` disk writes during stealth operations.
- **Hybrid Workspace Security Scanner (`sec scan`)**:
  - **Multi-Engine Plaintext Credential Detection**: Combines `sec-native` recursive AST/config/entropy scanning with optional Homebrew `gitleaks` and `trufflehog` engines (`--git-history`, `--deep`, `--verify-live`, `--install-tools`).
  - **3-Tier Integration Feasibility Advisor & Action List**: Classifies every finding into `DIRECT_READY` (`sec migrate-local` / `sec run`), `NEEDS_TOOL_CONFIG_REFACTOR` (env-var/template refactoring guidance), or `NEEDS_SEC_AGENT_EXTENSION`, and exports machine-readable reports via `--json` or `--output <file>`.
- **Accessible Dual-Format Architecture Diagrams**:
  - Upgraded architecture diagrams in `README.md` and `docs/` with WCAG-accessible Mermaid `flowchart` blocks (`accTitle`, `accDescr`, high-contrast dark/light classes) paired with collapsible `<details>` plain-text walkthroughs and ASCII diagrams.

## [v2.19.0] - 2026-10-18

### Added & Enhanced
- **Companion Public Key Shredding (`sec ssh import-key --shred`, `sec ssh init --shred`)**:
  - **Automatic Companion Discovery & Overwrite**: When `--shred` is active, `sec-agent` inspects `<path>.pub` and `<path>-cert.pub`. If present, companion public keys are multi-pass overwritten with random and zero bytes, synced, and unlinked alongside the private key to leave zero forensic metadata (usernames, comments, fingerprints) on disk.
  - **`--keep-pub` Override**: Added `--keep-pub` across `sec ssh import-key` and `sec ssh init` to allow operators to preserve companion `.pub` files on disk when required for external portals or consoles.
  - **Vault Write Safety Invariant**: Ingestion preserves both private and companion public keys on disk if format parsing, passphrase decryption, or vault write fails.
- **Shared Vault Key References & Single-Point Rotation (`--key-secret`, `--shared`)**:
  - **Fabric-Wide Shared Key Ingestion (`--shared <name>`)**: Added `sec ssh import-key --shared <name> <file>` to ingest administrative deployment keys directly into `ssh/shared/<name>/private_key` with key algorithm and fingerprint metadata, decoupled from single-host targets.
  - **Shared Key Secret Pointers in Target Init**: Added `--key-secret <vault-path>` (and alias `--ssh-key-secret`) to `sec ssh init`. Bare names (e.g. `sonic_fabric`) automatically expand to `ssh/shared/sonic_fabric/private_key`. Target definitions store pointer references instead of duplicating private key bytes.
  - **$O(1)$ Runtime Dereferencing**: `sec ssh <target>` dynamically resolves key secret pointers at runtime, fetching and parsing the shared key directly in RAM to achieve instant key rotation across multi-node fabrics without target re-initialization.

## [v2.18.0] - 2026-10-18

### Added & Enhanced
- **Automated Key Ingestion Shredder (`sec ssh import-key --shred`)**:
  - **In-Memory PEM & OpenSSH Validation**: Added `sec ssh import-key <target> <file_path>` supporting direct ingestion of OpenSSH and standard PEM private keys (ED25519, RSA, ECDSA) into `ssh/<target>/private_key` with key type and fingerprint extraction. Supports `--passphrase-key` for encrypted private keys.
  - **Cryptographic Multi-Pass File Shredder (`--shred`)**: Implemented `shredFile(path)` executing multi-pass overwrite with cryptographically secure random bytes (`crypto/rand`) and zero bytes (`0x00`), each followed by `f.Sync()` before file truncation and unlinking.
  - **Vault Write Confirmation Safety Invariant**: The shredding operation is strictly executed only upon verified vault write confirmation over IPC; corrupt, unparseable, or invalid keys leave the source file on disk intact.
  - **`sec ssh init` Integration**: Added `--import-key <file>` and `--shred` flags to `sec ssh init` to import private keys into the vault during onboarding without leaving plaintext paths in `.secrc`.
- **Zero-Trace Host Sanitizer (`sec ssh sanitize`)**:
  - **Dual-Format `known_hosts` Scrubbing**: Implemented `sec ssh sanitize [<target>] [--all]` to purge target hostnames, IPs, and custom ports from `~/.ssh/known_hosts`. Supports both cleartext entries and standard OpenSSH HMAC-SHA1 hashed hosts (`|1|<salt>|<hash>`).
  - **Atomic Replacement & Backup Unlinking**: Sanitization updates the known hosts file atomically with `0600` permissions and automatically removes `~/.ssh/known_hosts.old` to prevent forensic leakage of target hosts.
  - **Automated Sanitization on Key Import**: `sec ssh import-key` automatically sanitizes the target host from `~/.ssh/known_hosts` by default, configurable via `--sanitize` / `--no-sanitize`.
- **Autocompletion & Registry Parity**:
  - Full bidirectional registry and autocompletion synchronization across Zsh, Bash, and Fish with zero command drift.

## [v2.17.0] - 2026-10-18

### Added & Enhanced
- **Vault-Stored SSH Private Keys & Zero-Trace Host Execution (`sec ssh`, `sec run --ssh-key-secret`)**:
  - **Direct Vault Key Storage & In-Memory Parsing**: Added first-class support for storing SSH private keys (ED25519, RSA, ECDSA) directly in the encrypted vault (`ssh/<target>/key` or `ssh/<target>/private_key`). Supports `--ssh-key-secret` (alias `--key-secret`) across `sec ssh` and `sec run` without temporary file writes or filesystem leakage.
  - **Native Pure Go SSH Engine as Default**: Wired `runNativeSSH` (`golang.org/x/crypto/ssh`) as default execution engine for both password and private key authentication, connecting directly in-process without invoking `/usr/bin/ssh` or `sshpass`.
  - **Zero-Trace OpenSSH Delegation (`--no-trace`)**: When delegating to system OpenSSH via `--openssh`, `--no-trace` suppresses saving host keys to disk by injecting `-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -o IdentitiesOnly=yes`, leaving zero host traces in `~/.ssh/known_hosts`.
  - **Vault-Backed TOFU & Host Key Pinning Lifecycle**: Remote host public keys are verified against SHA-256 fingerprints stored in the active vault under `ssh/<target>/host_fingerprint`. Includes automated auto-pinning (`--tofu` / `--trust-first-use`), MitM abort protection (`HOST_KEY_MISMATCH`), insecure bypass (`--insecure` / `--no-verify`), in-flight key rotation (`--update-host-key`), and lifecycle commands (`sec ssh host-key show <target>`, `sec ssh reset-host-key <target>`).
  - **Ephemeral SSH Agent for Child Processes (`sec run --ssh-key-secret`)**: In-process ephemeral SSH agent spun up from vault bytes in RAM, exposing `SSH_AUTH_SOCK` to child processes and cleanly shredded upon process exit.

## [v2.16.0] - 2026-10-07

### Added & Enhanced
- **Autonomous AI Agent Self-Unlock Protocol & Anti-Stall Remediation**:
  - **Exit 3 Imperative Stderr Banner**: When `sec-agent` encounters a locked vault (`ERR_VAULT_LOCKED`, exit 3), it now prints an unmistakable, high-priority imperative directive directly to `stderr`:
    ```
    [!] SEC-AGENT VAULT LOCKED (Exit 3)
    [!] MANDATORY AGENT DIRECTIVE: DO NOT STALL OR GIVE UP.
    [!] Run: sec open --ttl 24h
    [!] Ask user for Touch ID confirmation if needed, then resume.
    ```
    This banner is emitted across standard commands (`sec run`, `sec stream`, `sec pipe`, `sec get`, `sec env`) to immediately trigger agentic self-recovery workflows.
  - **Machine-Readable JSON Error Remediation DTO**: Extended `JSONError` structure across all JSON error paths with `can_agent_execute: true`, `remediation_cmd: "sec open --ttl 24h"`, and `action: "EXECUTE_IMMEDIATELY"`, enabling programmatic recovery for LLM tool-calling engines without text parsing.
  - **Universal Multi-Agent Rule Auto-Installation (`sec install-rules` / `sec skill install-rules`)**:
    - Added dedicated CLI command `sec skill install-rules` (with top-level alias `sec install-rules`) supporting `--global` (`-g`) and `--workspace` (`-w`) target directories.
    - Automatically detects and installs authoritative multi-agent rules into Google Antigravity (`~/.gemini/config/rules/sec-agent.md`), Cursor (`~/.cursor/rules/sec-agent.mdc`), Windsurf (`~/.windsurf/rules/sec-agent.md`), and Cline/Roo-Code (`~/.clinerules/sec-agent.md`).
    - Rule templates are embedded directly in the compiled binary, requiring zero network access or external file dependencies.
  - **`.secrc` v2 Environment `auto_open` & Timeout Inheritance**:
    - Environment profiles in `.secrc` v2 now support `"auto_open": true` to attempt biometric vault unlocking automatically when commands require active credentials.
- **Accidental Command & Shell Prompt Detection Guardrail (`sec set --stdin`)**:
  - Implemented heuristic analysis in `handleSet` to catch accidental command lines (`sec set `, `sec-agent `, `export `, `echo `, `eval `) and prompt patterns (`user@host:~$ `, `bash-.*[$#] `, `% `, `\$ `) passed into `sec set --stdin` or `sec set <path> -`.
  - Aborts execution cleanly with **exit code 2** (`INVALID_ARGUMENT`) before modifying vault data.
  - Added `--allow-command-string` and `--force` flags to allow deliberate storage of shell commands or prompt strings when intended.
- **Secret Lifecycle Hygiene Scanner (`sec list --incomplete`)**:
  - Added `--incomplete` (with aliases `--hygiene` and `--audit-hygiene`) to `sec list` to audit vault secrets against lifecycle hygiene rules.
  - Identifies secrets lacking expiration timestamps (`Expires`), descriptions (`Description` or legacy `Comment`), or operational renewal notes (`Notes`).
  - Emits aligned, human-readable terminal tables with missing field tags and actionable remediation guidance for interactive users.
  - Emits structured JSON arrays when invoked with `--json` for automated script and autonomous AI agent consumption.
- **Biometric Timeout, Attention Audio Chimes & Graceful Task Deferral**:
  - Integrated native macOS Cocoa `NSSound` Pop chime trigger on Touch ID biometric authorization prompts via Cgo.
  - Added `--timeout <duration>` flag and `.secrc` configuration (`biometrics.timeout_sec`, default 120s) for biometric authentication prompts.
  - Introduced dedicated **exit code 4 (`ERR_BIOMETRIC_TIMEOUT`)** differentiating biometric timeouts from operator cancellations (exit code 3 `ERR_BIOMETRIC_CANCELLED`), enabling autonomous AI agents to defer vault-dependent steps while completing vault-free tasks unblocked.
- **Interactive Metadata Ingestion Flow**:
  - Added optional interactive prompts in `sec set` when executed in a physical terminal without metadata flags to prompt the operator for an optional description and expiration duration after accepting the secret.
  - Cleanly bypassed in automated environments, non-interactive sessions, test mode (`SEC_TEST_MODE=1`), piped stdin, or when `--quick` / `-q` is provided.
- **AI Skill Enrichment Protocol & Parameter Guidance**:
  - Updated canonical `SKILL.md` (embedded and external integration skills) with Section 5.8: "Secret Lifecycle Metadata & Proactive Enrichment Protocol" providing standardized markdown renewal runbook templates.
  - Added Section 5.9: "Secret Hygiene Scanning & Remediation (`sec list --incomplete`)".
  - Updated `docs/operations_and_parameter_guide.md` with complete documentation for `sec set`, `sec relabel`, and `sec ls` parameters.
- **Ephemeral POSIX 0600 Temp File Handling**:
  - Added secure memory/temp file helper in `cmd/sec-agent/cmd_temp_file.go` with strict POSIX 0600 permissions and automated zero-fill shredding.
- **Homebrew Formula Modernization**:
  - Updated Homebrew tap formula DSL to use `post_install_steps` over deprecated `post_install`.

---

## [v2.15.0] - 2026-09-29

### Added & Enhanced
- **Keychain ACL Re-Sealing & Downgrade Attack Prevention (`sec keychain`)**:
  - **Automatic Re-Sealing on Upgrade**: Detects version transitions during `sec open` or master key unlocks, automatically re-sealing the Keychain item to the active binary under `kSecAccessControlBiometryCurrentSet | kSecAccessControlUserPresence`. This wipes historical binary `CDHash` authorizations from macOS Access Control Lists (ACLs), preventing downgrade attacks where an older vulnerable binary could otherwise prompt for Touch ID without macOS login password verification.
  - **Dedicated CLI Subcommand Tree (`sec keychain`)**:
    - `sec keychain prune [--profile <name>] [--all]`: Explicitly re-seals Keychain items to the active binary, purging stale historical version authorizations across a specific profile or all discovered profiles.
    - `sec keychain status [--profile <name>] [--json]`: Inspects Keychain item presence, biometry binding mode (`BiometryCurrentSet`), creation/modification timestamps, and active version sealing alignment without prompting for Touch ID.
  - **System Doctor Integration (`sec doctor`)**:
    - Added Keychain ACL audit to `sec doctor` reporting active binary alignment and warning when version drift is detected.
  - **Fail-Safe Memory Retention**:
    - Guaranteed in-memory retention of master keys during synchronous delete-and-add cycles with automatic retry to prevent key loss.
  - **Shell Autocompletion & Command Registry Parity**:
    - Registered `keychain` in `CommandRegistry` with full autocompletion across Zsh, Bash, and Fish.
- **Positional Command Disambiguation in `sec stream`**:
  - Augmented error handling when reading positional template files in `sec stream`. When a positional argument does not exist on disk, the system inspects `$PATH` via `exec.LookPath`. If it matches an executable binary (e.g. `sec stream python3 ...`), it emits an actionable hint: `"<cmd>" matches an executable on $PATH. Did you mean 'sec run -- <cmd>' or 'sec pipe <key>'?` to prevent confusion with process execution or raw secret streaming.

---

## [v2.14.4] - 2026-09-28

### Added & Enhanced
- **`sec relabel` Flag Parity for Two-Tier Metadata**:
  - Added `--desc`, `--description`, `--notes`, `--clear-desc`, and `--clear-notes` to `sec relabel` (and alias `sec edit-meta`), allowing updating or clearing descriptions and notes on existing secrets without modifying ciphertext or prompting for biometrics.
- **Unencrypted Profile Summaries & Zero-Biometric Inventory (`sec profile describe` & `sec profile ls`)**:
  - Added an optional unencrypted human-readable `Summary` string to the outer `VaultEnvelope` of `secrets_<profile>.enc` vault stores.
  - Implemented `sec profile describe <name> [--summary <text>] [--clear-summary] [--json]` to inspect or mutate profile metadata and summaries without requiring Touch ID Keychain unlocks.
  - Enhanced `sec profile new <name> [--summary <text>]` to store profile summaries upon initial envelope provisioning.
  - Formatted `sec profile ls` (and `sec profile list`) output into a structured columnar table displaying profile names, schema status (`[v2.0 Dual-Slot]`), and aligned summaries.
- **Project Root Marker Heuristic Hardening**:
  - Extended `hasProjectRootMarkers` to recognize `.arjan`, `.agent`, `config.yaml`, and `config.yml`, preventing false-positive "not a Git repository" warnings when creating `.secrc` in multi-tier repositories or workspaces.
- **Shell Autocompletion & Command Registry Bidirectional Parity**:
  - Updated `CommandRegistry` with metadata and summary flags for `relabel` and `profile`.
  - Updated shell completions across Zsh, Bash, and Fish with dynamic flag completion for `relabel` and `profile describe` / `profile new`.
  - Verified 100% bidirectional parity via `TestCommandRegistryBidirectionalParity`.
- **AI Skill & Documentation Sync**:
  - Updated embedded `SKILL.md`, external integration skill, and `README.md` to `v2.14.4`.

---

## [v2.14.3] - 2026-09-28

### Added & Enhanced
- **Subprocess Standard Input Streaming (`sec run --stdin-key` & `sec pipe`)**:
  - Implemented `sec run --stdin-key <key>` to inject secret values directly into a child subprocess's standard input stream in memory.
  - Added default trailing newline (`\n`) appending required by CLI password prompts (e.g. `keepassxc-cli`, `gpg`, `docker login`), with `--stdin-raw` / `--stdin-no-newline` flag to stream exact raw bytes without newline modification.
  - Implemented `sec pipe <key>` as a dedicated, pure binary streaming command outputting the raw decrypted secret directly to stdout with zero prefixes or ANSI color escapes, returning exit code 0 on success, 2 on not found, and 3 when locked.
- **Two-Tier Secret Metadata Architecture (`Description` & `Notes`)**:
  - Added first-class `Description` (concise single-line summary) and `Notes` (unbounded multiline documentation) fields to `store.SecretEntry` and `store.SecretVersion` while maintaining 100% backward compatibility with legacy v2.0 vault envelopes.
  - Updated `sec set` with `--desc` / `--description` and `--notes` flags.
  - Modernized `sec ls` table layout to feature a dedicated `DESCRIPTION` column with dynamic terminal truncation, falling back seamlessly to legacy `Comment`.
- **Secret Metadata Inspection & Interactive Editor (`sec describe` & `sec edit-notes`)**:
  - Implemented `sec describe <key> [--json]` providing a structured human-readable or JSON overview of secret metadata, creation/modification timestamps, version history, read metrics, and multiline notes.
  - Implemented `sec edit-notes <key>` to edit operational notes via `$EDITOR` using a secure 0600 temporary file with zero-fill memory wiping on exit and strict non-interactive terminal barrier protection (exit code 78).
- **Command Registry, Shell Completion & Universal Help Parity**:
  - Registered `describe`, `edit-notes`, and `pipe` subcommands along with flags for `set` and `run` in `CommandRegistry`.
  - Updated bidirectional completion parity tests and autocompletion generators across Zsh, Bash, and Fish shells.
- **AI Agent Skill & Documentation Synchronization**:
  - Updated embedded `SKILL.md`, external skill docs, and root `README.md` to version `v2.14.3` with detailed usage guidelines and examples.

---

## [v2.14.2] - 2026-09-24

### Added & Enhanced
- **Upfront Recovery Seed Choice in Profile Provisioning**:
  - `sec profile new <name>` now presents an upfront interactive prompt before generating any mnemonics, allowing operators to choose between generating a fresh 24-word seed phrase or directly linking an existing master recovery seed.
  - Linking an existing seed avoids printing throwaway mnemonics and security warnings to the screen.
- **Direct Seed Linking Flags (`--reuse-seed` / `--existing-seed`)**:
  - Added `--reuse-seed` and `--existing-seed` flags to `sec profile new` to bypass the selection menu and prompt directly for an existing 24-word master recovery seed phrase.
- **Command Registry & Shell Autocompletion Sync**:
  - Registered `--reuse-seed` and `--existing-seed` in `CommandRegistry` usage and flags with 100% bidirectional parity across Zsh, Bash, and Fish completion generators.
- **Comprehensive Unit Tests**:
  - Added unit test scenarios covering upfront choice selection, `--reuse-seed` / `--existing-seed` flag handling, word verification fallback switching (`r`), and non-interactive barriers.
- **Documentation & AI Skills Sync**:
  - Updated embedded skill (`cmd/sec-agent/SKILL.md`), external skill (`docs/skills/sec-agent-integration/SKILL.md`), and `README.md` with upfront recovery seed linking guidelines and cryptographic independence notes.

---

## [v2.14.1] - 2026-09-22

### Added & Enhanced
- **Profile Provisioning Ergonomics & Sensitive Directory Guard**:
  - `sec profile new --secrc` logs the absolute path of the generated `.secrc` configuration file and explicitly displays directory scoping rules (`Active for this directory and all subdirectories`).
  - Emits an advisory security warning when `.secrc` is provisioned inside sensitive global directories (`$HOME`, `$HOME/bin`, `/usr/local/bin`, `/tmp`), preventing accidental workstation-wide secret scope contamination.
- **Dual-Audience Daemon Error Remediation**:
  - Formatted daemon connection and lock diagnostics to simultaneously provide direct copy-paste remediation for interactive human operators (`eval $(sec open)`) and structured protocol instructions for autonomous AI coding agents and IDE runners.
  - Added prominent Autonomous Agent Biometric Protocol callouts in `SKILL.md` advising agents to verify session longevity (`sec status`) and request upfront biometric authorization at Turn 1 to prevent mid-session stalls.
- **Flexible Filepath & Positional Template Support in `sec stream`**:
  - Extended `sec stream` to read templates from filepaths via `-f` / `--file <path>` and as direct positional arguments (`sec stream <file>`).
  - Added automatic regular file detection when `--template <string>` matches an existing readable file on disk.
  - Updated command registry, usage documentation, and shell autocompletions (Zsh, Bash, Fish).
- **`.secignore` Wildcard Basename Matching & Template Entropy Normalization**:
  - Enhanced `ShouldIgnoreFile` to match `filepath.Base(file)` when a rule contains no `/`, providing full `.gitignore` wildcard parity across nested subdirectories (e.g., `*.tmpl` suppressing `terraform/prod/.secrets.tmpl`).
  - Updated `IsHighEntropyString` to strip mustache template placeholders (`\{\{[^}]+\}\}`) prior to evaluating token length and Shannon entropy, eliminating false-positive git pre-commit blocks while preserving exact-match secret leak detection.
- **Documentation & GitHub Showcase**:
  - Elevated `README.md` hero section with a visual Core Capabilities grid and modernized Solution Comparison Matrix.

---

## [v2.14.0] - 2026-09-22

### Added & Enhanced
- **Multi-Environment Workspace Contexts (`.secrc` Schema v2)**:
  - Extended workspace configuration (`.secrc` / `.secenv` / `.sec.json`) to support schema v2 with `environments` map and `default` selection, preserving 100% backward compatibility for legacy v1 single-profile configurations.
  - Added strict 5-tier environment resolution precedence: CLI flag overrides (`-P` / `-E`), environment variables (`SEC_ENV` / `SEC_PROFILE`), workspace `.secrc` defaults, and global `default` profile.
- **Process-Isolated Context Switching (`sec use` & `sec env`)**:
  - Implemented `sec use <alias>` and `eval $(sec use <alias>)` to switch subshell environment contexts in memory via POSIX exports (`SEC_ENV`, `SEC_PROFILE`) with zero shared disk files.
  - Implemented `sec use --clear` to reset shell context to default workspace bindings.
  - Implemented `sec env ls` / `sec env` displaying discovered workspace environments with active indicators (`*`), profile bindings, and ANSI color-coded tier badges (`[dev]`, `[staging]`, `[prod 🔴]`), with full `--json` support.
  - Added legacy secret export fallback for `sec env <prefix>` when executed in non-multi-environment or single-profile vaults.
  - Added global `-E <alias>` and `--env <alias>` command-level flag overrides.
- **Production Blast-Radius Mutation Guardrails**:
  - Intercepted all mutating subcommands (`set`, `rm`, `mv`, `rollback`, `restore-deleted`, `rotate`) targeting `tier: "prod"`.
  - Enforced interactive TTY prompt confirmation requiring typing `yes` before mutating production vaults.
  - Enforced non-interactive abort with exit code 2 and structured error code `PROD_MUTATION_CONFIRMATION_REQUIRED` for scripts, CI/CD runners, and AI agent tool calls unless `--confirm-prod` or `SEC_CONFIRM_PROD=1` is provided.
  - Preserved frictionless pass-through for all read-only operations (`get`, `ls`, `history`, `export`, `run`, `stream`).
- **Cross-Profile Template Interpolation (`sec stream`)**:
  - Enhanced template placeholder parsing in `sec stream` to support cross-profile syntax `{{@<alias_or_profile>:<key>}}` alongside standard `{{<key>}}` placeholders.
  - Added actionable diagnostic error reporting with remediation steps when a target cross-profile daemon is locked or stopped.
- **Shell Ergonomics & Autocompletions**:
  - Updated `sec prompt` with multi-environment tier formatting (e.g. `[sec: sandbox (xuntos-prod 🔴)]`).
  - Synchronized Zsh, Bash, and Fish autocompletions for `use`, `env`, `-E`, `--env`, and `--confirm-prod`, verified via automated bidirectional flag parity testing.

---

## [v2.13.4] - 2026-09-22

### Fixed & Enhanced
- **Daemon POSIX Session Detachment & SIGHUP Immunity**:
  - Configured `ensureDaemonRunning` to launch background daemons with `SysProcAttr: &syscall.SysProcAttr{Setsid: true}` and decouple standard streams (`Stdin`, `Stdout`, `Stderr`) to `/dev/null`.
  - Added `signal.Ignore(syscall.SIGHUP)` in `runDaemon` to guarantee background daemon persistence when spawned from short-lived subshells, subagents, or IDE terminal runners.
- **Strictly Non-Mutating Read-Only Commands & Opt-In Skill Sync**:
  - Early-dispatched informational and read-only commands (`version`, `--version`, `-v`, `help`, `--help`, `-h`, `completion`) prior to skill synchronization hooks, ensuring zero disk mutations during inspection.
  - Refactored `syncInstalledSkillsIfOutdated()` into a non-intrusive advisory notification on `stderr`, directing operators and AI agents to run `sec-agent skill update` instead of silently overwriting workspace files.
- **Global `--verbose` / `-V` CLI Flag Handling**:
  - Intercepted global `--verbose` and `-V` flags at root CLI entry point, supporting standalone execution (`sec-agent --verbose`) and subcommand modifier positions (`sec-agent --verbose status` / `sec-agent status --verbose`).
  - Standalone `--verbose` displays a comprehensive categorized command overview alongside runtime environment introspection (profile, config paths, daemon socket status).
  - Emits detailed socket probe, IPC action, and connection diagnostics to `stderr` when verbose mode is active.
- **Skill Scope Veracity & Manifest Auto-Healing**:
  - Implemented `determineSkillScope()` to enforce scope truth from physical file paths, auto-healing mislabeled `(global)` entries for workspace-relative skill installations in `skills_manifest.json`.
- **AI Agent Direct Biometric Execution & Persistence Guidance**:
  - Updated AI agent integration instructions (`SKILL.md`) and `.github/copilot-instructions.md` template to direct AI agents to execute `sec open` directly at Turn 1, documenting native macOS system UI rendering and 8-hour daemon persistence across independent tool turns.

---

## [v2.13.3] - 2026-09-22

### Added & Enhanced
- **Foreground Process Group Handover & Signal Forwarding (`sec run`)**:
  - Implemented terminal controlling foreground process group handover via `unix.TIOCSPGRP` with terminal state preservation and graceful cleanup (`tcsetpgrp`).
  - Child interactive processes (e.g. `az login`, `terraform`, REPLs) now directly receive terminal keyboard inputs and job control signals without stall.
  - Forwarded asynchronous POSIX signals (`SIGINT`, `SIGTERM`, `SIGHUP`, `SIGWINCH`) to child process groups.
- **Prefix-Aware Dynamic Stream Redaction**:
  - Enhanced stream redaction in `redactWriter` with an idle timer flush (25ms) so interactive prompts without trailing newlines (e.g. `[y/N]: ` or `Password: `) display immediately while preventing secret token boundary leaks.
- **Non-TTY Plaintext Safety Guard (`sec get`)**:
  - `sec get` now strictly requires `--raw` when standard output is redirected or piped (`!term.IsTerminal(os.Stdout)`), preventing accidental secret exposure in agent prompt contexts, scripts, or redirected log files.
- **Structured Daemon Failure & Security Audit Logging**:
  - Added structured audit trail logging for daemon authorization failures, profile mismatches, invalid token rejections, locked vault attempts, and lifecycle transitions.
- **Workspace Scope Enforcement & Integrity Hashing in `skill status`**:
  - `skill status` and `skill update` now verify workspace boundaries and display SHA-256 content hashes alongside skill versions across tracked IDE configurations.
- **Critical Recovery Seed Warning Banners**:
  - Enhanced `sec profile new` and `sec export` to display clear, prominent warning banners emphasizing the absolute criticality of offline recovery seed storage.
- **AI Agent Direct Biometric Execution Protocol**:
  - Updated AI agent integration instructions (`SKILL.md`) to execute Touch ID-prompting commands directly in the active terminal rather than delegating operator window switching.

---

## [v2.13.2] - 2026-09-16

### Added & Enhanced
- **In-Flight Session Extension (`sec extend`)**:
  - Added the `sec extend [--ttl <duration>] [--grace <duration>] [--profile <name>]` subcommand and daemon IPC action (`IPCActionExtend`).
  - Allows an authenticated client holding a valid session token to push back daemon expiration in memory without triggering Touch ID biometric prompts.
  - Automatically resets and extends auto-termination and grace period deadlines.
- **Workspace `.secrc` Duration Fallback**:
  - `WorkspaceConfig` now parses optional `ttl` and `grace` duration parameters (e.g. `"ttl": "24h"`, `"grace": "2h"`).
  - `sec open` automatically inherits these workspace-configured durations when explicit command-line flags are omitted.
- **Turn-1 Long-Job Session Longevity Protocol**:
  - Integrated explicit rules and instructions across `cmd/sec-agent/SKILL.md`, `cmd_skills_init.go`, and `.agents/AGENTS.md`.
  - Mandates AI agents verify session TTL at Turn 1 and proactively extend session lifetime or guide the operator to unlock with sufficient duration prior to running unattended tasks (e.g. `/goal`, overnight builds, migrations).
- **Synchronized Shell Autocompletions**:
  - Registered `extend` with `--ttl`, `--grace`, and `--profile` options in `registry.go`, automatically providing autocompletion scripts for Zsh, Bash, and Fish.

### Fixed
- **macOS SDK Tapi Linker Resilience**:
  - Added automatic SDK detection and fallback in `Makefile` to prevent linker tapi architecture errors (`arm64e.x1-macos`) during builds on macOS systems.

---

## [v2.13.1] - 2026-09-14

### Fixed
- **PROD Confirmation Gate Fatigue**:
  - Interactive production confirmation is now session-bound; confirming production execution persists in daemon memory for the duration of the session TTL rather than prompting on every single invocation.
  - Formally registered `--confirm-prod` in `registry.go` and synchronized shell completions for Zsh, Bash, and Fish.
  - `--dry-run` now bypasses production confirmation entirely, ensuring dry-runs and secret injection inspections are never blocked.
  - Profile environment detection now correctly falls back to parsing profile names (e.g. `prod`, `production`) when explicit `__profile_env__` tags are absent.
- **Daemon Deduplication & Mutual Exclusion**:
  - Added advisory file locking (`unix.Flock`) on `~/.config/sec-agent/sec-agent_<profile>.lock` preventing multiple concurrent daemon processes for the same profile.
  - Implemented automatic idle termination after 30 minutes of inactivity while unauthenticated/locked.
  - Added socket inode displacement and removal monitoring to automatically terminate orphaned daemons.
  - Fixed `ensureDaemonRunning` to always pass `--profile <profile>` when spawning daemons for non-default profiles.
- **Subprocess Tree & Orphaned Process Reaping**:
  - `sec run` now assigns subprocesses to their own dedicated process group (`Setpgid: true`) and forwards termination signals to `-pgid`, ensuring background scripts, child processes, and grandchildren are cleanly reaped upon exit rather than lingering as orphans.

### Added & Enhanced
- **Daemon Diagnostics (`sec daemon list` / `sec daemon ps`)**:
  - Added `sec daemon list` and `sec daemon ps` (with optional `--json`) for fast, non-blocking visibility into all running and stale daemon processes.
  - Enhanced `sec doctor` to detect duplicate daemon anomalies across running processes and display actionable `sec restart --profile <profile>` remediation.

---

## [v2.13.0] - 2026-09-13

### Fixed
- **Remote-Session-Hijack False Positive (`remotepairingd`)**: Removed Apple's Continuity/RemotePairing daemon (`remotepairingd`) from the daemon's hijack-detection process list. It runs persistently on most Macs regardless of any active remote-control session, and its mere presence was causing the daemon to wipe its in-memory vault cache and deny every secret-touching command (`get`, `run`, `list`, `audit`, `status`) — even read-only ones.
- **`sec status --quick` False-Healthy Report**: `handleStatusQuick` now checks the daemon ping response's `Success` field, not just transport-level connectivity, so a hijack-denied or otherwise-denied session is reported as `LOCKED`/`DENIED` instead of `ACTIVE`.

### Added & Enhanced
- **Hijack-Denial Audit Trail**: Every `ACCESS DENIED` hijack decision now writes an `audit.log` entry recording the triggering signal (process match, SSH environment variable, or SSH process ancestry) and the matched process name/PID, making denials diagnosable after the fact instead of leaving no trace on disk.

---

## [v2.12.0] - 2026-09-12

### Added & Enhanced
- **Vault Envelope Self-Healing & Peeling Protection**:
  - Implemented transparent multi-envelope iterative loop peeling in `store.ReadVaultEnvelope` and `store.LoadStore`, resolving `cipher: message authentication failed` caused by legacy re-wrap nesting (up to 50 depth levels) without requiring user intervention.
  - Added pre-save invariant validation in `store.SaveStore` to verify ciphertext bytes never unmarshal as a V2 vault envelope, returning typed `store.ErrNestedPayload` before touching disk.
  - Implemented offline un-nesting engine primitive `store.FlattenVaultFile` with automatic `.bak_nested` backup generation and atomic file replacement.
- **Offline CLI Diagnostics & Repair Mode (`sec doctor --repair`)**:
  - Extended `sec doctor` to audit envelope nesting depth across all local profile `.enc` files and report nesting anomalies even in non-interactive/headless (`--skip-keychain`) mode.
  - Implemented `sec doctor --repair` to inspect and flatten all detected multi-nested profile vaults offline without requiring Keychain biometrics, active sessions, or recovery seed phrases.
  - Synchronized shell autocompletion (`sec completion`) across Zsh, Bash, and Fish for `--repair`.
- **Proactive Feedback Guidance & Touchpoints**:
  - Added feedback invitation footers to `sec doctor` and `sec version` pointing users and agents to `sec feedback` and upstream issue trackers.
  - Updated embedded AI agent integration skill (`SKILL.md`) with explicit guidance on offline envelope recovery and a proactive feedback escalation directive for unexpected runtime friction.

---

## [v2.11.0] - 2026-09-08

### Added & Enhanced
- **CLI Parameter Parity & Registry Realignment**:
  - Replaced phantom `--show` in `sec get` documentation with canonical `--raw` (`-r`) and registered missing parameters `--prefix`, `--record`, and `--show-expired`. Added `--show` as a backwards-compatible alias for `--raw`.
  - Registered missing handler flags in `registry.go` across multiple core subcommands:
    - `set`: Added `--expires` (`-e`), `--rotate-cmd`, `--rotate-ttl`, `--env-alias` (`-a`), `--meta` (`-m`), `--comment` (`-c`).
    - `ls`: Added `--long` (`-l`), `--stale [N]`.
    - `open`: Added `--ttl`, `--grace`.
    - `export`: Added `--all-profiles`, `--envelope`, `--no-envelope`, `--format` (`-f`).
    - `check`: Added `--required` (`-r`), `--ping-host`, `--template` (`-t`), `--scan-weak` (`-w`), `--scan-scripts`.
    - `prompt`: Added `--profile`.
    - `profile`: Added `--seed`, `--secrc`, `--no-secrc`.
    - `ssh`: Added `--ssh-key`, `--ssh-passphrase-key`, `--port`, `--host`, `--user`, `--password`, `--key`, `--secrc`, `--no-secrc`.
    - `githook`: Added `--global`.
    - `ide-proxy` & `env-file`: Added `--profile`.
  - Integrated `sec backup import <file.kdbx>` and top-level `sec restore <file.kdbx>` with `handleRestore` (supporting password input, `--merge`, `--overwrite`, and `--full-metadata`).
- **AI Skill Discovery Hardening & Recursive Loop Fix**:
  - Fixed `sec-agent skill show` recursive loop: running `sec-agent skill show` without `--target` now defaults to displaying the full canonical manual (`embeddedSkillBytes`), while explicit `--target copilot` continues to serve the 20-line quick reference.
  - Multi-IDE target path alignment: aligned `SKILL.md` target tables with `cmd_skills_init.go` (`resolveSkillPath`) by removing non-existent target `copilot-agent`, updating Cursor rule to `sec-agent.mdc`, updating Claude rule to `sec-agent.md`, and documenting Windsurf (`.windsurfrules`).
- **Automated Verification & Test Safety**:
  - Added `TestCommandRegistryBidirectionalParity` in `cmd_shell_completion_test.go` verifying across all 45 registered commands that every documented parameter in `Usage` exists in `Flags`, and every flag in `Flags` is in `Usage` (or is a registered backwards-compatible alias).
  - Added `TestCommandRegistryFlagExecution` with 9 isolated subtests under `SEC_TEST_MODE=1` verifying execution safety of `--raw`, `--show`, `--show-expired`, `--expires`, `--rotate-cmd`, `--long`, `--stale`, `--all-profiles`, `backup export`, `backup import`, and `restore` without touching user vaults or macOS Keychain biometrics.

### Fixed & Hardened
- **Diagnostics & Redaction Hardening**:
  - Fixed `sec status --quick` socket ping to perform live connection probes and detect orphaned socket files without false-positive reporting.
  - Hardened sliding-window stream redaction against multiline tokens and prefix-matching corner cases.
  - Masked secret values in non-interactive / agent terminals unless explicit `--raw` flag is passed.

---

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
