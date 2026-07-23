# Changelog

All notable changes to `sec-agent` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
