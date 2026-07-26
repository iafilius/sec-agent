# sec-agent Tool & Feature Triage Log

This document records feature evaluation decisions, architecture triages, and roadmap items for `sec-agent` (v1.9.1+).

---

## ✅ Accepted Capabilities (Planned for OpenSpec Proposal)

### 1. Non-Interactive Initialization Flag (`sec-agent init --non-interactive` / `-y` / `--yes`)
* **Status**: ACCEPTED
* **Description**: Add an explicit `--non-interactive` (or `-y` / `--yes`) flag to `sec-agent init` that initializes `~/.config/sec-agent/` and `~/.config/sec-agent/backups/` silently without launching terminal prompt menus, guaranteeing zero stdin hangs in automated agent setups.

### 2. Universal Machine-Readable Error Schema (`--json`)
* **Status**: ACCEPTED
* **Description**: Ensure all CLI subcommands (`get`, `set`, `run`, `init`, `status`) honor top-level `--json` or `--json-errors` flags, returning standardized error JSON on any early exit or error condition:
  ```json
  {
    "success": false,
    "error": {
      "code": "VAULT_UNINITIALIZED",
      "message": "Vault configuration directory ~/.config/sec-agent/ missing.",
      "remediation": "Run 'sec-agent init --non-interactive' to setup."
    }
  }
  ```

### 3. Subagent Temporary Lease Revocation (`sec-agent lease revoke <token>`)
* **Status**: ACCEPTED
* **Description**: Implement `sec-agent lease revoke <token>` to allow parent orchestrator agents to immediately revoke temporary lease credentials as soon as a subagent task completes, enforcing strict zero-lingering credential hygiene before the original TTL expires.

### 4. Instant Fast-Path Socket Diagnostic (`sec-agent status --quick`)
* **Status**: ACCEPTED
* **Description**: Add `sec-agent status --quick` to check Unix domain socket file existence, user ownership permissions (`0600`), and daemon process PID in <5ms without querying database locks or triggering Touch ID session checks.

### 5. Mandatory Per-Workspace Vault Isolation & High-Level Schema Design Guide
* **Status**: ACCEPTED
* **Description**: Published `docs/VAULT_DESIGN_AND_PROJECT_MIGRATION_GUIDE.md` detailing the 3-phase methodology (High-Level Schema Design → Per-Workspace Vault Isolation via `.secrc` `"prefix": ""` → Hygienic Migration & Cleanup Checklist). Included mandatory skill instructions for AI agents onboarding new project workspaces.

### 6. Subshell Daemon Peer Authorization & Zero-Disk Token Enforcement
* **Status**: ACCEPTED & IMPLEMENTED
* **Description**: Fully purged plaintext session token files (`session_*.token`) from disk (0 bytes on disk). Updated daemon socket verification to authorize subshell requests (`req.Token == ""`) via kernel peer credentials (`LOCAL_PEERCRED` UID == owner) and BSD process tree checks when daemon RAM is in `UNLOCKED` state. Ensures seamless subshell/tool execution without disk token files.

---

## ⏸️ Deferred / Rejected Roadmap Ideas

### 1. Non-Interactive Production Safety Override (`SEC_ALLOW_PROD_EXECUTION`)
* **Status**: REJECTED / DEFERRED TO FUTURE ROADMAP
* **Initial Evaluation**: Proposed environment variable override (`SEC_ALLOW_PROD_EXECUTION=1`) for running production profiles in headless cloud CI/CD pipelines (e.g., SaaS GitHub Actions runners).
* **Rejection Rationale**: Running `sec-agent` inside SaaS cloud-hosted runners breaches the foundational security model of local macOS **Hardware Secure Enclave** isolation. `sec-agent` is intentionally designed for local developer workstations and hardware-enclosed enclaves, not untrusted SaaS cloud infrastructure. Bypassing production Touch ID confirmation via environment variables on cloud runners compromises vault security.

---

## 📜 Governance Rule

> **AI Assistant Guideline**: Never edit installed skill files (`~/.gemini/config/skills/`, `.agents/skills/`, `.cursor/rules/`) directly. Always record feedback and feature decisions in this document (`docs/SEC_TOOL_FEEDBACK.md`) within the `secure_secrets` repository so canonical updates are processed centrally in `docs/skills/sec-agent-integration/SKILL.md` and distributed via `sec-agent skill update`.
