---
sec-agent-version: v2.13.4
report-date: 2026-09-22T20:05:00Z
rfc-id: RFC-20260922-MULTI-PROFILE-WORKSPACES
target-repository: secure_secrets
author: Arjan Filius & Sovereign Fleet Core Team
status: PROPOSED
---

# RFC: Multi-Environment Workspace Contexts & Production Safety Guardrails

**Target Repository:** `secure_secrets` (`sec-agent`)  
**Target Component:** CLI | Configuration Engine | Daemon IPC | Template Injection Engine  
**Evaluation Date:** 2026-09-22  

---

## Executive Summary

As `sec-agent` evolves into the authoritative secrets management and injection engine for enterprise multi-tier infrastructure (e.g. Sovereign Kubernetes Fleets with distinct Dev, Staging, and Production enclaves), workspaces regularly govern multiple environments from a single repository.

Currently, workspace scope is defined via a single static `.secrc` file (`{"profile": "xuntos-dev"}`). While powerful, this static schema introduces operational friction, operator cognitive load, and safety hazards when orchestrating multi-environment fleets.

This RFC proposes:
1. **Multi-Environment `.secrc` Schema** (backward-compatible environment alias mapping).
2. **Context Switching Engine** (`sec use <env|profile>` and ephemeral session binding).
3. **Context Visibility & Status Indicators** (environment-aware prompt segments and CLI command banners).
4. **Production Mutation Safety Guardrails** (protection against accidental production writes/deletions).
5. **Cross-Profile Template Injection** (explicit `@<profile>:<path>` references in `sec stream`).

---

## Impact & Friction Classification

- [ ] 🔴 **Tier 0: Critical Security Leak** (Plaintext exposure)
- [x] 🟠 **Tier 1: Architectural / Boundary Violation** (Accidental cross-profile mutation, lack of strict prod blast-radius isolation)
- [x] 🟡 **Tier 2: Agent & Operator Friction** (Tedious `-P <profile>` / `SEC_PROFILE` overrides across scripts and tools)
- [x] 🟢 **Tier 3: Ergonomics / Token Budget Waste** (Repetitive flags, silent context ambiguity)

---

## 1. Problem Statement & Operational Scenarios

### Scenario 1: Multi-Enclave Fleet Repository
In repository `klus_7_poc2_k8s`, operators manage both:
- **Dev Enclave (`arjanf`)**: uses profile `xuntos-dev`
- **Prod Enclave (`sandbox`)**: uses profile `xuntos-prod`

Currently, `.secrc` is statically bound to one profile:
```json
{
  "profile": "xuntos-dev"
}
```

#### Friction Points:
1. **Operator Cognitive Strain**: To run commands against `sandbox`, the operator or AI agent must remember to pass `-P xuntos-prod` or set `SEC_PROFILE=xuntos-prod` on every single command:
   ```bash
   sec -P xuntos-prod set tenants/firmo/db_password "..."
   sec -P xuntos-prod stream --template manifest.yaml.tmpl | kubectl --context sandbox apply -f -
   ```
   If an operator forgets `-P xuntos-prod`, the command silently executes against `xuntos-dev`, leading to configuration drift or broken dev deployments.
2. **No Context Indication in Prompt/CLI**:
   When running `sec set ...`, the CLI does not display which profile is being modified. There is no visual feedback indicating whether you are touching Dev or Prod.
3. **No Guardrails on Production Profiles**:
   A destructive command (`sec rm --prefix tenants/` or `sec rollback`) executes with the same friction on a production profile as it does on a disposable dev profile.

---

## 2. Situation Sketch

### Current Flow (Static & Ambiguous):
```
[Terminal / AI Agent]
        │
        ├──> 'sec set db_pass ...'
        │       │
        │       ▼
        │   Reads .secrc ({"profile": "xuntos-dev"})
        │   Silently modifies Dev (No context banner)
        │
        └──> Operator intended Sandbox/Prod!
                └──> Dev corrupted, Prod unchanged!
```

### Proposed Multi-Environment Flow:
```
[Terminal / AI Agent]
        │
        ├──> 'sec use sandbox'
        │       ▼
        │   Switches local ephemeral session to 'xuntos-prod' (Tier: PROD)
        │   Prompt updates: [sec: xuntos-prod (🔴 PROD)]
        │
        └──> 'sec set db_pass ...'
                ▼
            [PROD ⚠️] Profile 'xuntos-prod' is marked as Production!
            Modifying 'db_pass'. Proceed? [y/N]:
```

---

## 3. Proposed Enhancements

### Enhancement A: Multi-Environment `.secrc` Schema

Support an extended, backward-compatible schema in `.secrc`:

```json
{
  "version": 2,
  "default": "xuntos-dev",
  "environments": {
    "dev": {
      "profile": "xuntos-dev",
      "tier": "dev",
      "description": "ArjanF Development Enclave"
    },
    "arjanf": {
      "profile": "xuntos-dev",
      "tier": "dev"
    },
    "sandbox": {
      "profile": "xuntos-prod",
      "tier": "prod",
      "description": "Sovereign Sandbox Production Enclave"
    },
    "prod": {
      "profile": "xuntos-prod",
      "tier": "prod"
    }
  }
}
```

*Backward Compatibility*: If `.secrc` contains `{"profile": "name"}`, it continues to work identically as today with `default = name`.

---

### Enhancement B: Workspace Context Switching (`sec use` / `sec env`)

Introduce a lightweight command to switch the active context without editing files tracked by Git:

```bash
# Switch active workspace context for the current shell / directory:
sec use sandbox
# Output:
# ✓ Active workspace context switched to 'sandbox' -> profile 'xuntos-prod' (Tier: PROD 🔴)

# List configured environments:
sec env ls
# Output:
# Configured Workspace Environments:
#   * dev      -> xuntos-dev  [dev] (Default)
#     sandbox  -> xuntos-prod [prod] 🔴
```

#### Resolution Precedence:
When `sec` executes a command, it resolves the target profile in this strict order:
1. Explicit CLI flag: `-P <profile>` or `--profile <profile>`
2. Environment flag / alias: `--env <env>` (e.g. `--env sandbox`)
3. Environment variable: `SEC_PROFILE`
4. Directory session override: `.sec/context` (ephemeral, git-ignored)
5. Project `.secrc` default
6. Global fallback: `default`

---

### Enhancement C: Context Banner & Shell Prompt Integration

1. **CLI Execution Banners**:
   For any mutating operation (`set`, `rm`, `rotate`, `rollback`, `mv`, `restore-deleted`), print a 1-line context banner:
   ```text
   [sec-agent: profile=xuntos-prod | tier=prod 🔴 | key=tenants/gmp/chat_db_password]
   ```
   This gives instant visual confirmation and auditability in logs and CI/CD pipelines.

2. **Shell Prompt (`sec prompt`)**:
   Update `sec prompt --format p10k|starship|plain` to output tier styling:
   - Green `[sec: xuntos-dev]` for dev/dta tiers
   - High-visibility Yellow `[sec: staging]` for staging
   - Bold Red/Warning `[sec: ⚠️ xuntos-prod]` for prod

---

### Enhancement D: Production Mutation Guardrails

When a profile is designated with tier `prod` (via `sec profile set-env prod` or via `.secrc` `tier: prod`):
1. **Interactive Confirmation**: Destructive or mutating commands prompt:
   ```text
   ⚠️ WARNING: You are about to mutate secret 'ovh/consumer_key' in PRODUCTION profile 'xuntos-prod'.
   Are you sure? (type profile name to confirm): 
   ```
2. **Non-Interactive Bypass**: For scripts and automation, require explicit flags:
   ```bash
   sec set <path> <val> --confirm-prod
   # or
   sec set <path> <val> --force
   ```
   Without this flag in non-interactive mode (e.g. CI/CD or subagents), the command aborts with code `2` (`ErrProdSafetyHold`).

---

### Enhancement E: Cross-Profile Template Injection (`sec stream`)

In Kubernetes manifest pipelines, certain manifests may need to inject secrets from specific profiles regardless of the current active profile.

Support explicit profile prefixes in template placeholders:
```yaml
# chat-secrets.yaml.tmpl
apiVersion: v1
kind: Secret
metadata:
  name: chat-secrets
stringData:
  # Uses the currently active profile (dev or prod depending on context):
  CHAT_DATABASE_URL: "{{tenants/gmp/chat_db_url}}"
  
  # Explicitly forces extraction from xuntos-prod even if running in dev:
  SHARED_CERT_CA: "{{@xuntos-prod:shared/root_ca}}"
```

---

## 4. Implementation Plan in `secure_secrets`

1. **Phase 1: Config Parser Extension (`internal/config`)**
   - Enhance `.secrc` JSON deserializer to support schema v2 with `environments` map while maintaining 100% backward compatibility with `{"profile": "..."}`.
2. **Phase 2: Context Command (`cmd/use.go`, `cmd/env.go`)**
   - Implement `sec use <env>` and `sec env ls`.
   - Store active context in `$PROJECT_ROOT/.sec/context` (auto-added to `.gitignore`).
3. **Phase 3: Production Safety Interceptor (`internal/safety`)**
   - Add a pre-execution hook in Cobra commands checking if the resolved profile has tier `prod`.
   - Implement `--confirm-prod` and interactive prompt.
4. **Phase 4: Stream Parser Update (`internal/template`)**
   - Parse `{{@<profile>:<key>}}` syntax in `sec stream` and dispatch to the designated vault engine.

---

## 5. Summary & Recommendation

Implementing this RFC will make `sec-agent` the most ergonomic, developer-friendly, and safe secrets manager for multi-environment cloud and Kubernetes architectures. It eliminates human errors when toggling between dev and prod, prevents accidental production overwrites, and makes deployment automation radically cleaner.
