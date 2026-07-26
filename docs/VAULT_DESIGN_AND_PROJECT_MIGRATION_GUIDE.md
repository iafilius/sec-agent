# 🔒 Vault Taxonomy Design & Workspace Migration Guide

This guide establishes the mandatory 3-phase methodology for designing secret database schemas, isolating workspace project vaults, and performing hygienic migrations with `sec-agent`.

---

## 📐 1. Phase 1: High-Level Taxonomy Design First

**Rule**: Always design the high-level domain secret schema *before* populating secret values into vault stores. Avoid populating secrets on-the-fly without an agreed-upon key taxonomy.

### Key Naming Convention
Use standard relative domain trees:
```
<domain>/<subsystem>/<attribute>
```

#### Canonical Example:
```
orchestrator/
  ├── vco_url
  ├── vco_token
  └── vco_enterprise_id
bgp/
  ├── inbound_password
  └── outbound_password
ipsec/
  └── psk
wifi/
  └── passphrase
```

### Anti-Patterns to Avoid
1. ❌ **Tool-Prefixed Duplication**: Storing `terraform/vco-token` alongside `orchestrator/vco_token`. Keys should represent the underlying credential domain, not the consuming utility.
2. ❌ **Flat Unscoped Keys**: Storing `token` or `url` at root level without domain context.
3. ❌ **Inconsistent Casing**: Mixing `snake_case` (`vco_url`) and `kebab-case` (`vco-url`) for the same entity. Use `snake_case` for attribute names.

---

## 🛡️ 2. Phase 2: Per-Workspace Vault Profile Isolation

**Rule**: Every repository/workspace project MUST target a dedicated vault profile. Never store project-specific secrets in the `default` vault profile.

### Workspace `.secrc` Configuration
Add `.secrc` to the root of your project workspace:

```json
{
  "profile": "velocloud-provider-dev",
  "prefix": "",
  "env": "dev",
  "auto_open": true
}
```

### Why Set `"prefix": ""`?
Setting `"prefix": ""` ensures command calls like `sec get orchestrator/vco_url` resolve directly to `orchestrator/vco_url` inside `secrets_velocloud-provider-dev.enc`.

If `"prefix"` were set to `"velocloud-provider-dev/"`, the key would be double-scoped inside an already-dedicated profile store (`secrets_velocloud-provider-dev.enc` -> `velocloud-provider-dev/orchestrator/vco_url`).

---

## 🧹 3. Phase 3: Migration & Hygienic Cleanup Protocol

When onboarding an existing project or migrating legacy unisolated secrets, follow this checklist to prevent vault store clutter and orphaned sockets.

### Migration Checklist

1. **Export Safety Backup**:
   ```bash
   sec-agent -P <project-profile> backup <project>-secrets-dev.kdbx
   ```
2. **Re-key / Import to Dedicated Profile**:
   Ensure keys in `secrets_<project-profile>.enc` use canonical relative paths (`orchestrator/vco_url`).
3. **Purge Legacy Keys from Default Profile**:
   If secrets were originally stored in `secrets.enc` (the default profile), remove them:
   ```bash
   sec-agent rm <legacy-prefix> --prefix --permanent
   ```
4. **Clean Orphaned Socket and Store Files**:
   Inspect `~/.config/sec-agent/` and remove deprecated files:
   - Old database stores: `secrets_legacy.enc`
   - Orphaned daemon sockets: `sec_legacy.sock`, `sec-agent_legacy.sock`
   - Orphaned tokens: `session_legacy.token`
5. **Verify Resolution**:
   ```bash
   sec-agent -P <project-profile> ls --json
   sec-agent -P <project-profile> status
   ```
6. **Re-export Clean Portable Backup**:
   ```bash
   sec-agent -P <project-profile> backup <project>-secrets-dev.kdbx
   ```
