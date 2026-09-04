# sec-agent Disaster Recovery & Backup Restoration Handbook

This handbook details emergency procedures for inspecting backups, restoring vault databases, and re-authenticating sessions in `sec-agent` (v2.1+).

---

## 🛡️ Overview of Vault Architecture (v2.0 Dual-Slot)

sec-agent v2.0+ vaults have **two access slots** protecting the master key:

| Slot | Method | When Used |
|------|--------|-----------|
| **Slot 0** | Touch ID / Face ID (kSecAccessControlBiometryCurrentSet) | Normal daily operation |
| **Slot 1** | 24-word BIP39 recovery mnemonic (Argon2id-derived) | Recovery after Touch ID failure, hardware change |

In addition, two backup layers protect your data:

1. **Point-in-Time Vault Snapshots** (`~/.config/sec-agent/snapshots/<profile>/`):
   Before write mutations and restores, sec-agent fsync's an encrypted `.enc` snapshot alongside an indexed `.meta.json` sidecar file containing SHA-256 master key fingerprints, secret counts, and actor metadata.
2. **Manual Portable Exports** (`.kdbx`, `.json`, `.csv`):
   Portable encrypted archives created via `sec backup export <file.kdbx>`.

---

## 🔑 Recovery Path 1: BIP39 Mnemonic Recovery (Touch ID Lost/Changed)

Use this when:
- Touch ID is no longer working (hardware failure, OS reinstall, fingerprint set change)
- Your vault is in v2.0 format and you have your 24-word recovery mnemonic

```bash
# Interactive recovery — requires a real terminal (TTY)
sec session recover
```

What happens:
1. You are prompted to enter your 24-word mnemonic (one line, space-separated)
2. Argon2id key derivation runs (~5 seconds) — no key material is written to disk
3. The vault payload is test-decrypted to confirm the mnemonic is correct
4. The master key is re-enrolled in the macOS Keychain with Touch ID protection
5. Run `sec open` to start a fresh session

**Security rules:**
- `sec session recover` will REFUSE to run in non-interactive (piped/scripted) sessions
- Never type your mnemonic into a chat, AI assistant, or shell script
- The command exits 78 (EX_CONFIG) if no TTY is detected

---

## 🔄 Snapshot Restoration & Schema Verification

```bash
# List indexed point-in-time snapshots with key fingerprint matching
sec snapshot list (alias: sec snapshots)

# Create a manual point-in-time snapshot
sec snapshot create [--comment "note"]

# Restore an internal snapshot (creates pre-restore safety snapshot automatically)
sec snapshot restore <SNAPSHOT_ID> [--force]

# Import external KeePassXC archives
sec backup import my_vault_backup.kdbx --merge
```

### Snapshot Metadata Sidecar Schema (`<snap_id>.meta.json`)
Point-in-time snapshots use JSON Schema [snapshot_meta.schema.json](file:///Users/arjan/personal/secure_secrets/docs/schemas/snapshot_meta.schema.json):

```json
{
  "id": "snap-20260810-180656-11",
  "profile": "default",
  "created_at": "2026-08-10T18:06:56.11Z",
  "trigger_reason": "manual",
  "actor": "terminal",
  "master_key_sha256": "d17ec93086938fd8",
  "schema_version": "2.0",
  "secret_count": 17,
  "file_path": "~/.config/sec-agent/snapshots/default/snap-20260810-180656-11.enc",
  "comment": "Test manual snapshot",
  "key_match": true
}
```

### Operations Flight Data Recorder Schema (`operations.log`)
All administrative operations log structured entries adhering to JSON Schema [operations_log.schema.json](file:///Users/arjan/personal/secure_secrets/docs/schemas/operations_log.schema.json):

```json
{
  "timestamp": "2026-08-10T18:06:56Z",
  "actor": "terminal",
  "action": "SNAPSHOT_CREATE",
  "profile": "default",
  "master_key_sha256": "d17ec93086938fd8",
  "details": "Created snapshot snap-20260810-180656-11",
  "success": true
}
```

---

## 🔄 Step 2: Restoring a Vault Snapshot or Backup

### Option A: Restoring from an Automatic Write Snapshot (`.enc`)
```bash
sec restore ~/.config/sec-agent/backups/secrets_20260725_100000.enc --overwrite
```

### Option B: Restoring from a KeePassXC Backup (`.kdbx`)

If the KDBX was created by `sec backup` without `--custom-password`, the password is the
Argon2id key derived from your 24-word mnemonic + the vault's Argon2 salt.

```bash
# Merge missing entries into existing vault
sec restore vault_backup.kdbx --merge

# Overwrite active vault completely
sec restore vault_backup.kdbx --overwrite
```

When prompted for the KDBX password, use the deterministic value:

```text
KeePassXC password = Argon2id(mnemonic, vault_slot1_salt) as hex string
```

> Alternatively, open the KDBX in KeePassXC by computing the Argon2id key:
> `argon2 -id -t 3 -m 16 -p 4 -l 32 <mnemonic> <salt_hex> | xxd -p`

---

## 🔁 Step 3: Restarting Daemon & Re-authenticating Session

After restoring, reload the session:

```bash
sec restart
eval $(sec open)
```

---

## 🆙 Upgrading to v2.0 Dual-Slot (First-Time Setup)

If your vault is still on v1.0 (no BIP39 recovery key enrolled):

```bash
# Requires interactive TTY — will generate and display 24 words
sec migrate-v2
```

What happens:
1. 24 words are displayed — write them on paper NOW
2. You verify 3 random words before the upgrade proceeds
3. Vault is atomically rewritten to v2.0 JSON envelope format
4. If interrupted (Ctrl+C, power loss), re-run `sec migrate-v2` — it's safe to retry

---

## 🤖 AI Assistant Emergency Troubleshooting Guide

**If vault is uninitialized:**
1. Run `sec init` to initialize config directory
2. Run `sec open` to authenticate

**If Touch ID fails (v2.0 vault):**
1. Run `sec session recover` in an interactive terminal
2. Enter the 24-word mnemonic when prompted
3. Run `sec open` after recovery completes

**If Touch ID fails (v1.0 vault without recovery key):**
1. Restore from the most recent `.enc` snapshot: `sec restore <snapshot.enc> --overwrite`
2. Run `sec restart` and `eval $(sec open)`
3. Upgrade to v2.0 immediately: `sec migrate-v2`

**CRITICAL for AI agents:**
- NEVER attempt to read, log, or pass a recovery mnemonic to any external system
- `sec session recover` and `sec migrate-v2` are intentionally TTY-locked
- These commands will exit with code 78 if invoked non-interactively


---

## 🛠️ Overview of Backup Architecture

`sec-agent` maintains two layers of database backups:

1. **Automatic Atomic Snapshots (`~/.config/sec-agent/backups/`)**:
   Before every database mutation, `sec-agent` writes an encrypted snapshot payload to `~/.config/sec-agent/backups/<profile>/secrets_<timestamp>.enc`. The last 10 snapshots are rotated automatically.
2. **Manual KeePassXC Exports (`.kdbx`)**:
   Portable encrypted KeePassXC files created explicitly via `sec-agent backup <file.kdbx>`.

---

## 🔍 Step 1: Listing Available Vault Snapshots & Backups

To inspect all automatic write snapshots and local KeePassXC backup files:

```bash
sec-agent backup list
```

*Example Output*:
```text
=== 📁 sec-agent Vault Snapshots & Backups ===
Search Path: ~/.config/sec-agent/backups

Automatic Write Snapshots (.enc):
  • secrets_20260725_100000.enc  (4908 bytes, 2026-07-25 10:00:00)
    Path: ~/.config/sec-agent/backups/secrets_20260725_100000.enc
  • secrets_20260724_204900.enc  (3391 bytes, 2026-07-24 20:49:00)

Local KeePassXC Backup Files (.kdbx):
  • my_vault_backup.kdbx  (5120 bytes, 2026-07-24 18:00:00)

To restore a backup or snapshot, run:
  sec-agent restore <file-path> [--merge|--overwrite]
```

---

## 🔄 Step 2: Restoring a Vault Snapshot or Backup

### Option A: Restoring from an Automatic Write Snapshot (`.enc`)
To restore from an automatic snapshot file:

```bash
# Overwrite current database with snapshot
sec-agent restore ~/.config/sec-agent/backups/secrets_20260725_100000.enc --overwrite
```

### Option B: Restoring from a KeePassXC Backup (`.kdbx`)
To import secrets from a KeePassXC archive:

```bash
# Merge missing entries into existing vault without overwriting
sec-agent restore my_vault_backup.kdbx --merge

# Or overwrite active vault completely from backup
sec-agent restore my_vault_backup.kdbx --overwrite
```

---

## 🔁 Step 3: Restarting Daemon & Re-authenticating Session

After restoring a database snapshot or backup file, the background session daemon needs to reload memory state and re-authenticate:

1. **Restart the Session Daemon**:
   ```bash
   sec-agent restart
   ```
   *Action*: Clears in-process memory cache, stops socket listener, re-launches daemon process, and prompts for Touch ID verification.

2. **Re-authenticate Shell Session**:
   ```bash
   eval $(sec-agent open)
   ```
   *Action*: Obtains a fresh session authorization token for your active shell environment.

---

## 🤖 AI Assistant Emergency Troubleshooting Guide

If an AI coding assistant encounters database errors or uninitialized errors:
1. Verify if `sec-agent init` has been run.
2. If database is corrupted, advise the user to run `sec-agent backup list` and restore the latest snapshot.
3. Instruct the user to run `sec-agent restart` followed by `eval $(sec-agent open)`.
