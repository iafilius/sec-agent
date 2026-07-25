# sec-agent Disaster Recovery & Backup Restoration Handbook

This handbook details emergency procedures for inspecting backups, restoring vault databases, and re-authenticating sessions in `sec-agent` (v1.9.1+).

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
Search Path: /Users/arjan/.config/sec-agent/backups

Automatic Write Snapshots (.enc):
  • secrets_20260725_100000.enc  (4908 bytes, 2026-07-25 10:00:00)
    Path: /Users/arjan/.config/sec-agent/backups/secrets_20260725_100000.enc
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
