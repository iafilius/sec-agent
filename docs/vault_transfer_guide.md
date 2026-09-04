# 📱 Vault Transfer & Multi-Device Portability Guide (`sec-agent`)

This guide explains how to transfer encrypted `sec-agent` profile vaults from one macOS laptop (or workstation) to another using your **24-word BIP39 recovery seed phrase**, and how automatic Touch ID hardware re-enrollment works on the destination device.

---

## 🏗️ Architecture: Dual-Slot Security Model

`sec-agent` v2.0+ uses a **Dual-Slot Vault Architecture** to balance hardware-bound security with full cross-device portability:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ~/.config/sec-agent/secrets_<profile>.enc                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ 🔒 Slot 0: macOS Keychain (Hardware-Bound)                                  │
│    └─ Master Key stored in Secure Enclave, protected by Touch ID.           │
│       (Local to Device A only)                                             │
│                                                                             │
│ 🗝️ Slot 1: BIP39 Mnemonic + Argon2id (Portable)                             │
│    └─ Master Key encrypted with key derived from 24-word seed phrase:       │
│       AES-256-GCM( Argon2id(24_words, salt), MasterKey )                    │
│       (Stays inside vault file — portable across any Mac/Linux device)       │
│                                                                             │
│ 📦 Payload: AES-256-GCM( MasterKey, EncryptedStore JSON )                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Step-by-Step Vault Transfer Walkthrough

```
       LAPTOP A (Source)                                      LAPTOP B (Destination)
 ┌──────────────────────────────┐                       ┌──────────────────────────────┐
 │ ~/.config/sec-agent/         │    Copy file over     │ ~/.config/sec-agent/         │
 │ secrets_velocloud-dev.enc ──┼──────────────────────▶│ secrets_velocloud-dev.enc    │
 └──────────────────────────────┘   (AirDrop/SCP/USB)   └──────────────┬───────────────┘
                                                                       │
                                                         Run: 'sec open --profile velocloud-dev'
                                                                       │
                                                         Laptop B Keychain has no key yet!
                                                                       │
                                                         Prompt: "Enter 24-word seed phrase"
                                                                       │
                                                         Argon2id unwraps MasterKey from Slot 1
                                                                       │
                                                         ✨ Enrolls MasterKey into Laptop B's
                                                            Touch ID / Keychain automatically!
```

---

### Step 1: Locate the Vault File on Laptop A
All vaults are stored in `~/.config/sec-agent/`:
- **Default Profile**: `~/.config/sec-agent/secrets.enc`
- **Named Profiles**: `~/.config/sec-agent/secrets_<profile>.enc` (e.g. `secrets_velocloud-provider-dev.enc`)

### Step 2: Transfer the Vault File to Laptop B
Copy the `.enc` file from Laptop A into `~/.config/sec-agent/` on Laptop B via your preferred secure transfer method:
- **AirDrop**
- **Secure Copy (SCP)**: `scp ~/.config/sec-agent/secrets_prod.enc user@laptop-b:~/.config/sec-agent/`
- **Encrypted USB drive** or **Private Git Repository**

> [!NOTE]
> Even if intercepted in transit, the vault file is 100% encrypted with AES-256-GCM and cannot be decrypted without the 24-word seed phrase.

### Step 3: Unlock Vault on Laptop B
On Laptop B, open your terminal and run:
```bash
sec open --profile <profile>
# Example:
sec open --profile velocloud-provider-dev
```

### Step 4: Enter 24-Word Seed Phrase for Initial Unwrapping
Because Laptop B's Keychain does not contain the vault's master key yet, `sec-agent` will automatically detect `Slot 1` and prompt:

```
🔑 Keychain entry not found for profile "velocloud-provider-dev".
Enter 24-word recovery seed phrase:
```

Carefully type your 24-word seed phrase.

### Step 5: Automatic Touch ID Re-Enrollment
Once the 24-word seed phrase is verified:
1. `sec-agent` uses `Argon2id` KDF to decrypt `Slot 1` and recover the master key.
2. It decrypts and verifies the vault payload.
3. **It automatically enrolls the master key into Laptop B's local macOS Keychain tied to Laptop B's Touch ID sensor!**

```
✅ Successfully unwrapped master key via Slot 1 (Argon2id).
✨ Enrolled master key into macOS Keychain for profile "velocloud-provider-dev".
🔓 Session unlocked (Daemon PID 12345).
```

### Step 6: Seamless Daily Touch ID Usage
From this point forward on Laptop B, opening the vault requires **Touch ID only**:
```bash
sec get VELOCLOUD_API_KEY
# 👆 Prompts for Touch ID on Laptop B!
```

---

## 🔍 Verification & Troubleshooting

### How to Check Master Key Fingerprint Parity Across Laptops
To verify that both Laptop A and Laptop B are using the exact same master key, run `sec snapshot` or inspect `sec audit`:

```bash
sec snapshot
```

Verify that the **`KEY SHA-256`** fingerprint (e.g. `sha256:ca8f0582`) matches across both laptops!

---

## 🛡️ Security Best Practices
1. **Never store seed phrases in plain text**: Store your 24-word seed phrase offline (e.g., printed on paper or stamped in metal in a secure vault).
2. **Device Isolation**: Removing a vault from Laptop A does not affect Laptop B. Each laptop maintains independent Touch ID hardware credentials bound to the shared vault envelope payload.
