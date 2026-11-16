## Why

When Touch ID (Slot 0) is invalidated — e.g. by a fingerprint re-enrollment after a
password reset — recovery depends entirely on the Slot 1 24-word BIP39 mnemonic.
Today that mnemonic is only ever displayed as a numbered 4-column grid, formatted
to encourage handwriting and discourage digital copy/paste. Users who want to
store the phrase in a durable, retrievable way (e.g. a password manager entry)
currently have to manually retype it word-by-word from the grid. Recovery input
(`sec session recover`) already accepts the mnemonic as a single space-separated
line — the generation side should offer the same shape so it can be captured
correctly in one pass.

## What Changes

- `sec migrate-v2` and `sec profile new` mnemonic-generation output ALWAYS also
  prints the 24 words as a single space-separated line, in addition to the
  existing 4-column grid.
- A new opt-out flag (e.g. `--no-single-line`) suppresses the single-line
  rendering for users who want the original grid-only, handwriting-oriented
  output.
- The 3-word manual verification step (positions #4, #12, #20) is unchanged and
  still required before the mnemonic is accepted, regardless of which display
  format(s) were shown.
- **Trade-off to document, not hide**: a single-line, copy/paste-shaped output
  is easier to route into a clipboard, clipboard-history tool, terminal
  scrollback, or password-manager field than a handwriting-oriented grid. That
  is the whole point of this change, but it does measurably widen the phrase's
  digital exposure surface compared to today's grid-only default. The relevant
  docs (`disaster_recovery_and_backups.md`, `operations_and_parameter_guide.md`,
  README) currently tell users to "write it on paper, do NOT photograph or copy
  it" — those sections need to be revised to acknowledge the new default rather
  than contradict it, while still steering users toward secure storage (typed
  directly into a password manager field, not via general OS clipboard) over
  screenshots or plaintext files.

## Capabilities

### New Capabilities
- `vault-recovery`: BIP39 recovery mnemonic generation, display formatting, and
  write-down verification behavior for `sec migrate-v2`, `sec profile new`, and
  `sec session recover`.

### Modified Capabilities
(none — no existing specs predate this change)

## Impact

- **Code**: `cmd/sec-agent/cmd_import_export.go` (`handleMigrateV2` mnemonic
  display block), `cmd/sec-agent/cmd_profile.go` (`handleProfileNew` mnemonic
  display block), `cmd/sec-agent/registry.go` (new `--no-single-line` flag),
  possibly a shared formatting helper in `internal/crypto/mnemonic.go`.
- **Docs**: `docs/disaster_recovery_and_backups.md`,
  `docs/operations_and_parameter_guide.md`, `README.md` — revise the
  "write it on paper, do not copy" guidance to reflect the new default and its
  trade-off.
- **Security posture**: default output becomes more copy/paste-friendly; the
  opt-out flag preserves today's grid-only behavior for users who prefer it.
- **No breaking change** to `sec session recover`'s input handling — it already
  accepts a single space-separated line.
