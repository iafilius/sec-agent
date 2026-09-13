## Purpose

Defines the contract for `sec status --all --json`: when `--json` is
requested, the command must emit structured, parseable JSON instead of
silently falling back to plain-text output.

## ADDED Requirements

### Requirement: `--json` produces machine-readable output
When `sec status --all` is invoked with `--json`, the system SHALL emit a
single JSON document to stdout representing the same information shown in
the plain-text table (profiles, environment tier, session status, stored
key counts, expired key counts, and per-profile namespace/group listings),
instead of the plain-text table format.

#### Scenario: `--json` flag requested
- **WHEN** `sec status --all --json` is run
- **THEN** the system's stdout output parses as valid JSON containing the
  per-profile status information

#### Scenario: `--json` flag omitted
- **WHEN** `sec status --all` is run without `--json`
- **THEN** the system continues to emit the existing human-readable
  plain-text table, unchanged
