## Purpose

Defines how `sec open` must report per-profile unlock outcomes, so its
output and exit code are never contradictory regardless of why a given
profile's unlock attempt failed.

## ADDED Requirements

### Requirement: Success banner reflects actual unlock outcome
The system SHALL print the "Session unlocked successfully" banner only
when at least one requested profile actually unlocked. It SHALL NOT print
that banner when every requested profile's unlock attempt failed,
regardless of the failure's cause (authentication failure, daemon IPC
error, corrupted keychain entry, security-gate denial, or any other
per-profile failure).

#### Scenario: Single profile fails to unlock
- **WHEN** `sec open` is run for a single profile and that profile's
  unlock attempt fails for any reason
- **THEN** the system does not print the "Session unlocked successfully"
  banner and does not export a session token

#### Scenario: Single profile unlocks successfully
- **WHEN** `sec open` is run for a single profile and that profile's
  unlock attempt succeeds
- **THEN** the system prints the "Session unlocked successfully" banner
  and exports the resulting session token

#### Scenario: Multiple profiles, at least one succeeds
- **WHEN** `sec open` is run for multiple profiles (e.g. the active
  profile plus a workspace-linked profile) and at least one unlocks
  successfully while another fails
- **THEN** the system prints the failure for the profile that failed, and
  still prints the success banner reflecting the profile(s) that actually
  unlocked

### Requirement: Exit code reflects actual unlock outcome
The system SHALL exit with a non-zero status when every requested profile
failed to unlock, and SHALL exit zero when at least one requested profile
unlocked successfully.

#### Scenario: All requested profiles fail
- **WHEN** every profile requested by `sec open` fails to unlock
- **THEN** the system exits with a non-zero status code

#### Scenario: At least one requested profile succeeds
- **WHEN** at least one profile requested by `sec open` unlocks
  successfully
- **THEN** the system exits with a zero status code
