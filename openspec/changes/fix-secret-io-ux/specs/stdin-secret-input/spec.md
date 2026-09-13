## Purpose

Defines how `sec set --stdin` behaves when reading a secret value from
standard input, so an interactive user gets clear guidance and cannot
mistake the read-until-EOF wait for a hang, while piped/non-interactive
input continues to work exactly as before.

## ADDED Requirements

### Requirement: Interactive stdin reads are announced before blocking
When `sec set --stdin` (or `sec set <path> -`) is invoked and its standard
input is an interactive terminal, the system SHALL print an instructional
message describing how to finish input (end with EOF) and how to cancel,
before blocking to read the value.

#### Scenario: Interactive TTY stdin
- **WHEN** `sec set --stdin` is run with an interactive terminal attached to
  standard input
- **THEN** the system prints an instructional message (mentioning how to
  signal end-of-input and how to cancel) to the terminal before it starts
  waiting to read the secret value

#### Scenario: Piped/non-interactive stdin unaffected
- **WHEN** `sec set --stdin` is run with standard input piped from another
  process or redirected from a file
- **THEN** the system reads the value and completes without requiring or
  waiting on the interactive instructional message, matching existing
  piped behavior

### Requirement: Interactively typed stdin input is masked
When `sec set --stdin`'s standard input is an interactive terminal, the
system SHALL mask the typed/pasted input so the secret value is not echoed
to the screen or terminal scrollback, consistent with the masking already
applied by the tool's interactive password-prompt fallback.

#### Scenario: Secret typed directly into an interactive terminal
- **WHEN** a user types or pastes a secret value directly into `sec set
  --stdin` with an interactive terminal attached
- **THEN** the typed/pasted characters are not echoed in plaintext to the
  screen

### Requirement: Interactive stdin reads time out with an informative error
When waiting for interactive terminal input, `sec set --stdin` SHALL apply
a bounded timeout. If the timeout elapses before input is completed, the
system SHALL abort the read and report an informative error explaining
that the read timed out and how to retry (including the option to pipe
input instead).

#### Scenario: No input received before timeout
- **WHEN** `sec set --stdin` is waiting on an interactive terminal and no
  completed input is received before the timeout elapses
- **THEN** the system aborts the read, does not store a secret, and prints
  an error explaining the timeout and how to retry or pipe input instead

#### Scenario: Piped stdin is not subject to the interactive timeout
- **WHEN** `sec set --stdin` reads from a pipe or redirected file
- **THEN** the timeout applied to interactive terminal waits does not cause
  a piped read that completes normally to fail
