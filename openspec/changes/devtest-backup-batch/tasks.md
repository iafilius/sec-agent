# Tasks

## 1. Batch storage

- [x] 1.1 Define the batch entry type with name, ordered jobs, and retry settings
- [x] 1.2 Store batch entries encrypted in the vault
- [x] 1.3 Exclude batch details from public job listings

## 2. Batch run

- [x] 2.1 Add a batch run command that refuses to start with a locked vault
- [x] 2.2 Build rsync arguments from structured job fields, resolving the date once per run
- [x] 2.3 Run jobs in defined order and record each result

## 3. Retry and keepalive

- [x] 3.1 Retry each failed job up to 5 attempts with doubling waits capped at 30 minutes
- [x] 3.2 Continue the batch after a job exhausts its attempts
- [x] 3.3 Keep the vault session valid for the duration of the batch
- [x] 3.4 Exit non-zero when any job failed

## 4. Verification

- [ ] 4.1 Test that a failing job retries with the expected waits and is then skipped
- [ ] 4.2 Test that a locked vault stops the run before any job starts
- [ ] 4.3 Test that the batch exit status reflects job failures

## 5. Documentation

- [ ] 5.1 Document how to define, run, and retry a batch
