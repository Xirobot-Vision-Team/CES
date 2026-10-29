# EC235 targeted development fixtures (NOT customer acceptance)

`construction/test_cycle_permission_pause.py` creates synthetic input bytes in
actual temporary owner-private POSIX directories through the implemented
EC231 `CycleMetadataStore.create`, then calls the *real* EC234 budget guard,
EC233 route/EC232 DAG, and EC235 durable permission checkpoint. No fabricated
RunId JSON is imported as a live run and no real CodeSave/AI handler is called.

Exercises fresh pending and explicit declined-only persistence, process restart
read, original unexecuted inventory, exact CodeSave/ApprovePersist route,
missing permission, first-root ordering, dependency/cycle/AI/unimplemented
blocking, source and SHA drift, independent caller pins, budget refusal,
atomically exclusive create, concurrent duplicate attempts, same-user sidecar
mutation, symlink/hardlink refusal, partial-write uncertainty, CLI and strict
Draft 2020-12 positive/negative schema. Operator rejection is a synthetic,
**unverified** declaration, never an authenticated real user's consent.

Not OS crash tests, multi-machine locking, a privileged grant mechanism,
production native PowerShell7/15 Smoke or a real enterprise permission check.
All those tests are deferred to the final user-assisted acceptance stage.
