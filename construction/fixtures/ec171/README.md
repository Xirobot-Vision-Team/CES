# EC171 focused synthetic development cases

`construction/test_handoff_lifecycle.py` constructs bounded synthetic EC170 context
objects using earlier EC170 and EC165 test helpers. It creates real **ephemeral**
OS-random run/handoff IDs in the test process only. No fixture contains a
fabricated or fixed 'already created' ID, and no checkpoint here is evidence
of an externally executed or persisted AI job.

Run from `construction/`:

```bash
python -m unittest -q test_handoff_lifecycle.py
```

The cases cover WorkingTree/DeliveredTarget/ProposedPR source binding, actual
ID creation point, entropy/shape, forbidden skips/restarts, terminal outcomes,
explicit PARTIAL acknowledgement, declaration-only actor labels, CAS/concurrent
operations, duplicate/conflicting operation keys, source mixing, event chain,
strict JSON, serialized size and the unauthenticated-recovery quarantine. Native
PowerShell, live Provider, external AI and user-assisted end-to-end acceptance
are NOT_RUN.
