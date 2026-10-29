# EC206 disposable local fixture conventions

All source and candidate files are constructed under per-test `TemporaryDirectory`
by `construction/test_knowledge_candidate_store.py`; no production data, real
access grants, organizational keys or in-repo authoritative knowledge are written.

Cases include: private-empty 0700 store initialization; independent append,
restricted-content, restricted-provenance and read/list permission gates; actual atomic single-record
persistence and idempotent retry; immutable-key conflict; root/scope/period
binding; EC205 chapter association and EC204 exact selected-source intake;
manual assertions and unknown delivery; caller-supplied result consistency;
local record MAC/tamper/hardlink/symlink refusal; 5-thread same-key writes.
One optional integration case replays actual EC205 temporary Git/snapshot with
random ephemeral development Ed25519 signatures. No real org authority.

Run from `construction/`:

    python -m unittest -q test_knowledge_candidate_store.py

Native PowerShell7 and original 15 Smoke, live grants/delivery and production
cross-OS/NFS/performance/final-assisted checks remain deferred.
