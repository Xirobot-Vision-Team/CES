# EC227 reproducible development boundary

Tests in `construction/test_delivery_reconcile.py` reuse the **real EC225/EC226
Python source paths**, existing EC200–224 synthetic private-store fixtures,
full signed original payload/target, temporary 0700 local outbox and disposable
Ed25519 keys with a fake signed Provider + independent inbox observer. The
HMAC key is *ephemeral fixture material only*. They exercise explicit host
opt-in, durable start/result, accepted/inbox delivery separation, different
signed read nonces, replay and concurrent-lock denial, crash-like incomplete
writes, tamper/gaps/wrong HMAC, known-state conflicts and provider timeout.

Run from `construction/`: `python -m unittest -v test_delivery_reconcile`
with the local cryptography and jsonschema development dependencies available.
No real network, permission service, private inbox, enterprise PKI,
transactional FS durability proof or actual delivery occurs. A Python test
PASS is **not** a claim of deployed Provider, multihost race protection,
PowerShell/Smoke execution or final end-to-end acceptance.
