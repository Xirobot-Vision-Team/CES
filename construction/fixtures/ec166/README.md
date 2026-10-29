# EC166 focused synthetic fixtures

The EC166 development tests intentionally reuse the existing synthetic GH/GL
EC161/163 metadata responses and EC165 mock receipt constructor rather than
copying secrets, exposing real API payloads or creating a fake authenticated
Provider transcript. All test transport objects are injected and marked
synthetic; no network, native PowerShell, or remote write is invoked.

Run only the focused development scenarios (not the deferred final acceptance):

```bash
cd ces
python construction/test_proposed_pr_reconcile.py -q
```

Cases include complete metadata match, exact count drift with stable commit
OIDs, GitHub source/target ID transfers, GitLab `diff_refs` start/head
consistency, merged/status changes without merge proof, missing fork or Token,
count caps, missing provider diff refs, incompatible synthetic/live histories,
malformed/recomputed receipts, and previous patch secrecy. No tests certify
real provider permissions, provider-atomic snapshots or delivery.
