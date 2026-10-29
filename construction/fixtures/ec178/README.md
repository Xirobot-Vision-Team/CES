# EC178 — FindingSave synthetic development fixture coverage

This directory describes development-only focused cases implemented in
[`../test_finding_save.py`](../../test_finding_save.py). Fixtures use disposable
owner-private temp roots, **genuine** local EC170-177 Python builders and
where requested an actual separate EC176 HMAC metadata store, plus a synthetic
HMAC reviewer and injected fake candidate callback; they do not connect to a
real external AI provider, CI, real human identity, remote Git or native CLI.

## Executed offline functional areas (31 local cases)

- An independently authorized `FindingSaver.initialize` followed by real
  `save` publishes a POSIX CES-only HMAC-sealed batch; no code, source path,
  model claim text or review notes are stored. Repo bytes and source stage
  remain unchanged; aggregate-only independently gated inspect is supported.
- Per-Finding approved ID set, unknown/unapproved/duplicate ID rejection,
  multi-finding partial selection, immutable two-batch hash-linked append;
  same operation+payload returns stable no-write/no-TTL-renewal result;
  different op cannot re-save the same exact Finding ID.
- Explicit separate source/save grants, stage/business/store identity separation,
  symlink/hardlink refusal, unknown file and incomplete pending publication
  refusal, private-key mutation and batch tamper rejection.
- Genuine re-projection defeats copied unkeyed projection SHA, missing or
  altered EC175 HMAC reviewer authority, changed/expired sealed source,
  stale EC175 receipt, missing independent optional EC176 HMAC read grant.
- REVIEWED-by-default, optional dual acknowledgment for unreviewed/rejected/
  inconclusive (no semantic/test upgrade), independent historical ProposedPR
  and incomplete coverage save grants, preservation of counter-evidence
  anchor and caller interpretation *hashes only*.
- Concurrent calls against one private store publish exactly one batch, then
  replay; after-link fsync failure explicitly reports uncertain publish.
  Prior sequence deletion/tamper and expiry narrowing/renewal refusal fail
  closed. Signed batch matches JSON Schema Draft 2020-12; false CI flag fails
  structural schema validation.

## How to repeat this *local development* check

```sh
cd ces/construction
python -m unittest -q test_finding_save
```

Observed during EC178 authoring: **31/31 synthetic focused tests passed**.
This does not replace Windows/macOS and real Linux filesystem adversarial tests,
true power loss, independent key custody, real Git/Provider/CI/human review,
native PowerShell7, 15 frozen Smoke, E63-E66 or final assisted acceptance.
